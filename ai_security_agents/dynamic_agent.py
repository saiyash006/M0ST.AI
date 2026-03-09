import os
import platform
import shutil
from typing import Dict, List, Optional, Tuple

from core.capabilities import Capability
from core.config import get_config

try:
    from pygdbmi.gdbcontroller import GdbController
    _PYGDBMI_AVAILABLE = True
except ImportError:
    _PYGDBMI_AVAILABLE = False


class DynamicAgent:
    """
    Executes the binary in a controlled environment.
    Uses gdb for step-by-step tracing to capture register states,
    memory changes, and executed basic blocks.
    """
    CAPABILITIES = {Capability.DYNAMIC_EXECUTE}

    def __init__(self, graph_store, bus=None):
        self.g = graph_store
        self.bus = bus

    def run(self, binary_path: str, run_id: str = "run_1"):
        if not _PYGDBMI_AVAILABLE:
            print("[DynamicAgent] pygdbmi is not installed. Install it for dynamic tracing.")
            print("[DynamicAgent] Skipping dynamic trace.")
            if self.bus is not None:
                self.bus.publish("DYNAMIC_TRACE_READY", {"run_id": run_id, "binary": binary_path})
            return

        if not os.path.isfile(binary_path):
            print(f"[DynamicAgent] Binary not found: {binary_path}")
            if self.bus is not None:
                self.bus.publish("DYNAMIC_TRACE_READY", {"run_id": run_id, "binary": binary_path})
            return

        gdb_path = get_config().get("tools", {}).get("gdb_path") or "gdb"
        if not shutil.which(gdb_path):
            print(f"[DynamicAgent] GDB not found at '{gdb_path}'. Skipping dynamic trace.")
            if self.bus is not None:
                self.bus.publish("DYNAMIC_TRACE_READY", {"run_id": run_id, "binary": binary_path})
            return

        if platform.system() == "Windows":
            print("[DynamicAgent] GDB-based tracing is not supported natively on Windows. Skipping.")
            if self.bus is not None:
                self.bus.publish("DYNAMIC_TRACE_READY", {"run_id": run_id, "binary": binary_path})
            return

        bb_addrs = self.g.fetch_all_basic_blocks()
        if not bb_addrs:
            return

        self.g.create_run(run_id, binary_path)

        gdbmi = None
        try:
            gdbmi = GdbController(command=[gdb_path, "--interpreter=mi2", binary_path])
            self._send_cmd(gdbmi, "-gdb-set pagination off")
            self._send_cmd(gdbmi, "-gdb-set confirm off")

            for addr in bb_addrs:
                self._send_cmd(gdbmi, f"-break-insert *0x{addr:x}")

            self._send_cmd(gdbmi, "-exec-run")

            reg_names = self._get_register_names(gdbmi)
            seen_blocks = set()
            last_bb = None
            seq = 0
            pending_stop = None
            pending_from_step = False
            bb_set = set(bb_addrs)
            non_bb_hits = 0

            while True:
                stop = pending_stop or self._wait_for_stop(gdbmi)
                from_step = pending_from_step
                pending_stop = None
                pending_from_step = False
                if stop is None:
                    break
                reason = stop.get("reason")
                if self._is_exit_reason(reason):
                    break
                if reason not in {"breakpoint-hit", "end-stepping-range", "signal-received"}:
                    continue

                pc = self._parse_addr(stop)
                if pc is None:
                    pc = self._read_pc(gdbmi)
                if pc is None:
                    continue
                if pc not in bb_set:
                    non_bb_hits += 1
                    if non_bb_hits > 8:
                        self._send_cmd(gdbmi, "-exec-continue")
                    else:
                        self._send_cmd(gdbmi, "-exec-step-instruction")
                    continue
                non_bb_hits = 0

                regs = self._get_register_values(gdbmi, reg_names)
                self._record_syscall_if_any(run_id, seq, pc, regs, gdbmi)
                next_pc, pending_stop = self._step_for_next_pc(gdbmi)
                pending_from_step = pending_stop is not None

                self.g.add_executes_edge(
                    run_id=run_id, bb_addr=pc, seq=seq, pc=pc,
                    next_pc=next_pc if next_pc is not None else pc, regs=regs,
                )
                if last_bb is not None:
                    self.g.add_runtime_flow(
                        run_id=run_id, src_bb=last_bb, dst_bb=pc, seq=seq, pc=pc,
                        next_pc=next_pc if next_pc is not None else pc, regs=regs,
                    )

                seq += 1
                if pc in seen_blocks and not from_step:
                    break
                seen_blocks.add(pc)
                last_bb = pc

                if pending_stop is None:
                    self._send_cmd(gdbmi, "-exec-continue")

        finally:
            if gdbmi is not None:
                try:
                    gdbmi.exit()
                except Exception:
                    pass

        if self.bus is not None:
            self.bus.publish("DYNAMIC_TRACE_READY", {"run_id": run_id, "binary": binary_path})

    def _send_cmd(self, gdbmi, cmd: str):
        gdbmi.write(cmd)

    def _wait_for_stop(self, gdbmi, timeout_sec: float = 1.0):
        while True:
            responses = gdbmi.get_gdb_response(timeout_sec=timeout_sec)
            if not responses:
                return None
            for resp in responses:
                if resp.get("type") == "notify" and resp.get("message") == "stopped":
                    payload = resp.get("payload", {})
                    if isinstance(payload, dict):
                        return payload

    def _parse_addr(self, stop_payload: Dict) -> Optional[int]:
        frame = stop_payload.get("frame")
        if not isinstance(frame, dict):
            return None
        addr = frame.get("addr")
        if isinstance(addr, str):
            try:
                return int(addr, 16)
            except Exception:
                return None
        if isinstance(addr, int):
            return addr
        return None

    def _read_pc(self, gdbmi) -> Optional[int]:
        gdbmi.write("-data-evaluate-expression $pc")
        responses = gdbmi.get_gdb_response(timeout_sec=1.0)
        for resp in responses:
            if resp.get("type") == "result" and resp.get("message") == "done":
                payload = resp.get("payload", {})
                value = payload.get("value")
                if isinstance(value, str):
                    try:
                        return int(value, 0)
                    except Exception:
                        return None
        return None

    def _get_register_names(self, gdbmi) -> List[str]:
        gdbmi.write("-data-list-register-names")
        responses = gdbmi.get_gdb_response(timeout_sec=1.0)
        for resp in responses:
            if resp.get("type") == "result" and resp.get("message") == "done":
                payload = resp.get("payload", {})
                names = payload.get("register-names")
                if isinstance(names, list):
                    return [n for n in names if isinstance(n, str)]
        return []

    def _get_register_values(self, gdbmi, reg_names: List[str]) -> Dict:
        gdbmi.write("-data-list-register-values x")
        responses = gdbmi.get_gdb_response(timeout_sec=1.0)
        for resp in responses:
            if resp.get("type") == "result" and resp.get("message") == "done":
                payload = resp.get("payload", {})
                values = payload.get("register-values")
                if not isinstance(values, list):
                    return {}
                regs = {}
                for item in values:
                    if not isinstance(item, dict):
                        continue
                    idx = item.get("number")
                    val = item.get("value")
                    if isinstance(idx, str):
                        try:
                            idx = int(idx, 10)
                        except Exception:
                            continue
                    if isinstance(idx, int) and idx < len(reg_names):
                        name = reg_names[idx]
                        regs[name] = val
                return regs
        return {}

    def _step_for_next_pc(self, gdbmi) -> Tuple[Optional[int], Optional[Dict]]:
        self._send_cmd(gdbmi, "-exec-step-instruction")
        stop = self._wait_for_stop(gdbmi)
        if stop is None:
            return None, None
        next_pc = self._parse_addr(stop)
        if next_pc is None:
            next_pc = self._read_pc(gdbmi)
        if stop.get("reason") == "breakpoint-hit":
            return next_pc, stop
        if stop.get("reason") == "signal-received":
            return next_pc, None
        return next_pc, None

    def _is_exit_reason(self, reason: Optional[str]) -> bool:
        if not reason:
            return False
        return reason.startswith("exited")

    def _record_syscall_if_any(self, run_id: str, seq: int, pc: int, regs: Dict, gdbmi):
        insn = self._read_current_instruction(gdbmi)
        if not insn:
            return
        text = insn.lower()
        if "syscall" in text:
            self._emit_syscall_event(run_id, seq, pc, regs)
            return
        if "int" in text and "0x80" in text:
            self._emit_syscall_event(run_id, seq, pc, regs)

    def _read_current_instruction(self, gdbmi) -> Optional[str]:
        gdbmi.write("-data-disassemble -s $pc -e $pc+1 -- 0")
        responses = gdbmi.get_gdb_response(timeout_sec=1.0)
        for resp in responses:
            if resp.get("type") == "result" and resp.get("message") == "done":
                payload = resp.get("payload", {})
                asm = payload.get("asm_insns")
                if isinstance(asm, list) and asm:
                    insn = asm[0]
                    if isinstance(insn, dict):
                        return insn.get("inst")
        return None

    def _emit_syscall_event(self, run_id: str, seq: int, pc: int, regs: Dict):
        syscall_num = self._read_reg(regs, ["rax", "eax"])
        args = [
            self._read_reg(regs, ["rdi", "edi"]),
            self._read_reg(regs, ["rsi", "esi"]),
            self._read_reg(regs, ["rdx", "edx"]),
            self._read_reg(regs, ["r10"]),
            self._read_reg(regs, ["r8"]),
            self._read_reg(regs, ["r9"]),
        ]
        if syscall_num is None:
            return
        self.g.add_syscall_event(run_id, seq, pc, syscall_num, args)

    def _read_reg(self, regs: Dict, names: List[str]) -> Optional[int]:
        for name in names:
            val = regs.get(name)
            if isinstance(val, str):
                try:
                    return int(val, 0)
                except Exception:
                    return None
            if isinstance(val, int):
                return val
        return None
