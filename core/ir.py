from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class Instruction:
    addr: int
    mnemonic: str
    operands: List[str]

@dataclass
class BasicBlock:
    addr: int
    instructions: List[Instruction] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)

@dataclass
class FunctionIR:
    name: str
    addr: int
    basic_blocks: List[BasicBlock] = field(default_factory=list)

    def get_block(self, addr: int) -> Optional[BasicBlock]:
        for bb in self.basic_blocks:
            if bb.addr == addr:
                return bb
        return None
