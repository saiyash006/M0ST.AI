from typing import Dict, Any

try:
    from z3 import Int, Solver, sat
    _Z3_AVAILABLE = True
except ImportError:
    _Z3_AVAILABLE = False


class Z3Agent:
    """
    Lightweight symbolic solver for branch feasibility and expression solving.
    Supports simple arithmetic + comparison expressions.
    Falls back to always-feasible when z3 is not installed.
    """

    def _parse_expr(self, expr: str, vars: Dict[str, Any]):
        """
        Convert a simple Python-like expression to a Z3 expression.
        Example: "x + 5 == 10"
        """
        if not _Z3_AVAILABLE:
            return None
        tokens = expr.replace("==", " ==").replace("!=", " !=").split()
        for tok in tokens:
            if tok.isidentifier() and tok not in vars:
                vars[tok] = Int(tok)
        return eval(expr, {"__builtins__": None, "not": lambda x: __import__('z3').Not(x)}, vars)

    def check_branch_feasible(self, expr: str) -> bool:
        if not _Z3_AVAILABLE:
            return True  # Assume feasible when z3 is unavailable
        try:
            vars = {}
            z3expr = self._parse_expr(expr, vars)
            if z3expr is None:
                return True
            solver = Solver()
            solver.add(z3expr)
            return solver.check() == sat
        except Exception:
            return True

    def solve_expression(self, expr: str) -> Dict[str, int]:
        if not _Z3_AVAILABLE:
            return {}
        try:
            vars = {}
            z3expr = self._parse_expr(expr, vars)
            if z3expr is None:
                return {}
            solver = Solver()
            solver.add(z3expr)
            if solver.check() != sat:
                return {}
            model = solver.model()
            result = {}
            for v in vars:
                val = model[vars[v]]
                if val is not None:
                    result[str(v)] = val.as_long()
            return result
        except Exception:
            return {}
