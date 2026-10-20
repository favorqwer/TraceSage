import ast
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PACKAGE = ROOT / "provenance"

# 只允许依赖左边列出的包；main.py 是装配根，不参与检查。
ALLOWED = {
    "provenance.core": {"provenance.core"},
    "provenance.graph": {"provenance.core", "provenance.graph"},
    "provenance.runtime": {"provenance.core", "provenance.graph", "provenance.runtime"},
    "provenance.adapters": {"provenance.core", "provenance.adapters"},
    "provenance.settings": {"provenance.core", "provenance.settings"},
}


def _module(path: Path) -> str:
    return ".".join(path.relative_to(ROOT).with_suffix("").parts)


def _resolve_import(path: Path, node: ast.ImportFrom) -> str:
    if node.level == 0:
        return node.module or ""
    package = _module(path).split(".")[:-1]
    package = package[: len(package) - (node.level - 1)]
    module = node.module.split(".") if node.module else []
    return ".".join(package + module)


class ArchitectureTest(unittest.TestCase):
    def test_dependency_direction(self):
        violations = []
        for path in PACKAGE.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            module = _module(path)
            owner = next(
                (name for name in ALLOWED if module == name or module.startswith(name + ".")),
                None,
            )
            if owner is None:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    target = _resolve_import(path, node)
                elif isinstance(node, ast.Import):
                    target = node.names[0].name
                else:
                    continue
                if not target.startswith("provenance."):
                    continue
                if target == "provenance":
                    continue
                if not any(
                    target == allowed or target.startswith(allowed + ".")
                    for allowed in ALLOWED[owner]
                ):
                    violations.append(f"{module} -> {target}")
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
