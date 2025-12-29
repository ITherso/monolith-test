from pathlib import Path


HOOK = """#!/bin/sh
if git diff --cached --name-only | grep -q "^pytest.ini$"; then
  python3 scripts/update_coverage_badge.py
  git add README.md
fi
"""


def main():
    root = Path(__file__).resolve().parents[1]
    hooks_dir = root / ".git" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / "pre-commit"
    hook_path.write_text(HOOK, encoding="utf-8")
    hook_path.chmod(0o755)


if __name__ == "__main__":
    main()
