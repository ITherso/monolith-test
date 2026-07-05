import re
from pathlib import Path


def _read_fail_under(pytest_ini_path):
    content = pytest_ini_path.read_text(encoding="utf-8")
    match = re.search(r"--cov-fail-under=(\d+)", content)
    if not match:
        return None
    return int(match.group(1))


def _badge_line(target):
    label = "coverage%20target"
    color = "yellow" if target < 70 else "green"
    return f"![Coverage Target](https://img.shields.io/badge/{label}-{target}%25-{color})"


def update_readme(readme_path, target):
    lines = readme_path.read_text(encoding="utf-8").splitlines()
    badge = _badge_line(target)
    out = []
    replaced = False
    for line in lines:
        if line.startswith("![Coverage Target]"):
            out.append(badge)
            replaced = True
        else:
            out.append(line)
    if not replaced:
        for idx, line in enumerate(out):
            if line.startswith("# "):
                out.insert(idx + 1, "")
                out.insert(idx + 2, badge)
                break
    readme_path.write_text("\n".join(out) + "\n", encoding="utf-8")


def main():
    root = Path(__file__).resolve().parents[1]
    pytest_ini = root / "pytest.ini"
    readme = root / "README.md"

    target = _read_fail_under(pytest_ini)
    if target is None:
        raise SystemExit("Could not find --cov-fail-under in pytest.ini")

    update_readme(readme, target)


if __name__ == "__main__":
    main()
