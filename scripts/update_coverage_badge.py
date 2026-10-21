import configparser
import shlex
from pathlib import Path


def _read_fail_under(pytest_ini_path):
    config = configparser.ConfigParser(interpolation=None)
    config.read_string(pytest_ini_path.read_text(encoding="utf-8"))
    arguments = iter(shlex.split(config.get("pytest", "addopts", fallback="")))
    target = None
    for argument in arguments:
        if argument == "--cov-fail-under":
            value = next(arguments, "")
        elif argument.startswith("--cov-fail-under="):
            value = argument.split("=", 1)[1]
        else:
            continue
        target = float(value)
        if not 0 <= target <= 100:
            raise ValueError("Coverage target must be between 0 and 100")
    return target


def _badge_line(target):
    label = "coverage%20target"
    color = "yellow" if target < 70 else "green"
    return f"![Coverage Target](https://img.shields.io/badge/{label}-{target:g}%25-{color})"


def update_readme(readme_path, target):
    lines = readme_path.read_text(encoding="utf-8").splitlines()
    badge = _badge_line(target) if target is not None else None
    out = []
    replaced = False
    for line in lines:
        if line.startswith("![Coverage Target]"):
            if badge:
                out.append(badge)
            replaced = True
        else:
            out.append(line)
    if badge and not replaced:
        for idx, line in enumerate(out):
            if line.startswith("# "):
                out.insert(idx + 1, "")
                out.insert(idx + 2, badge)
                break
        else:
            out[0:0] = [badge, ""]
    if badge is None and not replaced:
        return
    readme_path.write_text("\n".join(out) + "\n", encoding="utf-8")


def main():
    root = Path(__file__).resolve().parents[1]
    pytest_ini = root / "pytest.ini"
    readme = root / "README.md"

    target = _read_fail_under(pytest_ini)
    if target is None:
        print("No coverage target is configured; removing any stale target badge.")
    else:
        print(
            f"Updating configured coverage target to {target:g}% (not measured coverage)."
        )

    update_readme(readme, target)


if __name__ == "__main__":
    main()
