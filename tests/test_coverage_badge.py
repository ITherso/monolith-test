"""Coverage-target maintenance checks with temporary files and no repo imports."""

import importlib.util
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def badge_script():
    # Loading by path avoids scripts/__init__.py and all application packages.
    spec = importlib.util.spec_from_file_location(
        "isolated_coverage_badge", ROOT / "scripts/update_coverage_badge.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_badge_workflow_is_manual_and_uses_only_stdlib_script():
    workflow = yaml.load(
        (ROOT / ".github/workflows/update-badge.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    assert set(workflow["on"]) == {"workflow_dispatch"}
    job = workflow["jobs"]["update-badge"]
    assert job["permissions"] == {"contents": "write"}
    script_step = next(
        step for step in job["steps"] if step.get("name") == "Update badge"
    )
    assert script_step["run"].strip() == "python3 scripts/update_coverage_badge.py"


@pytest.mark.parametrize(
    "options,target",
    [
        ("--cov-fail-under=45", 45),
        ("--cov-fail-under 72.5", 72.5),
        ("--cov-fail-under=0", 0),
        ("--cov-fail-under=100", 100),
    ],
)
def test_reads_real_configured_target(tmp_path, badge_script, options, target):
    config = tmp_path / "pytest.ini"
    config.write_text(f"[pytest]\naddopts = -q {options}\n", encoding="utf-8")
    assert badge_script._read_fail_under(config) == target


def test_commented_example_is_not_a_coverage_target(tmp_path, badge_script):
    config = tmp_path / "pytest.ini"
    config.write_text(
        "[pytest]\n# --cov-fail-under=99\naddopts = -q\n", encoding="utf-8"
    )
    assert badge_script._read_fail_under(config) is None


@pytest.mark.parametrize("value", ["-1", "101", "nan", "inf", "invalid", ""])
def test_invalid_targets_fail_instead_of_publishing_badges(
    tmp_path, badge_script, value
):
    config = tmp_path / "pytest.ini"
    config.write_text(
        f"[pytest]\naddopts = --cov-fail-under={value}\n", encoding="utf-8"
    )
    with pytest.raises(ValueError):
        badge_script._read_fail_under(config)


def test_updates_target_badge_without_claiming_measured_coverage(
    tmp_path, badge_script
):
    readme = tmp_path / "README.md"
    readme.write_text("# Example\n\nBody\n", encoding="utf-8")
    badge_script.update_readme(readme, 72.5)
    result = readme.read_text(encoding="utf-8")
    assert "coverage%20target-72.5%25-green" in result
    assert "Body" in result
    badge_script.update_readme(readme, 45)
    result = readme.read_text(encoding="utf-8")
    assert result.count("![Coverage Target]") == 1
    assert "coverage%20target-45%25-yellow" in result


def test_no_configured_target_removes_stale_claim(tmp_path, badge_script):
    readme = tmp_path / "README.md"
    readme.write_text(
        "# Example\n" + badge_script._badge_line(99) + "\nBody\n", encoding="utf-8"
    )
    badge_script.update_readme(readme, None)
    assert readme.read_text(encoding="utf-8") == "# Example\nBody\n"


def test_no_target_or_badge_leaves_readme_untouched(tmp_path, badge_script):
    readme = tmp_path / "README.md"
    original = "<h1>Example</h1>\nBody without final newline"
    readme.write_text(original, encoding="utf-8")
    badge_script.update_readme(readme, None)
    assert readme.read_text(encoding="utf-8") == original


def test_adds_badge_to_readme_with_html_heading(tmp_path, badge_script):
    readme = tmp_path / "README.md"
    readme.write_text("<h1>Example</h1>\nBody\n", encoding="utf-8")
    badge_script.update_readme(readme, 45)
    assert readme.read_text(encoding="utf-8").startswith("![Coverage Target]")


def test_main_with_no_threshold_makes_no_false_coverage_claim(
    tmp_path, badge_script, capsys
):
    (tmp_path / "scripts").mkdir()
    badge_script.__file__ = str(tmp_path / "scripts/update_coverage_badge.py")
    (tmp_path / "pytest.ini").write_text("[pytest]\naddopts = -q\n", encoding="utf-8")
    readme = tmp_path / "README.md"
    readme.write_text("# Example\n", encoding="utf-8")
    badge_script.main()
    assert readme.read_text(encoding="utf-8") == "# Example\n"
    assert "No coverage target is configured" in capsys.readouterr().out
