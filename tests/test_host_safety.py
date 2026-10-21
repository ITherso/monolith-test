"""Host-protection checks; never import an operational package or launch a command."""

import ast
import builtins
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def safety_module(
    os_name="nt", sys_platform="win32", release="Windows", environment=None
):
    spec = importlib.util.spec_from_file_location(
        "isolated_host_safety", ROOT / "cyberapp/host_safety.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    environment = environment or {}
    module.os = SimpleNamespace(name=os_name, getenv=environment.get)
    module.sys = SimpleNamespace(platform=sys_platform)
    module.platform = SimpleNamespace(release=lambda: release)
    return module


@pytest.mark.parametrize(
    "os_name,sys_platform,release,environment",
    [
        ("nt", "win32", "Windows", {}),
        ("nt", "linux", "Linux", {}),
        ("posix", "win32", "Linux", {}),
        ("posix", "cygwin", "CYGWIN_NT", {}),
        ("posix", "msys", "MSYS_NT", {}),
        ("posix", "linux", "Linux", {"WSL_INTEROP": "/run/WSL/1_interop"}),
        ("posix", "linux", "Linux", {"WSL_DISTRO_NAME": "test"}),
        ("posix", "linux", "5.15.0-microsoft-standard-WSL2", {}),
    ],
)
def test_windows_and_wsl_fail_closed(os_name, sys_platform, release, environment):
    module = safety_module(os_name, sys_platform, release, environment)
    with pytest.raises(RuntimeError, match="HOST_SAFETY_BLOCK"):
        module.enforce_host_safety()


def test_environment_flags_cannot_disable_the_guard():
    module = safety_module(
        environment={"MONOLITH_SAFE_MODE": "false", "ALLOW_UNSAFE_EXECUTION": "1"}
    )
    with pytest.raises(RuntimeError, match="HOST_SAFETY_BLOCK"):
        module.enforce_host_safety()


@pytest.mark.parametrize(
    "path",
    [
        "cyber.py",
        "wsgi.py",
        "cyberapp/app.py",
        "cyberapp/routes/__init__.py",
        "cybermodules/__init__.py",
        "evasion/__init__.py",
        "tools/__init__.py",
        "agents/__init__.py",
        "monolith/__init__.py",
        "cyberapp/workers/__init__.py",
        "c2/__init__.py",
        "scripts/__init__.py",
        "tools/purple_team_validator.py",
    ],
)
def test_entrypoint_stops_before_any_feature_import(path):
    guard = safety_module()
    imports = []

    def restricted_import(name, globals=None, locals=None, fromlist=(), level=0):
        imports.append(name)
        if name == "cyberapp.host_safety":
            return guard
        raise AssertionError(
            f"A feature import was attempted before the protection stop: {name}"
        )

    namespace = {"__builtins__": dict(vars(builtins), __import__=restricted_import)}
    code = compile((ROOT / path).read_text(encoding="utf-8"), path, "exec")
    with pytest.raises(RuntimeError, match="HOST_SAFETY_BLOCK"):
        exec(code, namespace)
    assert imports == ["cyberapp.host_safety"]


def test_cli_stops_before_importing_app_or_worker():
    tree = ast.parse((ROOT / "cyberapp/cli.py").read_text(encoding="utf-8"))
    main = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "main"
    )
    guard = safety_module()

    def restricted_import(name, *args, **kwargs):
        if name == "cyberapp.host_safety":
            return guard
        raise AssertionError(f"CLI tried to import {name} before the protection stop")

    namespace = {"__builtins__": dict(vars(builtins), __import__=restricted_import)}
    exec(
        compile(ast.Module(body=[main], type_ignores=[]), "isolated_cli", "exec"),
        namespace,
    )
    with pytest.raises(RuntimeError, match="HOST_SAFETY_BLOCK"):
        namespace["main"]()


def test_real_atomic_execution_is_disabled_even_when_called_directly():
    path = ROOT / "tools/purple_team_validator.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    cls = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "TestExecutor"
    )
    method = next(
        node
        for node in cls.body
        if isinstance(node, ast.FunctionDef) and node.name == "_real_execution"
    )
    module = ast.Module(
        body=[
            ast.ImportFrom(
                module="__future__", names=[ast.alias(name="annotations")], level=0
            ),
            method,
        ],
        type_ignores=[],
    )

    def forbidden_command(*args, **kwargs):
        raise AssertionError("A local command must never be launched")

    namespace = {"subprocess": SimpleNamespace(run=forbidden_command)}
    exec(compile(ast.fix_missing_locations(module), str(path), "exec"), namespace)
    with pytest.raises(RuntimeError, match="Local atomic-test execution is disabled"):
        namespace["_real_execution"](
            None, SimpleNamespace(executor="cmd", command="unused")
        )
