"""Static checks: the scanner never executes, evaluates, or dynamically imports anything."""

import ast
import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"

BANNED_MODULES = frozenset(
    {
        "subprocess",
        "runpy",
        "pty",
        "ctypes",
        "multiprocessing",
        "code",
        "codeop",
        "pickle",
    }
)
# importlib is allowed only for reading packaged data files and the package's own version.
ALLOWED_IMPORTLIB = frozenset({"importlib.resources", "importlib.metadata"})
BANNED_BUILTINS = frozenset({"eval", "exec", "compile", "__import__", "breakpoint"})
BANNED_ATTRS = {
    "os": ("system", "popen", "exec", "spawn", "posix_spawn", "fork", "startfile"),
    "importlib": ("import_module", "util", "machinery", "reload"),
    # Only yaml.safe_load: yaml.load and friends can construct arbitrary objects.
    "yaml": (
        "load",
        "unsafe_load",
        "full_load",
        "load_all",
        "unsafe_load_all",
        "full_load_all",
    ),
}


def violations(source: str) -> list[str]:
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in BANNED_MODULES:
                    found.append(f"import {alias.name}")
                if top == "importlib" and alias.name not in ALLOWED_IMPORTLIB:
                    found.append(f"import {alias.name}")
        elif isinstance(node, ast.ImportFrom) and node.module:
            top = node.module.split(".")[0]
            if top in BANNED_MODULES:
                found.append(f"from {node.module} import")
            if top == "importlib":
                for alias in node.names:
                    full = (
                        f"{node.module}.{alias.name}"
                        if node.module == "importlib"
                        else node.module
                    )
                    if full not in ALLOWED_IMPORTLIB:
                        found.append(f"from {node.module} import {alias.name}")
            if node.module == "os":
                for alias in node.names:
                    if alias.name.startswith(BANNED_ATTRS["os"]):
                        found.append(f"from os import {alias.name}")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in BANNED_BUILTINS:
                found.append(f"{node.func.id}()")
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            prefixes = BANNED_ATTRS.get(node.value.id)
            if prefixes and node.attr.startswith(prefixes):
                found.append(f"{node.value.id}.{node.attr}")
    return found


def test_src_never_executes_or_dynamically_imports():
    hits = {
        str(p.relative_to(SRC)): v
        for p in SRC.rglob("*.py")
        if (v := violations(p.read_text(encoding="utf-8")))
    }
    assert not hits, hits


@pytest.mark.parametrize(
    "snippet",
    [
        "import subprocess",
        "from subprocess import run",
        "import os\nos.system('x')",
        "import os\nos.execv('x', [])",
        "from os import popen",
        "eval('1')",
        "exec('x = 1')",
        "__import__('x')",
        "import importlib\nimportlib.import_module('x')",
        "from importlib import import_module",
        "import importlib.util",
        "import yaml\nyaml.load('x', Loader=None)",
        "import runpy",
    ],
)
def test_checker_catches_each_banned_pattern(snippet):
    # Guards the guard: the checker must not silently pass everything.
    assert violations(snippet)


def test_checker_allows_resources_and_safe_load():
    assert not violations(
        "from importlib import resources\nimport importlib.resources\n"
        "import yaml\nyaml.safe_load('a: 1')"
    )


# httpx settings that would weaken TLS, read proxy/netrc credentials from the
# environment, or follow redirects without the per-hop host check.
FORBIDDEN_SETTINGS = {"verify": False, "trust_env": True, "follow_redirects": True}


def unsafe_http_settings(source: str) -> list[str]:
    found = []

    def bad(name: object, value: ast.AST) -> bool:
        return (
            isinstance(name, str)
            and name in FORBIDDEN_SETTINGS
            and isinstance(value, ast.Constant)
            and value.value is FORBIDDEN_SETTINGS[name]
        )

    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.keyword) and bad(node.arg, node.value):
            found.append(f"{node.arg}={node.value.value}")
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Attribute) and bad(target.attr, node.value):
                    found.append(f".{target.attr} = {node.value.value}")
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=True):
                if isinstance(key, ast.Constant) and bad(key.value, value):
                    found.append(f"{{{key.value!r}: {value.value}}}")
    return found


def test_src_never_weakens_http_settings():
    hits = {
        str(p.relative_to(SRC)): v
        for p in SRC.rglob("*.py")
        if (v := unsafe_http_settings(p.read_text(encoding="utf-8")))
    }
    assert not hits, hits


@pytest.mark.parametrize(
    "snippet",
    [
        "httpx.AsyncClient(verify=False)",
        "httpx.AsyncClient(trust_env=True)",
        "httpx.AsyncClient(follow_redirects=True)",
        "client.get(url, follow_redirects=True)",
        "client.follow_redirects = True",
        "client.trust_env = True",
        "httpx.AsyncClient(**{'verify': False})",
    ],
)
def test_http_settings_checker_catches(snippet):
    assert unsafe_http_settings(snippet)


# stdout carries only the protocol (JSON-RPC over stdio); logs go to stderr.
_STDOUT_WRITE = re.compile(r"\bprint\s*\(|\bsys\.(?:__stdout__|stdout)\b")


def test_src_never_writes_to_stdout():
    hits = {
        f"{p.relative_to(SRC)}:{n}": line.strip()
        for p in SRC.rglob("*.py")
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        if _STDOUT_WRITE.search(line)
    }
    assert not hits, hits


@pytest.mark.parametrize(
    "snippet", ["print('x')", "print (x)", "sys.stdout.write('x')", "sys.__stdout__"]
)
def test_stdout_checker_catches(snippet):
    assert _STDOUT_WRITE.search(snippet)


def test_http_settings_checker_allows_safe_values():
    assert not unsafe_http_settings(
        "httpx.AsyncClient(verify=True, trust_env=False, follow_redirects=False)"
    )
