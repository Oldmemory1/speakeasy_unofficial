"""Each upper-case int constant of speakeasy has one definition, so two copies cannot get different values."""

import ast
from collections import defaultdict
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent.parent / "speakeasy"
if not PACKAGE.is_dir():
    # A resolved copy can be run outside the checkout; inspect the package that
    # the test process imported instead of silently scanning an empty directory.
    import speakeasy

    PACKAGE = Path(speakeasy.__file__).resolve().parent

# Local extensions that deliberately keep their own copy of a Windows constant:
# the page-protection / process-memory helpers, the diagnostic modules, the PE
# compat layer and the win32 emulator are standalone modules that must not
# import the winenv definition tables. These duplicates are documented local
# extensions (FX-001/003/004/005/009/016), not merge drift; their values are
# pinned by their own tests. Any other duplicate is still a failure.
LOCAL_EXTENSION_DUPLICATES: dict[str, set[str]] = {
    "DEFAULT_PAGE_SIZE": {"speakeasy/windows/page_protection.py", "speakeasy/windows/process_memory.py"},
    "ERROR_INVALID_ADDRESS": {"speakeasy/windows/page_protection.py", "speakeasy/winenv/defs/windows/windows.py"},
    "ERROR_INVALID_WINDOW_HANDLE": {
        "speakeasy/winenv/api/usermode/user32.py",
        "speakeasy/winenv/defs/windows/windows.py",
    },
    "ERROR_NOACCESS": {"speakeasy/windows/process_memory.py", "speakeasy/winenv/defs/windows/windows.py"},
    "IMAGE_FILE_MACHINE_AMD64": {"speakeasy/windows/pe_compat.py", "speakeasy/winenv/defs/windows/windows.py"},
    "IMAGE_FILE_MACHINE_I386": {"speakeasy/windows/pe_compat.py", "speakeasy/winenv/defs/windows/windows.py"},
    "MAX_TEXT_BYTES": {
        "speakeasy/windows/module_trace_diagnostics.py",
        "speakeasy/windows/page_trace_diagnostics.py",
    },
    "MAX_TEXT_CHARS": {
        "speakeasy/windows/api_name_resolution_diagnostics.py",
        "speakeasy/windows/api_trace_diagnostics.py",
        "speakeasy/windows/module_trace_diagnostics.py",
        "speakeasy/windows/page_trace_diagnostics.py",
    },
    "PAGE_GUARD": {"speakeasy/windows/page_protection.py", "speakeasy/winenv/defs/windows/windows.py"},
    "PAGE_NOCACHE": {"speakeasy/windows/page_protection.py", "speakeasy/winenv/defs/windows/windows.py"},
    "PAGE_SIZE": {"speakeasy/windows/common.py", "speakeasy/winenv/arch.py"},
    "PAGE_WRITECOMBINE": {"speakeasy/windows/page_protection.py", "speakeasy/winenv/defs/windows/windows.py"},
    "PAGE_WRITECOPY": {"speakeasy/windows/page_protection.py", "speakeasy/winenv/defs/windows/windows.py"},
    "SCHEMA_VERSION": {
        "speakeasy/windows/api_diagnostics.py",
        "speakeasy/windows/api_name_resolution_diagnostics.py",
        "speakeasy/windows/api_trace_diagnostics.py",
        "speakeasy/windows/module_trace_diagnostics.py",
        "speakeasy/windows/page_trace_diagnostics.py",
    },
    "SIGFPE": {"speakeasy/winenv/api/usermode/msvcrt.py", "speakeasy/winenv/defs/windows/windows.py"},
    "SIGILL": {"speakeasy/winenv/api/usermode/msvcrt.py", "speakeasy/winenv/defs/windows/windows.py"},
    "SIGSEGV": {"speakeasy/winenv/api/usermode/msvcrt.py", "speakeasy/winenv/defs/windows/windows.py"},
    "S_OK": {"speakeasy/winenv/defs/windows/com.py", "speakeasy/winenv/defs/windows/windows.py"},
    "UNLIMITED_API_CALLS": {"speakeasy/windows/win32.py", "speakeasy/windows/winemu.py"},
    "WSAEFAULT": {"speakeasy/winenv/api/usermode/ws2_32.py", "speakeasy/winenv/defs/winsock/winsock.py"},
}


def is_int_expression(node: ast.expr) -> bool:
    if isinstance(node, ast.Constant):
        return type(node.value) is int
    if isinstance(node, ast.UnaryOp):
        return is_int_expression(node.operand)
    if isinstance(node, ast.BinOp):
        return is_int_expression(node.left) and is_int_expression(node.right)
    return isinstance(node, ast.Name) and node.id.isupper()


def get_duplicate_constants(package: Path) -> dict[str, list[str]]:
    locations = defaultdict(list)
    for path in sorted(package.rglob("*.py")):
        for statement in ast.parse(path.read_text(encoding="utf-8")).body:
            if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
                continue
            target = statement.targets[0]
            if isinstance(target, ast.Name) and target.id.isupper() and is_int_expression(statement.value):
                locations[target.id].append(f"{path.relative_to(package.parent)}:{statement.lineno}")
    return {name: places for name, places in locations.items() if len(places) > 1}


def unexpected_duplicates(duplicates: dict[str, list[str]]) -> dict[str, list[str]]:
    """Keep only duplicates that the local-extension allowlist does not cover."""
    unexpected = {}
    for name, places in duplicates.items():
        allowed = LOCAL_EXTENSION_DUPLICATES.get(name, set())
        extra = [place for place in places if place.split(":", 1)[0] not in allowed]
        if extra:
            unexpected[name] = places
    return unexpected


def test_constants_have_one_definition() -> None:
    assert unexpected_duplicates(get_duplicate_constants(PACKAGE)) == {}
