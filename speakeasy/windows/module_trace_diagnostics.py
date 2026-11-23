"""Read-only module/unload trace diagnostics for FX-004.

The FX-004 work item (``Loader / loadlibrary``, diagnostic mode) combines three
failure mechanisms whose reports currently stop at ``last_api``:

* ``LdrUnloadDll`` has no handler in this engine; it is emulated from the
  bundled phnt signature, whose ``i32`` default return is 0
  (``STATUS_SUCCESS``) even though no module is unloaded.  ``FreeLibrary``
  returns TRUE and also leaves the module table unchanged.  The report needs
  the argument, the return value, whether the module table actually changed,
  and the caller registers that later participate in address computation.
* ``GetModuleHandleExW`` may miss the module table and return 0 (NULL), which a
  caller can mistake for a module base.  The report needs flags (including
  ``FROM_ADDRESS``), the module-name argument, the ``phModule`` write-back,
  the module table and the miss reason.
* Packer samples drop a PE to the emulated filesystem, ``LoadLibraryA`` it and
  resolve exports with ``GetProcAddress``.  The report needs the synthetic
  module's base/size/loader and per-section mapping/readability, plus the
  resolved target's mapping/module/section provenance and sentinel membership.

This module adds *evidence*, never behaviour.  Every builder is read-only,
bounded and best effort; failures are logged at debug level and never raise
into an API handler.  Handler return values, module tables, page permissions,
exception dispatch and control flow are not changed.  Observations are stored
in ``ctx["_api_observation"]`` (the existing ``ApiEvent.observation`` report
field); ``merge_key`` nests the observation inside a pre-existing one (FX-015
already attaches a ``scatter_diagnostic`` to ``FreeLibrary``).

Observation contract
--------------------
* Every observation is a JSON-safe ``dict`` with
  ``kind="module_trace_diagnostic"`` and ``schema_version=SCHEMA_VERSION``.
* Module tables are bounded by ``MAX_MODULES``, sections by ``MAX_SECTIONS``,
  memory probes by ``MAX_PROBE_BYTES``; truncation is reported explicitly.
* Unknown inputs produce explicit fields (``available=False``,
  ``mapped=False``, ``readable=False``, ``null`` values) rather than guesses.
* No sample/address/family special cases, no environment variables, no
  configuration switches, no guest memory writes.

Applicable architecture: pointer-size driven x86/AMD64.  Focused caller
registers are EAX/EBX/ECX/EDX (x64: RAX/RBX/RCX/RDX).
"""

from __future__ import annotations

import json
import logging
import ntpath
import os
from typing import Any

import speakeasy.winenv.arch as _arch
from speakeasy.windows import api_diagnostics, api_trace_diagnostics

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
OBSERVATION_KIND = "module_trace_diagnostic"

MAX_MODULES = 32
MAX_SECTIONS = 24
MAX_PROBE_BYTES = 32
MAX_TEXT_BYTES = 64
MAX_TEXT_CHARS = 256

_FOCUSED_X86 = ("eax", "ebx", "ecx", "edx")
_FOCUSED_X64 = ("rax", "rbx", "rcx", "rdx")

#: Signature-only APIs whose semantics are "unload a module".  The engine has
#: no handler for these; the signature fallback's default i32 return is 0.
_UNLOAD_SIGNATURE_APIS = frozenset({"ldrunloaddll"})

_GET_MODULE_HANDLE_EX_FLAGS = {
    0x1: "GET_MODULE_HANDLE_EX_FLAG_PIN",
    0x2: "GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT",
    0x4: "GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS",
}

_NTSTATUS_NAMES = {
    0x0: "STATUS_SUCCESS",
    0x80000000: "STATUS_UNSUCCESSFUL",
    0xC0000005: "STATUS_ACCESS_VIOLATION",
    0xC000000D: "STATUS_INVALID_PARAMETER",
    0xC0000135: "STATUS_DLL_NOT_FOUND",
}


def hex_value(value: Any) -> str | None:
    """Render an integer (including bool) as a hex string, else ``None``."""
    return api_trace_diagnostics.hex_value(value)


def _int_value(value: Any) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    return None


def _parse_hex(value: Any) -> int | None:
    if isinstance(value, str):
        try:
            return int(value, 16)
        except ValueError:
            return None
    return _int_value(value)


def _bounded_text(value: Any) -> str | None:
    if value is None:
        return None
    try:
        text = str(value).replace("\x00", "")
        text = text.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    except Exception:
        return None
    return text[:MAX_TEXT_CHARS]


def _status_name(value: Any) -> str | None:
    status = _int_value(value)
    if status is None:
        return None
    return _NTSTATUS_NAMES.get(status & 0xFFFFFFFF)


def _safe_attr(obj: Any, name: str) -> Any:
    try:
        return getattr(obj, name, None)
    except Exception:
        return None


def _safe_call(obj: Any, name: str) -> Any:
    method = getattr(obj, name, None)
    if not callable(method):
        return None
    try:
        return method()
    except Exception:
        logger.debug("module trace diagnostic: %s failed", name, exc_info=True)
        return None


def _pointer_size(emu: Any) -> int:
    try:
        return int(emu.get_ptr_size())
    except Exception:
        logger.debug("module trace diagnostic: pointer size unavailable", exc_info=True)
        return 0


def _module_name(module: Any) -> str | None:
    base_name = _safe_call(module, "get_base_name")
    if isinstance(base_name, str) and base_name:
        return _bounded_text(base_name)
    return _bounded_text(_safe_attr(module, "name"))


def _module_base(module: Any) -> int | None:
    return _int_value(_safe_attr(module, "base"))


def _module_size(module: Any) -> int | None:
    value = _int_value(_safe_attr(module, "image_size"))
    if value is None:
        value = _int_value(_safe_attr(module, "_image_size"))
    return value


def _loader_class(module: Any) -> str | None:
    loader = _safe_attr(module, "loader")
    if loader is None:
        return None
    return type(loader).__name__


def module_entry(emu: Any, module: Any) -> dict[str, Any] | None:
    """Describe one loaded module without touching it.

    Returns ``None`` for an unknown module.  ``name`` is the module's base file
    name (``kernel32.dll``) and ``module_name`` the engine's internal name.
    """
    if module is None:
        return None
    base = _module_base(module)
    size = _module_size(module)
    entry: dict[str, Any] = {
        "name": _module_name(module),
        "module_name": _bounded_text(_safe_attr(module, "name")),
        "emu_path": _bounded_text(_safe_attr(module, "emu_path")),
        "base": hex_value(base),
        "image_size": hex_value(size),
        "end": hex_value(base + size) if base is not None and size is not None else None,
        "module_type": _bounded_text(_safe_attr(module, "module_type")),
        "loader": _loader_class(module),
        "visible_in_peb": bool(_safe_attr(module, "visible_in_peb")),
        "entry_point": hex_value(
            base + _int_value(_safe_attr(module, "ep"))
            if base is not None and _int_value(_safe_attr(module, "ep")) is not None
            else None
        ),
    }
    for flag in ("exe", "dll", "driver", "decoy"):
        is_flag = getattr(module, f"is_{flag}", None)
        entry[f"is_{flag}"] = bool(is_flag()) if callable(is_flag) else None
    return entry


def _modules(emu: Any) -> list[Any]:
    modules = _safe_attr(emu, "modules")
    if not isinstance(modules, (list, tuple)):
        return []
    return list(modules)


def module_table(emu: Any, *, limit: int = MAX_MODULES) -> dict[str, Any]:
    """Snapshot the loaded-module table (name/base/size/type/loader)."""
    modules = _modules(emu)
    entries: list[dict[str, Any]] = []
    for module in modules[: max(0, limit)]:
        entry = module_entry(emu, module)
        if entry is not None:
            entries.append(entry)
    return {
        "available": True,
        "count": len(modules),
        "limit": limit,
        "truncated": len(modules) > len(entries),
        "modules": entries,
    }


def _safe_read(emu: Any, address: Any, size: int = MAX_PROBE_BYTES) -> dict[str, Any]:
    """Best-effort bounded memory read; failures become explicit fields."""
    address_int = _int_value(address)
    if address_int is None or address_int < 0 or size <= 0:
        return {"available": False, "error": "invalid_address", "preview": None}
    try:
        data = bytes(emu.mem_read(address_int, min(size, MAX_PROBE_BYTES)))
    except Exception as exc:
        return {"available": False, "error": type(exc).__name__, "preview": None}
    return {"available": True, "error": None, "preview": data.hex()}


def _header_probe(emu: Any, module: Any) -> dict[str, Any]:
    """Read the module's first bytes: an unreadable header is explicit."""
    base = _module_base(module)
    read = _safe_read(emu, base, MAX_PROBE_BYTES)
    return {
        "readable": read["available"],
        "preview": read["preview"],
        "error": read["error"],
    }


def _section_name(module: Any, address: int) -> str | None:
    base = _module_base(module)
    if base is None:
        return None
    offset = address - base
    sections = _safe_attr(module, "sections") or []
    for section in sections:
        va = _int_value(_safe_attr(section, "virtual_address"))
        vs = _int_value(_safe_attr(section, "virtual_size"))
        if va is None or vs is None:
            continue
        if va <= offset < va + vs:
            return _bounded_text(_safe_attr(section, "name"))
    return None


def _section_trace_entry(emu: Any, module: Any, section: Any) -> dict[str, Any]:
    base = _module_base(module)
    va = _int_value(_safe_attr(section, "virtual_address"))
    vs = _int_value(_safe_attr(section, "virtual_size"))
    start = base + va if base is not None and va is not None else None
    end = start + vs if start is not None and vs is not None else None
    perms = _int_value(_safe_attr(section, "perms"))
    protection = None
    if perms is not None:
        try:
            from speakeasy.windows.loaders import get_prot_string

            protection = get_prot_string(perms)
        except Exception:
            protection = None
    read = _safe_read(emu, start, 8) if start is not None else {"available": False, "error": None}
    return {
        "name": _bounded_text(_safe_attr(section, "name")),
        "virtual_address": hex_value(va),
        "virtual_size": hex_value(vs),
        "start": hex_value(start),
        "end": hex_value(end),
        "perms": hex_value(perms),
        "protection": protection,
        "mapping": api_diagnostics.address_map_info(emu, start) if start is not None else {"mapped": False},
        "readable": read["available"],
    }


def section_trace(emu: Any, module: Any, *, limit: int = MAX_SECTIONS) -> list[dict[str, Any]]:
    """Describe each section's mapped span, permissions and readability."""
    if module is None:
        return []
    sections = _safe_attr(module, "sections") or []
    trace: list[dict[str, Any]] = []
    for section in list(sections)[: max(0, limit)]:
        try:
            trace.append(_section_trace_entry(emu, module, section))
        except Exception:
            logger.debug("module trace diagnostic: section trace failed", exc_info=True)
    return trace


def module_detail(emu: Any, module: Any, *, limit: int = MAX_SECTIONS) -> dict[str, Any] | None:
    """Describe one module including header and per-section mapping evidence."""
    entry = module_entry(emu, module)
    if entry is None:
        return None
    sections = _safe_attr(module, "sections") or []
    entry["header"] = _header_probe(emu, module)
    entry["sections"] = section_trace(emu, module, limit=limit)
    entry["sections_truncated"] = len(sections) > len(entry["sections"])
    return entry


def _module_for_handle(emu: Any, handle: Any) -> Any | None:
    """Resolve an HMODULE to a loaded module (Windows: handle == load base)."""
    handle_int = _int_value(handle)
    if not handle_int:
        return None
    for module in _modules(emu):
        if _module_base(module) == handle_int:
            return module
    return None


def _module_for_address(emu: Any, address: Any) -> Any | None:
    """Resolve an address inside ``[base, base+image_size)`` to a module."""
    address_int = _int_value(address)
    if address_int is None or address_int <= 0:
        return None
    for module in _modules(emu):
        base = _module_base(module)
        size = _module_size(module)
        if base is None or size is None or size <= 0:
            continue
        if base <= address_int < base + size:
            return module
    return None


def _pointer_origin(emu: Any, value: Any) -> dict[str, Any]:
    """Compact provenance for one pointer value (register/argument)."""
    value_int = _int_value(value)
    origin: dict[str, Any] = {
        "value": hex_value(value_int),
        "mapped": False,
        "map_tag": None,
        "module": None,
        "module_offset": None,
        "section": None,
        "readable": False,
    }
    if value_int is None or value_int <= 0:
        return origin
    try:
        mapping = api_diagnostics.address_map_info(emu, value_int)
    except Exception:
        mapping = {"mapped": False}
    origin["mapped"] = bool(mapping.get("mapped"))
    origin["map_tag"] = mapping.get("tag")
    module = _module_for_address(emu, value_int)
    if module is not None:
        base = _module_base(module)
        origin["module"] = _module_name(module)
        if base is not None:
            origin["module_offset"] = hex_value(value_int - base)
        origin["section"] = _section_name(module, value_int)
    origin["readable"] = _safe_read(emu, value_int, 8)["available"]
    return origin


def address_provenance(emu: Any, address: Any, *, probe_size: int = MAX_PROBE_BYTES) -> dict[str, Any]:
    """Describe an address: mapping, loaded module, section and readability."""
    address_int = _int_value(address)
    result: dict[str, Any] = {
        "address": hex_value(address_int),
        "mapping": api_diagnostics.address_map_info(emu, address_int)
        if address_int is not None
        else {"mapped": False, "address": None},
        "module": None,
        "section": None,
        "readable": False,
        "read_probe": None,
        "read_error": None,
    }
    if address_int is None or address_int <= 0:
        return result
    module = _module_for_address(emu, address_int)
    if module is not None:
        result["module"] = module_entry(emu, module)
        base = _module_base(module)
        result["module_offset"] = hex_value(address_int - base) if base is not None else None
        result["section"] = _section_name(module, address_int)
    read = _safe_read(emu, address_int, probe_size)
    result["readable"] = read["available"]
    result["read_probe"] = read["preview"]
    result["read_error"] = read["error"]
    return result


def _register_names(emu: Any) -> tuple[str, ...]:
    try:
        arch = emu.get_arch()
    except Exception:
        return ()
    if arch == _arch.ARCH_X86:
        return _FOCUSED_X86
    if arch == _arch.ARCH_AMD64:
        return _FOCUSED_X64
    return ()


def registers_snapshot(emu: Any) -> dict[str, str | None]:
    """Return the focused caller registers as hex strings (best effort)."""
    snapshot: dict[str, str | None] = {}
    for name in _register_names(emu):
        try:
            snapshot[name] = hex_value(emu.reg_read(name))
        except Exception:
            logger.debug("module trace diagnostic: register %s unavailable", name, exc_info=True)
            snapshot[name] = None
    return snapshot


def register_provenance(emu: Any, names: tuple[str, ...] | None = None) -> dict[str, Any]:
    """Map each focused register value to its mapping/module/section origin."""
    provenance: dict[str, Any] = {}
    registers = registers_snapshot(emu)
    for name in names or tuple(registers):
        if name not in registers:
            continue
        provenance[name] = _pointer_origin(emu, _parse_hex(registers[name]))
    return provenance


def caller_context(emu: Any, *, call_pc: Any = None) -> dict[str, Any]:
    """Snapshot the caller PC/return address/stack pointer and registers."""
    context: dict[str, Any] = {
        "pc": hex_value(_safe_call(emu, "get_pc")),
        "prev_pc": hex_value(_safe_attr(emu, "prev_pc")),
        "return_address": hex_value(_safe_call(emu, "get_ret_address")),
        "stack_pointer": hex_value(_safe_call(emu, "get_stack_ptr")),
        "registers": registers_snapshot(emu),
        "register_provenance": register_provenance(emu),
    }
    if call_pc is not None:
        context["call_pc"] = hex_value(call_pc)
    return context


def _read_text(emu: Any, address: Any, char_width: int) -> str | None:
    """Best-effort bounded C-string preview for an ANSI/UTF-16 API argument."""
    address_int = _int_value(address)
    if address_int is None or address_int <= 0 or char_width not in (1, 2):
        return None
    try:
        data = bytes(emu.mem_read(address_int, MAX_TEXT_BYTES))
    except Exception:
        return None
    if char_width == 1:
        raw = data.split(b"\x00", 1)[0]
        return _bounded_text(raw.decode("utf-8", "replace"))
    text = data.decode("utf-16le", "replace").split("\x00", 1)[0]
    return _bounded_text(text)


def _normalized_module_name(text: Any) -> str | None:
    name = _bounded_text(text)
    if not name:
        return None
    base = ntpath.basename(name)
    stem, _ = os.path.splitext(base)
    return _bounded_text(stem)


def _observation(api_name: str | None, domain: str, handler: str | None) -> dict[str, Any]:
    return {
        "kind": OBSERVATION_KIND,
        "schema_version": SCHEMA_VERSION,
        "api": api_name,
        "domain": domain,
        "handler": handler,
    }


def _log_observation(observation: dict[str, Any]) -> None:
    if not logger.isEnabledFor(logging.INFO):
        return
    try:
        logger.info(
            "module-trace-diagnostic %s",
            json.dumps(observation, ensure_ascii=False, sort_keys=True),
        )
    except Exception:
        logger.debug("module trace diagnostic: observation not JSON-serializable", exc_info=True)


def attach(ctx: dict[str, Any] | None, observation: dict[str, Any] | None, *, merge_key: str | None = None) -> None:
    """Attach one observation without affecting handler behaviour.

    When ``merge_key`` is set and the context already carries an observation
    (FX-015's ``scatter_diagnostic`` on ``FreeLibrary``), the module trace is
    nested under that key so the pre-existing report fields are preserved.
    """
    if not isinstance(ctx, dict) or not isinstance(observation, dict):
        return
    try:
        existing = ctx.get("_api_observation")
        if merge_key and isinstance(existing, dict):
            existing[merge_key] = observation
        else:
            ctx["_api_observation"] = observation
        _log_observation(observation)
    except Exception:
        logger.debug("module trace diagnostic: observation attachment failed", exc_info=True)


def _api_name(ctx: Any, fallback: str) -> str:
    if isinstance(ctx, dict):
        name = ctx.get("func_name")
        if isinstance(name, str) and name:
            return name
    return fallback


def _pointer_view(emu: Any, address: Any) -> dict[str, Any]:
    address_int = _int_value(address)
    ptr_size = _pointer_size(emu)
    if address_int is None or address_int <= 0 or ptr_size <= 0:
        return {"available": False, "value": None, "error": "invalid_address"}
    try:
        data = bytes(emu.mem_read(address_int, ptr_size))
    except Exception as exc:
        return {"available": False, "value": None, "error": type(exc).__name__}
    return {"available": True, "value": int.from_bytes(data, "little"), "error": None}


# ---------------------------------------------------------------------------
# Unload: FreeLibrary handler and signature-emulated LdrUnloadDll
# ---------------------------------------------------------------------------


def start_unload(
    emu: Any,
    ctx: dict[str, Any] | None,
    argv: Any,
    *,
    handler: str = "kernel32.FreeLibrary",
    argument_name: str = "h_lib_module",
) -> dict[str, Any] | None:
    """Snapshot an unload call: handle, matched module and module table."""
    try:
        values = list(argv or ())
        handle = _int_value(values[0]) if values else None
        module = _module_for_handle(emu, handle)
        observation = _observation(_api_name(ctx, handler), "loader_unload", handler)
        table = module_table(emu)
        observation.update(
            {
                "arguments": {
                    "argument_name": argument_name,
                    argument_name: hex_value(handle),
                    "handle": hex_value(handle),
                },
                "module_before": module_entry(emu, module),
                "module_table_before": table,
                "module_count_before": table["count"],
                "caller": caller_context(emu),
                "return_value": None,
                "return_status": None,
                "module_table_after": None,
                "module_present_after": None,
                "module_unloaded": None,
                "miss_reason": None if module is not None else "handle_not_in_module_table",
            }
        )
        attach(ctx, observation, merge_key="module_unload_trace")
        return observation
    except Exception:
        logger.debug("module trace diagnostic: unload snapshot failed", exc_info=True)
        return None


def finish_unload(
    emu: Any,
    ctx: dict[str, Any] | None,
    observation: dict[str, Any] | None,
    *,
    return_value: Any,
) -> dict[str, Any] | None:
    """Record the unload return value and the post-call module table."""
    if not isinstance(observation, dict):
        return None
    try:
        arguments = observation.get("arguments")
        handle = arguments.get("handle") if isinstance(arguments, dict) else None
        module_before = observation.get("module_before")
        module_after = _module_for_handle(emu, _parse_hex(handle))
        table = module_table(emu)
        observation["module_table_after"] = table
        observation["module_present_after"] = module_after is not None
        observation["module_unloaded"] = bool(module_before is not None and module_after is None)
        observation["return_value"] = hex_value(return_value)
        observation["return_status"] = _status_name(return_value)
        attach(ctx, observation, merge_key="module_unload_trace")
    except Exception:
        logger.debug("module trace diagnostic: unload finish failed", exc_info=True)
    return observation


def signature_call_observation(
    emu: Any,
    dll: Any,
    name: Any,
    sig: Any,
    argv: Any,
    return_value: Any,
    call_pc: Any,
) -> dict[str, Any] | None:
    """Describe a signature-emulated unload call (``LdrUnloadDll``).

    Returns ``None`` for every other signature-emulated API so unrelated
    observations are unchanged.  The engine performs no module mutation on
    this path; ``unload_implemented=False`` records that explicitly next to
    the success-like i32 default return.
    """
    try:
        api_name = f"{dll}.{name}"
        if str(name).lower() not in _UNLOAD_SIGNATURE_APIS:
            return None
        values = list(argv or ())
        handle = _int_value(values[0]) if values else None
        module = _module_for_handle(emu, handle)
        params = list(_safe_attr(sig, "params") or [])
        argument_name = _bounded_text(_safe_attr(params[0], "name")) if params else None
        observation = _observation(api_name, "loader_unload", None)
        table = module_table(emu)
        observation.update(
            {
                "emulated_from_signature": True,
                "signature_source": _bounded_text(_safe_attr(sig, "source")),
                "signature_return_kind": _bounded_text(_safe_attr(sig, "ret_kind")),
                "arguments": {
                    "argument_name": argument_name or "DllHandle",
                    "dll_handle": hex_value(handle),
                    "handle": hex_value(handle),
                },
                "module_before": module_entry(emu, module),
                "module_table": table,
                "module_count": table["count"],
                "module_present_at_call": module is not None,
                "caller": caller_context(emu, call_pc=call_pc),
                "return_value": hex_value(return_value),
                "return_status": _status_name(return_value),
                "unload_implemented": False,
                "miss_reason": None if module is not None else "handle_not_in_module_table",
            }
        )
        # Signature-emulated APIs have no handler context to attach to; the
        # observation is returned to winemu for the ApiEvent, and the log line
        # is the only out-of-band record when a report serializes a digest.
        _log_observation(observation)
        return observation
    except Exception:
        logger.debug("module trace diagnostic: signature unload observation failed", exc_info=True)
        return None


# ---------------------------------------------------------------------------
# GetModuleHandleEx
# ---------------------------------------------------------------------------


def _flag_names(flags: int | None) -> list[str]:
    if flags is None:
        return []
    return [name for bit, name in _GET_MODULE_HANDLE_EX_FLAGS.items() if flags & bit]


def start_get_module_handle_ex(
    emu: Any,
    ctx: dict[str, Any] | None,
    argv: Any,
    char_width: int = 1,
) -> dict[str, Any] | None:
    """Snapshot ``GetModuleHandleEx`` arguments, flags and module table."""
    try:
        values = list(argv or ())
        while len(values) < 3:
            values.append(None)
        flags, lp_module_name, ph_module = values[:3]
        flags_int = _int_value(flags)
        from_address = bool(flags_int is not None and flags_int & 0x4)
        module_name_kind = "address" if from_address else ("name" if lp_module_name else "null")
        decoded = None if from_address else _read_text(emu, lp_module_name, char_width)
        address_module = (
            module_entry(emu, _module_for_address(emu, lp_module_name)) if from_address else None
        )
        observation = _observation(
            _api_name(ctx, "kernel32.GetModuleHandleEx"),
            "loader_module_handle",
            "kernel32.GetModuleHandleEx",
        )
        observation.update(
            {
                "flags": hex_value(flags_int),
                "flags_names": _flag_names(flags_int),
                "from_address": from_address,
                "lp_module_name_raw": hex_value(_int_value(lp_module_name)),
                "lp_module_name": decoded,
                "module_name_kind": module_name_kind,
                "address_module": address_module,
                # The handler passes lpModuleName to the string-name path in
                # every case; FROM_ADDRESS callers therefore need this marker.
                "handler_treats_address_as_name": bool(from_address),
                "module_table_before": module_table(emu),
                "caller": caller_context(emu),
                "ph_module": hex_value(_int_value(ph_module)),
                "return_value": None,
                "ph_module_written": None,
                "ph_module_read_error": None,
                "module_found": None,
                "module": None,
                "miss_reason": None,
            }
        )
        attach(ctx, observation)
        return observation
    except Exception:
        logger.debug("module trace diagnostic: GetModuleHandleEx snapshot failed", exc_info=True)
        return None


def finish_get_module_handle_ex(
    emu: Any,
    ctx: dict[str, Any] | None,
    observation: dict[str, Any] | None,
    *,
    return_value: Any,
    ph_module_written: Any = None,
) -> dict[str, Any] | None:
    """Record the HMODULE result, ``phModule`` write-back and miss reason."""
    if not isinstance(observation, dict):
        return None
    try:
        return_int = _int_value(return_value)
        module = _module_for_handle(emu, return_int)
        observation["return_value"] = hex_value(return_int)
        observation["module_found"] = bool(return_int)
        observation["module"] = module_entry(emu, module)
        if ph_module_written is not None:
            observation["ph_module_written"] = hex_value(ph_module_written)
        else:
            read = _pointer_view(emu, _parse_hex(observation.get("ph_module")))
            observation["ph_module_written"] = hex_value(read["value"]) if read["available"] else None
            observation["ph_module_read_error"] = read["error"]
        if return_int:
            observation["miss_reason"] = None
        elif observation.get("from_address"):
            observation["miss_reason"] = "address_not_in_module_table"
        else:
            observation["miss_reason"] = "name_not_in_module_table"
        attach(ctx, observation)
    except Exception:
        logger.debug("module trace diagnostic: GetModuleHandleEx finish failed", exc_info=True)
    return observation


# ---------------------------------------------------------------------------
# LoadLibrary
# ---------------------------------------------------------------------------


def start_load_library(
    emu: Any,
    ctx: dict[str, Any] | None,
    argv: Any,
    char_width: int = 1,
    normalized_name: str | None = None,
) -> dict[str, Any] | None:
    """Snapshot a ``LoadLibrary`` request and the pre-call module table."""
    try:
        values = list(argv or ())
        lib_name = values[0] if values else None
        requested = _read_text(emu, lib_name, char_width)
        observation = _observation(_api_name(ctx, "kernel32.LoadLibrary"), "loader_load", "kernel32.LoadLibrary")
        observation.update(
            {
                "lp_lib_file_name_raw": hex_value(_int_value(lib_name)),
                "lp_lib_file_name": requested,
                "normalized_name": _bounded_text(normalized_name) or _normalized_module_name(requested),
                "module_table_before": module_table(emu),
                "caller": caller_context(emu),
                "return_value": None,
                "module_loaded": None,
                "loaded_module": None,
                "miss_reason": None,
            }
        )
        attach(ctx, observation)
        return observation
    except Exception:
        logger.debug("module trace diagnostic: LoadLibrary snapshot failed", exc_info=True)
        return None


def finish_load_library(
    emu: Any,
    ctx: dict[str, Any] | None,
    observation: dict[str, Any] | None,
    *,
    return_value: Any,
) -> dict[str, Any] | None:
    """Record the HMODULE result and the loaded module's section mapping."""
    if not isinstance(observation, dict):
        return None
    try:
        return_int = _int_value(return_value)
        module = _module_for_handle(emu, return_int)
        table = module_table(emu)
        observation["return_value"] = hex_value(return_int)
        observation["module_loaded"] = module is not None
        observation["loaded_module"] = module_detail(emu, module)
        if module is not None:
            observation["miss_reason"] = None
        elif not return_int:
            observation["miss_reason"] = "returned_null"
        else:
            observation["miss_reason"] = "handle_not_in_module_table"
        observation["module_table_after"] = table
        attach(ctx, observation)
    except Exception:
        logger.debug("module trace diagnostic: LoadLibrary finish failed", exc_info=True)
    return observation


# ---------------------------------------------------------------------------
# GetProcAddress
# ---------------------------------------------------------------------------


def start_get_proc_address(
    emu: Any,
    ctx: dict[str, Any] | None,
    argv: Any,
    char_width: int = 1,
) -> dict[str, Any] | None:
    """Snapshot an export lookup: module handle, name and module table."""
    try:
        values = list(argv or ())
        while len(values) < 2:
            values.append(None)
        h_module, proc_name = values[:2]
        h_module_int = _int_value(h_module)
        module = _module_for_handle(emu, h_module_int)
        ordinal = None
        decoded = None
        if isinstance(proc_name, int) and not isinstance(proc_name, bool) and 0 <= proc_name < 0x10000:
            ordinal = proc_name
        else:
            decoded = _read_text(emu, proc_name, char_width)
        observation = _observation(
            _api_name(ctx, "kernel32.GetProcAddress"),
            "loader_get_proc_address",
            "kernel32.GetProcAddress",
        )
        observation.update(
            {
                "h_module": hex_value(h_module_int),
                "module_handle_kind": (
                    "null" if not h_module_int else ("base" if module is not None else "unknown")
                ),
                "module": module_entry(emu, module),
                "lp_proc_name_raw": hex_value(_int_value(proc_name)),
                "lp_proc_name": decoded,
                "ordinal": ordinal,
                "module_table_before": module_table(emu),
                "caller": caller_context(emu),
                "return_value": None,
                "export_found": None,
                "export": None,
                "resolved_is_sentinel": None,
                "sentinel_target": None,
                "target": None,
                "module_header": None,
                "module_sections": None,
                "miss_reason": None,
            }
        )
        attach(ctx, observation)
        return observation
    except Exception:
        logger.debug("module trace diagnostic: GetProcAddress snapshot failed", exc_info=True)
        return None


def finish_get_proc_address(
    emu: Any,
    ctx: dict[str, Any] | None,
    observation: dict[str, Any] | None,
    *,
    return_value: Any,
) -> dict[str, Any] | None:
    """Record export resolution, sentinel membership and target provenance."""
    if not isinstance(observation, dict):
        return None
    try:
        return_int = _int_value(return_value)
        module = _module_for_handle(emu, _parse_hex(observation.get("h_module")))
        proc_name = observation.get("lp_proc_name")
        export = None
        if module is not None and proc_name:
            entry = module.get_export_by_name(proc_name)
            if entry is not None:
                export = {
                    "name": _bounded_text(_safe_attr(entry, "name")),
                    "address": hex_value(_int_value(_safe_attr(entry, "address"))),
                    "ordinal": _int_value(_safe_attr(entry, "ordinal")),
                    "execution_mode": _bounded_text(_safe_attr(entry, "execution_mode")),
                }
        sentinel_target = None
        import_table = _safe_attr(emu, "import_table")
        if return_int and isinstance(import_table, dict):
            target = import_table.get(return_int)
            if isinstance(target, (tuple, list)) and len(target) >= 2:
                sentinel_target = {
                    "module": _bounded_text(target[0]),
                    "function": _bounded_text(target[1]),
                }
        observation["return_value"] = hex_value(return_int)
        observation["export_found"] = export is not None
        observation["export"] = export
        observation["resolved_is_sentinel"] = sentinel_target is not None
        observation["sentinel_target"] = sentinel_target
        observation["target"] = address_provenance(emu, return_int) if return_int else None
        observation["module_header"] = _header_probe(emu, module) if module is not None else None
        observation["module_sections"] = section_trace(emu, module) if module is not None else None
        if export is not None:
            observation["miss_reason"] = None
        elif module is None:
            observation["miss_reason"] = "null_or_unknown_module_handle"
        else:
            observation["miss_reason"] = "export_not_in_module"
        attach(ctx, observation)
    except Exception:
        logger.debug("module trace diagnostic: GetProcAddress finish failed", exc_info=True)
    return observation


__all__ = [
    "MAX_MODULES",
    "MAX_PROBE_BYTES",
    "MAX_SECTIONS",
    "OBSERVATION_KIND",
    "SCHEMA_VERSION",
    "address_provenance",
    "attach",
    "caller_context",
    "finish_get_module_handle_ex",
    "finish_get_proc_address",
    "finish_load_library",
    "finish_unload",
    "hex_value",
    "module_detail",
    "module_entry",
    "module_table",
    "register_provenance",
    "registers_snapshot",
    "section_trace",
    "signature_call_observation",
    "start_get_module_handle_ex",
    "start_get_proc_address",
    "start_load_library",
    "start_unload",
]
