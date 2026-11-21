"""Read-only API-trace provenance for the FX-016 diagnostics.

FX-016 covers no-PC/nonfatal scatters and low-confidence singletons whose
reports only carried ``last_api``.  This module adds *evidence*, never
behaviour: every helper snapshots guest state and returns a JSON-safe ``dict``
that is attached to the existing public report fields
(``ApiEvent.provenance`` / ``ApiEvent.observation`` / ``ErrorInfo.diagnostics``).

Observation contract
--------------------
* Every helper returns a dict with ``kind="api_trace_diagnostic"`` and
  ``schema_version=SCHEMA_VERSION``.
* All guest reads are bounded (``MAX_ARGUMENTS`` arguments,
  ``MAX_STACK_WORDS`` stack words, ``MAX_TAIL_ENTRIES`` recent API calls) and
  best effort: unreadable state is reported as ``available=False`` or
  ``mapped=False`` instead of propagating into a handler.
* ``attach_observation`` stores the dict in ``ctx["_api_observation"]`` and
  emits one structured log line.  It never raises, even when the payload is
  not JSON-serializable.
* No guest memory writes, no permission changes, no control-flow changes, no
  address/SHA/sample/family special cases, no configuration switches and no
  environment variables.

Applicable architecture: pointer-size driven x86/AMD64.  Unknown inputs produce
explicit fields (``value=None``, ``mapped=False``, ``found=False``) rather than
guesses.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Iterable
from typing import Any

from speakeasy.windows import api_diagnostics

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
PROVENANCE_KIND = "api_trace_diagnostic"

MAX_ARGUMENTS = 16
MAX_STACK_WORDS = 8
MAX_TAIL_ENTRIES = 8
MAX_TEXT_CHARS = 256

_WAIT_RESULTS = {
    0x00000000: "WAIT_OBJECT_0",
    0x00000080: "WAIT_ABANDONED",
    0x00000102: "WAIT_TIMEOUT",
    0xFFFFFFFF: "WAIT_FAILED",
}

_FAKEOUT_MARKERS = (
    "invalid_read",
    "invalid_write",
    "invalid_fetch",
    "invalid memory fetch",
    "invalid memory read",
    "invalid memory write",
)


def hex_value(value: Any) -> str | None:
    """Render an integer (including bool) as a hex string, else ``None``."""
    return api_diagnostics.hex_value(value)


def _int_value(value: Any) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    return None


def _bounded_text(value: Any, limit: int = MAX_TEXT_CHARS) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"
    try:
        text = str(value).replace("\x00", "")
        # Keep report JSON serializable: replace lone surrogates that guest
        # string decoding can produce.
        text = text.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    except Exception:
        return None
    return text[:limit]


def _render_value(value: Any) -> Any:
    """Render an argument without embedding unbounded/unsafe objects."""
    if value is None or isinstance(value, str):
        return _bounded_text(value)
    if isinstance(value, bool):
        return f"0x{int(value):x}"
    if isinstance(value, int):
        return f"0x{value:x}"
    if isinstance(value, bytes):
        return _bounded_text(value)
    return f"<{type(value).__name__}>"


def _safe_int_call(emu: Any, name: str) -> int | None:
    getter = getattr(emu, name, None)
    if not callable(getter):
        return None
    try:
        return _int_value(getter())
    except Exception:
        logger.debug("api trace diagnostic: %s unavailable", name, exc_info=True)
        return None


def _safe_last_error(emu: Any) -> Any:
    getter = getattr(emu, "get_last_error", None)
    if not callable(getter):
        return None
    try:
        return getter()
    except Exception:
        logger.debug("api trace diagnostic: last error unavailable", exc_info=True)
        return None


def _safe_ptr_size(emu: Any) -> int:
    getter = getattr(emu, "get_ptr_size", None)
    if not callable(getter):
        return 0
    try:
        value = _int_value(getter())
    except Exception:
        logger.debug("api trace diagnostic: pointer size unavailable", exc_info=True)
        return 0
    return value if value is not None and value > 0 else 0


def _first_word(emu: Any, address: int) -> str | None:
    """Best-effort read of the first pointer-sized word at ``address``."""
    ptr_size = _safe_ptr_size(emu)
    if ptr_size <= 0:
        return None
    try:
        return hex(int.from_bytes(bytes(emu.mem_read(address, ptr_size)), "little"))
    except Exception:
        logger.debug("api trace diagnostic: first word unreadable at 0x%x", address, exc_info=True)
        return None


def module_context(emu: Any, address: Any) -> dict[str, Any]:
    """Describe the mapping and image containing ``address`` (read-only)."""
    address_int = _int_value(address)
    context: dict[str, Any] = {
        "address": hex_value(address_int),
        "module": None,
        "module_base": None,
        "module_size": None,
        "module_offset": None,
        "mapping": {"mapped": False, "address": hex_value(address_int)},
    }
    if address_int is None or address_int <= 0:
        return context
    context["mapping"] = api_diagnostics.address_map_info(emu, address_int)
    get_module = getattr(emu, "get_module_from_addr", None)
    module = None
    if callable(get_module):
        try:
            module = get_module(address_int)
        except Exception:
            logger.debug("api trace diagnostic: module lookup failed", exc_info=True)
            module = None
    if module is not None:
        name = getattr(module, "name", None) or getattr(module, "mod_name", None)
        base = _int_value(getattr(module, "base", None))
        size = _int_value(getattr(module, "image_size", None))
        context["module"] = _bounded_text(name, 128)
        context["module_base"] = hex_value(base)
        context["module_size"] = hex_value(size)
        if base is not None:
            context["module_offset"] = hex_value(address_int - base)
    return context


def pointer_provenance(emu: Any, value: Any) -> dict[str, Any]:
    """Describe whether a pointer-shaped value is mapped and where it lives."""
    value_int = _int_value(value)
    provenance: dict[str, Any] = {
        "value": hex_value(value_int),
        "mapped": False,
        "module": None,
        "module_offset": None,
        "mapping": None,
        "first_word": None,
    }
    if value_int is None or value_int <= 0:
        return provenance
    mapping = api_diagnostics.address_map_info(emu, value_int)
    module = module_context(emu, value_int)
    provenance.update(
        {
            "mapped": bool(mapping.get("mapped")),
            "module": module.get("module"),
            "module_offset": module.get("module_offset"),
            "mapping": mapping,
        }
    )
    if provenance["mapped"]:
        provenance["first_word"] = _first_word(emu, value_int)
    return provenance


def argument_provenance(
    emu: Any,
    argv: Iterable[Any] | None,
    display: list[str] | None = None,
) -> tuple[list[dict[str, Any]], bool]:
    """Render a bounded argument list with pointer provenance."""
    raw_args = list(argv or ())
    entries: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_args[:MAX_ARGUMENTS]):
        entry: dict[str, Any] = {
            "index": index,
            "kind": type(raw).__name__,
            "value": _render_value(raw),
        }
        if display is not None and index < len(display):
            entry["display"] = _bounded_text(display[index])
        if isinstance(raw, int) and not isinstance(raw, bool):
            entry["pointer"] = pointer_provenance(emu, raw)
        entries.append(entry)
    return entries, len(raw_args) > MAX_ARGUMENTS


def guest_snapshot(emu: Any) -> dict[str, Any]:
    """Snapshot PC, call/return addresses, registers and a bounded stack window."""
    context = api_diagnostics.guest_context(emu)
    context["stack_words"] = api_diagnostics.stack_words(emu, MAX_STACK_WORDS)
    return context


def api_provenance(
    emu: Any,
    *,
    api_name: str | None,
    argv: Iterable[Any] | None,
    ret: Any,
    call_pc: Any,
    display: list[str] | None = None,
) -> dict[str, Any]:
    """Describe one API return: arguments, result, registers and call context."""
    snapshot = guest_snapshot(emu)
    arguments, truncated = argument_provenance(emu, argv, display)
    handler_pc = _safe_int_call(emu, "get_pc")
    previous_pc = _int_value(getattr(emu, "prev_pc", None))
    return_address = _safe_int_call(emu, "get_ret_address")
    caller_address = return_address if return_address is not None else call_pc
    call_pc_int = _int_value(call_pc)

    return {
        "kind": PROVENANCE_KIND,
        "schema_version": SCHEMA_VERSION,
        "api": api_name,
        "pointer_size": snapshot.get("pointer_size"),
        "call_pc": hex_value(call_pc_int),
        "handler_pc": hex_value(handler_pc),
        "previous_pc": hex_value(previous_pc),
        "return_address": hex_value(return_address),
        "caller": module_context(emu, caller_address),
        "handler_module": module_context(emu, handler_pc),
        "arguments": arguments,
        "arguments_truncated": truncated,
        "return_value": hex_value(_int_value(ret)),
        "return_pointer": pointer_provenance(emu, ret),
        "registers": snapshot.get("registers", {}),
        "stack_pointer": snapshot.get("stack_pointer"),
        "stack_words": snapshot.get("stack_words", []),
        "last_error": hex_value(_safe_last_error(emu)),
    }


def observe_set_last_error(emu: Any, argv: Iterable[Any] | None) -> dict[str, Any]:
    """Record ``SetLastError`` guest control-flow provenance (read-only)."""
    raw_args = list(argv or ())
    set_value = raw_args[0] if raw_args else None
    snapshot = guest_snapshot(emu)
    return_address = _safe_int_call(emu, "get_ret_address")
    previous_pc = _int_value(getattr(emu, "prev_pc", None))
    call_pc = previous_pc if previous_pc is not None else return_address
    return {
        "kind": PROVENANCE_KIND,
        "schema_version": SCHEMA_VERSION,
        "api": "kernel32.SetLastError",
        "diagnostic": "set_last_error",
        "set_value": hex_value(_int_value(set_value)),
        "previous_last_error": hex_value(_safe_last_error(emu)),
        "call_pc": hex_value(call_pc),
        "previous_pc": hex_value(previous_pc),
        "return_address": hex_value(return_address),
        "caller": module_context(emu, return_address),
        "registers": snapshot.get("registers", {}),
        "stack_pointer": snapshot.get("stack_pointer"),
        "stack_words": snapshot.get("stack_words", []),
    }


def observe_wait_for_single_object(
    emu: Any,
    argv: Iterable[Any] | None,
    return_value: Any,
) -> dict[str, Any]:
    """Record ``WaitForSingleObject`` stack/handle provenance (read-only)."""
    raw_args = list(argv or ())
    handle = raw_args[0] if raw_args else None
    timeout_ms = raw_args[1] if len(raw_args) > 1 else None
    handle_int = _int_value(handle)
    handle_provenance: dict[str, Any] = {
        "handle": hex_value(handle_int),
        "found": False,
        "object_type": None,
        "object_name": None,
        "object_id": None,
        "object_address": None,
        "handle_count": None,
        "mapping": pointer_provenance(emu, handle_int),
    }
    get_object = getattr(emu, "get_object_from_handle", None)
    if handle_int is not None and callable(get_object):
        try:
            obj = get_object(handle_int)
        except Exception:
            logger.debug("api trace diagnostic: handle lookup failed", exc_info=True)
            obj = None
        if obj is not None:
            class_name = None
            get_class_name = getattr(obj, "get_class_name", None)
            if callable(get_class_name):
                try:
                    class_name = get_class_name()
                except Exception:
                    class_name = None
            handles = getattr(obj, "handles", None)
            handle_provenance.update(
                {
                    "found": True,
                    "object_type": _bounded_text(class_name or type(obj).__name__, 64),
                    "object_name": _bounded_text(getattr(obj, "name", None)),
                    "object_id": _int_value(getattr(obj, "id", None)),
                    "object_address": hex_value(_int_value(getattr(obj, "address", None))),
                    "handle_count": len(handles) if isinstance(handles, (list, tuple)) else None,
                }
            )

    result_int = _int_value(return_value)
    snapshot = guest_snapshot(emu)
    return_address = _safe_int_call(emu, "get_ret_address")
    previous_pc = _int_value(getattr(emu, "prev_pc", None))
    return {
        "kind": PROVENANCE_KIND,
        "schema_version": SCHEMA_VERSION,
        "api": "kernel32.WaitForSingleObject",
        "diagnostic": "wait_for_single_object",
        "handle": hex_value(handle_int),
        "timeout_ms": hex_value(_int_value(timeout_ms)),
        "return_value": hex_value(result_int),
        "wait_result": _WAIT_RESULTS.get(result_int & 0xFFFFFFFF) if result_int is not None else None,
        "handle_provenance": handle_provenance,
        "call_pc": hex_value(previous_pc if previous_pc is not None else return_address),
        "return_address": hex_value(return_address),
        "caller": module_context(emu, return_address),
        "registers": snapshot.get("registers", {}),
        "stack_pointer": snapshot.get("stack_pointer"),
        "stack_words": snapshot.get("stack_words", []),
    }


def _fakeout_page(description: Any, address: Any) -> int | None:
    if not isinstance(description, str):
        return None
    folded = description.casefold()
    if not any(marker in folded for marker in _FAKEOUT_MARKERS):
        return None
    address_int = _int_value(address)
    if address_int is None or address_int < 0:
        return None
    return address_int & ~0xFFF


def error_diagnostics(
    emu: Any,
    *,
    description: Any,
    address: Any,
    access_type: Any,
    pc: Any,
    pc_module: Any,
    last_api: dict[str, Any] | None = None,
    api_tail: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Collect fault-page, last-API and register evidence for an error report."""
    address_int = _int_value(address)
    snapshot = guest_snapshot(emu)
    diagnostics: dict[str, Any] = {
        "kind": PROVENANCE_KIND,
        "schema_version": SCHEMA_VERSION,
        "description": _bounded_text(description),
        "pc": hex_value(_int_value(pc)),
        "pc_module": _bounded_text(pc_module),
        "address": hex_value(address_int),
        "access_type": _bounded_text(access_type, 32),
        "previous_pc": hex_value(_int_value(getattr(emu, "prev_pc", None))),
        "return_address": hex_value(_safe_int_call(emu, "get_ret_address")),
        "registers": snapshot.get("registers", {}),
        "stack_pointer": snapshot.get("stack_pointer"),
        "stack_words": snapshot.get("stack_words", []),
        "last_api": last_api,
        "api_tail": list(api_tail or [])[-MAX_TAIL_ENTRIES:],
    }
    fakeout = _fakeout_page(description, address_int)
    if fakeout is not None:
        diagnostics["fakeout"] = {
            "base": hex_value(fakeout),
            "size": hex_value(0x1000),
            "contains_fault": bool(address_int is not None and fakeout <= address_int < fakeout + 0x1000),
            "temporary": True,
        }
    return diagnostics


def summary_marker(
    description: Any,
    address: Any,
    last_api: dict[str, Any] | None,
) -> str | None:
    """Build the compact one-line marker appended to ``context_summary``."""
    parts: list[str] = []
    fakeout = _fakeout_page(description, address)
    if fakeout is not None:
        parts.append(f"fakeout_page=0x{fakeout:x}")
    if isinstance(last_api, dict) and last_api.get("api"):
        parts.append(f"last_api={last_api['api']}")
        if last_api.get("call_pc"):
            parts.append(f"last_api_call_pc={last_api['call_pc']}")
        if last_api.get("return_address"):
            parts.append(f"last_api_return={last_api['return_address']}")
    return "; ".join(parts) if parts else None


def compact_trace(provenance: dict[str, Any] | None) -> dict[str, Any] | None:
    """Reduce a provenance record to the bounded last-API trace entry."""
    if not isinstance(provenance, dict):
        return None
    arguments = [
        {
            "index": entry.get("index"),
            "value": entry.get("value"),
            "display": entry.get("display"),
        }
        for entry in (provenance.get("arguments") or [])[:MAX_ARGUMENTS]
        if isinstance(entry, dict)
    ]
    return {
        "api": provenance.get("api"),
        "call_pc": provenance.get("call_pc"),
        "handler_pc": provenance.get("handler_pc"),
        "previous_pc": provenance.get("previous_pc"),
        "return_address": provenance.get("return_address"),
        "arguments": arguments,
        "return_value": provenance.get("return_value"),
        "last_error": provenance.get("last_error"),
    }


def attach_observation(
    ctx: dict[str, Any] | None,
    observation_builder: Callable[[], dict[str, Any] | None],
) -> None:
    """Attach one diagnostic observation without affecting handler behaviour.

    The builder is evaluated lazily.  Any diagnostic failure (including a
    non-JSON-serializable payload) is logged at debug level and discarded, so
    instrumentation can never change a handler's return value, memory accesses
    or control flow.  On success the observation is stored in
    ``ctx["_api_observation"]`` (reported with the matching ``ApiEvent``).
    """
    try:
        if not isinstance(ctx, dict):
            return
        observation = observation_builder()
        if not isinstance(observation, dict):
            return
        ctx["_api_observation"] = observation
        try:
            if logger.isEnabledFor(logging.INFO):
                logger.info(
                    "api-trace-diagnostic %s",
                    json.dumps(observation, ensure_ascii=False, sort_keys=True),
                )
        except Exception:
            logger.debug("api trace diagnostic: observation not JSON-serializable", exc_info=True)
    except Exception:
        logger.debug("api trace diagnostic: observation failed", exc_info=True)


__all__ = [
    "MAX_ARGUMENTS",
    "MAX_STACK_WORDS",
    "MAX_TAIL_ENTRIES",
    "PROVENANCE_KIND",
    "SCHEMA_VERSION",
    "api_provenance",
    "argument_provenance",
    "attach_observation",
    "compact_trace",
    "error_diagnostics",
    "guest_snapshot",
    "hex_value",
    "module_context",
    "observe_set_last_error",
    "observe_wait_for_single_object",
    "pointer_provenance",
    "summary_marker",
]
