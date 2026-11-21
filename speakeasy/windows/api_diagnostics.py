"""Read-only API diagnostics for the FX-015 scatter samples.

This module collects evidence around four scattered failures whose
``last_api`` is not the root cause: ``kernel32.CreateFileA``,
``kernel32.FreeLibrary`` (IMalloc vtable), ``gdi32.GetStockObject`` and
``user32.IsZoomed`` (HeapAlloc).  It is a *diagnostic* module: it never changes
handler return values, memory permissions, exception dispatch or control flow.

Observation contract
--------------------
* Every ``observe_*`` function returns a JSON-safe ``dict`` with
  ``kind="scatter_diagnostic"`` and ``schema_version=SCHEMA_VERSION``.
* Guest memory reads are bounded and best effort: an unreadable address is
  reported as ``{"available": False, "error": "<ExceptionType>"}`` instead of
  propagating into the API handler.
* ``attach_observation`` stores the dict in ``ctx["_api_observation"]`` (the
  existing ``ApiEvent.observation`` report field) and emits one structured
  ``scatter-diagnostic`` log line.  It never raises: a diagnostic failure must
  not alter emulation behaviour.
* No address, sample SHA or family special cases; no guest memory writes; no
  configuration switches and no environment variables.

Applicable architecture: pointer-size driven x86/AMD64.  Unknown inputs produce
explicit fields (``available=False``, ``mapped=False``, ``status="unknown"``)
rather than guesses.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any

import speakeasy.winenv.arch as _arch

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
OBSERVATION_KIND = "scatter_diagnostic"
COMINTERFACE_TAG_PREFIX = "emu.COM."

_X86_REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip")
_AMD64_REGISTERS = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip")

_HEAP_ALLOC_STATUS_NULL = "null"
_HEAP_ALLOC_STATUS_MAPPED = "mapped"
_HEAP_ALLOC_STATUS_UNMAPPED = "returned_nonnull_but_unmapped"


def hex_value(value: Any) -> str | None:
    """Render an integer (including bool) as a hex string, else ``None``."""
    if isinstance(value, bool):
        return f"0x{int(value):x}"
    if isinstance(value, int):
        return f"0x{value:x}"
    return None


def _int_value(value: Any) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    return None


def _signed_value(value: Any, bits: int) -> int | None:
    """Interpret ``value`` as a ``bits``-wide two's-complement integer."""
    raw = _int_value(value)
    if raw is None or bits <= 0:
        return None
    mask = (1 << bits) - 1
    unsigned = raw & mask
    sign_bit = 1 << (bits - 1)
    return unsigned - (1 << bits) if unsigned & sign_bit else unsigned


def _bounded_int(value: Any, default: int) -> int:
    raw = _int_value(value)
    if raw is None:
        return default
    return raw if raw > 0 else default


def _safe_ptr_size(emu: Any) -> int:
    try:
        return int(emu.get_ptr_size())
    except Exception:
        logger.debug("scatter diagnostic: pointer size unavailable", exc_info=True)
        return 0


def _read_pointer(emu: Any, address: int, ptr_size: int) -> dict[str, Any]:
    """Read one pointer-sized value; failures become explicit fields."""
    if not isinstance(address, int) or address < 0 or ptr_size <= 0:
        return {"available": False, "error": "invalid_address"}
    try:
        data = emu.mem_read(address, ptr_size)
        return {"available": True, "value": int.from_bytes(bytes(data), "little")}
    except Exception as exc:
        logger.debug("scatter diagnostic: unreadable address 0x%x", address, exc_info=True)
        return {"available": False, "error": type(exc).__name__}


def _read_memory(emu: Any, address: int, size: int) -> dict[str, Any]:
    if not isinstance(address, int) or address < 0 or size <= 0:
        return {"available": False, "error": "invalid_address"}
    try:
        return {"available": True, "data": bytes(emu.mem_read(address, size))}
    except Exception as exc:
        logger.debug("scatter diagnostic: unreadable memory 0x%x", address, exc_info=True)
        return {"available": False, "error": type(exc).__name__}


def _register_names(emu: Any) -> tuple[str, ...]:
    try:
        arch = emu.get_arch()
    except Exception:
        return ()
    if arch == _arch.ARCH_X86:
        return _X86_REGISTERS
    if arch == _arch.ARCH_AMD64:
        return _AMD64_REGISTERS
    return ()


def guest_context(emu: Any) -> dict[str, Any]:
    """Snapshot the PC, call/return addresses, general registers and stack head.

    All reads are best effort.  The first stack word at the handler entry is the
    caller return address; ``stack_words`` lists a bounded number of words
    starting at the stack pointer.
    """
    ptr_size = _safe_ptr_size(emu)
    context: dict[str, Any] = {"pointer_size": ptr_size or None}
    for key, getter in (
        ("pc", getattr(emu, "get_pc", None)),
        ("prev_pc", None),
        ("stack_pointer", getattr(emu, "get_stack_ptr", None)),
        ("return_address", getattr(emu, "get_ret_address", None)),
    ):
        if key == "prev_pc":
            context[key] = hex_value(getattr(emu, "prev_pc", None))
            continue
        if not callable(getter):
            context[key] = None
            continue
        try:
            context[key] = hex_value(getter())
        except Exception:
            logger.debug("scatter diagnostic: %s unavailable", key, exc_info=True)
            context[key] = None

    registers: dict[str, str | None] = {}
    reg_read = getattr(emu, "reg_read", None)
    if callable(reg_read):
        for name in _register_names(emu):
            constant = _arch.REG_LOOKUP.get(name)
            if constant is None:
                continue
            try:
                registers[name] = hex_value(reg_read(constant))
            except Exception:
                registers[name] = None
    context["registers"] = registers
    return context


def stack_words(emu: Any, count: int = 8) -> list[dict[str, Any]]:
    """Read a bounded window of pointer-sized words starting at the stack pointer."""
    ptr_size = _safe_ptr_size(emu)
    if ptr_size <= 0:
        return []
    try:
        sp = int(emu.get_stack_ptr())
    except Exception:
        logger.debug("scatter diagnostic: stack pointer unavailable", exc_info=True)
        return []
    words: list[dict[str, Any]] = []
    for index in range(max(0, count)):
        address = sp + index * ptr_size
        read = _read_pointer(emu, address, ptr_size)
        word: dict[str, Any] = {"index": index, "address": hex_value(address)}
        if read["available"]:
            word["value"] = hex_value(read["value"])
        else:
            word["available"] = False
            word["error"] = read["error"]
        words.append(word)
    return words


def address_map_info(emu: Any, address: Any) -> dict[str, Any]:
    """Describe the emulator mapping that contains ``address`` (read-only)."""
    if not isinstance(address, int):
        return {"mapped": False, "address": None}
    get_map = getattr(emu, "get_address_map", None)
    mapping = None
    if callable(get_map):
        try:
            mapping = get_map(address)
        except Exception:
            logger.debug("scatter diagnostic: address map lookup failed", exc_info=True)
            mapping = None
    if mapping is None:
        return {"mapped": False, "address": hex_value(address)}
    return {
        "mapped": True,
        "address": hex_value(address),
        "base": hex_value(getattr(mapping, "base", None)),
        "size": hex_value(getattr(mapping, "size", None)),
        "tag": getattr(mapping, "tag", None),
        "protection": hex_value(getattr(mapping, "prot", None)),
        "is_image": bool(getattr(mapping, "is_image", False)),
        "free": bool(getattr(mapping, "free", False)),
    }


def com_interface_snapshot(
    emu: Any,
    *,
    max_interfaces: int = 8,
    max_slots: int = 12,
) -> dict[str, Any]:
    """Read the live ``emu.COM.*`` interface vtables.

    The COM manager maps each interface as a pointer table and fills supported
    method slots with emulator callbacks; unsupported slots stay zero.  This
    snapshot records which slots are non-zero so an ``IUnknown::Release`` or
    ``IMalloc`` dispatch failure can be told apart from a missing interface.
    """
    ptr_size = _safe_ptr_size(emu)
    get_maps = getattr(emu, "get_mem_maps", None)
    if ptr_size <= 0 or not callable(get_maps):
        return {"available": False, "count": 0, "interfaces": []}
    try:
        maps = list(get_maps())
    except Exception:
        logger.debug("scatter diagnostic: memory maps unavailable", exc_info=True)
        return {"available": False, "count": 0, "interfaces": []}

    interfaces: list[dict[str, Any]] = []
    matched = 0
    for mapping in maps:
        tag = getattr(mapping, "tag", "") or ""
        if not tag.startswith(COMINTERFACE_TAG_PREFIX):
            continue
        matched += 1
        if len(interfaces) >= max_interfaces:
            continue
        base = getattr(mapping, "base", None)
        size = getattr(mapping, "size", None)
        slots: list[dict[str, Any]] = []
        if isinstance(base, int):
            for index in range(max_slots):
                address = base + index * ptr_size
                read = _read_pointer(emu, address, ptr_size)
                slot: dict[str, Any] = {
                    "index": index,
                    "offset": hex_value(index * ptr_size),
                    "address": hex_value(address),
                }
                if read["available"]:
                    slot["value"] = hex_value(read["value"])
                    slot["nonzero"] = bool(read["value"])
                else:
                    slot["available"] = False
                    slot["error"] = read["error"]
                slots.append(slot)
        interfaces.append(
            {
                "tag": tag,
                "base": hex_value(base),
                "size": hex_value(size),
                "slots": slots,
                "slots_truncated": bool(isinstance(size, int) and size > max_slots * ptr_size),
            }
        )
    return {
        "available": True,
        "count": matched,
        "interfaces": interfaces,
        "max_interfaces": max_interfaces,
        "max_slots": max_slots,
        "interfaces_truncated": matched > len(interfaces),
    }


def _observation(api_name: str | None, diagnostic: str) -> dict[str, Any]:
    return {
        "kind": OBSERVATION_KIND,
        "schema_version": SCHEMA_VERSION,
        "api": api_name,
        "diagnostic": diagnostic,
    }


def observe_create_file(
    emu: Any,
    argv: Any,
    return_value: Any,
    *,
    char_width: int,
    decoded_path: str | None = None,
    api_name: str | None = None,
    stack_word_count: int = 8,
) -> dict[str, Any]:
    """Describe a ``CreateFileA``/``CreateFileW`` call and its caller context."""
    raw = list(argv or ())
    arguments: dict[str, Any] = {}
    names = (
        "lp_file_name",
        "desired_access",
        "share_mode",
        "security_attributes",
        "creation_disposition",
        "flags_and_attributes",
        "template_file",
    )
    for index, name in enumerate(names):
        value = raw[index] if index < len(raw) else None
        arguments[name] = hex_value(value) if isinstance(value, int) else value
    observation = _observation(api_name, "create_file")
    observation.update(
        {
            "char_width": int(char_width),
            "arguments": arguments,
            "decoded_path": decoded_path,
            "return_handle": hex_value(return_value),
            "last_error": hex_value(_safe_last_error(emu)),
            "guest": guest_context(emu),
            "stack_words": stack_words(emu, stack_word_count),
        }
    )
    return observation


def observe_free_library(
    emu: Any,
    argv: Any,
    return_value: Any,
    *,
    api_name: str | None = None,
    max_interfaces: int = 8,
    max_slots: int = 12,
) -> dict[str, Any]:
    """Describe ``FreeLibrary`` plus the live COM interface vtable slots."""
    raw = list(argv or ())
    observation = _observation(api_name, "free_library")
    observation.update(
        {
            "h_lib_module": hex_value(raw[0]) if raw else None,
            "return_value": hex_value(return_value),
            "last_error": hex_value(_safe_last_error(emu)),
            "guest": guest_context(emu),
            "com_interfaces": com_interface_snapshot(
                emu,
                max_interfaces=max_interfaces,
                max_slots=max_slots,
            ),
        }
    )
    return observation


def observe_get_stock_object(
    stock_object: Any,
    return_value: Any,
    *,
    valid: bool,
    api_name: str | None = None,
    handle_base: int | None = None,
    object_size: int = 4,
) -> dict[str, Any]:
    """Describe ``GetStockObject`` and compare it with the HGDIOBJ pseudo-handle model.

    Windows/Wine implement stock objects as opaque pseudo-handles.  Speakeasy
    models the documented ``0x7000 + 4*i`` form for valid selectors and 0 for
    invalid selectors; the guest must not dereference these values.
    """
    selector = _int_value(stock_object)
    returned = _int_value(return_value)
    expected = None
    if valid and selector is not None and handle_base is not None:
        expected = handle_base + selector * object_size
    observation = _observation(api_name, "get_stock_object")
    observation.update(
        {
            "stock_object": hex_value(selector) if selector is not None else None,
            "valid_selector": bool(valid),
            "returned_handle": hex_value(returned),
            "handle_base": hex_value(handle_base),
            "wine_semantics": {
                "type": "HGDIOBJ_pseudo_handle",
                "valid_formula": (
                    f"0x{handle_base:x} + {object_size} * i" if handle_base is not None else None
                ),
                "invalid_value": "0x0",
                "opaque": True,
                "note": "HGDIOBJ values are opaque pseudo-handles; dereferencing them is a sample error",
            },
            "matches_pseudo_handle_formula": (
                expected is not None and returned == expected
            ),
        }
    )
    return observation


def observe_heap_alloc(
    emu: Any,
    heap_handle: Any,
    flags: Any,
    size: Any,
    return_value: Any,
    *,
    api_name: str | None = None,
    heap_tag: str = "api.heap.HeapAlloc",
) -> dict[str, Any]:
    """Describe a ``HeapAlloc`` request and whether the returned pointer is mapped."""
    ptr_size = _safe_ptr_size(emu)
    bits = ptr_size * 8 if ptr_size > 0 else 0
    returned = _int_value(return_value)
    signed_size = _signed_value(size, bits) if bits else None
    mapping = address_map_info(emu, returned)
    if returned in (None, 0):
        status = _HEAP_ALLOC_STATUS_NULL
    elif mapping["mapped"]:
        status = _HEAP_ALLOC_STATUS_MAPPED
    else:
        status = _HEAP_ALLOC_STATUS_UNMAPPED
    observation = _observation(api_name, "heap_alloc")
    observation.update(
        {
            "heap_handle": hex_value(heap_handle),
            "flags": hex_value(flags),
            "requested_size": hex_value(size),
            "requested_size_signed": signed_size,
            "requested_size_unsigned": _int_value(size),
            "return_value": hex_value(returned),
            "allocation_status": status,
            "expected_heap_tag": heap_tag,
            "returned_mapping": mapping,
            "last_error": hex_value(_safe_last_error(emu)),
            "guest": guest_context(emu),
        }
    )
    return observation


def observe_is_zoomed(
    emu: Any,
    window_handle: Any,
    return_value: Any,
    last_error: Any,
    *,
    window_known: bool | None = None,
    api_name: str | None = None,
) -> dict[str, Any]:
    """Describe ``IsZoomed`` (a BOOL predicate) without changing its semantics."""
    observation = _observation(api_name, "is_zoomed")
    observation.update(
        {
            "h_wnd": hex_value(window_handle),
            "return_value": hex_value(return_value),
            "truthy": bool(return_value) if isinstance(return_value, int) else None,
            "window_known": window_known,
            "last_error": hex_value(last_error),
            "guest": guest_context(emu),
        }
    )
    return observation


def _safe_last_error(emu: Any) -> Any:
    getter = getattr(emu, "get_last_error", None)
    if not callable(getter):
        return None
    try:
        return getter()
    except Exception:
        logger.debug("scatter diagnostic: last error unavailable", exc_info=True)
        return None


def attach_observation(
    ctx: dict[str, Any] | None,
    observation_builder: Callable[[], dict[str, Any] | None],
) -> None:
    """Attach one diagnostic observation without affecting handler behaviour.

    The builder is evaluated lazily.  Any diagnostic failure is logged at debug
    level and discarded, so instrumentation can never change a handler's return
    value, memory accesses or control flow.  On success the observation is
    stored in ``ctx["_api_observation"]`` (reported with the matching
    ``ApiEvent``) and written as one JSON log line.
    """
    if not isinstance(ctx, dict):
        return
    try:
        observation = observation_builder()
    except Exception:
        logger.debug("scatter diagnostic: observation builder failed", exc_info=True)
        return
    if not isinstance(observation, dict):
        return
    try:
        ctx["_api_observation"] = observation
        if logger.isEnabledFor(logging.INFO):
            try:
                logger.info(
                    "scatter-diagnostic %s",
                    json.dumps(observation, ensure_ascii=False, sort_keys=True),
                )
            except Exception:
                logger.debug("scatter diagnostic: observation not JSON-serializable", exc_info=True)
    except Exception:
        logger.debug("scatter diagnostic: observation attachment failed", exc_info=True)


__all__ = [
    "SCHEMA_VERSION",
    "OBSERVATION_KIND",
    "address_map_info",
    "attach_observation",
    "com_interface_snapshot",
    "guest_context",
    "hex_value",
    "observe_create_file",
    "observe_free_library",
    "observe_get_stock_object",
    "observe_heap_alloc",
    "observe_is_zoomed",
    "stack_words",
]
