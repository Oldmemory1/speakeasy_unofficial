"""Read-only page-protection trace diagnostics for FX-003.

The FX-003 work item (``MemoryProtection / virtualprotect``) needs evidence for
three representative failures: a ``NtAllocateVirtualMemory`` request whose
``Protect`` value cannot be checked against the protection the mapping really
got, a ``NtProtectVirtualMemory`` call after which the guest fetches at PC=0
(no pre/post register provenance in the report), and a
``VirtualProtect``/``lstrcpyA`` self-modifying-patch sequence whose per-page
state and patch bytes are invisible.

This module adds *evidence*, never behaviour.  Each ``start_*`` snapshot is
read-only, bounded and best effort; ``finish_*`` records the outcome on the
same dictionary and re-attaches it.  The observation is stored in
``ctx["_api_observation"]`` (the existing ``ApiEvent.observation`` report
field).  Handler return values, page permissions, exception dispatch and
control flow are never changed.

Observation contract
--------------------
* Every observation is a JSON-safe ``dict`` with ``kind="page_trace_diagnostic"``
  and ``schema_version=SCHEMA_VERSION``.
* Guest reads are bounded (``MAX_PAGES`` pages, ``MAX_PATCH_BYTES`` patch bytes,
  ``MAX_TEXT_BYTES`` source bytes) and reported as ``mapped=False``/``None``
  when unavailable instead of raising.
* ``start_*``/``finish_*`` never raise: a diagnostic failure is logged at debug
  level and the handler continues unchanged.
* No address/sample/family special cases, no environment variables, no
  configuration switches, no guest memory writes.

Applicable architecture: pointer-size driven x86/AMD64.  The focused register
set is EAX/EDI/EBP/ESP on x86 and RAX/RDI/RBP/RSP on AMD64; ``registers_after``
is the handler-exit state (the guest-visible post-return registers and
fault-time registers remain in the existing report fields ``provenance`` and
``ErrorInfo.regs``).
"""

from __future__ import annotations

import logging
from typing import Any

import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.windows import api_diagnostics, api_trace_diagnostics, page_protection

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
OBSERVATION_KIND = "page_trace_diagnostic"

MAX_PAGES = 64
MAX_PATCH_BYTES = 64
MAX_TEXT_BYTES = 64
MAX_TEXT_CHARS = 256
MAX_PROTECT_NAMES = 16

_FOCUSED_X86 = ("eax", "edi", "ebp", "esp")
_FOCUSED_X64 = ("rax", "rdi", "rbp", "rsp")

_UNSET = object()


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
        # Keep report JSON serializable: guest decoding can produce lone
        # surrogates, which json.dumps refuses.
        text = text.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    except Exception:
        return None
    return text[:MAX_TEXT_CHARS]


def _focused_register_names(emu: Any) -> tuple[str, ...]:
    try:
        arch = emu.get_arch()
    except Exception:
        logger.debug("page trace diagnostic: arch unavailable", exc_info=True)
        return ()
    if arch == _arch.ARCH_X86:
        return _FOCUSED_X86
    if arch == _arch.ARCH_AMD64:
        return _FOCUSED_X64
    return ()


def registers_snapshot(emu: Any) -> dict[str, str | None]:
    """Return the focused guest registers EAX/EDI/EBP/ESP (x64 RAX/RDI/RBP/RSP).

    Read-only and best effort: a register that cannot be read is reported as
    ``None``.  Unknown architectures yield an empty dict rather than a guess.
    """
    snapshot: dict[str, str | None] = {}
    for name in _focused_register_names(emu):
        try:
            snapshot[name] = hex_value(emu.reg_read(name))
        except Exception:
            logger.debug("page trace diagnostic: register %s unavailable", name, exc_info=True)
            snapshot[name] = None
    return snapshot


def _empty_page_trace(address: Any) -> dict[str, Any]:
    return {
        "address": hex_value(_int_value(address)),
        "mapped": False,
        "tag": None,
        "map_base": None,
        "is_image": None,
        "emu_perms": None,
        "win_protect": None,
    }


def page_trace(emu: Any, address: Any) -> dict[str, Any]:
    """Describe one page's protection state without changing it.

    Reports whether the page is mapped, its mapping tag/base, whether it
    belongs to an image, the effective emulator permissions and the Win32
    ``PAGE_*`` value guests would observe.  Unmapped or unknown addresses
    report ``mapped=False``.
    """
    address_int = _int_value(address)
    entry = _empty_page_trace(address_int)
    if address_int is None or address_int <= 0:
        return entry
    try:
        mapping = api_diagnostics.address_map_info(emu, address_int)
    except Exception:
        logger.debug("page trace diagnostic: mapping lookup failed", exc_info=True)
        return entry
    entry["mapped"] = bool(mapping.get("mapped"))
    if not entry["mapped"]:
        return entry
    entry["tag"] = _bounded_text(mapping.get("tag"))
    entry["map_base"] = hex_value(_parse_hex(mapping.get("base")))
    entry["is_image"] = mapping.get("is_image")
    try:
        entry["emu_perms"] = hex_value(emu.get_address_perms(address_int))
    except Exception:
        logger.debug("page trace diagnostic: emulator perms unavailable", exc_info=True)
    try:
        entry["win_protect"] = hex_value(page_protection.emulator_page_win_protection(emu, address_int))
    except Exception:
        logger.debug("page trace diagnostic: Win32 protection unavailable", exc_info=True)
    return entry


def range_page_trace(emu: Any, lp_address: Any, dw_size: Any) -> dict[str, Any]:
    """Describe the protection of every page covering ``[lp_address, +dw_size)``.

    Bounded to ``MAX_PAGES`` entries; ``truncated`` marks a longer range.
    ``dw_size <= 0`` and unparseable inputs yield an empty page list.
    """
    result: dict[str, Any] = {"start": None, "end": None, "pages": [], "truncated": False}
    address_int = _int_value(lp_address)
    size_int = _int_value(dw_size)
    if address_int is None or size_int is None or size_int <= 0:
        return result
    page_size = page_protection.DEFAULT_PAGE_SIZE
    try:
        page_size = int(getattr(emu, "page_size", 0) or 0) or page_protection.DEFAULT_PAGE_SIZE
    except Exception:
        logger.debug("page trace diagnostic: page size unavailable", exc_info=True)
    try:
        start, end = page_protection.page_span(address_int, size_int, page_size)
    except Exception:
        logger.debug("page trace diagnostic: page span failed", exc_info=True)
        return result
    result["start"] = hex_value(start)
    result["end"] = hex_value(end)
    if end <= start:
        return result
    count = 0
    for page in range(start, end, page_size):
        if count >= MAX_PAGES:
            result["truncated"] = True
            break
        result["pages"].append(page_trace(emu, page))
        count += 1
    return result


def _protect_names(protect: Any) -> list[str]:
    protect_int = _int_value(protect)
    if protect_int is None:
        return []
    try:
        names = windefs.get_page_rights(protect_int)
    except Exception:
        logger.debug("page trace diagnostic: protect names unavailable", exc_info=True)
        return []
    if not names:
        return []
    return [str(name) for name in names][:MAX_PROTECT_NAMES]


def _read_pointer(emu: Any, address: Any) -> int | None:
    address_int = _int_value(address)
    if address_int is None or address_int <= 0:
        return None
    try:
        ptr_size = int(emu.get_ptr_size())
    except Exception:
        logger.debug("page trace diagnostic: pointer size unavailable", exc_info=True)
        return None
    if ptr_size <= 0:
        return None
    try:
        return int.from_bytes(bytes(emu.mem_read(address_int, ptr_size)), "little")
    except Exception:
        logger.debug("page trace diagnostic: pointer unreadable at 0x%x", address_int, exc_info=True)
        return None


def _read_text(emu: Any, address: Any, char_width: int) -> str | None:
    """Best-effort bounded C-string preview (NUL terminator excluded)."""
    address_int = _int_value(address)
    if address_int is None or address_int <= 0 or char_width not in (1, 2):
        return None
    data = None
    for size in (MAX_TEXT_BYTES, 32, 16, 8, 4, 2, 1):
        size -= size % char_width
        if size < char_width:
            continue
        try:
            data = bytes(emu.mem_read(address_int, size))
            break
        except Exception:
            continue
    if data is None:
        logger.debug("page trace diagnostic: source text unreadable at 0x%x", address_int)
        return None
    if char_width == 1:
        raw = data.split(b"\x00", 1)[0]
        try:
            text = raw.decode("utf-8", "replace")
        except Exception:
            logger.debug("page trace diagnostic: source text decode failed", exc_info=True)
            return None
    else:
        text = data.decode("utf-16le", "replace").split("\x00", 1)[0]
    return _bounded_text(text)


def attach(ctx: dict[str, Any] | None, observation: dict[str, Any] | None) -> None:
    """Attach one observation without affecting handler behaviour."""
    api_trace_diagnostics.attach_observation(
        ctx,
        lambda: observation if isinstance(observation, dict) else None,
    )


def start_nt_allocate(emu: Any, ctx: dict[str, Any] | None, argv: Any) -> dict[str, Any] | None:
    """Snapshot a ``NtAllocateVirtualMemory`` request before the handler runs.

    Records ProcessHandle, BaseAddress/RegionSize pointers and their values,
    ZeroBits, AllocationType and Protect.  Attached immediately so the
    evidence also survives a handler exception (e.g. an unreadable
    BaseAddress write-back).
    """
    try:
        values = list(argv or ())
        while len(values) < 6:
            values.append(None)
        process_handle, base_ptr, zero_bits, size_ptr, alloc_type, protect = values[:6]
        observation = {
            "kind": OBSERVATION_KIND,
            "schema_version": SCHEMA_VERSION,
            "api": "ntdll.NtAllocateVirtualMemory",
            "handler": "ntoskrnl.ZwAllocateVirtualMemory",
            "process_handle": hex_value(_int_value(process_handle)),
            "base_address_ptr": hex_value(_int_value(base_ptr)),
            "base_address_requested": hex_value(_read_pointer(emu, base_ptr)),
            "zero_bits": hex_value(_int_value(zero_bits)),
            "region_size_ptr": hex_value(_int_value(size_ptr)),
            "region_size": hex_value(_read_pointer(emu, size_ptr)),
            "allocation_type": hex_value(_int_value(alloc_type)),
            "requested_protect": hex_value(_int_value(protect)),
            "requested_protect_names": _protect_names(protect),
            "status": None,
            "base_address_out": None,
            "region_size_out": None,
            "mapping": None,
        }
        attach(ctx, observation)
        return observation
    except Exception:
        logger.debug("page trace diagnostic: NtAllocateVirtualMemory snapshot failed", exc_info=True)
        return None


def finish_nt_allocate(
    emu: Any,
    ctx: dict[str, Any] | None,
    observation: dict[str, Any] | None,
    *,
    status: Any,
    base_out: Any,
    region_size: Any,
) -> dict[str, Any] | None:
    """Record the ``NtAllocateVirtualMemory`` STATUS and the returned mapping."""
    if not isinstance(observation, dict):
        return None
    try:
        observation["status"] = hex_value(_int_value(status))
        observation["base_address_out"] = hex_value(_int_value(base_out))
        observation["region_size_out"] = hex_value(_int_value(region_size))
        observation["mapping"] = page_trace(emu, base_out)
    except Exception:
        logger.debug("page trace diagnostic: NtAllocateVirtualMemory finish failed", exc_info=True)
    attach(ctx, observation)
    return observation


def start_nt_protect(emu: Any, ctx: dict[str, Any] | None, argv: Any) -> dict[str, Any] | None:
    """Snapshot a ``NtProtectVirtualMemory`` call before the handler runs.

    Records the IN/OUT pointers and their values, the requested protection and
    the focused guest registers (EAX/EDI/EBP/ESP or x64 equivalents) plus the
    page state of the target range.
    """
    try:
        values = list(argv or ())
        while len(values) < 5:
            values.append(None)
        process_handle, base_ptr, size_ptr, new_protect, old_ptr = values[:5]
        base_value = _read_pointer(emu, base_ptr)
        size_value = _read_pointer(emu, size_ptr)
        observation = {
            "kind": OBSERVATION_KIND,
            "schema_version": SCHEMA_VERSION,
            "api": "ntdll.NtProtectVirtualMemory",
            "handler": "ntoskrnl.ZwProtectVirtualMemory",
            "process_handle": hex_value(_int_value(process_handle)),
            "base_address_ptr": hex_value(_int_value(base_ptr)),
            "region_size_ptr": hex_value(_int_value(size_ptr)),
            "old_protect_ptr": hex_value(_int_value(old_ptr)),
            "base_address_value": hex_value(base_value),
            "region_size_value": hex_value(size_value),
            "requested_protect": hex_value(_int_value(new_protect)),
            "requested_protect_names": _protect_names(new_protect),
            "registers_before": registers_snapshot(emu),
            "range_before": range_page_trace(emu, base_value, size_value),
            "status": None,
            "base_address_written": None,
            "region_size_written": None,
            "old_protect_written": None,
            "registers_after": None,
            "range_after": None,
        }
        attach(ctx, observation)
        return observation
    except Exception:
        logger.debug("page trace diagnostic: NtProtectVirtualMemory snapshot failed", exc_info=True)
        return None


def finish_nt_protect(
    emu: Any,
    ctx: dict[str, Any] | None,
    observation: dict[str, Any] | None,
    *,
    status: Any,
    base_address_written: Any = None,
    region_size_written: Any = None,
    old_protect_written: Any = None,
) -> dict[str, Any] | None:
    """Record the NTSTATUS, write-back values and handler-exit registers."""
    if not isinstance(observation, dict):
        return None
    try:
        observation["status"] = hex_value(_int_value(status))
        observation["base_address_written"] = hex_value(_int_value(base_address_written))
        observation["region_size_written"] = hex_value(_int_value(region_size_written))
        observation["old_protect_written"] = hex_value(_int_value(old_protect_written))
        observation["registers_after"] = registers_snapshot(emu)
        base_after = base_address_written
        if base_after is None:
            base_after = _parse_hex(observation.get("base_address_value"))
        size_after = region_size_written
        if size_after is None:
            size_after = _parse_hex(observation.get("region_size_value"))
        observation["range_after"] = range_page_trace(emu, base_after, size_after)
    except Exception:
        logger.debug("page trace diagnostic: NtProtectVirtualMemory finish failed", exc_info=True)
    attach(ctx, observation)
    return observation


def start_virtual_protect(emu: Any, ctx: dict[str, Any] | None, argv: Any) -> dict[str, Any] | None:
    """Snapshot a ``VirtualProtect`` call: arguments and per-page "before" state."""
    try:
        values = list(argv or ())
        while len(values) < 4:
            values.append(None)
        lp_address, dw_size, new_protect, old_ptr = values[:4]
        span = range_page_trace(emu, lp_address, dw_size)
        pages = [
            {"address": page.get("address"), "before": page, "after": None}
            for page in span.get("pages", [])
        ]
        observation = {
            "kind": OBSERVATION_KIND,
            "schema_version": SCHEMA_VERSION,
            "api": "kernel32.VirtualProtect",
            "handler": "kernel32.VirtualProtect",
            "lp_address": hex_value(_int_value(lp_address)),
            "dw_size": hex_value(_int_value(dw_size)),
            "new_protect": hex_value(_int_value(new_protect)),
            "new_protect_names": _protect_names(new_protect),
            "old_protect_ptr": hex_value(_int_value(old_ptr)),
            "range_start": span.get("start"),
            "range_end": span.get("end"),
            "pages": pages,
            "pages_truncated": span.get("truncated", False),
            "success": None,
            "return_value": None,
            "error": None,
            "last_error": None,
            "old_protect_written": None,
        }
        attach(ctx, observation)
        return observation
    except Exception:
        logger.debug("page trace diagnostic: VirtualProtect snapshot failed", exc_info=True)
        return None


def finish_virtual_protect(
    emu: Any,
    ctx: dict[str, Any] | None,
    observation: dict[str, Any] | None,
    *,
    success: bool,
    error: Any = None,
    last_error: Any = _UNSET,
    old_protect_written: Any = None,
) -> dict[str, Any] | None:
    """Record the ``VirtualProtect`` outcome and per-page "after" state.

    ``last_error`` defaults to the emulator's current ``GetLastError`` value,
    read after the handler applied its own ``SetLastError``; an emulator
    without the accessor reports ``None``.
    """
    if not isinstance(observation, dict):
        return None
    try:
        if last_error is _UNSET:
            getter = getattr(emu, "get_last_error", None)
            try:
                last_error = getter() if callable(getter) else None
            except Exception:
                logger.debug("page trace diagnostic: last error unavailable", exc_info=True)
                last_error = None
        observation["success"] = bool(success)
        observation["return_value"] = "0x1" if success else "0x0"
        observation["error"] = hex_value(_int_value(error))
        observation["last_error"] = hex_value(_int_value(last_error))
        observation["old_protect_written"] = hex_value(_int_value(old_protect_written))
        for entry in observation.get("pages", []):
            if isinstance(entry, dict):
                entry["after"] = page_trace(emu, _parse_hex(entry.get("address")))
    except Exception:
        logger.debug("page trace diagnostic: VirtualProtect finish failed", exc_info=True)
    attach(ctx, observation)
    return observation


def start_lstrcpy(
    emu: Any,
    ctx: dict[str, Any] | None,
    argv: Any,
    char_width: int,
) -> dict[str, Any] | None:
    """Snapshot ``lstrcpyA/W`` pointers, page state and a bounded source preview."""
    try:
        values = list(argv or ())
        while len(values) < 2:
            values.append(None)
        dest, src = values[:2]
        api_name = "kernel32.lstrcpyW" if char_width == 2 else "kernel32.lstrcpyA"
        observation = {
            "kind": OBSERVATION_KIND,
            "schema_version": SCHEMA_VERSION,
            "api": api_name,
            "handler": "kernel32.lstrcpy",
            "destination": hex_value(_int_value(dest)),
            "source": hex_value(_int_value(src)),
            "char_width": char_width,
            "source_preview": _read_text(emu, src, char_width),
            "source_page": page_trace(emu, src),
            "destination_page": page_trace(emu, dest),
            "patch_byte_length": None,
            "patch_preview": None,
            "patch_truncated": False,
        }
        attach(ctx, observation)
        return observation
    except Exception:
        logger.debug("page trace diagnostic: lstrcpy snapshot failed", exc_info=True)
        return None


def finish_lstrcpy(
    emu: Any,
    ctx: dict[str, Any] | None,
    observation: dict[str, Any] | None,
    *,
    text: Any,
    char_width: int,
) -> dict[str, Any] | None:
    """Record the bytes ``lstrcpy`` is about to write to the destination.

    Called after the source string is decoded and before the guest memory
    write, so the patch evidence exists even when the write raises.
    """
    if not isinstance(observation, dict):
        return None
    try:
        size = None
        patch = None
        if isinstance(text, str):
            encoding = "utf-8" if char_width == 1 else "utf-16le"
            patch = text.encode(encoding)
            size = len(patch)
        elif isinstance(text, (bytes, bytearray)):
            patch = bytes(text)
            size = len(patch)
        observation["patch_byte_length"] = size
        if patch is not None:
            observation["patch_preview"] = patch[:MAX_PATCH_BYTES].hex()
            observation["patch_truncated"] = len(patch) > MAX_PATCH_BYTES
    except Exception:
        logger.debug("page trace diagnostic: lstrcpy finish failed", exc_info=True)
    attach(ctx, observation)
    return observation


__all__ = [
    "MAX_PAGES",
    "MAX_PATCH_BYTES",
    "MAX_TEXT_BYTES",
    "OBSERVATION_KIND",
    "SCHEMA_VERSION",
    "attach",
    "finish_lstrcpy",
    "finish_nt_allocate",
    "finish_nt_protect",
    "finish_virtual_protect",
    "hex_value",
    "page_trace",
    "range_page_trace",
    "registers_snapshot",
    "start_lstrcpy",
    "start_nt_allocate",
    "start_nt_protect",
    "start_virtual_protect",
]
