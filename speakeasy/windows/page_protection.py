"""Page-granular Windows memory protection semantics.

This module is the single place that translates Win32 ``PAGE_*`` protection
values into emulator permissions and applies a protection change to exactly
the pages covering ``[lpAddress, lpAddress+dwSize)``.

Windows and Wine treat writable image pages as copy-on-write: a page mapped
from an image section whose characteristics include ``IMAGE_SCN_MEM_WRITE`` is
reported as ``PAGE_WRITECOPY`` / ``PAGE_EXECUTE_WRITECOPY`` and the first write
creates a private copy (Wine ``dlls/ntdll/unix/virtual.c:3004-3008`` maps only
writable sections to ``VPROT_WRITECOPY``).  An explicit
``VirtualProtect(PAGE_READONLY)`` must still remove write permission: Wine maps
it to ``VPROT_READ`` and calls ``mprotect`` (``virtual.c:1602-1635``), so COW
is never a way around an explicit read-only request.

The emulator has no on-disk write-back for loaded images, so the copy-on-write
model is bookkeeping: writable image pages are writable in the emulator and
carry the write-copy Win32 protection value for VirtualQuery/VirtualProtect.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import speakeasy.common as common
import speakeasy.winenv.defs.windows.windows as windefs

if TYPE_CHECKING:
    from speakeasy.memmgr import MemoryManager

# ``windefs`` defines every base PAGE_* value except PAGE_WRITECOPY.
PAGE_WRITECOPY = 0x08
PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400

# Win32 error used when any page in the requested range is not committed.
ERROR_INVALID_ADDRESS = 487

_BASE_PROTECTIONS = frozenset(
    {
        windefs.PAGE_NOACCESS,
        windefs.PAGE_READONLY,
        windefs.PAGE_READWRITE,
        PAGE_WRITECOPY,
        windefs.PAGE_EXECUTE,
        windefs.PAGE_EXECUTE_READ,
        windefs.PAGE_EXECUTE_READWRITE,
        windefs.PAGE_EXECUTE_WRITECOPY,
    }
)
_COPY_PROTECTIONS = frozenset({PAGE_WRITECOPY, windefs.PAGE_EXECUTE_WRITECOPY})

DEFAULT_PAGE_SIZE = 0x1000


@dataclass(frozen=True)
class PageProtectionResult:
    """Outcome of a page-protection request.

    Attributes:
        success: True when the whole range was protected.
        old_protect: Win32 protection of the first affected page, valid only
            on success.  VirtualProtect writes this to ``lpflOldProtect``.
        start: Page-aligned start of the affected range.
        end: Page-aligned (exclusive) end of the affected range.
        error: Win32 error code to expose via ``SetLastError`` on failure;
            None on success.
    """

    success: bool
    old_protect: int = 0
    start: int = 0
    end: int = 0
    error: int | None = None


def page_span(lp_address: int, dw_size: int, page_size: int = DEFAULT_PAGE_SIZE) -> tuple[int, int]:
    """Return the page-aligned ``[start, end)`` covered by an address range.

    ``start = lp_address & ~(page_size - 1)`` and
    ``end = (lp_address + dw_size + page_size - 1) & ~(page_size - 1)``, which
    is the range Windows protects (the low bits of ``lpAddress`` contribute to
    the end of the last page).
    """
    start = lp_address & ~(page_size - 1)
    end = (lp_address + dw_size + page_size - 1) & ~(page_size - 1)
    return start, end


def win_protect_to_emu_perms(protect: int) -> int:
    """Convert a Win32 ``PAGE_*`` value to emulator permissions.

    Modifier bits (PAGE_GUARD/NOCACHE/WRITECOMBINE) are ignored because the
    emulator does not model guard pages or cache attributes.  Write-copy
    protections are writable from the guest's perspective.  Unknown base
    values yield ``PERM_MEM_NONE`` (the previous behaviour of
    ``Kernel32.win_perms_to_emu_perms``).
    """
    base = protect & 0xFF
    if base == windefs.PAGE_NOACCESS:
        return common.PERM_MEM_NONE
    if base == windefs.PAGE_READONLY:
        return common.PERM_MEM_READ
    if base in (windefs.PAGE_READWRITE, PAGE_WRITECOPY):
        return common.PERM_MEM_READ | common.PERM_MEM_WRITE
    if base == windefs.PAGE_EXECUTE:
        return common.PERM_MEM_EXEC
    if base == windefs.PAGE_EXECUTE_READ:
        return common.PERM_MEM_READ | common.PERM_MEM_EXEC
    if base in (windefs.PAGE_EXECUTE_READWRITE, windefs.PAGE_EXECUTE_WRITECOPY):
        return common.PERM_MEM_READ | common.PERM_MEM_WRITE | common.PERM_MEM_EXEC
    return common.PERM_MEM_NONE


def emu_perms_to_win_protect(perms: int) -> int:
    """Convert emulator permissions to the closest Win32 ``PAGE_*`` value."""
    execute = bool(perms & common.PERM_MEM_EXEC)
    read = bool(perms & common.PERM_MEM_READ)
    write = bool(perms & common.PERM_MEM_WRITE)

    if execute:
        if write:
            return windefs.PAGE_EXECUTE_READWRITE
        if read:
            return windefs.PAGE_EXECUTE_READ
        return windefs.PAGE_EXECUTE
    if write:
        # Windows has no user-mode write-only page protection.
        return windefs.PAGE_READWRITE
    if read:
        return windefs.PAGE_READONLY
    return windefs.PAGE_NOACCESS


def image_protection_for_emu_perms(perms: int) -> int:
    """Return the Win32 protection of an image-section page.

    Wine's image mapping gives writable sections ``VPROT_WRITECOPY`` and
    reports them as ``PAGE_WRITECOPY`` (or ``PAGE_EXECUTE_WRITECOPY`` when the
    section is executable); read-only sections keep ordinary protections
    (``virtual.c:3004-3008`` and the VPROT->Win32 table at ``virtual.c:147-161``).
    """
    execute = bool(perms & common.PERM_MEM_EXEC)
    read = bool(perms & common.PERM_MEM_READ)
    write = bool(perms & common.PERM_MEM_WRITE)

    if write:
        if execute:
            return windefs.PAGE_EXECUTE_WRITECOPY
        return PAGE_WRITECOPY
    if execute:
        if read:
            return windefs.PAGE_EXECUTE_READ
        return windefs.PAGE_EXECUTE
    if read:
        return windefs.PAGE_READONLY
    return windefs.PAGE_NOACCESS


def current_win_protection(emu: MemoryManager, address: int) -> int:
    """Return the effective Win32 protection for ``address``.

    Page-level state (including write-copy values recorded at image load) wins;
    otherwise the containing map's effective emulator permissions are
    converted.  An unmapped address reports PAGE_NOACCESS.
    """
    protect = emu.get_address_win_protection(address)
    if protect is not None:
        return protect

    perms = emu.get_address_perms(address)
    if perms is None:
        mm = emu.get_address_map(address)
        perms = mm.prot if mm is not None else common.PERM_MEM_NONE
    return emu_perms_to_win_protect(perms)


def _resolve_new_protection(base_protect: int, mm) -> int | None:
    """Map a requested base protection to the page's resulting Win32 value.

    Image views turn readable+writable requests into write-copy requests
    (Wine ``get_vprot_flags(..., image=TRUE)``).  Explicit write-copy on a
    private VirtualAlloc view is invalid (Wine ``set_protection`` rejects
    ``VPROT_WRITECOPY`` for valloc views); ``MemMap.flags`` is non-zero exactly
    for VirtualAlloc mappings in this emulator.
    """
    is_image = bool(mm.is_image)
    if base_protect in _COPY_PROTECTIONS:
        if not is_image and mm.flags:
            return None
        return base_protect
    if is_image:
        if base_protect == windefs.PAGE_READWRITE:
            return PAGE_WRITECOPY
        if base_protect == windefs.PAGE_EXECUTE_READWRITE:
            return windefs.PAGE_EXECUTE_WRITECOPY
    return base_protect


def apply_page_protection(
    emu: MemoryManager,
    lp_address: int,
    dw_size: int,
    fl_new_protect: int,
    *,
    page_size: int | None = None,
) -> PageProtectionResult:
    """Apply a Win32 protection change to exactly the covered pages.

    The request is validated before any page is touched: ``dwSize`` must be
    non-zero, the base protection must be one of the eight Win32 values, and
    every page in the range must be mapped.  The old protection of the first
    page is captured before the change, matching VirtualProtect's
    ``lpflOldProtect`` contract.  The containing ``MemMap.prot`` is never
    modified; only per-page protection state is updated, so neighbours and
    other sections of the same map keep their protections.

    Args:
        emu: Memory manager (Windows emulator).
        lp_address: ``lpAddress`` from VirtualProtect.
        dw_size: ``dwSize`` in bytes.
        fl_new_protect: Win32 ``PAGE_*`` value.
        page_size: Override page size; defaults to ``emu.page_size``.

    Returns:
        PageProtectionResult.  On failure ``success`` is False, ``error`` holds
        the Win32 error to set, and no page state has changed.

    Unknown inputs: invalid base protections and write-copy requests on private
    VirtualAlloc views fail with ``ERROR_INVALID_PARAMETER``; ranges with an
    unmapped page or outside the address width fail with
    ``ERROR_INVALID_ADDRESS``.  PAGE_GUARD/NOCACHE/WRITECOMBINE are accepted
    and ignored because the emulator does not model them.
    """
    page_size = page_size or getattr(emu, "page_size", 0) or DEFAULT_PAGE_SIZE
    if dw_size <= 0:
        return PageProtectionResult(False, error=windefs.ERROR_INVALID_PARAMETER)

    base_protect = fl_new_protect & 0xFF
    if base_protect not in _BASE_PROTECTIONS:
        return PageProtectionResult(False, error=windefs.ERROR_INVALID_PARAMETER)

    start, end = page_span(lp_address, dw_size, page_size)
    if end <= start:
        return PageProtectionResult(False, error=ERROR_INVALID_ADDRESS)

    pointer_bits = 32
    get_ptr_size = getattr(emu, "get_ptr_size", None)
    if get_ptr_size is not None:
        pointer_bits = get_ptr_size() * 8
    if end > (1 << pointer_bits):
        return PageProtectionResult(False, error=ERROR_INVALID_ADDRESS)

    plans: list[tuple[int, int, int]] = []
    for page in range(start, end, page_size):
        mm = emu.get_address_map(page)
        if mm is None:
            return PageProtectionResult(False, error=ERROR_INVALID_ADDRESS)
        win_protect = _resolve_new_protection(base_protect, mm)
        if win_protect is None:
            return PageProtectionResult(False, error=windefs.ERROR_INVALID_PARAMETER)
        plans.append((page, win_protect_to_emu_perms(win_protect), win_protect))

    old_protect = current_win_protection(emu, start)

    # Coalesce consecutive pages that end up with identical state so a large
    # section costs one mem_protect call per run instead of one per page.
    runs: list[list[int]] = []
    for page, perms, win_protect in plans:
        if runs and runs[-1][1] == page and runs[-1][2] == perms and runs[-1][3] == win_protect:
            runs[-1][1] = page + page_size
        else:
            runs.append([page, page + page_size, perms, win_protect])

    for run_start, run_end, perms, win_protect in runs:
        emu.mem_protect(run_start, run_end - run_start, perms, win_protect=win_protect)

    return PageProtectionResult(
        True,
        old_protect=old_protect,
        start=start,
        end=end,
    )
