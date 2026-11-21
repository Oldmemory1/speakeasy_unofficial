"""Per-process virtual address views for cross-process memory APIs.

Windows gives every process an independent virtual address space.  Speakeasy
has a single global ``MemoryManager.maps`` list and one emulator instance, so
``VirtualAllocEx``/``WriteProcessMemory``/``ReadProcessMemory`` on another
process used to act on the caller's own memory (FX-012,
``AddressSpace / per_process_isolation``).

This module models the missing target-process view as an explicit,
bookkeeping-only shadow address space:

* the current/executing process keeps using the global emulator memory;
* a non-current process gets a :class:`ProcessAddressSpace` holding its own
  region table, overlay bytes, and page-protection table;
* no Unicorn/host mappings are created for shadow views, so model-only child
  processes never become runnable through this module.

Windows/Wine references: ``VirtualAllocEx`` fails a ``MEM_RESERVE`` request
whose base is already occupied in the target process with
``ERROR_INVALID_ADDRESS`` instead of relocating it; ``WriteProcessMemory``
writes the target process's pages and temporarily relaxes their protection,
restoring it afterwards.  The page-protection conversions are shared with
:mod:`speakeasy.windows.page_protection` (FX-004/FX-009).

Phase 3 (FX-012-extended) adds three explicit model paths on top of the
shadow view:

* :meth:`ProcessAddressSpace.capture_runtime_write` /
  :meth:`ProcessAddressSpace.sync_runtime_region` project bytes observed in a
  child process's own runtime memory back into its shadow overlay; the parent
  view is never touched;
* :meth:`ProcessAddressSpace.map_loaded_image` seeds a view from an already
  memory-mapped PE image plus explicit per-page protections (pe-only children
  that have ``process.pe`` but no ``process.pe_data``);
* :meth:`ProcessAddressSpace.unmap` implements ``VirtualFreeEx``
  ``MEM_RELEASE``/``MEM_DECOMMIT`` bookkeeping.

Child execution is still ``model_only`` in the engine, so no code here claims
that a child executed; the runtime paths are driven by explicit callers.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import pefile

import speakeasy.common as common
import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.windows.page_protection import (
    ERROR_INVALID_ADDRESS,
    PAGE_WRITECOPY,
    page_span,
    win_protect_to_emu_perms,
)

if TYPE_CHECKING:
    from speakeasy.memmgr import MemoryManager

DEFAULT_PAGE_SIZE = 0x1000
ALLOCATION_GRANULARITY = 0x10000
#: Upper bound for one shadow region.  Larger requests fail explicitly rather
#: than allocating unbounded host memory (the shadow view is not a real
#: mapping and only needs to describe model-only processes).
MAX_SHADOW_REGION_SIZE = 0x10000000

MEM_COMMIT = windefs.MEM_COMMIT
MEM_RESERVE = windefs.MEM_RESERVE
MEM_DECOMMIT = 0x4000
MEM_RELEASE = 0x8000
MEM_TOP_DOWN = 0x100000
_SUPPORTED_ALLOC_TYPES = MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN
_FREE_TYPES = frozenset({MEM_DECOMMIT, MEM_RELEASE})

ERROR_INVALID_PARAMETER = windefs.ERROR_INVALID_PARAMETER
ERROR_NOACCESS = 998
ERROR_PARTIAL_COPY = 299

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

_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_IMAGE_SCN_MEM_READ = 0x40000000
_IMAGE_SCN_MEM_WRITE = 0x80000000


class ProcessMemoryError(Exception):
    """Explicit Windows-style failure for a per-process memory operation.

    Args:
        win_error: Win32 error code the API handler must expose through
            ``SetLastError``.
        message: Optional diagnostic text; never shown to the guest.
    """

    def __init__(self, win_error: int, message: str = ""):
        self.win_error = int(win_error)
        super().__init__(message or f"Win32 error {self.win_error}")


@dataclass
class ShadowRegion:
    """One committed region inside a per-process shadow address space.

    Attributes:
        base: Page-aligned region base.
        size: Page-aligned region size in bytes.
        protect: Win32 base protection supplied at allocation time.
        data: Overlay bytes; reads and writes operate on this bytearray.
        tag: Diagnostic label (image path or API tag).
        is_image: True for the initial PE image view.
    """

    base: int
    size: int
    protect: int
    data: bytearray
    tag: str = ""
    is_image: bool = False

    @property
    def end(self) -> int:
        """Exclusive region end address."""
        return self.base + self.size


def _section_win_protect(characteristics: int) -> int:
    """Return the Win32 protection of an image section.

    Writable sections are file-backed and are reported as write-copy, matching
    Wine's image mapping (see ``windows.page_protection``).
    """
    execute = bool(characteristics & _IMAGE_SCN_MEM_EXECUTE)
    read = bool(characteristics & _IMAGE_SCN_MEM_READ)
    write = bool(characteristics & _IMAGE_SCN_MEM_WRITE)

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


class ProcessAddressSpace:
    """Shadow virtual-address view for a process that is not executing.

    The view owns a region table, one bytearray per region, and a page-level
    Win32 protection table.  It never creates emulator mappings.  Unmapped
    accesses raise :class:`ProcessMemoryError` with an explicit Win32 code;
    they never return synthetic zeros or silently succeed.

    Args:
        pid: Process id owning this view (diagnostics only).
        pointer_bits: 32 or 64; bounds the modellable address range.
        page_size: Page size in bytes; defaults to 0x1000.
    """

    def __init__(self, pid: int, pointer_bits: int = 32, page_size: int = DEFAULT_PAGE_SIZE):
        if pointer_bits not in (32, 64):
            raise ValueError("pointer_bits must be 32 or 64")
        if page_size <= 0 or page_size & (page_size - 1):
            raise ValueError("page_size must be a positive power of two")
        self.pid = int(pid)
        self.pointer_bits = pointer_bits
        self.page_size = page_size
        self._regions: dict[int, ShadowRegion] = {}
        self._page_protect: dict[int, int] = {}

    @property
    def regions(self) -> tuple[ShadowRegion, ...]:
        """Current regions in registration order."""
        return tuple(self._regions.values())

    @property
    def address_limit(self) -> int:
        """Exclusive upper bound of the modellable address space."""
        return 1 << self.pointer_bits

    # -- internal helpers ---------------------------------------------------

    def _span(self, base: int, size: int) -> tuple[int, int]:
        if size < 0 or base < 0:
            raise ProcessMemoryError(ERROR_INVALID_ADDRESS, "negative address range")
        start = base & ~(self.page_size - 1)
        end = (base + size + self.page_size - 1) & ~(self.page_size - 1)
        if end > self.address_limit:
            raise ProcessMemoryError(ERROR_INVALID_ADDRESS, "range outside address space")
        return start, end

    def _region_for(self, address: int) -> ShadowRegion | None:
        for region in self._regions.values():
            if region.base <= address < region.end:
                return region
        return None

    def _range_mapped(self, start: int, size: int) -> bool:
        if size <= 0:
            return False
        for page in range(start, start + size, self.page_size):
            if page not in self._page_protect:
                return False
        return True

    def _range_occupied(self, start: int, size: int) -> bool:
        """True when every page is inside a region (committed or reserved)."""
        if size <= 0:
            return False
        for page in range(start, start + size, self.page_size):
            if self._region_for(page) is None:
                return False
        return True

    def _commit_range(self, start: int, size: int, protect: int) -> None:
        """Commit reserved pages, zero-filling pages that were decommitted."""
        for page in range(start, start + size, self.page_size):
            region = self._region_for(page)
            if region is None:
                raise ProcessMemoryError(
                    ERROR_INVALID_ADDRESS, f"page 0x{page:x} is not reserved in target"
                )
            if page not in self._page_protect:
                offset = page - region.base
                end = min(offset + self.page_size, len(region.data))
                region.data[offset:end] = b"\x00" * (end - offset)
            self._page_protect[page] = protect

    def _set_protect_range(self, base: int, size: int, protect: int) -> None:
        start, end = self._span(base, size)
        for page in range(start, end, self.page_size):
            if page in self._page_protect:
                self._page_protect[page] = protect

    def _add_region(
        self,
        base: int,
        size: int,
        protect: int,
        *,
        data: bytes | None = None,
        tag: str = "",
        is_image: bool = False,
    ) -> ShadowRegion:
        if size <= 0 or size > MAX_SHADOW_REGION_SIZE:
            raise ProcessMemoryError(ERROR_INVALID_PARAMETER, "unsupported region size")
        if base % self.page_size:
            raise ProcessMemoryError(ERROR_INVALID_ADDRESS, "region base is not page aligned")
        start, end = self._span(base, size)
        aligned_size = end - start
        if not self.is_free(start, aligned_size):
            raise ProcessMemoryError(ERROR_INVALID_ADDRESS, "region overlaps existing mapping")

        if data is not None and len(data) > aligned_size:
            raise ProcessMemoryError(ERROR_INVALID_PARAMETER, "initial data exceeds region")

        content = bytearray(aligned_size)
        if data:
            content[: len(data)] = data
        region = ShadowRegion(
            base=start,
            size=aligned_size,
            protect=protect,
            data=content,
            tag=tag,
            is_image=is_image,
        )
        self._regions[start] = region
        for page in range(start, end, self.page_size):
            self._page_protect[page] = protect
        return region

    def _validate_access(
        self,
        base: int,
        size: int,
        *,
        need_write: bool,
        bypass_protection: bool,
    ) -> None:
        if size < 0:
            raise ProcessMemoryError(ERROR_INVALID_PARAMETER, "negative size")
        if size == 0:
            return
        self._span(base, size)
        offset = 0
        while offset < size:
            address = base + offset
            region = self._region_for(address)
            if region is None:
                raise ProcessMemoryError(
                    ERROR_PARTIAL_COPY if need_write else ERROR_NOACCESS,
                    f"address 0x{address:x} is not mapped in process {self.pid}",
                )
            page = address & ~(self.page_size - 1)
            protect = self._page_protect.get(page)
            if protect is None:
                # Reserved but not committed (after VirtualFreeEx
                # MEM_DECOMMIT): inaccessible even through WriteProcessMemory,
                # which only bypasses page *protection*, not commit state.
                raise ProcessMemoryError(
                    ERROR_PARTIAL_COPY if need_write else ERROR_NOACCESS,
                    f"page 0x{page:x} is not committed in process {self.pid}",
                )
            if need_write and not bypass_protection:
                perms = win_protect_to_emu_perms(protect)
                if not perms & common.PERM_MEM_WRITE:
                    raise ProcessMemoryError(
                        ERROR_NOACCESS, f"page 0x{page:x} is not writable"
                    )
            elif not need_write:
                perms = win_protect_to_emu_perms(protect)
                if not perms & common.PERM_MEM_READ:
                    raise ProcessMemoryError(
                        ERROR_NOACCESS, f"page 0x{page:x} is not readable"
                    )
            page_end = page + self.page_size
            offset += min(size - offset, region.end - address, page_end - address)

    # -- public contract ----------------------------------------------------

    def map_pe_image(self, data: bytes, image_base: int | None = None) -> int:
        """Register a PE image in this view from raw file bytes.

        Args:
            data: Complete PE file contents.
            image_base: Optional override of the PE ``ImageBase``.

        Returns:
            The page-aligned image base.

        Raises:
            ProcessMemoryError: ``ERROR_INVALID_PARAMETER`` for malformed or
            oversized images, ``ERROR_INVALID_ADDRESS`` if the image range is
            not free in this view (including a previously registered image).

        Side effects:
            Adds one image region: headers PAGE_READONLY, sections with their
            Win32 protections (writable sections write-copy), gaps PAGE_NOACCESS.
        """
        if not isinstance(data, (bytes, bytearray, memoryview)) or not data:
            raise ProcessMemoryError(ERROR_INVALID_PARAMETER, "empty or non-bytes PE image")
        raw = bytes(data)
        try:
            pe = pefile.PE(data=raw, fast_load=True)
        except pefile.PEFormatError as err:
            raise ProcessMemoryError(ERROR_INVALID_PARAMETER, f"invalid PE image: {err}") from err

        try:
            base = int(pe.OPTIONAL_HEADER.ImageBase if image_base is None else image_base)
            image_size = int(pe.OPTIONAL_HEADER.SizeOfImage)
            headers_size = int(pe.OPTIONAL_HEADER.SizeOfHeaders)
        except AttributeError as err:
            raise ProcessMemoryError(ERROR_INVALID_PARAMETER, f"invalid PE headers: {err}") from err

        region = self._add_region(
            base,
            image_size,
            windefs.PAGE_NOACCESS,
            tag=f"image.pid{self.pid}.0x{base:x}",
            is_image=True,
        )

        copy_len = min(headers_size, len(raw), region.size)
        region.data[:copy_len] = raw[:copy_len]
        if headers_size > 0:
            self._set_protect_range(base, min(headers_size, region.size), windefs.PAGE_READONLY)

        for section in pe.sections:
            virtual_address = int(section.VirtualAddress)
            virtual_size = max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
            if virtual_size <= 0:
                continue
            section_start = base + virtual_address
            section_end = min(section_start + virtual_size, region.end)
            if section_end <= section_start:
                continue
            protect = _section_win_protect(int(section.Characteristics))
            self._set_protect_range(section_start, section_end - section_start, protect)
            section_data = section.get_data()
            section_copy = min(len(section_data), section_end - section_start)
            if section_copy:
                offset = section_start - region.base
                region.data[offset : offset + section_copy] = section_data[:section_copy]

        return base

    def is_free(self, base: int, size: int) -> bool:
        """Return True when ``[base, base+size)`` overlaps no region.

        Invalid ranges (negative, overflow, beyond the address limit) report
        False.  The check uses page-aligned spans, like Windows allocation.
        """
        if base < 0 or size <= 0 or base + size > self.address_limit:
            return False
        start, end = self._span(base, size)
        if end <= start:
            return False
        for region in self._regions.values():
            if start < region.end and region.base < end:
                return False
        return True

    def _find_free(self, size: int, *, top_down: bool) -> int | None:
        span_start, span_end = self._span(0, size)
        span = span_end - span_start
        if top_down:
            base = (self.address_limit - span) & ~(ALLOCATION_GRANULARITY - 1)
            while base >= ALLOCATION_GRANULARITY:
                if self.is_free(base, span):
                    return base
                base -= ALLOCATION_GRANULARITY
            return None
        base = ALLOCATION_GRANULARITY
        while base + span <= self.address_limit:
            if self.is_free(base, span):
                return base
            base += ALLOCATION_GRANULARITY
        return None

    def virtual_alloc(self, lp_address: int, size: int, alloc_type: int, protect: int) -> int:
        """Emulate ``VirtualAllocEx`` inside this process view.

        Args:
            lp_address: Requested base (0/None selects a free base).
            size: Requested size in bytes; rounded up to the page size.
            alloc_type: MEM_COMMIT / MEM_RESERVE bit mask.
            protect: Win32 ``PAGE_*`` base protection.

        Returns:
            Page-aligned allocation base.

        Raises:
            ProcessMemoryError: ``ERROR_INVALID_PARAMETER`` for zero/oversized
            sizes, unknown protection or unsupported allocation flags;
            ``ERROR_INVALID_ADDRESS`` when the requested base is occupied in
            this view or no free range exists.  A requested base is never
            relocated around another process's mappings.
        """
        if size <= 0 or size > MAX_SHADOW_REGION_SIZE:
            raise ProcessMemoryError(ERROR_INVALID_PARAMETER, "unsupported allocation size")
        if protect & 0xFF not in _BASE_PROTECTIONS:
            raise ProcessMemoryError(ERROR_INVALID_PARAMETER, "invalid page protection")
        if alloc_type & ~_SUPPORTED_ALLOC_TYPES:
            raise ProcessMemoryError(ERROR_INVALID_PARAMETER, "unsupported allocation type")
        reserve = bool(alloc_type & MEM_RESERVE)
        commit = bool(alloc_type & MEM_COMMIT)
        if not reserve and not commit:
            raise ProcessMemoryError(ERROR_INVALID_PARAMETER, "no allocation type supplied")

        if lp_address:
            start, end = self._span(lp_address, size)
            region_size = end - start
            if reserve:
                self._add_region(start, region_size, protect)
                return start
            if not self._range_occupied(start, region_size):
                raise ProcessMemoryError(
                    ERROR_INVALID_ADDRESS, "MEM_COMMIT range is not reserved in target"
                )
            self._commit_range(start, region_size, protect)
            return start

        base = self._find_free(size, top_down=bool(alloc_type & MEM_TOP_DOWN))
        if base is None:
            raise ProcessMemoryError(ERROR_INVALID_ADDRESS, "no free range in target view")
        start, end = self._span(base, size)
        self._add_region(start, end - start, protect)
        return start

    def read(self, base: int, size: int) -> bytes:
        """Read exactly ``size`` bytes from this view.

        Raises:
            ProcessMemoryError: ``ERROR_NOACCESS`` when any page is unmapped or
            not readable, ``ERROR_INVALID_ADDRESS`` for ranges outside the
            address space.  No partial data is returned.
        """
        self._validate_access(base, size, need_write=False, bypass_protection=False)
        if size <= 0:
            return b""
        out = bytearray()
        offset = 0
        while offset < size:
            address = base + offset
            region = self._region_for(address)
            assert region is not None  # validated above
            page_end = (address & ~(self.page_size - 1)) + self.page_size
            chunk = min(size - offset, region.end - address, page_end - address)
            data_offset = address - region.base
            out += region.data[data_offset : data_offset + chunk]
            offset += chunk
        return bytes(out)

    def write(self, base: int, data: bytes, bypass_protection: bool = True) -> int:
        """Write ``data`` to this view.

        Args:
            base: Target address in the target process view.
            data: Bytes to write.
            bypass_protection: When True (WriteProcessMemory semantics), mapped
                pages are writable regardless of their current protection.
                When False, the page must be mapped and writable.

        Returns:
            Number of bytes written.

        Raises:
            ProcessMemoryError: ``ERROR_PARTIAL_COPY`` when any page is
            unmapped or reserved-but-decommitted, ``ERROR_NOACCESS`` when
            protection denies a non-bypass write.  Validation happens before
            mutation, so a failure never leaves a partial write behind.
        """
        self._validate_access(base, len(data), need_write=True, bypass_protection=bypass_protection)
        return self._write_overlay(base, data)

    def _write_overlay(self, base: int, data: bytes) -> int:
        """Copy validated bytes into region overlays."""
        if not data:
            return 0
        offset = 0
        while offset < len(data):
            address = base + offset
            region = self._region_for(address)
            assert region is not None  # callers validate first
            page_end = (address & ~(self.page_size - 1)) + self.page_size
            chunk = min(len(data) - offset, region.end - address, page_end - address)
            data_offset = address - region.base
            region.data[data_offset : data_offset + chunk] = data[offset : offset + chunk]
            offset += chunk
        return len(data)

    def protect(self, base: int, size: int, new_protect: int) -> tuple[int, int, int]:
        """Apply a page-granular protection change to this view.

        Returns:
            ``(page_aligned_base, page_aligned_size, old_protect)`` where
            ``old_protect`` is the protection of the first affected page.
        """
        if size <= 0:
            raise ProcessMemoryError(ERROR_INVALID_PARAMETER, "zero protect size")
        if new_protect & 0xFF not in _BASE_PROTECTIONS:
            raise ProcessMemoryError(ERROR_INVALID_PARAMETER, "invalid page protection")
        start, end = self._span(base, size)
        if not self._range_mapped(start, end - start):
            raise ProcessMemoryError(ERROR_INVALID_ADDRESS, "protect range is not mapped")
        old_protect = self._page_protect[start]
        for page in range(start, end, self.page_size):
            self._page_protect[page] = new_protect
        return start, end - start, old_protect

    def query(self, base: int) -> dict[str, Any] | None:
        """Return an explicit snapshot of the region containing ``base``."""
        region = self._region_for(base)
        if region is None:
            return None
        page = base & ~(self.page_size - 1)
        committed = page in self._page_protect
        return {
            "base": region.base,
            "size": region.size,
            "protect": self._page_protect.get(page, windefs.PAGE_NOACCESS),
            "allocation_protect": region.protect,
            "tag": region.tag,
            "is_image": region.is_image,
            "state": MEM_COMMIT if committed else MEM_RESERVE,
        }

    def map_loaded_image(
        self,
        image_base: int,
        image_size: int,
        data: bytes,
        page_protections: Mapping[int, int],
    ) -> int:
        """Seed this view from an already memory-mapped PE image.

        Used for pe-only child processes: ``Process.pe`` holds a loaded
        ``RuntimeModule`` but ``Process.pe_data`` is ``None``, so there are no
        raw file bytes to parse.  The caller supplies the mapped image bytes
        (for example read from the emulator's image mapping) and the Win32
        protection of every page.

        Args:
            image_base: Page-aligned image base in this view.
            image_size: PE ``SizeOfImage`` in bytes.
            data: Memory-mapped image bytes; at least ``image_size`` long.
            page_protections: Mapping of every page in the page-aligned image
                span to its Win32 ``PAGE_*`` protection.  Missing pages,
                unknown protections and out-of-range keys are rejected.

        Returns:
            The page-aligned image base.

        Raises:
            ProcessMemoryError: ``ERROR_INVALID_PARAMETER`` for an empty/short
            image or an incomplete protection map; ``ERROR_INVALID_ADDRESS``
            for a misaligned/out-of-range base or an overlap with an existing
            region.  A failure never leaves a partial image region behind.

        Side effects:
            Adds one ``is_image`` region holding the supplied bytes and page
            protections.  No emulator mapping is created.
        """
        if image_size <= 0 or image_size > MAX_SHADOW_REGION_SIZE:
            raise ProcessMemoryError(ERROR_INVALID_PARAMETER, "unsupported image size")
        if not isinstance(data, (bytes, bytearray, memoryview)) or len(data) < image_size:
            raise ProcessMemoryError(ERROR_INVALID_PARAMETER, "image bytes shorter than image size")
        if not isinstance(page_protections, Mapping) or not page_protections:
            raise ProcessMemoryError(ERROR_INVALID_PARAMETER, "missing page protection map")
        if image_base < 0 or image_base % self.page_size:
            raise ProcessMemoryError(ERROR_INVALID_ADDRESS, "image base is not page aligned")

        start, end = self._span(image_base, image_size)
        pages = list(range(start, end, self.page_size))
        for page in page_protections:
            if page not in pages:
                raise ProcessMemoryError(
                    ERROR_INVALID_PARAMETER, f"protection page 0x{page:x} is outside the image"
                )
        for page in pages:
            protect = page_protections.get(page)
            if protect is None or int(protect) & 0xFF not in _BASE_PROTECTIONS:
                raise ProcessMemoryError(
                    ERROR_INVALID_PARAMETER, f"invalid image protection for page 0x{page:x}"
                )

        region = self._add_region(
            start,
            end - start,
            windefs.PAGE_NOACCESS,
            tag=f"image.pid{self.pid}.0x{start:x}",
            is_image=True,
        )
        region.data[:image_size] = bytes(data[:image_size])
        for page in pages:
            self._page_protect[page] = int(page_protections[page])
        return start

    def capture_runtime_write(self, base: int, data: bytes, *, bypass_protection: bool = True) -> int:
        """Project a write observed in the child's own runtime memory.

        Model path (child execution remains ``model_only`` in the engine): an
        execution backend that runs a child in the emulator's shared memory
        reports each observed write here so the child's shadow overlay reflects
        the runtime bytes.  The parent's global mappings are never touched.
        Tests drive this method with controlled bytes; no child execution is
        claimed or required.

        Args:
            base: Address in the child's own address view.
            data: Bytes the child wrote at ``base``.
            bypass_protection: When True (default), the runtime already enforced
                the child's page protection, so stale shadow protections do not
                reject the observed write.  When False, the page must also be
                writable in this view.

        Returns:
            Number of bytes written to the shadow overlay.

        Raises:
            ProcessMemoryError: ``ERROR_PARTIAL_COPY`` when a page is unmapped
            or reserved-but-decommitted, ``ERROR_NOACCESS`` when
            ``bypass_protection=False`` and protection denies the write.
            Validation happens before mutation.
        """
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise ProcessMemoryError(ERROR_INVALID_PARAMETER, "runtime write data must be bytes")
        self._validate_access(base, len(data), need_write=True, bypass_protection=bypass_protection)
        return self._write_overlay(base, bytes(data))

    def sync_runtime_region(
        self,
        base: int,
        data: bytes,
        *,
        page_protections: Sequence[int] | None = None,
    ) -> int:
        """Backfill an authoritative runtime snapshot for a region.

        This is the range form of :meth:`capture_runtime_write` for executors
        that do not intercept individual writes: they read the child's runtime
        bytes after execution and supply them here, optionally with the child's
        current per-page Win32 protections (for example after a guest
        ``VirtualProtect``).

        Args:
            base: Address in the child's own address view.
            data: Runtime bytes for ``[base, base + len(data))``.
            page_protections: Optional Win32 protection for each page covering
                the range, in ascending page order.  The number of entries must
                match the page count exactly.

        Returns:
            Number of bytes written to the shadow overlay.

        Raises:
            ProcessMemoryError: ``ERROR_INVALID_PARAMETER`` for empty/non-bytes
            input or a malformed protection list, ``ERROR_PARTIAL_COPY`` when a
            page is unmapped or not committed.  Validation happens before
            mutation.
        """
        if not isinstance(data, (bytes, bytearray, memoryview)) or not data:
            raise ProcessMemoryError(ERROR_INVALID_PARAMETER, "runtime snapshot must be non-empty bytes")
        payload = bytes(data)
        self._validate_access(base, len(payload), need_write=True, bypass_protection=True)

        pages: list[int] = []
        if page_protections is not None:
            start, end = self._span(base, len(payload))
            pages = list(range(start, end, self.page_size))
            if len(page_protections) != len(pages):
                raise ProcessMemoryError(
                    ERROR_INVALID_PARAMETER, "one protection per page is required"
                )
            for protect in page_protections:
                if int(protect) & 0xFF not in _BASE_PROTECTIONS:
                    raise ProcessMemoryError(ERROR_INVALID_PARAMETER, "invalid page protection")

        self._write_overlay(base, payload)
        if page_protections is not None:
            for page, protect in zip(pages, page_protections):
                self._page_protect[page] = int(protect)
        return len(payload)

    def unmap(self, base: int, size: int, free_type: int) -> tuple[int, int]:
        """Emulate ``VirtualFreeEx`` inside this view.

        ``MEM_RELEASE`` removes the whole region (``size`` must be 0 and
        ``base`` must be the region base).  ``MEM_DECOMMIT`` makes the pages
        inaccessible but keeps the reservation, so the range stays occupied
        and can be committed again with ``VirtualAllocEx(MEM_COMMIT)``.

        Args:
            base: Address in the target view.
            size: 0 for ``MEM_RELEASE``; nonzero for ``MEM_DECOMMIT``.
            free_type: Exactly ``MEM_RELEASE`` or ``MEM_DECOMMIT``.

        Returns:
            Page-aligned ``(base, size)`` of the affected range.

        Raises:
            ProcessMemoryError: ``ERROR_INVALID_PARAMETER`` for an unknown free
            type or ``MEM_RELEASE`` with nonzero size; ``ERROR_INVALID_ADDRESS``
            when the address is not a region base / not committed.  All
            validation happens before mutation.
        """
        free_type = int(free_type)
        if free_type not in _FREE_TYPES:
            raise ProcessMemoryError(ERROR_INVALID_PARAMETER, "invalid free type")

        if free_type == MEM_RELEASE:
            if size != 0:
                raise ProcessMemoryError(
                    ERROR_INVALID_PARAMETER, "MEM_RELEASE requires dwSize == 0"
                )
            region = self._region_for(base)
            if region is None or region.base != base:
                raise ProcessMemoryError(
                    ERROR_INVALID_ADDRESS, "MEM_RELEASE address is not a region base"
                )
            del self._regions[region.base]
            for page in range(region.base, region.end, self.page_size):
                self._page_protect.pop(page, None)
            return region.base, region.size

        if size <= 0:
            raise ProcessMemoryError(ERROR_INVALID_PARAMETER, "MEM_DECOMMIT requires a size")
        start, end = self._span(base, size)
        for page in range(start, end, self.page_size):
            if page not in self._page_protect or self._region_for(page) is None:
                raise ProcessMemoryError(
                    ERROR_INVALID_ADDRESS, f"page 0x{page:x} is not committed"
                )
        for page in range(start, end, self.page_size):
            region = self._region_for(page)
            assert region is not None  # validated above
            offset = page - region.base
            length = min(self.page_size, len(region.data) - offset)
            region.data[offset : offset + length] = b"\x00" * length
            self._page_protect.pop(page, None)
        return start, end - start


def write_current_process_memory(
    emu: MemoryManager,
    base: int,
    data: bytes,
    *,
    writer: Callable[[int, bytes], Any] | None = None,
) -> int:
    """Write the caller process's memory with WriteProcessMemory semantics.

    ``WriteProcessMemory`` temporarily relaxes the target page protection,
    writes, then restores it; this also makes same-process writes to read-only
    image pages succeed like on Windows/Wine.

    Args:
        emu: Emulator memory manager.
        base: Target address in the caller's (global) address space.
        data: Bytes to write.
        writer: Optional explicit writer ``(address, data)``. Callers pass the
            API handler's ``mem_write`` so its shared-mapping view propagation
            is preserved; defaults to ``emu.mem_write``.

    Returns:
        Number of bytes written.

    Raises:
        ProcessMemoryError: ``ERROR_PARTIAL_COPY`` when any page in the range
        is unmapped (before any mutation), ``ERROR_NOACCESS`` when the engine
        write or a protection update fails.
    """
    if not data:
        return 0
    page_size = getattr(emu, "page_size", 0) or DEFAULT_PAGE_SIZE
    start, end = page_span(base, len(data), page_size)
    write = writer or emu.mem_write

    saved: list[tuple[int, int, int | None]] = []
    for page in range(start, end, page_size):
        mm = emu.get_address_map(page)
        if mm is None:
            raise ProcessMemoryError(
                ERROR_PARTIAL_COPY, f"address 0x{page:x} is not mapped in caller"
            )
        perms = emu.get_address_perms(page)
        if perms is None:
            perms = mm.prot
        saved.append((page, perms, emu.get_address_win_protection(page)))

    restore_error: Exception | None = None
    try:
        for page, _perms, _win_protect in saved:
            emu.mem_protect(page, page_size, common.PERM_MEM_READ | common.PERM_MEM_WRITE)
        write(base, data)
    except Exception as err:
        raise ProcessMemoryError(ERROR_NOACCESS, f"caller memory write failed: {err}") from err
    finally:
        for page, perms, win_protect in saved:
            try:
                emu.mem_protect(page, page_size, perms, win_protect=win_protect)
            except Exception as err:  # pragma: no cover - engine failure path
                restore_error = err

    if restore_error is not None:  # pragma: no cover - engine failure path
        raise ProcessMemoryError(ERROR_NOACCESS, f"protection restore failed: {restore_error}")
    return len(data)
