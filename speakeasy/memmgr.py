# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

from speakeasy import common
from speakeasy.errors import OutOfMemoryError

if TYPE_CHECKING:
    from speakeasy.config import SpeakeasyConfig
    from speakeasy.engines.unicorn_eng import EmuEngine


class MemMap:
    """
    Describe one allocation, such as a heap block, a pool block or an image.

    Allocations smaller than a page share a page block. ``block_base`` and ``block_size`` give the block
    that holds the allocation.
    """

    def __init__(
        self,
        base,
        size,
        tag,
        prot,
        flags,
        block_base,
        block_size,
        shared=False,
        process=None,
        is_image=False,
        dep_exec=False,
    ):
        self.base: int = base
        self.size: int = size

        base_addr_tag = f".0x{base:x}"
        if tag and base_addr_tag not in tag:
            tag += base_addr_tag

        if tag:
            tag = list(tag)
            bad_chars = "\\?[]:]"
            [tag.__setitem__(j, "_") for j in [i for i, e in enumerate(tag) if e in bad_chars]]
            tag = "".join(tag)

        self.tag: str | None = tag
        self.prot: int = prot
        self.flags: int = flags
        self.shared: bool = shared
        self.free: bool = False
        self.process: Any = process
        self.block_base: int = block_base
        self.block_size: int = block_size

        # True for PE image views (SEC_IMAGE). Image pages use write-copy
        # semantics and are reported with PAGE_WRITECOPY by VirtualQuery.
        self.is_image: bool = is_image
        # True when the engine holds execute permission that the guest did not
        # request, because the process image opted out of DEP (FX-001). ``prot``
        # keeps the protection the guest asked for; the effective engine
        # permission and the guest-visible Win32 protection are reported by
        # MemoryManager.get_address_perms/get_address_win_protection.
        self.dep_exec: bool = dep_exec

    def get_tag_without_address(self) -> str | None:
        """Get the tag without the ``.0x<base>`` suffix, or ``None`` if the allocation has no tag."""
        suffix = f".0x{self.base:x}"
        if self.tag and self.tag.endswith(suffix):
            return self.tag[: -len(suffix)] or None
        return self.tag or None

    def __hash__(self):
        return hash(self.base)

    def __eq__(self, other):
        if other is not None:
            return self.base == other.base

    def __ne__(self, other):
        return not (self == other)


class MemoryManager:
    """
    Keep the mapped and reserved memory of the emulator, and find free ranges for allocations.

    An allocation smaller than a page that gives no address goes into a shared page block. The class that
    inherits this class must set ``hooks``, ``emu_eng`` and ``config``.
    """

    hooks: dict[int, Any]
    emu_eng: EmuEngine
    config: SpeakeasyConfig

    def get_current_process(self) -> Any:
        return None

    def get_address_limit(self) -> int | None:
        """Return the end of the address space that allocations which start below it must fit in."""
        return None

    def __init__(self, *args, **kwargs):
        super().__init__()
        self.maps: list[MemMap] = []
        self._page_protections: dict[int, int] = {}
        self._page_win_protections: dict[int, int] = {}
        self.mem_reserves: list[MemMap] = []
        self.block_base: int = 0
        self.block_size: int = 0
        self.block_offset: int = 0
        self.page_size: int = 0x1000
        # Base-less allocations start at the first page. This keeps the local
        # FX-009 contract that a shellcode image is based at page 0x1000
        # (tests/test_zwprotect_virtual_memory.py); upstream starts them at
        # 0x10000 (ALLOCATION_GRANULARITY), which would relocate shellcode.
        # ``allocations_from`` still moves the search base for a caller, e.g.
        # winemu.MACHINE_BASE for the machine structures.
        self.alloc_base: int = self.page_size
        # The Data Execution Prevention (DEP) state of the emulation. Without DEP, code can run from every
        # readable page. See get_native_perms.
        self.dep_enabled: bool = True

    @contextmanager
    def allocations_from(self, base: int) -> Iterator[None]:
        """Start the search for free memory at ``base`` for allocations in this block that give no address."""
        previous = self.alloc_base
        self.alloc_base = base
        # Start a new shared block for small allocations, here and after the block, so that small
        # allocations also come from the current search base.
        self.block_base = self.block_offset = 0
        try:
            yield
        finally:
            self.alloc_base = previous
            self.block_base = self.block_offset = 0

    def _hook_mem_map_dispatch(self, mm):
        hl = self.hooks.get(common.HOOK_MEM_MAP, [])
        # Copy the list, because a callback can remove its hook.
        for mem_map_hook in list(hl):
            if mem_map_hook.enabled:
                if mem_map_hook.begin <= mm.base:
                    if not mem_map_hook.end or mem_map_hook.end > mm.base:
                        mem_map_hook.cb(mem_map_hook.emu, mm.base, mm.size, mm.tag, mm.prot, mm.flags)

    @staticmethod
    def _dep_exec_eligible(image: bool, flags: int) -> bool:
        """
        Return whether a mapping may gain execute permission under the local DEP rule.

        Local FX-001 permits DEP execute relaxation only for a writable private
        ``VirtualAlloc`` view of a process image that opted out of DEP. Image
        views, stack pages, heap blocks and other private mappings keep their
        protection; a writable image page is relaxed one page at a time by the
        deferred protected-fault grant of the Windows emulator. ``flags`` is the
        Win32 allocation protection of a ``VirtualAlloc`` view, whose low byte is
        the base ``PAGE_*`` value that the guest observes.
        """
        return not image and bool(flags) and bool(int(flags) & 0xFF)

    def get_native_perms(self, perms: int, *, dep: bool = True, image: bool = False, flags: int = 0) -> int:
        """
        Get the permissions that the engine gives to memory that has the protection ``perms``.

        With DEP off, the processor does not apply the no-execute bit to the pages of the process. Upstream
        grants execute permission to every readable page; the local FX-001 rule narrows that to a writable
        private ``VirtualAlloc`` view (``image`` false and a non-zero Win32 ``flags`` value). Image pages are
        relaxed only through the deferred protected-fault grant in the Windows emulator, and stack, heap and
        other private mappings keep their protection. ``dep=False`` gives ``perms`` without a change, for
        memory that must keep its protection, such as the synthetic modules or PE image sections.
        """
        if dep and not self.dep_enabled and (perms & common.PERM_MEM_WRITE):
            if self._dep_exec_eligible(image, flags):
                return perms | common.PERM_MEM_EXEC
        return perms

    def mem_map(
        self,
        size: int,
        base: int | None = None,
        perms: int = common.PERM_MEM_RWX,
        tag: str | None = None,
        flags: int = 0,
        *,
        shared: bool = False,
        process: Any = None,
        image: bool = False,
        dep: bool = True,
    ) -> int:
        """
        Map memory and return its address.

        If ``base`` is ``None`` and ``size`` is smaller than a page, the allocation goes into the shared page
        block, which the emulator maps RWX. Otherwise the emulator maps a page-aligned range at or after
        ``base``. ``perms`` is the protection that the guest asked for. See ``get_native_perms`` for ``dep``.

        ``image=True`` marks a PE image view (SEC_IMAGE), which affects write-copy protection semantics; see
        ``windows.page_protection``. Image views request exactly their section permissions (the Windows
        emulator maps them with ``dep=False``) and become executable only through the deferred
        protected-fault grant, never for the whole view.

        Raises:
            OutOfMemoryError: if no free range fits below the address limit.
        """
        if not process and tag and not tag.startswith("emu"):
            process = self.get_current_process()

        if base is None:
            if size < self.page_size and size % self.page_size:
                addr = self.block_base + self.block_offset
                pad_size = 0x10 - (size % 0x10)
                size += pad_size
                if not self.block_base or ((addr + size) > self.block_base + self.page_size):
                    block = self.get_valid_ranges(self.page_size)
                    self.block_base, self.block_size = block

                    self.emu_eng.mem_map(self.block_base, self.block_size)
                    self.block_offset = 0
                    addr = self.block_base + self.block_offset

                self.block_offset += size
                base = addr

                mm = MemMap(
                    base,
                    size,
                    tag,
                    perms,
                    flags,
                    self.block_base,
                    self.block_size,
                    shared,
                    process,
                    is_image=image,
                )

                self.maps.append(mm)
                self._hook_mem_map_dispatch(mm)
                return base

        block = self.get_valid_ranges(size, addr=base)
        base, size = block

        block_size = self.block_size
        if size > self.block_size:
            block_size = size
        native_perms = self.get_native_perms(perms, dep=dep, image=image, flags=flags)
        mm = MemMap(
            base,
            size,
            tag,
            perms,
            flags,
            base,
            block_size,
            shared,
            process,
            is_image=image,
            dep_exec=native_perms != perms,
        )
        self.emu_eng.mem_map(base, size, perms=native_perms)
        self.maps.append(mm)
        self._hook_mem_map_dispatch(mm)
        return base

    def mem_free(self, base) -> None:
        """
        Mark the allocation at ``base`` as free.

        When all allocations in its block are free, unmap the block, unless the config keeps freed memory.
        """
        mm = self.get_address_map(base)
        if mm:
            mm.free = True

            if self.config.memory.freed_regions:
                return

            ml = [m for m in self.get_mem_maps() if m.block_base == mm.block_base]
            if all([m.free for m in ml]):
                self.block_base = 0
                self.mem_unmap(mm.block_base, mm.block_size)
                for m in ml:
                    self.maps.remove(m)

    def mem_unmap(self, base, size):
        """Unmap a range in the engine. The ``MemMap`` objects of the range stay."""
        self.clear_page_protections(base, size)
        self.emu_eng.mem_unmap(base, size)

    def mem_write(self, addr, data) -> None:
        """Write bytes into the emulated address space."""
        self.emu_eng.mem_write(addr, data)

    def mem_read(self, addr, size) -> bytes:
        """Read bytes from the emulated address space."""
        return bytes(self.emu_eng.mem_read(addr, size))

    def _range_is_private_virtual_alloc(self, addr: int, size: int) -> bool:
        """Return whether every page of a range belongs to a private ``VirtualAlloc`` mapping."""
        page_size = self.page_size
        start = int(addr) & ~(page_size - 1)
        end = int(addr) + int(size)
        if end <= start:
            return False
        for page in range(start, end, page_size):
            mm = self.get_address_map(page)
            if mm is None or not self._dep_exec_eligible(mm.is_image, mm.flags):
                return False
        return True

    def mem_protect(self, addr, size, perms, *, dep: bool = True, win_protect=None):
        """
        Change the protection of a range.

        ``win_protect`` optionally records the Win32 protection value that the
        guest should observe for these pages (for example PAGE_WRITECOPY on
        writable image pages). When omitted, any previous Win32 override is
        dropped and VirtualQuery derives the value from the emulator perms.

        ``dep`` follows ``get_native_perms``: a writable private VirtualAlloc
        range gains execute permission only when the guest-visible Win32
        protection is recorded in the same call. Without it the range keeps
        ``perms`` and the deferred protected-fault grant of the Windows emulator
        adds execute permission for the faulting page, so the recorded page
        state and the engine permission never disagree.
        """
        native_perms = perms
        if (
            dep
            and not self.dep_enabled
            and win_protect is not None
            and (perms & common.PERM_MEM_WRITE)
            and self._range_is_private_virtual_alloc(addr, size)
        ):
            native_perms = perms | common.PERM_MEM_EXEC
        self.emu_eng.mem_protect(addr, size, native_perms)
        self._set_page_protections(addr, size, native_perms, win_protect)

    def _set_page_protections(self, addr, size, perms, win_protect=None):
        """Record effective page protections overlaid on broad memory maps."""
        if size <= 0:
            return

        page = addr & ~(self.page_size - 1)
        end = addr + size
        while page < end:
            self._page_protections[page] = perms
            if win_protect is None:
                self._page_win_protections.pop(page, None)
            else:
                self._page_win_protections[page] = win_protect
            page += self.page_size

    def clear_page_protections(self, addr, size):
        """Forget page-protection overrides in an unmapped range."""
        if size <= 0:
            return

        page = addr & ~(self.page_size - 1)
        end = addr + size
        while page < end:
            self._page_protections.pop(page, None)
            self._page_win_protections.pop(page, None)
            page += self.page_size

    def get_address_perms(self, address):
        """
        Return the effective permissions for an address.

        Image maps commonly span multiple PE sections. Their initial map-level
        protection is not enough to answer VirtualQuery after section
        protections have been applied. A map whose engine protection was raised
        by the DEP rule reports that effective permission here.
        """
        mm = self.get_address_map(address)
        if not mm:
            return None

        page = address & ~(self.page_size - 1)
        if page in self._page_protections:
            return self._page_protections[page]
        if mm.dep_exec:
            return mm.prot | common.PERM_MEM_EXEC
        return mm.prot

    def get_address_win_protection(self, address):
        """Return the recorded Win32 PAGE_* value for an address, if any.

        Image pages carry explicit write-copy/read-only values recorded when
        the image was mapped or when VirtualProtect changed them. A private
        VirtualAlloc view whose engine protection was raised by the DEP rule
        reports the allocation protection (``MemMap.flags & 0xFF``), which the
        guest asked for and still observes. None means the caller should derive
        the Win32 value from ``get_address_perms``.
        """
        mm = self.get_address_map(address)
        if not mm:
            return None

        page = address & ~(self.page_size - 1)
        if page in self._page_win_protections:
            return self._page_win_protections[page]
        if mm.dep_exec and (int(mm.flags) & 0xFF):
            return int(mm.flags) & 0xFF
        return None

    def _protection_state(self, address):
        """Return the (emulator perms, Win32 protection) pair for a page."""
        page = address & ~(self.page_size - 1)
        return self.get_address_perms(page), self.get_address_win_protection(page)

    def get_protection_region(self, address):
        """
        Return the page-aligned region with one effective protection.

        Both the emulator permissions and the recorded Win32 protection must
        match: PAGE_READWRITE and PAGE_WRITECOPY are both writable in the
        emulator but are distinct VirtualQuery regions.
        """
        mm = self.get_address_map(address)
        if not mm:
            return None

        page = address & ~(self.page_size - 1)
        state = self._protection_state(page)
        map_end = mm.base + mm.size

        start = page
        while start > mm.base:
            previous = start - self.page_size
            if previous < mm.base or self._protection_state(previous) != state:
                break
            start = previous

        end = page + self.page_size
        while end < map_end:
            if self._protection_state(end) != state:
                break
            end += self.page_size

        return start, min(end, map_end) - start

    def _mem_unmap_region(self, base, size):
        """Unmap a range in the engine, also a range that has no allocations."""
        self.emu_eng.mem_unmap(base, size)

    def get_address_map(self, address):
        """Get the ``MemMap`` of the mapped allocation that contains an address, or ``None``."""
        for m in self.maps:
            if m.base <= address <= (m.base + m.size) - 1:
                return m

    def get_reserve_map(self, address):
        """Get the ``MemMap`` of the reserved range that contains an address, or ``None``."""
        for m in self.mem_reserves:
            if m.base <= address <= (m.base + m.size) - 1:
                return m

    def is_address_valid(self, address) -> bool:
        """Return whether an address is in a mapped allocation or a reserved range."""
        if self.get_address_map(address):
            return True
        if self.get_reserve_map(address):
            return True
        return False

    def get_address_tag(self, address):
        """Get the tag of the allocation that contains an address, or ``None``."""
        for m in self.maps:
            if address >= m.base and address <= (m.base + m.size) - 1:
                return m.tag

    def mem_reserve(self, size, base=None, perms=None, tag=None, flags=0, *, shared=False):
        """Reserve a range without a map, so that other allocations do not use it, and return its address."""
        if base is None:
            block = self.get_valid_ranges(size)
            base, size = block

        mm = MemMap(base, size, tag, perms, flags, base, self.block_size, shared)

        self.mem_reserves.append(mm)
        return base

    def mem_unreserve(self, base):
        """Release the reserved range at ``base`` without a map."""
        self.mem_reserves = [r for r in self.mem_reserves if r.base != base]

    def get_mem_maps(self) -> list[MemMap]:
        """Get the ``MemMap`` objects of the mapped allocations."""
        return self.maps

    def mem_map_reserve(self, mapped_base):
        """Map the reserved range at ``mapped_base`` with its permissions and tag, and return its address."""
        for r in self.mem_reserves:
            if mapped_base == r.base:
                self.mem_reserves.remove(r)
                perms = common.PERM_MEM_RWX if r.prot is None else r.prot
                return self.mem_map(r.size, base=r.base, perms=perms, tag=r.tag)
        return None

    def get_mem_regions(self):
        """Get the mapped regions of the engine."""
        return self.emu_eng.mem_regions()

    def get_valid_ranges(self, size: int, addr: int | None = None) -> tuple[int, int]:
        """
        Get the first free page-aligned range at or after ``addr`` that has no mapped or reserved page.

        The search works on *intervals* (mapped regions and reservations) instead of materialising the set
        of every mapped page. Building that page set is O(total mapped pages); guests can reserve huge
        regions (tens of GB -> millions of pages), which made a single call take minutes and showed up as a
        hang (e.g. a sample that VirtualAlloc-reserves 32 GB and then faults page by page inside that range).

        Args:
            size: Number of bytes to allocate.
            addr: Address at which to start the search. Defaults to the allocation base.

        Returns:
            The base address and the page-aligned size of the range.

        Raises:
            OutOfMemoryError: if the range would cross the address limit.
        """
        page_size = self.page_size

        # mem_map needs to be page aligned
        total = size

        # alloced address needs to also be on a page boundary
        if addr is None:
            addr = self.alloc_base
        base = addr - (addr % page_size)

        if total < page_size:
            total = page_size
        elif total % page_size:
            total += page_size - (total % page_size)

        # Occupied intervals: mapped regions plus reserved ranges. Starts are
        # aligned down to a page so a partially used page counts as occupied.
        occupied = []
        for m in self.get_mem_regions():
            o_start = int(m[0]) & ~(page_size - 1)
            o_end = int(m[1])
            if o_end > o_start:
                occupied.append((o_start, o_end))
        for res in self.mem_reserves:
            o_start = int(res.base) & ~(page_size - 1)
            o_end = int(res.base) + int(res.size)
            if o_end > o_start:
                occupied.append((o_start, o_end))
        occupied.sort()

        attempts = 9999
        while attempts:
            end = base + total
            if not any(o_start < end and base < o_end for o_start, o_end in occupied):
                limit = self.get_address_limit()
                if limit is not None and addr < limit < end:
                    raise OutOfMemoryError(f"no free range of 0x{total:x} bytes below 0x{limit:x}")
                return (base, total)

            if not attempts % 10:
                base += page_size * 1000
            else:
                base += total
            attempts -= 1

        raise OutOfMemoryError("Failed to allocate emulator memory")
