"""Per-thread implicit TLS for PE images (``IMAGE_TLS_DIRECTORY`` semantics).

Windows/Wine treat the TLS directory's ``StartAddressOfRawData`` as an immutable
template: each thread receives its own writable copy of
``(EndAddressOfRawData - StartAddressOfRawData + SizeOfZeroFill)`` bytes, and the
loader publishes the module's TLS index through ``AddressOfIndex`` so the thread
can find its block via ``TEB->ThreadLocalStoragePointer[index]``.

This module keeps that state out of ``winemu``/``objman`` behind two explicit
operations:

* :meth:`TlsManager.register_module` - allocate a module index and write it to
  ``AddressOfIndex`` (once per loaded PE module with a TLS directory).
* :meth:`TlsManager.init_thread` - allocate the thread's pointer array and
  per-module writable copies, then return the array address for the caller to
  store in the TEB.

The manager never changes section protections and never writes the template;
callers only pass emulator objects that expose the small ``TlsMemory`` surface.

A directory whose template and zero-fill are both empty (a callback-only TLS
directory) keeps a null per-thread slot by default, matching Wine's
``alloc_thread_tls``. ``init_thread(..., allocate_empty=True)`` opts a caller
into the v2.1.0 emulator policy instead: map a minimal non-NULL block so the
module's TLS callbacks and entry point can use valid per-thread storage.
"""

from __future__ import annotations

import logging
import struct
import weakref
from dataclasses import dataclass
from typing import Any, Protocol

logger = logging.getLogger(__name__)

# Minimal per-thread block mapped for a data-less (callback-only) TLS directory
# when ``init_thread(..., allocate_empty=True)`` opts into the v2.1.0 policy.
# Upstream's ``Thread.init_tls`` maps ``max(len(data), 1)`` for the same reason.
_EMPTY_TLS_BLOCK_SIZE = 1


class TlsError(Exception):
    """Raised when TLS state cannot be represented faithfully."""


class TlsMemory(Protocol):
    """The emulator surface used by :class:`TlsManager`."""

    def get_ptr_size(self) -> int: ...

    def mem_map(
        self,
        size: int,
        base: int | None = None,
        perms: Any = None,
        tag: str | None = None,
    ) -> int: ...

    def mem_read(self, address: int, size: int) -> bytes: ...

    def mem_write(self, address: int, data: bytes) -> None: ...


class TlsThread(Protocol):
    """The thread surface used by :class:`TlsManager` (only ``tid`` for tags)."""

    tid: int


@dataclass(frozen=True)
class TlsDirectory:
    """The six fields of a PE ``IMAGE_TLS_DIRECTORY``.

    All addresses are absolute virtual addresses in the emulated address space.

    Attributes:
        start: ``StartAddressOfRawData``, the immutable template start.
        end: ``EndAddressOfRawData``, the template end (exclusive).
        index_va: ``AddressOfIndex``, address of the DWORD that receives the
            module's TLS index.  Zero means the image publishes no index.
        callbacks_va: ``AddressOfCallBacks``, address of the callback array.
        zero_fill: ``SizeOfZeroFill``, bytes appended to each per-thread block
            and zero-initialised.
        characteristics: ``Characteristics``, preserved for callers that inspect
            it; it does not affect block allocation.
    """

    start: int
    end: int
    index_va: int
    callbacks_va: int = 0
    zero_fill: int = 0
    characteristics: int = 0

    @property
    def template_size(self) -> int:
        """Template length, saturated at zero for malformed directories."""

        return max(0, self.end - self.start)

    @property
    def has_thread_data(self) -> bool:
        """True when a per-thread block is required (template or zero-fill)."""

        return self.template_size > 0 or self.zero_fill > 0


@dataclass(frozen=True)
class _RegisteredDirectory:
    index: int
    directory: TlsDirectory
    module_name: str


@dataclass
class _ThreadTlsState:
    array: int
    blocks: list[int]
    allocate_empty: bool = False


def _thread_tag(thread: TlsThread) -> str:
    tid = getattr(thread, "tid", None)
    if tid is None:
        return f"object{id(thread):x}"
    return f"thread{tid}"


class TlsManager:
    """Allocates module TLS indices and per-thread writable TLS blocks.

    One manager belongs to one emulator instance (one shared address space).
    Indices are assigned in registration order and never reused while the
    emulator lives, which matches the loader contract observed in Wine's
    ``alloc_tls_slot``.

    Unknown input policy:
        * ``end < start`` or ``zero_fill < 0`` raises :class:`TlsError` instead
          of silently allocating a bogus block.
        * ``AddressOfIndex == 0`` assigns the index but skips the write and logs
          a warning; the caller may still use the returned index.
        * A directory with no template bytes, no zero-fill and no callbacks
          consumes no index (Wine returns FALSE from ``alloc_tls_slot``).
        * A directory with no template bytes and no zero-fill but with callbacks
          keeps a null per-thread slot by default (Wine's rule); an explicit
          ``init_thread(..., allocate_empty=True)`` maps a minimal block instead
          (the v2.1.0 emulator policy).
        * Memory faults while copying a template propagate from the emulator.
    """

    def __init__(self) -> None:
        self._entries: list[_RegisteredDirectory] = []
        self._thread_states: weakref.WeakKeyDictionary[Any, _ThreadTlsState] = (
            weakref.WeakKeyDictionary()
        )

    @property
    def module_count(self) -> int:
        """Number of modules that currently hold a TLS index."""

        return len(self._entries)

    def register_module(
        self,
        emu: TlsMemory,
        directory: TlsDirectory,
        *,
        module_name: str = "",
    ) -> int | None:
        """Assign a TLS index to one module and publish it via ``AddressOfIndex``.

        Returns the assigned index, or ``None`` when the directory describes no
        per-thread state or callbacks.  The index is written as a 4-byte
        ``ULONG`` regardless of pointer size, matching Wine's
        ``*(DWORD *)AddressOfIndex = i``.

        Raises:
            TlsError: if ``end < start`` or ``zero_fill`` is negative.
        """

        if directory.end < directory.start:
            raise TlsError(
                f"{module_name or 'module'}: EndAddressOfRawData "
                f"(0x{directory.end:x}) precedes StartAddressOfRawData "
                f"(0x{directory.start:x})"
            )
        if directory.zero_fill < 0:
            raise TlsError(
                f"{module_name or 'module'}: negative SizeOfZeroFill "
                f"({directory.zero_fill})"
            )
        if not directory.has_thread_data and not directory.callbacks_va:
            logger.debug(
                "TLS directory for %s has no data or callbacks; no index allocated",
                module_name or "<unnamed>",
            )
            return None

        index = len(self._entries)
        if directory.index_va:
            emu.mem_write(directory.index_va, struct.pack("<I", index))
        else:
            logger.warning(
                "TLS directory for %s has no AddressOfIndex; index %d is not published",
                module_name or "<unnamed>",
                index,
            )

        self._entries.append(
            _RegisteredDirectory(index=index, directory=directory, module_name=module_name)
        )
        return index

    def init_thread(
        self,
        emu: TlsMemory,
        thread: TlsThread,
        *,
        allocate_empty: bool = False,
    ) -> int | None:
        """Create or refresh one thread's TLS pointer array and blocks.

        Returns the address of the ``(module_count * pointer_size)`` array to
        store in ``TEB->ThreadLocalStoragePointer``, or ``None`` when no module
        registered TLS state (the caller must then leave the TEB untouched).

        Args:
            emu: The emulator memory surface.
            thread: The thread whose per-thread state is initialised.
            allocate_empty: Opt into the v2.1.0 emulator policy for a directory
                whose template and zero-fill are both empty but which publishes
                callbacks: map a minimal non-NULL block so the callbacks and the
                entry point use valid per-thread storage. The default ``False``
                keeps Wine's rule that such a directory gets a null slot.

        Repeated calls for the same thread are idempotent unless new modules were
        registered in between; then the array is reallocated with room for the
        new indices while existing slot pointers are preserved (the running
        thread is extended the way Wine extends threads in ``alloc_tls_slot``).
        Each per-module block is a fresh writable emulator mapping; the template
        itself is only read. Modules with neither template nor zero-fill keep a
        null slot unless ``allocate_empty`` is set. Once a thread has been
        initialised or upgraded with ``allocate_empty=True`` the policy is
        sticky for that thread's later empty slots; it is never downgraded.
        """

        if not self._entries:
            return None

        ptr_size = emu.get_ptr_size()
        entry_count = len(self._entries)
        state = self._thread_states.get(thread)
        if state is not None and len(state.blocks) == entry_count:
            if allocate_empty and not state.allocate_empty:
                self._fill_empty_blocks(emu, thread, state)
            return state.array

        if state is not None and state.allocate_empty:
            allocate_empty = True

        if state is None:
            blocks: list[int] = []
            start_index = 0
            array_size = max(entry_count * ptr_size, ptr_size)
            array = emu.mem_map(
                array_size, tag=f"emu.tls.{_thread_tag(thread)}.array"
            )
            emu.mem_write(array, b"\x00" * array_size)
        else:
            blocks = list(state.blocks)
            start_index = len(blocks)
            array_size = max(entry_count * ptr_size, ptr_size)
            previous = emu.mem_read(state.array, len(blocks) * ptr_size)
            array = emu.mem_map(
                array_size, tag=f"emu.tls.{_thread_tag(thread)}.array"
            )
            emu.mem_write(array, previous + b"\x00" * (array_size - len(previous)))

        for entry in self._entries[start_index:]:
            block = self._allocate_block(
                emu, thread, entry, allocate_empty=allocate_empty
            )
            slot = array + entry.index * ptr_size
            emu.mem_write(slot, block.to_bytes(ptr_size, "little"))
            blocks.append(block)

        self._thread_states[thread] = _ThreadTlsState(
            array=array, blocks=blocks, allocate_empty=allocate_empty
        )
        return array

    def _fill_empty_blocks(
        self,
        emu: TlsMemory,
        thread: TlsThread,
        state: _ThreadTlsState,
    ) -> None:
        """Map blocks for slots a previous call left null (opt-in upgrade).

        Only ``init_thread(..., allocate_empty=True)`` reaches here. The array
        already holds a slot for every registered module, so the slots are
        patched in place; entries that already have a block are untouched.
        """

        ptr_size = emu.get_ptr_size()
        for position, entry in enumerate(self._entries):
            if state.blocks[position]:
                continue
            block = self._allocate_block(emu, thread, entry, allocate_empty=True)
            slot = state.array + entry.index * ptr_size
            emu.mem_write(slot, block.to_bytes(ptr_size, "little"))
            state.blocks[position] = block
        state.allocate_empty = True

    def _allocate_block(
        self,
        emu: TlsMemory,
        thread: TlsThread,
        entry: _RegisteredDirectory,
        *,
        allocate_empty: bool = False,
    ) -> int:
        """Map and populate one module's block for one thread; 0 means no block.

        A directory with no template bytes and no zero-fill returns 0 (Wine's
        ``alloc_thread_tls`` rule) unless ``allocate_empty`` is set, which maps
        a minimal block for a callback-only directory (the v2.1.0 policy).
        """

        directory = entry.directory
        template_size = directory.template_size
        total_size = template_size + directory.zero_fill
        if total_size == 0:
            if not allocate_empty:
                return 0
            total_size = _EMPTY_TLS_BLOCK_SIZE

        block = emu.mem_map(
            total_size,
            tag=f"emu.tls.{_thread_tag(thread)}.{entry.index}",
        )
        if template_size:
            template = emu.mem_read(directory.start, template_size)
            if len(template) != template_size:
                raise TlsError(
                    f"{entry.module_name or 'module'}: short TLS template read "
                    f"(wanted {template_size}, got {len(template)})"
                )
            emu.mem_write(block, template)
        if directory.zero_fill:
            emu.mem_write(block + template_size, b"\x00" * directory.zero_fill)
        return block
