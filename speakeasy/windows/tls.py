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
"""

from __future__ import annotations

import logging
import struct
import weakref
from dataclasses import dataclass
from typing import Any, Protocol

logger = logging.getLogger(__name__)


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

    def init_thread(self, emu: TlsMemory, thread: TlsThread) -> int | None:
        """Create or refresh one thread's TLS pointer array and blocks.

        Returns the address of the ``(module_count * pointer_size)`` array to
        store in ``TEB->ThreadLocalStoragePointer``, or ``None`` when no module
        registered TLS state (the caller must then leave the TEB untouched).

        Repeated calls for the same thread are idempotent unless new modules were
        registered in between; then the array is reallocated with room for the
        new indices while existing slot pointers are preserved (the running
        thread is extended the way Wine extends threads in ``alloc_tls_slot``).
        Each per-module block is a fresh writable emulator mapping; the template
        itself is only read.  Modules with neither template nor zero-fill keep a
        null slot, matching Wine's ``alloc_thread_tls``.
        """

        if not self._entries:
            return None

        ptr_size = emu.get_ptr_size()
        entry_count = len(self._entries)
        state = self._thread_states.get(thread)
        if state is not None and len(state.blocks) == entry_count:
            return state.array

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
            block = self._allocate_block(emu, thread, entry)
            slot = array + entry.index * ptr_size
            emu.mem_write(slot, block.to_bytes(ptr_size, "little"))
            blocks.append(block)

        self._thread_states[thread] = _ThreadTlsState(array=array, blocks=blocks)
        return array

    def _allocate_block(
        self,
        emu: TlsMemory,
        thread: TlsThread,
        entry: _RegisteredDirectory,
    ) -> int:
        """Map and populate one module's block for one thread; 0 means no block."""

        directory = entry.directory
        template_size = directory.template_size
        total_size = template_size + directory.zero_fill
        if total_size == 0:
            return 0

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
