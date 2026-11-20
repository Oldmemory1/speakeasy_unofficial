# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

"""``TOKEN_GROUPS`` buffer codec and per-token group state.

``AdjustTokenGroups`` reads a caller-supplied ``TOKEN_GROUPS`` buffer, applies
it to the token, and can return the previous state in another ``TOKEN_GROUPS``
buffer. The layout is pointer-size dependent::

    x86:  DWORD GroupCount; SID_AND_ATTRIBUTES Groups[];  header 4, entry  8
    x64:  DWORD GroupCount; (padding); SID_AND_ATTRIBUTES Groups[];
          header 8, entry 16
    SID_AND_ATTRIBUTES: PSID Sid; DWORD Attributes; (padding on x64)

This module keeps the buffer codec and the token's stored state together and
away from the API handler, so the handler only maps results to Win32 BOOL /
GetLastError values. The state lives on the token object itself (an instance
attribute written through :func:`set_token_groups`), so every handle that
resolves to the same token observes the same groups.

Applies to x86 (``ptr_size == 4``) and x64 (``ptr_size == 8``). Invalid
pointer sizes and undersized caller buffers are rejected explicitly; mapped
memory errors from the guest are left to the emulator's fault handling.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

# TOKEN_GROUPS / SID_AND_ATTRIBUTES layout per pointer size (WinNT.h).
_HEADER_SIZE = {4: 4, 8: 8}
_ENTRY_SIZE = {4: 8, 8: 16}
_COUNT_OFFSET = 0
_COUNT_SIZE = 4

_TOKEN_GROUPS_ATTR = "_token_groups"


class TokenGroupsBufferError(ValueError):
    """A caller-supplied ``TOKEN_GROUPS`` buffer is smaller than its count declares.

    Attributes:
        required: Bytes the declared ``GroupCount`` needs.
        available: Bytes the caller said are available (``BufferLength``).
    """

    def __init__(self, required: int, available: int) -> None:
        super().__init__(
            f"TOKEN_GROUPS needs {required} bytes for its declared count, "
            f"but the caller supplied {available}"
        )
        self.required = required
        self.available = available


@dataclass(frozen=True)
class TokenGroupEntry:
    """One ``SID_AND_ATTRIBUTES`` element stored by the token."""

    sid: int
    attributes: int


def _layout(ptr_size: int) -> tuple[int, int]:
    try:
        return _HEADER_SIZE[ptr_size], _ENTRY_SIZE[ptr_size]
    except KeyError as exc:
        raise ValueError(f"pointer size must be 4 or 8, got {ptr_size!r}") from exc


def token_groups_size(ptr_size: int, count: int) -> int:
    """Return the byte size of a ``TOKEN_GROUPS`` buffer holding ``count`` groups.

    Args:
        ptr_size: Guest pointer size (4 for x86, 8 for x64).
        count: Declared ``GroupCount``.

    Returns:
        Header plus ``count`` pointer-sized entries.

    Raises:
        ValueError: If ``ptr_size`` is not 4 or 8, or ``count`` is negative.
    """
    header, entry = _layout(ptr_size)
    if count < 0:
        raise ValueError(f"GroupCount must not be negative, got {count!r}")
    return header + entry * count


def read_token_groups(
    mem_read: Callable[[int, int], bytes],
    ptr_size: int,
    address: int,
    buffer_length: int,
) -> tuple[TokenGroupEntry, ...]:
    """Decode a guest ``TOKEN_GROUPS`` buffer.

    Args:
        mem_read: ``mem_read(address, size)`` returning guest memory.
        ptr_size: Guest pointer size (4 or 8).
        address: Guest address of the ``TOKEN_GROUPS`` buffer.
        buffer_length: The caller's ``BufferLength`` in bytes.

    Returns:
        The declared groups in order.

    Raises:
        TokenGroupsBufferError: If ``buffer_length`` cannot hold the declared
            ``GroupCount``; the handler maps this to
            ``ERROR_INSUFFICIENT_BUFFER`` without reading past the declared
            buffer.
        ValueError: If ``ptr_size`` is not 4 or 8.
        Exception: Whatever ``mem_read`` raises for unmapped guest memory; the
            emulator's fault handling owns that case.
    """
    header, entry = _layout(ptr_size)
    count = int.from_bytes(mem_read(address + _COUNT_OFFSET, _COUNT_SIZE), "little")
    required = token_groups_size(ptr_size, count)
    if buffer_length < required:
        raise TokenGroupsBufferError(required, buffer_length)

    groups = []
    for index in range(count):
        base = header + index * entry
        sid = int.from_bytes(mem_read(address + base, ptr_size), "little")
        attributes = int.from_bytes(mem_read(address + base + ptr_size, 4), "little")
        groups.append(TokenGroupEntry(sid=sid, attributes=attributes))
    return tuple(groups)


def write_token_groups(
    mem_write: Callable[[int, bytes], None],
    ptr_size: int,
    address: int,
    groups: Iterable[TokenGroupEntry],
) -> int:
    """Encode ``groups`` into a guest ``TOKEN_GROUPS`` buffer.

    Padding bytes are written as zero.

    Args:
        mem_write: ``mem_write(address, data)`` into guest memory.
        ptr_size: Guest pointer size (4 or 8).
        address: Guest address to receive the structure.
        groups: Entries to write, in order.

    Returns:
        Number of bytes written.

    Raises:
        ValueError: If ``ptr_size`` is not 4 or 8.
        Exception: Whatever ``mem_write`` raises for unmapped guest memory.
    """
    header, entry = _layout(ptr_size)
    entries = tuple(groups)
    data = bytearray(token_groups_size(ptr_size, len(entries)))
    data[_COUNT_OFFSET : _COUNT_OFFSET + _COUNT_SIZE] = len(entries).to_bytes(
        _COUNT_SIZE, "little"
    )
    for index, group in enumerate(entries):
        base = header + index * entry
        data[base : base + ptr_size] = int(group.sid).to_bytes(ptr_size, "little")
        data[base + ptr_size : base + ptr_size + 4] = int(group.attributes).to_bytes(
            4, "little"
        )
    mem_write(address, bytes(data))
    return len(data)


def get_token_groups(token: object) -> tuple[TokenGroupEntry, ...]:
    """Return the token's current groups; the default token state is empty."""
    return getattr(token, _TOKEN_GROUPS_ATTR, ())


def set_token_groups(token: object, groups: Iterable[TokenGroupEntry]) -> None:
    """Replace the token's group state with ``groups``."""
    setattr(token, _TOKEN_GROUPS_ATTR, tuple(groups))


def reset_token_groups(token: object) -> None:
    """Reset the token's group state to the default (empty) state."""
    set_token_groups(token, ())
