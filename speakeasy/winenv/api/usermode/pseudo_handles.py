"""Windows user-mode pseudo-handle helpers."""

from __future__ import annotations

_SUPPORTED_POINTER_SIZES = frozenset({4, 8})


def current_process_pseudo_handle(pointer_size: int) -> int:
    """Return the current-process pseudo-handle for a user-mode bitness."""
    if pointer_size not in _SUPPORTED_POINTER_SIZES:
        raise ValueError(f"unsupported pointer size: {pointer_size}")
    return (1 << (pointer_size * 8)) - 1


def is_current_process_pseudo_handle(handle: int, pointer_size: int) -> bool:
    """Return whether *handle* denotes the current process pseudo-handle."""
    return int(handle) == current_process_pseudo_handle(pointer_size)
