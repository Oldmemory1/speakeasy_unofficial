# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

"""Per-window ``GWL_*`` long-value storage.

Windows windows carry long-sized attributes selected by ``nIndex`` (for
example ``GWL_USERDATA`` = -21 holds a caller-defined pointer and
``GWL_WNDPROC`` = -4 holds the window procedure). ``SetWindowLong`` stores a
value and returns the previous one; ``GetWindowLong`` returns the stored value
or 0 when the attribute was never set.

This module keeps the generic ``(hWnd, nIndex) -> value`` store only.
``GWL_WNDPROC`` is deliberately *not* stored here: the ``SessionManager``
window procedure is the single source of truth for that selector, and the
user32 API handler routes it through ``SessionManager.get_window_proc`` /
``set_window_proc`` so ``GetWindowLong(GWL_WNDPROC)`` always agrees with the
procedure used for message dispatch.
"""

from __future__ import annotations

# Window long selectors from WinUser.h. Negative values are the documented
# API-level constants; ``canonical_window_long_index`` maps the 32-bit and
# 64-bit sign-extended argument forms onto one key.
GWL_WNDPROC = -4
GWL_USERDATA = -21

_WINDOW_LONG_INDEX_MASK = 0xFFFFFFFF


def canonical_window_long_index(nIndex: int) -> int:
    """Normalize a ``GWL_*`` selector to its stable 32-bit key.

    ``nIndex`` is an ``int`` in the Win32 prototypes, so a 64-bit guest passes
    ``-4`` as ``0xFFFFFFFFFFFFFFFC`` while a 32-bit guest passes
    ``0xFFFFFFFC``. Both must address the same stored attribute.
    """
    return int(nIndex) & _WINDOW_LONG_INDEX_MASK


def mask_window_long_value(value: int, size: int) -> int:
    """Truncate ``value`` to ``size`` bytes (4 for LONG, 8 for LONG_PTR).

    Raises:
        ValueError: if ``size`` is not 4 or 8.
    """
    if size not in (4, 8):
        raise ValueError(f"window long size must be 4 or 8 bytes, got {size!r}")
    return int(value) & ((1 << (size * 8)) - 1)


class WindowState:
    """In-memory ``(hWnd, nIndex) -> value`` store for one emulator instance.

    The store is intentionally permissive about handles: the GUI layer only
    models windows created through user32 and does not validate arbitrary HWND
    values, and the ``GetWindowLong`` contract is "return the previously stored
    value, 0 when unset". ``GWL_WNDPROC`` is excluded (see module docstring).
    """

    def __init__(self) -> None:
        self._values: dict[tuple[int, int], int] = {}

    def get(self, hWnd: int, nIndex: int) -> int:
        """Return the stored value for ``(hWnd, nIndex)``, or 0 when unset."""
        key = (int(hWnd), canonical_window_long_index(nIndex))
        return self._values.get(key, 0)

    def set(self, hWnd: int, nIndex: int, value: int) -> int:
        """Store ``value`` and return the previous value (0 when unset)."""
        key = (int(hWnd), canonical_window_long_index(nIndex))
        previous = self._values.get(key, 0)
        self._values[key] = int(value)
        return previous
