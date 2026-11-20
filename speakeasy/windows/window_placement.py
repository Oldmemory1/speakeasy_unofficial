# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

"""Per-window maximize state backing ``IsZoomed``.

Windows exposes the window "zoomed" (maximized) state as a boolean predicate:
``IsZoomed(hWnd)`` is nonzero only while the window is maximized. The
``SessionManager`` window table tracks identity (class, procedure, name) but
not placement, so this module owns the placement bit and lets the user32
handlers update it from the two APIs that change it:

* ``CreateWindowEx`` with ``WS_MAXIMIZE`` creates an already-maximized window;
* ``ShowWindow`` with ``SW_MAXIMIZE`` / ``SW_SHOWMAXIMIZED`` maximizes, while
  ``SW_RESTORE`` / ``SW_SHOWNORMAL`` / ``SW_MINIMIZE`` / ``SW_SHOWMINIMIZED`` /
  ``SW_SHOWMINNOACTIVE`` leave the window not maximized. ``SW_HIDE``,
  ``SW_SHOW`` and the remaining display commands keep the current placement.

Unknown ``nCmdShow`` values leave the state unchanged; unknown windows report
"not maximized" (FALSE), which is the safe predicate default. Applies to both
x86 and x64 guests (handles are guest-sized integers).
"""

from __future__ import annotations

# WinUser.h ShowWindow commands interpreted here.
SW_HIDE = 0
SW_SHOWNORMAL = 1
SW_SHOWMINIMIZED = 2
SW_SHOWMAXIMIZED = 3
SW_SHOWNOACTIVATE = 4
SW_SHOW = 5
SW_MINIMIZE = 6
SW_SHOWMINNOACTIVE = 7
SW_SHOWNA = 8
SW_RESTORE = 9
SW_SHOWDEFAULT = 10

# WinUser.h window style: the window is created maximized.
WS_MAXIMIZE = 0x01000000

_MAXIMIZED_COMMANDS = frozenset({SW_SHOWMAXIMIZED})
_UNMAXIMIZED_COMMANDS = frozenset(
    {
        SW_SHOWNORMAL,
        SW_SHOWMINIMIZED,
        SW_MINIMIZE,
        SW_SHOWMINNOACTIVE,
        SW_RESTORE,
    }
)


class WindowPlacement:
    """In-memory maximize state for the windows of one emulator instance.

    The store is keyed by HWND. Windows that were never shown with a placement
    command, and handles the GUI layer does not know, are reported as not
    maximized.
    """

    def __init__(self) -> None:
        self._maximized: dict[int, bool] = {}

    def is_maximized(self, hwnd: int) -> bool:
        """Return True when ``hwnd`` is currently maximized."""
        return self._maximized.get(int(hwnd), False)

    def set_maximized(self, hwnd: int, maximized: bool) -> None:
        """Set the maximize state of ``hwnd`` explicitly."""
        key = int(hwnd)
        if maximized:
            self._maximized[key] = True
        else:
            self._maximized.pop(key, None)

    def apply_show_command(self, hwnd: int, n_cmd_show: int) -> None:
        """Update the placement for a ``ShowWindow`` command.

        Recognized maximize/restore/minimize commands change the state;
        ``SW_HIDE``/``SW_SHOW``, unknown commands and non-positive handles
        leave it unchanged.
        """
        key = int(hwnd)
        if key <= 0:
            return
        if n_cmd_show in _MAXIMIZED_COMMANDS:
            self._maximized[key] = True
        elif n_cmd_show in _UNMAXIMIZED_COMMANDS:
            self._maximized.pop(key, None)

    def forget(self, hwnd: int) -> None:
        """Drop the placement recorded for ``hwnd`` (window destroyed)."""
        self._maximized.pop(int(hwnd), None)
