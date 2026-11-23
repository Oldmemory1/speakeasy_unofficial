# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes
import logging
from typing import TYPE_CHECKING, Any

import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.windows.user32 as u32defs
from speakeasy.windows import api_diagnostics, guest_callbacks, objman, sessman, window_placement
from speakeasy.windows.guest_callbacks import GuestCall
from speakeasy.windows.gui_messages import QueuedWindowMessage
from speakeasy.windows.window_state import (
    GWL_WNDPROC,
    WindowState,
    canonical_window_long_index,
    mask_window_long_value,
)
from speakeasy.winenv.defs.enums import WINDOWS_HOOK_ID
from speakeasy.winenv.defs.lookup import decode
from speakeasy.winenv.defs.windows import windef
from speakeasy.winenv.defs.windows import windows as windefs

from .. import api

if TYPE_CHECKING:
    from speakeasy.windows.win32 import Win32Emulator

logger = logging.getLogger(__name__)

IDOK = 1
IDCANCEL = 2
IDABORT = 3
IDYES = 6

MB_TYPEMASK = 0xF
MB_OK = 0x0
MB_ABORTRETRYIGNORE = 0x2
MB_YESNO = 0x4

IDI_APPLICATION = 32512
IDI_ASTERISK = 32516
IDI_ERROR = 32513
IDI_EXCLAMATION = 32515
IDI_HAND = 32513
IDI_INFORMATION = 32516
IDI_QUESTION = 32514
IDI_SHIELD = 32518
IDI_WARNING = 32515
IDI_WINLOGO = 32517

# WinError.h: the HWND is not a window the session manager knows about.
ERROR_INVALID_WINDOW_HANDLE = 1400

UOI_FLAGS = 1

# GetSystemMetrics selectors. Values follow WinUser.h.
SM_CXSCREEN = 0
SM_CYSCREEN = 1
SM_CXVSCROLL = 2
SM_CYHSCROLL = 3
SM_CYCAPTION = 4
SM_CXBORDER = 5
SM_CYBORDER = 6
SM_CXDLGFRAME = 7
SM_CYDLGFRAME = 8
SM_CYVTHUMB = 9
SM_CXHTHUMB = 10
SM_CXICON = 11
SM_CYICON = 12
SM_CXCURSOR = 13
SM_CYCURSOR = 14
SM_CYMENU = 15
SM_CXFULLSCREEN = 16
SM_CYFULLSCREEN = 17
SM_CYKANJIWINDOW = 18
SM_MOUSEPRESENT = 19
SM_CYVSCROLL = 20
SM_CXHSCROLL = 21
SM_DEBUG = 22
SM_SWAPBUTTON = 23
SM_CXMIN = 28
SM_CYMIN = 29
SM_CXSIZE = 30
SM_CYSIZE = 31
SM_CXFRAME = 32
SM_CYFRAME = 33
SM_CXMINTRACK = 34
SM_CYMINTRACK = 35
SM_CXDOUBLECLK = 36
SM_CYDOUBLECLK = 37
SM_CXICONSPACING = 38
SM_CYICONSPACING = 39
SM_MENUDROPALIGNMENT = 40
SM_PENWINDOWS = 41
SM_DBCSENABLED = 42
SM_CMOUSEBUTTONS = 43
SM_SECURE = 44
SM_CXEDGE = 45
SM_CYEDGE = 46
SM_CXMINSPACING = 47
SM_CYMINSPACING = 48
SM_CXSMICON = 49
SM_CYSMICON = 50
SM_CYSMCAPTION = 51
SM_CXSMSIZE = 52
SM_CYSMSIZE = 53
SM_CXMENUSIZE = 54
SM_CYMENUSIZE = 55
SM_ARRANGE = 56
SM_CXMINIMIZED = 57
SM_CYMINIMIZED = 58
SM_CXMAXTRACK = 59
SM_CYMAXTRACK = 60
SM_CXMAXIMIZED = 61
SM_CYMAXIMIZED = 62
SM_NETWORK = 63
SM_CLEANBOOT = 67
SM_CXDRAG = 68
SM_CYDRAG = 69
SM_SHOWSOUNDS = 70
SM_CXMENUCHECK = 71
SM_CYMENUCHECK = 72
SM_SLOWMACHINE = 73
SM_MIDEASTENABLED = 74
SM_MOUSEWHEELPRESENT = 75
SM_XVIRTUALSCREEN = 76
SM_YVIRTUALSCREEN = 77
SM_CXVIRTUALSCREEN = 78
SM_CYVIRTUALSCREEN = 79
SM_CMONITORS = 80
SM_SAMEDISPLAYFORMAT = 81
SM_IMMENABLED = 82
SM_CXFOCUSBORDER = 83
SM_CYFOCUSBORDER = 84
SM_TABLETPC = 86
SM_MEDIACENTER = 87
SM_STARTER = 88
SM_SERVERR2 = 89
SM_MOUSEHORIZONTALWHEELPRESENT = 91
SM_CXPADDEDBORDER = 92
SM_DIGITIZER = 94
SM_MAXIMUMTOUCHES = 95
SM_SHUTTINGDOWN = 8192
SM_REMOTECONTROL = 8193
SM_CONVERTIBLESLATEMODE = 8195
SM_SYSTEMDOCKED = 8196
SM_REMOTESESSION = 4096

SYSTEM_METRIC_NAMES = {
    SM_CXSCREEN: "SM_CXSCREEN",
    SM_CYSCREEN: "SM_CYSCREEN",
    SM_CXVSCROLL: "SM_CXVSCROLL",
    SM_CYHSCROLL: "SM_CYHSCROLL",
    SM_CYCAPTION: "SM_CYCAPTION",
    SM_CXBORDER: "SM_CXBORDER",
    SM_CYBORDER: "SM_CYBORDER",
    SM_CXDLGFRAME: "SM_CXFIXEDFRAME",
    SM_CYDLGFRAME: "SM_CYFIXEDFRAME",
    SM_CYVTHUMB: "SM_CYVTHUMB",
    SM_CXHTHUMB: "SM_CXHTHUMB",
    SM_CXICON: "SM_CXICON",
    SM_CYICON: "SM_CYICON",
    SM_CXCURSOR: "SM_CXCURSOR",
    SM_CYCURSOR: "SM_CYCURSOR",
    SM_CYMENU: "SM_CYMENU",
    SM_CXFULLSCREEN: "SM_CXFULLSCREEN",
    SM_CYFULLSCREEN: "SM_CYFULLSCREEN",
    SM_CYKANJIWINDOW: "SM_CYKANJIWINDOW",
    SM_MOUSEPRESENT: "SM_MOUSEPRESENT",
    SM_CYVSCROLL: "SM_CYVSCROLL",
    SM_CXHSCROLL: "SM_CXHSCROLL",
    SM_DEBUG: "SM_DEBUG",
    SM_SWAPBUTTON: "SM_SWAPBUTTON",
    SM_CXMIN: "SM_CXMIN",
    SM_CYMIN: "SM_CYMIN",
    SM_CXSIZE: "SM_CXSIZE",
    SM_CYSIZE: "SM_CYSIZE",
    SM_CXFRAME: "SM_CXSIZEFRAME",
    SM_CYFRAME: "SM_CYSIZEFRAME",
    SM_CXMINTRACK: "SM_CXMINTRACK",
    SM_CYMINTRACK: "SM_CYMINTRACK",
    SM_CXDOUBLECLK: "SM_CXDOUBLECLK",
    SM_CYDOUBLECLK: "SM_CYDOUBLECLK",
    SM_CXICONSPACING: "SM_CXICONSPACING",
    SM_CYICONSPACING: "SM_CYICONSPACING",
    SM_MENUDROPALIGNMENT: "SM_MENUDROPALIGNMENT",
    SM_PENWINDOWS: "SM_PENWINDOWS",
    SM_DBCSENABLED: "SM_DBCSENABLED",
    SM_CMOUSEBUTTONS: "SM_CMOUSEBUTTONS",
    SM_SECURE: "SM_SECURE",
    SM_CXEDGE: "SM_CXEDGE",
    SM_CYEDGE: "SM_CYEDGE",
    SM_CXMINSPACING: "SM_CXMINSPACING",
    SM_CYMINSPACING: "SM_CYMINSPACING",
    SM_CXSMICON: "SM_CXSMICON",
    SM_CYSMICON: "SM_CYSMICON",
    SM_CYSMCAPTION: "SM_CYSMCAPTION",
    SM_CXSMSIZE: "SM_CXSMSIZE",
    SM_CYSMSIZE: "SM_CYSMSIZE",
    SM_CXMENUSIZE: "SM_CXMENUSIZE",
    SM_CYMENUSIZE: "SM_CYMENUSIZE",
    SM_ARRANGE: "SM_ARRANGE",
    SM_CXMINIMIZED: "SM_CXMINIMIZED",
    SM_CYMINIMIZED: "SM_CYMINIMIZED",
    SM_CXMAXTRACK: "SM_CXMAXTRACK",
    SM_CYMAXTRACK: "SM_CYMAXTRACK",
    SM_CXMAXIMIZED: "SM_CXMAXIMIZED",
    SM_CYMAXIMIZED: "SM_CYMAXIMIZED",
    SM_NETWORK: "SM_NETWORK",
    SM_CLEANBOOT: "SM_CLEANBOOT",
    SM_CXDRAG: "SM_CXDRAG",
    SM_CYDRAG: "SM_CYDRAG",
    SM_SHOWSOUNDS: "SM_SHOWSOUNDS",
    SM_CXMENUCHECK: "SM_CXMENUCHECK",
    SM_CYMENUCHECK: "SM_CYMENUCHECK",
    SM_SLOWMACHINE: "SM_SLOWMACHINE",
    SM_MIDEASTENABLED: "SM_MIDEASTENABLED",
    SM_MOUSEWHEELPRESENT: "SM_MOUSEWHEELPRESENT",
    SM_XVIRTUALSCREEN: "SM_XVIRTUALSCREEN",
    SM_YVIRTUALSCREEN: "SM_YVIRTUALSCREEN",
    SM_CXVIRTUALSCREEN: "SM_CXVIRTUALSCREEN",
    SM_CYVIRTUALSCREEN: "SM_CYVIRTUALSCREEN",
    SM_CMONITORS: "SM_CMONITORS",
    SM_SAMEDISPLAYFORMAT: "SM_SAMEDISPLAYFORMAT",
    SM_IMMENABLED: "SM_IMMENABLED",
    SM_CXFOCUSBORDER: "SM_CXFOCUSBORDER",
    SM_CYFOCUSBORDER: "SM_CYFOCUSBORDER",
    SM_TABLETPC: "SM_TABLETPC",
    SM_MEDIACENTER: "SM_MEDIACENTER",
    SM_STARTER: "SM_STARTER",
    SM_SERVERR2: "SM_SERVERR2",
    SM_MOUSEHORIZONTALWHEELPRESENT: "SM_MOUSEHORIZONTALWHEELPRESENT",
    SM_CXPADDEDBORDER: "SM_CXPADDEDBORDER",
    SM_DIGITIZER: "SM_DIGITIZER",
    SM_MAXIMUMTOUCHES: "SM_MAXIMUMTOUCHES",
    SM_SHUTTINGDOWN: "SM_SHUTTINGDOWN",
    SM_REMOTECONTROL: "SM_REMOTECONTROL",
    SM_CONVERTIBLESLATEMODE: "SM_CONVERTIBLESLATEMODE",
    SM_SYSTEMDOCKED: "SM_SYSTEMDOCKED",
    SM_REMOTESESSION: "SM_REMOTESESSION",
}


def _ui_metric(ui: Any, name: str, default: int) -> int:
    if isinstance(ui, dict):
        value = ui.get(name, default)
    else:
        value = getattr(ui, name, default)
    return int(value)


def resolve_system_metric(n_index: int, ui: Any = None) -> tuple[int, str | None, bool]:
    """Resolve a GetSystemMetrics selector to a profile-backed Windows value."""
    width = max(1, _ui_metric(ui, "screen_width", 1024))
    height = max(1, _ui_metric(ui, "screen_height", 768))
    monitor_count = max(1, _ui_metric(ui, "monitor_count", 1))
    mouse_present = _ui_metric(ui, "mouse_present", 1)
    mouse_buttons = _ui_metric(ui, "mouse_buttons", 3)
    mouse_wheel_present = _ui_metric(ui, "mouse_wheel_present", 1)
    horizontal_wheel_present = _ui_metric(ui, "horizontal_wheel_present", 1)
    clean_boot = _ui_metric(ui, "clean_boot", 0)
    remote_session = _ui_metric(ui, "remote_session", 0)
    remote_control = _ui_metric(ui, "remote_control", 0)
    swap_buttons = _ui_metric(ui, "swap_buttons", 0)
    secure = _ui_metric(ui, "secure", 0)

    values = {
        SM_CXSCREEN: width,
        SM_CYSCREEN: height,
        SM_CXVSCROLL: 17,
        SM_CYHSCROLL: 17,
        SM_CYCAPTION: 23,
        SM_CXBORDER: 1,
        SM_CYBORDER: 1,
        SM_CXDLGFRAME: 3,
        SM_CYDLGFRAME: 3,
        SM_CYVTHUMB: 17,
        SM_CXHTHUMB: 17,
        SM_CXICON: 32,
        SM_CYICON: 32,
        SM_CXCURSOR: 32,
        SM_CYCURSOR: 32,
        SM_CYMENU: 19,
        SM_CXFULLSCREEN: width,
        SM_CYFULLSCREEN: height,
        SM_CYKANJIWINDOW: 0,
        SM_MOUSEPRESENT: mouse_present,
        SM_CYVSCROLL: 17,
        SM_CXHSCROLL: 17,
        SM_DEBUG: 0,
        SM_SWAPBUTTON: swap_buttons,
        SM_CXMIN: 112,
        SM_CYMIN: 27,
        SM_CXSIZE: 30,
        SM_CYSIZE: 30,
        SM_CXFRAME: 8,
        SM_CYFRAME: 8,
        SM_CXMINTRACK: 112,
        SM_CYMINTRACK: 27,
        SM_CXDOUBLECLK: 4,
        SM_CYDOUBLECLK: 4,
        SM_CXICONSPACING: 75,
        SM_CYICONSPACING: 75,
        SM_MENUDROPALIGNMENT: 0,
        SM_PENWINDOWS: 0,
        SM_DBCSENABLED: 0,
        SM_CMOUSEBUTTONS: mouse_buttons,
        SM_SECURE: secure,
        SM_CXEDGE: 2,
        SM_CYEDGE: 2,
        SM_CXMINSPACING: 160,
        SM_CYMINSPACING: 24,
        SM_CXSMICON: 16,
        SM_CYSMICON: 16,
        SM_CYSMCAPTION: 17,
        SM_CXSMSIZE: 16,
        SM_CYSMSIZE: 16,
        SM_CXMENUSIZE: 20,
        SM_CYMENUSIZE: 20,
        SM_ARRANGE: 0,
        SM_CXMINIMIZED: 160,
        SM_CYMINIMIZED: 24,
        SM_CXMAXTRACK: width + 8,
        SM_CYMAXTRACK: height + 8,
        SM_CXMAXIMIZED: width,
        SM_CYMAXIMIZED: height,
        SM_NETWORK: 1,
        SM_CLEANBOOT: clean_boot,
        SM_CXDRAG: 4,
        SM_CYDRAG: 4,
        SM_SHOWSOUNDS: 0,
        SM_CXMENUCHECK: 13,
        SM_CYMENUCHECK: 13,
        SM_SLOWMACHINE: 0,
        SM_MIDEASTENABLED: 0,
        SM_MOUSEWHEELPRESENT: mouse_wheel_present,
        SM_XVIRTUALSCREEN: 0,
        SM_YVIRTUALSCREEN: 0,
        SM_CXVIRTUALSCREEN: width,
        SM_CYVIRTUALSCREEN: height,
        SM_CMONITORS: monitor_count,
        SM_SAMEDISPLAYFORMAT: 1,
        SM_IMMENABLED: 1,
        SM_CXFOCUSBORDER: 1,
        SM_CYFOCUSBORDER: 1,
        SM_TABLETPC: 0,
        SM_MEDIACENTER: 0,
        SM_STARTER: 0,
        SM_SERVERR2: 0,
        SM_MOUSEHORIZONTALWHEELPRESENT: horizontal_wheel_present,
        SM_CXPADDEDBORDER: 0,
        SM_DIGITIZER: 0,
        SM_MAXIMUMTOUCHES: 0,
        SM_SHUTTINGDOWN: 0,
        SM_REMOTECONTROL: remote_control,
        SM_CONVERTIBLESLATEMODE: 0,
        SM_SYSTEMDOCKED: 1,
        SM_REMOTESESSION: remote_session,
    }

    metric_name = SYSTEM_METRIC_NAMES.get(n_index)
    if metric_name is None:
        return 0, None, False
    return values[n_index], metric_name, True

LIST_VIEW_COLUMN_MESSAGES = (
    u32defs.LVM_INSERTCOLUMNA,
    u32defs.LVM_INSERTCOLUMNW,
    u32defs.LVM_GETCOLUMNA,
    u32defs.LVM_GETCOLUMNW,
    u32defs.LVM_GETCOLUMNWIDTH,
    u32defs.LVM_SETCOLUMNWIDTH,
    u32defs.LVM_DELETECOLUMN,
)

GWL_STYLE = -16

RT_STRING = 6

WS_POPUP = 0x80000000
WS_CHILD = 0x40000000

# The Windows MSG is 28 bytes on x86 and 48 bytes on x64. The local user32
# defs append a ``lPrivate`` field for the GUI message queue, so a handler that
# copies a queued message into guest memory must stop at the Windows size: the
# caller owns the buffer and Windows never writes a private field into it.
WINDOWS_MSG_SIZE = {4: 28, 8: 48}

# The devices that EnumDisplayDevices lists under each parent device name: one Intel adapter, as in an
# OptiPlex 7090, with one monitor. Each entry gives DeviceName, DeviceString, StateFlags, DeviceID and DeviceKey.
DISPLAY_DEVICES = {
    None: (
        "\\\\.\\DISPLAY1",
        "Intel(R) UHD Graphics 750",
        u32defs.DISPLAY_DEVICE_ATTACHED_TO_DESKTOP | u32defs.DISPLAY_DEVICE_PRIMARY_DEVICE,
        "PCI\\VEN_8086&DEV_4C8A&SUBSYS_0A6F1028&REV_04",
        "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Video\\{6E5A3F42-9C1B-4D7E-8F20-3B1A5C7D9E04}\\0000",
    ),
    "\\\\.\\DISPLAY1": (
        "\\\\.\\DISPLAY1\\Monitor0",
        "Generic PnP Monitor",
        u32defs.DISPLAY_DEVICE_ACTIVE | u32defs.DISPLAY_DEVICE_ATTACHED,
        "MONITOR\\DELA1A8\\{4d36e96e-e325-11ce-bfc1-08002be10318}\\0000",
        "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Class\\{4d36e96e-e325-11ce-bfc1-08002be10318}\\0000",
    ),
}

# Windows GUI objects and colors that GetSysColor lists. Indexes that are not here return 0.
SYS_COLORS = {
    0: 0xC8C8C8,  # COLOR_SCROLLBAR
    2: 0xD1B499,  # COLOR_ACTIVECAPTION
    3: 0xDBCDBF,  # COLOR_INACTIVECAPTION
    4: 0xF0F0F0,  # COLOR_MENU
    5: 0xFFFFFF,  # COLOR_WINDOW
    6: 0x646464,  # COLOR_WINDOWFRAME
    10: 0xB4B4B4,  # COLOR_ACTIVEBORDER
    11: 0xFCF7F4,  # COLOR_INACTIVEBORDER
    12: 0xABABAB,  # COLOR_APPWORKSPACE
    13: 0xD77800,  # COLOR_HIGHLIGHT
    14: 0xFFFFFF,  # COLOR_HIGHLIGHTTEXT
    15: 0xF0F0F0,  # COLOR_BTNFACE
    16: 0xA0A0A0,  # COLOR_BTNSHADOW
    17: 0x6D6D6D,  # COLOR_GRAYTEXT
    20: 0xFFFFFF,  # COLOR_BTNHIGHLIGHT
    21: 0x696969,  # COLOR_3DDKSHADOW
    22: 0xE3E3E3,  # COLOR_3DLIGHT
    24: 0xE1FFFF,  # COLOR_INFOBK
    26: 0xCC6600,  # COLOR_HOTLIGHT
    27: 0xEAD1B9,  # COLOR_GRADIENTACTIVECAPTION
    28: 0xF2E4D7,  # COLOR_GRADIENTINACTIVECAPTION
    29: 0xD77800,  # COLOR_MENUHILIGHT
    30: 0xF0F0F0,  # COLOR_MENUBAR
}


def map_char_case(raw: bytes, width: int, upper: bool) -> bytes:
    """
    Change the case of a buffer of characters without changing its length.
    ANSI buffers change only ASCII letters. A wide character keeps its case
    when the mapped form is more than one UTF-16 unit.
    """
    if width == 1:
        return raw.upper() if upper else raw.lower()
    out = []
    for ch in raw.decode("utf-16le", "surrogatepass"):
        mapped = ch.upper() if upper else ch.lower()
        out.append(mapped if len(mapped) == 1 and ord(mapped) <= 0xFFFF else ch)
    return "".join(out).encode("utf-16le", "surrogatepass")


def _ctx_func_name(ctx: Any) -> str | None:
    """Get the API name of a handler context, or None when it does not name one."""
    if isinstance(ctx, dict):
        name = ctx.get("func_name")
    else:
        name = getattr(ctx, "func_name", None)
    return name if isinstance(name, str) and name else None


def _char_width(handler: Any, ctx: Any) -> int:
    """Return 1 for an ANSI API or 2 for a W-suffixed API from its context.

    The context name decides the width for an ``ApiContext`` and for the plain
    dict context that the handler contract tests pass; an unnamed context falls
    back to the handler's own ``get_char_width`` (ANSI on error).
    """
    name = _ctx_func_name(ctx)
    if name is not None:
        return 2 if name.endswith("W") else 1
    try:
        return handler.get_char_width(ctx)
    except Exception:
        return 1


def _set_arg_display(ctx: Any, key: int | str, value: Any) -> None:
    """Render one API argument in the report without requiring an ApiContext.

    Handlers are also called directly (and with a plain dict context) from the
    handler contract tests; a missing argument table must never change the
    handler result.
    """
    args = getattr(ctx, "args", None)
    if args is None:
        return
    try:
        args[key].display = value
    except Exception:
        logger.debug("user32: argument display failed", exc_info=True)


def _replace_args(ctx: Any, *values: str) -> None:
    """Replace the report arguments of a printf-style API with its output."""
    args = getattr(ctx, "args", None)
    if args is None:
        return
    try:
        args.clear()
        for value in values:
            args.append(value)
    except Exception:
        logger.debug("user32: argument display failed", exc_info=True)


def _set_observation(ctx: Any, observation: Any) -> None:
    """Attach an observation to a dict context or to the emulator's ApiContext.

    The diagnostics modules attach observations to dict contexts; the emulator
    passes an ``ApiContext`` instance, which the v2.1.0 API event path reads
    with ``getattr(ctx, "_api_observation", None)``.
    """
    if not isinstance(observation, dict):
        return
    if isinstance(ctx, dict):
        ctx["_api_observation"] = observation
        return
    if ctx is None or ctx is api.NO_CONTEXT:
        # The shared no-context sentinel is not a per-call report context.
        return
    try:
        setattr(ctx, "_api_observation", observation)
    except Exception:
        logger.debug("user32: diagnostic observation attachment failed", exc_info=True)


def _attach_scatter_observation(ctx: Any, builder: Any) -> None:
    """Attach an FX-015 observation through its diagnostics module.

    ``api_diagnostics.attach_observation`` accepts dict contexts only, so an
    ApiContext gets the same public builder's result stored on the context.
    """
    if isinstance(ctx, dict):
        api_diagnostics.attach_observation(ctx, builder)
        return
    if ctx is None or ctx is api.NO_CONTEXT:
        return
    try:
        observation = builder()
    except Exception:
        logger.debug("user32: scatter observation builder failed", exc_info=True)
        return
    _set_observation(ctx, observation)


def _find_queued_message(
    queue: Any,
    message_hwnd: int | None,
    message_min: int,
    message_max: int,
    remove: bool,
) -> Any:
    """Find the first queued message that a filter matches, optionally removing it.

    ``WindowsMessageQueue`` exposes only an unfiltered ``peek`` and a filter
    that treats HWND 0 as "any window". The queue is drained and restored in
    place, so a message that must stay queued keeps its FIFO position and an
    ``HWND`` of 0 selects the messages that have no window.
    """
    messages = []
    while True:
        queued = queue.pop()
        if queued is None:
            break
        messages.append(queued)
    match = None
    for index, queued in enumerate(messages):
        if queued.message == u32defs.WM_QUIT:
            match = index
            break
        if message_hwnd is not None and queued.hwnd != message_hwnd:
            continue
        if message_min and queued.message < message_min:
            continue
        if message_max and queued.message > message_max:
            continue
        match = index
        break
    found = None
    for index, queued in enumerate(messages):
        if index == match:
            found = queued
            if not remove:
                queue.append(queued)
            continue
        queue.append(queued)
    return found


def _resolve_metric(emu: Any, n_index: int, ctx: Any) -> int:
    """Resolve one GetSystemMetrics selector from the configured UI profile.

    The observation is attached to the handler context (``_api_observation``)
    so the API event can report which metric the guest queried without changing
    the returned value.
    """
    ui = getattr(getattr(emu, "config", None), "ui", None)
    value, metric_name, known = resolve_system_metric(n_index, ui)

    if not known:
        logger.warning("GetSystemMetrics received unknown selector 0x%x; returning 0", n_index)

    if ctx is not None:
        profile = getattr(ui, "profile", ui.get("profile") if isinstance(ui, dict) else "normal")
        observation: dict[str, Any] = {
            "kind": "system_metric",
            "selector": n_index,
            "metric": metric_name,
            "value": value,
            "known": known,
            "profile": profile,
        }
        if metric_name == "SM_CLEANBOOT":
            observation["interpretation"] = {
                0: "normal_boot",
                1: "safe_mode",
                2: "safe_mode_with_networking",
            }.get(value, "invalid_clean_boot_value")
        elif metric_name == "SM_REMOTESESSION":
            observation["interpretation"] = "remote_session" if value else "local_session"
        _set_observation(ctx, observation)

    return value


class User32(api.ApiHandler):
    """
    Implements exported functions from user32.dll
    """

    name = "user32"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)

        self.funcs = {}
        self.data = {}
        self.window_hooks: dict[int, tuple[int, int, int]] = {}
        self.window_messages: dict[str, int] = {}
        self.dialog_results: dict[int, int] = {}
        self.timers: list[tuple[int, int, int]] = []
        self.next_timer: int = 0
        self.timer_count: int = 0
        self.sessman: sessman.SessionManager = emu.get_session_manager()
        self.foreground_window: int = 0
        self.window_state = WindowState()
        self.window_placement = window_placement.WindowPlacement()
        self.synthetic_async_keys: list[int] = [0x41, 0x42, 0x43]
        self.synthetic_async_key_index: int = 0
        self.synthetic_hook_keys: list[int] = [0x41, 0x42, 0x43]
        self.synthetic_hook_key_index: int = 0

        super().__get_hook_attrs__(self)

    def new_window_handle(self):
        """Get the handle of a new window that EnumWindows does not give."""
        return sessman.Window(self.sessman.handles).get_handle()

    def get_synthetic_async_key_state(self, vkey):
        if self.synthetic_async_key_index >= len(self.synthetic_async_keys):
            return 0

        if vkey != self.synthetic_async_keys[self.synthetic_async_key_index]:
            return 0

        self.synthetic_async_key_index += 1
        return 0x8001

    def get_synthetic_keyboard_hook(self):
        for _, hook in self.window_hooks.items():
            if len(hook) == 3 and hook[0] == WINDOWS_HOOK_ID.WH_KEYBOARD_LL:
                return hook
        return None

    def emit_synthetic_keyboard_hook_event(self, emu, caller_argv=None):
        hook = self.get_synthetic_keyboard_hook()
        if not hook:
            return None

        if self.synthetic_hook_key_index >= len(self.synthetic_hook_keys):
            return None

        hook_index = self.synthetic_hook_key_index
        vkey = self.synthetic_hook_keys[hook_index]
        self.synthetic_hook_key_index += 1

        wparam = u32defs.WM_KEYDOWN if (hook_index % 2 == 0) else u32defs.WM_SYSKEYDOWN

        kbd = u32defs.KBDLLHOOKSTRUCT(emu.get_ptr_size())
        kbd.vkCode = vkey
        kbd.scanCode = 0
        kbd.flags = 0
        kbd.time = 0
        kbd.dwExtraInfo = 0

        kbd_ptr = self.mem_alloc(kbd.sizeof(), tag="api.user32.kbdllhook")
        self.mem_write(kbd_ptr, kbd.get_bytes())

        _, lpfn, _ = hook
        self.setup_callback(lpfn, (0, wparam, kbd_ptr), caller_argv=caller_argv)
        return wparam, vkey

    def find_string_resource_by_id(self, pe, uID):
        """
        Find string uID in its RT_STRING block in the mapped image, which a packer may have written.
        Return the address of its characters and the string, or None.
        """
        pe_metadata = pe.get_pe_metadata()
        if not pe_metadata:
            return None
        block = uID // 16 + 1
        entry = next((r for r in pe_metadata.resources if r.type_id == RT_STRING and r.id == block), None)
        if not entry:
            return None
        address = pe.base + entry.data_rva
        data = self.mem_read(address, entry.size)
        offset = 0
        for _ in range(uID % 16):
            if offset + 2 > len(data):
                return None
            offset += 2 + int.from_bytes(data[offset : offset + 2], "little") * 2
        if offset + 2 > len(data):
            return None
        length = int.from_bytes(data[offset : offset + 2], "little")
        string = data[offset + 2 : offset + 2 + length * 2].decode("utf-16le", errors="replace")
        return address + offset + 2, string

    @apihook("GetDesktopWindow", argc=0)
    def GetDesktopWindow(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetDesktopWindow();
        """
        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("ShowWindow", argc=2)
    def ShowWindow(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL ShowWindow(
            HWND hWnd,
            int nCmdShow
        );
        """
        hWnd, nCmdShow = argv
        self.window_placement.apply_show_command(hWnd, nCmdShow)
        rv = 1

        return rv

    @apihook("CreateWindowStation", argc=4)
    def CreateWindowStation(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWINSTA CreateWindowStation(
            LPCTSTR lpwinsta,
            DWORD dwFlags,
            ACCESS_MASK dwDesiredAccess,
            LPSECURITY_ATTRIBUTES lpsa
        );
        """
        lpwinsta, dwFlags, dwDesiredAccess, lpsa = argv

        return emu.handle_allocator.allocate_handle()

    @apihook("SetProcessWindowStation", argc=1)
    def SetProcessWindowStation(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetProcessWindowStation(
            HWINSTA hWinSta
        );
        """
        (hWinSta,) = argv

        rv = False
        if hWinSta:
            rv = True

        return rv

    @apihook("GetDC", argc=1)
    def GetDC(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HDC GetDC(
            HWND hWnd
        );
        """
        rv = self.sessman.get_device_context()

        return rv

    @apihook("GetWindowDC", argc=1)
    def GetWindowDC(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HDC GetWindowDC(
            HWND hWnd
        );
        """
        return self.sessman.get_device_context()

    @apihook("RegisterClassEx", argc=1)
    def RegisterClassEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        ATOM RegisterClassEx(
            const WNDCLASSEX *lpwcx
        );
        """
        (lpwcx,) = argv
        return self.register_window_class(u32defs.WNDCLASSEX(emu.get_ptr_size()), lpwcx, ctx)

    @apihook("RegisterClass", argc=1)
    def RegisterClass(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        ATOM RegisterClass(
            const WNDCLASS *lpWndClass
        );
        """
        (lpWndClass,) = argv
        return self.register_window_class(u32defs.WNDCLASS(emu.get_ptr_size()), lpWndClass, ctx)

    def register_window_class(self, wclass, address, ctx):
        wclass = self.mem_cast(wclass, address)

        cn = None
        cw = _char_width(self, ctx)
        if wclass.lpszClassName > 0xFFFF:
            cn = self.read_mem_string(wclass.lpszClassName, cw)

        return self.sessman.create_window_class(wclass, cn)

    @apihook("UnregisterClass", argc=2)
    def UnregisterClass(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL UnregisterClass(
            LPCTSTR lpClassName,
            HINSTANCE hInstance
        );
        """
        class_name, _instance = argv
        cw = _char_width(self, ctx)
        if isinstance(class_name, int) and 0 < class_name <= 0xFFFF:
            class_key = class_name
        elif class_name:
            class_key = self.read_mem_string(class_name, cw)
        else:
            class_key = None
        return int(self.sessman.unregister_window_class(class_key))

    @apihook("SetCursorPos", argc=2)
    def SetCursorPos(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetCursorPos(
            int X,
            int Y
        );
        """
        return 1

    @apihook("CloseDesktop", argc=1)
    def CloseDesktop(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CloseDesktop(
            HDESK hDesktop
        );
        """
        return 1

    @apihook("CloseWindowStation", argc=1)
    def CloseWindowStation(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CloseWindowStation(
            HWINSTA hWinSta
        );
        """
        return 1

    @apihook("GetThreadDesktop", argc=1)
    def GetThreadDesktop(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HDESK GetThreadDesktop(
            DWORD dwThreadId
        );
        """
        return 1

    @apihook("OpenWindowStation", argc=3)
    def OpenWindowStation(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWINSTA OpenWindowStation(
            LPCTSTR lpszWinSta,
            BOOL fInherit,
            ACCESS_MASK dwDesiredAccess
        );
        """
        return 1

    @apihook("ChangeWindowMessageFilter", argc=2)
    def ChangeWindowMessageFilter(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL ChangeWindowMessageFilter(
            UINT message,
            DWORD dwFlag
        );
        """
        message, dwFlag = argv
        emu.enable_deferred_work_hook()
        return True

    @apihook("UpdateWindow", argc=1)
    def UpdateWindow(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL UpdateWindow(
            HWND hWnd
        );
        """
        (hWnd,) = argv
        window = self.sessman.get_window(hWnd)
        if not window:
            emu.set_last_error(windefs.ERROR_INVALID_WINDOW_HANDLE)
            return False

        wc = self.sessman.get_window_class(window.class_name)
        if wc and wc.wclass.lpfnWndProc:
            cb_args = (hWnd, u32defs.WM_PAINT, 0, 0)
            self.setup_callback(wc.wclass.lpfnWndProc, cb_args)

        return True

    @apihook("PostQuitMessage", argc=1)
    def PostQuitMessage(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID PostQuitMessage(
            int nExitCode
        );

        Speakeasy adds WM_QUIT to the end of the message queue of the thread. On Windows, GetMessage gives WM_QUIT
        after all posted messages, also after the messages that the thread posts after PostQuitMessage.
        """
        (nExitCode,) = argv
        thread = emu.get_current_thread()
        if thread is not None:
            thread.message_queue.post_quit(nExitCode)

    @apihook("DestroyWindow", argc=1)
    def DestroyWindow(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL DestroyWindow(
            HWND hWnd
        );

        The window leaves the session manager window table, so a later call that
        uses its handle sees the same "no such window" state as Windows.
        """
        hnd = argv[0]
        self.window_placement.forget(hnd)
        return int(self.sessman.destroy_window(hnd))

    @apihook("DefWindowProc", argc=4)
    def DefWindowProc(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LRESULT LRESULT DefWindowProc(
            HWND hWnd,
            UINT Msg,
            WPARAM wParam,
            LPARAM lParam
        );
        """
        hWnd, Msg, wParam, lParam = argv
        return int(Msg == u32defs.WM_NCCREATE)

    @apihook("CallWindowProc", argc=5)
    def CallWindowProc(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LRESULT CallWindowProc(
            WNDPROC lpPrevWndFunc,
            HWND hWnd,
            UINT Msg,
            WPARAM wParam,
            LPARAM lParam
        );
        """
        lpPrevWndFunc, hWnd, Msg, wParam, lParam = argv
        if not lpPrevWndFunc:
            return 0
        return (yield GuestCall(lpPrevWndFunc, (hWnd, Msg, wParam, lParam)))

    @apihook("CreateWindowEx", argc=12)
    def CreateWindowEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND CreateWindowEx(
            DWORD dwExStyle,
            LPCTSTR lpClassName,
            LPCTSTR lpWindowName,
            DWORD dwStyle,
            int X,
            int Y,
            int nWidth,
            int nHeight,
            HWND hWndParent,
            HMENU hMenu,
            HINSTANCE hInstance,
            LPVOID lpParam
        );

        A window class that has a window procedure gets WM_NCCREATE and then
        WM_CREATE, each with the same CREATESTRUCT of these arguments, as
        Windows sends them. The call fails, and the window is destroyed, when
        the procedure returns FALSE to WM_NCCREATE or -1 to WM_CREATE.
        """
        cw = _char_width(self, ctx)
        dwExStyle, class_token, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam = (
            argv
        )
        class_atom = None
        if isinstance(class_token, int) and 0 < class_token <= 0xFFFF:
            class_atom = class_token
            window_class = self.sessman.get_window_class(class_atom)
            cn = window_class.name if window_class is not None else None
            _set_arg_display(ctx, "lpClassName", cn)
        elif class_token:
            cn = self.read_mem_string(class_token, cw)
            _set_arg_display(ctx, "lpClassName", cn)
        else:
            cn = None
        if lpWindowName:
            wn = self.read_mem_string(lpWindowName, cw)
            _set_arg_display(ctx, "lpWindowName", wn)
        else:
            wn = None

        window_class = self.sessman.get_window_class(class_atom if class_atom is not None else cn)
        wndproc = window_class.wndproc if window_class is not None else None
        thread_id = process_id = 0
        if emu is not None:
            thread = emu.get_current_thread()
            process = emu.get_current_process()
            thread_id = thread.id if thread else 0
            process_id = process.pid if process else 0
        hnd = self.sessman.create_window(
            wn,
            cn,
            dwStyle,
            hWndParent,
            thread_id,
            process_id,
            class_atom=class_atom,
            wndproc=wndproc,
        )
        if hnd and dwStyle & window_placement.WS_MAXIMIZE:
            self.window_placement.set_maximized(hnd, True)
        if not hnd or not wndproc or emu is None:
            # A handler without an emulator cannot run guest code; the window
            # is still in the session manager with its procedure for dispatch.
            return hnd

        cs = u32defs.CREATESTRUCT(emu.get_ptr_size())
        cs.lpCreateParams = lpParam
        cs.hInstance = hInstance
        cs.hMenu = hMenu
        cs.hwndParent = hWndParent
        cs.cy = nHeight
        cs.cx = nWidth
        cs.y = Y
        cs.x = X
        cs.style = dwStyle
        cs.lpszName = lpWindowName
        cs.lpszClass = class_token
        cs.dwExStyle = dwExStyle
        return self.send_create_messages(emu, hnd, wndproc, cs)

    def send_create_messages(self, emu, hwnd: int, wndproc: int, createstruct):
        """
        Send WM_NCCREATE and WM_CREATE to the procedure of a new window.

        Both messages carry the address of the one CREATESTRUCT, as Windows
        does. A procedure that refuses the window at WM_NCCREATE (FALSE) or
        WM_CREATE (-1) makes CreateWindowEx fail, and the window is destroyed.
        """
        lparam = guest_callbacks.alloca(emu, createstruct.get_bytes())
        if not (yield GuestCall(wndproc, (hwnd, u32defs.WM_NCCREATE, 0, lparam))):
            self.sessman.destroy_window(hwnd)
            return 0
        if (yield GuestCall(wndproc, (hwnd, u32defs.WM_CREATE, 0, lparam))) == (1 << emu.get_ptr_size() * 8) - 1:
            self.sessman.destroy_window(hwnd)
            return 0
        return hwnd

    @apihook("SetLayeredWindowAttributes", argc=4)
    def SetLayeredWindowAttributes(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetLayeredWindowAttributes(
            HWND hwnd,
            COLORREF crKey,
            BYTE bAlpha,
            DWORD dwFlags
        );
        """
        hwnd, crKey, bAlpha, dwFlags = argv
        return 1

    @apihook("MessageBox", argc=4)
    def MessageBox(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int MessageBox(
            HWND hWnd,
            LPCTSTR lpText,
            LPCTSTR lpCaption,
            UINT uType
        );
        """
        hWnd, lpText, lpCaption, uType = argv

        cw = _char_width(self, ctx)

        if lpText:
            text = self.read_mem_string(lpText, cw)
            _set_arg_display(ctx, "lpText", text)
        if lpCaption:
            cap = self.read_mem_string(lpCaption, cw)
            _set_arg_display(ctx, "lpCaption", cap)

        # Dismiss the box with Cancel, or press the first button if it has no Cancel button
        return {MB_OK: IDOK, MB_ABORTRETRYIGNORE: IDABORT, MB_YESNO: IDYES}.get(uType & MB_TYPEMASK, IDCANCEL)

    @apihook("MessageBoxEx", argc=5)
    def MessageBoxEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int MessageBoxEx(
            HWND hWnd,
            LPCTSTR lpText,
            LPCTSTR lpCaption,
            UINT uType,
            WORD wLanguageId
        );
        """
        av = argv[:-1]
        rv = self.MessageBox(emu, av, ctx)
        return rv

    @apihook("LoadString", argc=4)
    def LoadString(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int LoadString(
            HINSTANCE hInstance,
            UINT uID,
            LPTSTR lpBuffer,
            int cchBufferMax
        );

        When cchBufferMax is 0, LoadStringW writes a pointer to the string resource,
        which has no terminator, into lpBuffer.
        """
        hInstance, uID, lpBuffer, cchBufferMax = argv
        cw = _char_width(self, ctx)

        if hInstance == 0:
            pe = emu.modules[0] if emu.modules else None
        else:
            pe = emu.get_mod_from_addr(hInstance)
            if pe and hInstance != pe.base:
                return 0

        if not pe:
            return 0

        found = self.find_string_resource_by_id(pe, uID)
        if not found or not found[1]:
            return 0
        address, s = found

        if cchBufferMax == 0:
            if cw != 2:
                return 0
            self.write_ptr(lpBuffer, address)
            _set_arg_display(ctx, "lpBuffer", s)
            return len(s)

        s = s[: cchBufferMax - 1]
        self.write_mem_string(s, lpBuffer, cw)
        _set_arg_display(ctx, "lpBuffer", s)

        return len(s)

    @apihook("GetCursorPos", argc=1)
    def GetCursorPos(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetCursorPos(
            LPPOINT lpPoint
        );
        """
        (lpPoint,) = argv
        if not lpPoint:
            return False

        pt = windef.POINT(emu.get_ptr_size())
        ui = getattr(getattr(emu, "config", None), "ui", None)
        pt.x = resolve_system_metric(SM_CXSCREEN, ui)[0] // 2
        pt.y = resolve_system_metric(SM_CYSCREEN, ui)[0] // 2
        self.mem_write(lpPoint, self.get_bytes(pt))
        return True

    @apihook("WindowFromPoint", argc=2)
    def WindowFromPoint(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND WindowFromPoint(
            POINT Point
        );

        Point is passed by value: two stack slots on x86, one register on x64.
        argc=2 covers the x86 layout.
        """
        return self.sessman.get_current_desktop().desktop_window.get_handle()

    @apihook("GetAsyncKeyState", argc=1)
    def GetAsyncKeyState(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        SHORT GetAsyncKeyState(
            int vKey
        );
        """
        (vKey,) = argv
        return self.get_synthetic_async_key_state(vKey)

    @apihook("GetKeyboardType", argc=1)
    def GetKeyboardType(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int GetKeyboardType(
            int nTypeFlag
        );
        """
        (nTypeFlag,) = argv
        if nTypeFlag == 0:
            return 4
        if nTypeFlag == 1:
            return 0
        if nTypeFlag == 2:
            return 12
        return 0

    @apihook("GetSystemMetrics", argc=1)
    def GetSystemMetrics(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int GetSystemMetrics(
            int nIndex
        );

        The value comes from the configured Windows UI profile, so a sample that
        checks the screen geometry, boot mode or session type sees one coherent
        environment. An unknown selector returns 0.
        """
        (nIndex,) = argv
        return _resolve_metric(emu, nIndex, ctx)

    @apihook("GetSystemMetricsForDpi", argc=2)
    def GetSystemMetricsForDpi(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int GetSystemMetricsForDpi(
            int nIndex,
            UINT dpi
        );

        The metric values of the UI profile are already the Windows values at
        the profile's DPI, so the requested ``dpi`` does not rescale them.
        """
        nIndex, _dpi = argv
        return _resolve_metric(emu, nIndex, ctx)

    @apihook("LoadBitmap", argc=2)
    def LoadBitmap(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HBITMAP LoadBitmap(
            HINSTANCE hInstance,
            LPCTSTR lpBitmapName
        );
        """
        hInstance, lpBitmapName = argv
        self.read_res_identifier(emu, ctx, "lpBitmapName", _char_width(self, ctx), lpBitmapName)
        rv = emu.handle_allocator.allocate_handle()
        return rv

    @apihook("GetClientRect", argc=2)
    def GetClientRect(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetClientRect(
            HWND hWnd,
            LPRECT lpRect
        );
        """
        return 0

    @apihook("RegisterWindowMessage", argc=1)
    def RegisterWindowMessage(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT RegisterWindowMessage(
            LPCTSTR lpString
        );
        """
        (lpString,) = argv
        if not lpString:
            return 0

        cw = _char_width(self, ctx)

        s = self.read_mem_string(lpString, cw)
        _set_arg_display(ctx, "lpString", s)

        return self.window_messages.setdefault(s.lower(), 0xC000 + len(self.window_messages))

    @apihook("wsprintf", argc=_arch.VAR_ARGS, conv=_arch.CALL_CONV_CDECL)
    def wsprintf(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int wsprintf(
            LPTSTR unnamedParam1,
            LPCTSTR unnamedParam2,
            ...
        );
        """
        cw = _char_width(self, ctx)

        buf, fmt = emu.get_func_argv(_arch.CALL_CONV_CDECL, 2)
        fmt_str = self.read_mem_string(fmt, cw)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        _args = emu.get_func_argv(_arch.CALL_CONV_CDECL, 2 + fmt_cnt)[2:]
        fin = self.do_str_format(fmt_str, _args, wide=cw == 2)

        self.write_mem_string(fin, buf, cw)

        _replace_args(ctx, fin, fmt_str)
        return len(fin)

    @apihook("PeekMessage", argc=5)
    def PeekMessage(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL PeekMessage(
            LPMSG lpMsg,
            HWND hWnd,
            UINT wMsgFilterMin,
            UINT wMsgFilterMax,
            UINT wRemoveMsg
        );

        Only posted messages are in the queue. PeekMessage does not give timer messages.
        """
        lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg = argv
        queue = emu.get_current_thread().message_queue
        if wRemoveMsg & u32defs.PM_REMOVE:
            queued = self.get_posted_message(emu, hWnd, wMsgFilterMin, wMsgFilterMax, remove=True)
        elif not hWnd and not wMsgFilterMin and not wMsgFilterMax:
            queued = queue.peek()
        else:
            queued = self.get_posted_message(emu, hWnd, wMsgFilterMin, wMsgFilterMax, remove=False)
        if queued is None:
            return False
        if lpMsg:
            self.write_queued_message(emu, lpMsg, queued)
        return True

    @apihook("PostMessage", argc=4)
    def PostMessage(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL PostMessage(
            HWND hWnd,
            UINT Msg,
            WPARAM wParam,
            LPARAM lParam
        );

        The message goes to the queue of the thread that created the window. Speakeasy drops a message for
        HWND_BROADCAST, and for a window of a thread that does not run in Speakeasy.
        """
        hWnd, Msg, wParam, lParam = argv
        if not hWnd:
            self.post_message(emu, emu.get_current_thread(), hWnd, Msg, wParam, lParam)
            return True
        window = self.sessman.get_window(hWnd)
        if window:
            thread = self.get_thread(emu, window.thread_id)
            if thread:
                self.post_message(emu, thread, hWnd, Msg, wParam, lParam)
        elif hWnd != u32defs.HWND_BROADCAST:
            emu.set_last_error(windefs.ERROR_INVALID_WINDOW_HANDLE)
            return False
        return True

    @apihook("PostThreadMessage", argc=4)
    def PostThreadMessage(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL PostThreadMessage(
            DWORD idThread,
            UINT Msg,
            WPARAM wParam,
            LPARAM lParam
        );

        Each thread has a message queue, so the message goes to any thread that Speakeasy knows. On Windows, the
        call fails for a thread that has not called a user32 or gdi32 function.
        """
        idThread, Msg, wParam, lParam = argv
        thread = self.get_thread(emu, idThread)
        if not thread:
            emu.set_last_error(windefs.ERROR_INVALID_THREAD_ID)
            return False
        self.post_message(emu, thread, 0, Msg, wParam, lParam)
        return True

    def get_thread(self, emu, tid):
        """Get the thread with the ID ``tid``, else None."""
        thread = emu.get_object_from_id(tid)
        return thread if isinstance(thread, objman.Thread) else None

    def post_message(self, emu, thread, hwnd, message, wparam, lparam):
        """Append one message to the queue of ``thread``."""
        queued = QueuedWindowMessage(
            hwnd=int(hwnd or 0),
            message=int(message),
            wparam=int(wparam or 0),
            lparam=int(lparam or 0),
        )
        thread.message_queue.append(queued)

    def write_queued_message(self, emu, lpMsg, queued):
        """
        Write one queued message to ``lpMsg`` as the Windows MSG.

        The local ``MSG`` definition appends ``lPrivate`` for the GUI queue, so
        only the bytes of the Windows structure go to the caller's buffer.
        """
        data = queued.to_native(emu.get_ptr_size()).get_bytes()
        self.mem_write(lpMsg, data[: WINDOWS_MSG_SIZE[emu.get_ptr_size()]])

    def get_posted_message(self, emu, hwnd, filter_min, filter_max, remove):
        """
        Get the first message in the queue of the current thread that matches the filter, else None.

        WM_QUIT matches every filter. An HWND filter matches only the messages of that window, not of its children.
        An HWND of -1 selects the messages that have no window, such as those of PostThreadMessage.
        """
        queue = emu.get_current_thread().message_queue
        if hwnd == (1 << (emu.get_ptr_size() * 8)) - 1:
            return _find_queued_message(queue, 0, filter_min, filter_max, remove)
        if remove:
            return queue.pop(hwnd=hwnd, message_min=filter_min, message_max=filter_max)
        if not hwnd and not filter_min and not filter_max:
            return queue.peek()
        return _find_queued_message(queue, hwnd or None, filter_min, filter_max, remove=False)

    @apihook("SendMessage", argc=4)
    def SendMessage(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LRESULT SendMessage(
            HWND hWnd,
            UINT Msg,
            WPARAM wParam,
            LPARAM lParam
        );
        """
        hWnd, Msg, wParam, lParam = argv
        window = self.sessman.windows.get(hWnd)
        if window and isinstance(window.class_name, str) and window.class_name.lower() == "syslistview32":
            if Msg in LIST_VIEW_COLUMN_MESSAGES:
                return self.send_list_view_column_message(emu, window, Msg, wParam, lParam)
        wndproc = self.sessman.get_window_proc(hWnd)
        if wndproc:
            self.setup_callback(
                wndproc,
                (hWnd, Msg, wParam, lParam),
                caller_argv=argv,
                complete=lambda result: result,
            )

        return 0

    def send_list_view_column_message(self, emu, window, msg, wparam, lparam):
        """Keep the columns of a list-view control as comctl32 does for the LVM_*COLUMN* messages."""
        columns = window.lv_columns
        index = ctypes.c_int32(wparam).value
        if msg in (u32defs.LVM_INSERTCOLUMNA, u32defs.LVM_INSERTCOLUMNW):
            if not lparam or index < 0:
                return -1
            col = self.mem_cast(u32defs.LVCOLUMN(emu.get_ptr_size()), lparam)
            index = min(index, len(columns))
            text = ""
            if col.mask & u32defs.LVCF_TEXT and col.pszText:
                text = self.read_mem_string(col.pszText, 1 if msg == u32defs.LVM_INSERTCOLUMNA else 2)
            columns.insert(
                index,
                sessman.ListViewColumn(
                    fmt=col.fmt if col.mask & u32defs.LVCF_FMT else 0,
                    cx=col.cx if col.mask & u32defs.LVCF_WIDTH else 0,
                    text=text,
                    sub_item=col.iSubItem if col.mask & u32defs.LVCF_SUBITEM else index,
                ),
            )
            return index
        if not 0 <= index < len(columns):
            return 0
        column = columns[index]
        if msg in (u32defs.LVM_GETCOLUMNA, u32defs.LVM_GETCOLUMNW):
            if not lparam:
                return False
            col = self.mem_cast(u32defs.LVCOLUMN(emu.get_ptr_size()), lparam)
            if col.mask & u32defs.LVCF_FMT:
                col.fmt = column.fmt
            if col.mask & u32defs.LVCF_WIDTH:
                col.cx = column.cx
            if col.mask & u32defs.LVCF_SUBITEM:
                col.iSubItem = column.sub_item
            self.mem_write(lparam, col.get_bytes())
            if col.mask & u32defs.LVCF_TEXT and col.pszText and col.cchTextMax > 0:
                cw = 1 if msg == u32defs.LVM_GETCOLUMNA else 2
                self.write_mem_string(column.text[: col.cchTextMax - 1], col.pszText, cw)
            return True
        if msg == u32defs.LVM_GETCOLUMNWIDTH:
            return column.cx
        if msg == u32defs.LVM_SETCOLUMNWIDTH:
            column.cx = ctypes.c_int16(lparam).value
            return True
        del columns[index]
        return True

    @apihook("CallNextHookEx", argc=4)
    def CallNextHookEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LRESULT CallNextHookEx(
            HHOOK hhk,
            int nCode,
            WPARAM wParam,
            LPARAM lParam
        );
        """
        hhk, nCode, wParam, lParam = argv
        return 0

    @apihook("SetWindowsHookEx", argc=4)
    def SetWindowsHookEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HHOOK SetWindowsHookEx(
            int idHook,
            HOOKPROC lpfn,
            HINSTANCE hmod,
            DWORD dwThreadId
        );
        """
        idHook, lpfn, hmod, dwThreadId = argv

        _set_arg_display(ctx, "idHook", decode(WINDOWS_HOOK_ID, idHook))

        hnd = emu.handle_allocator.allocate_handle()
        self.window_hooks.update({hnd: (idHook, lpfn, hmod)})
        return hnd

    @apihook("UnhookWindowsHookEx", argc=1)
    def UnhookWindowsHookEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL UnhookWindowsHookEx(
            HHOOK hhk
        );
        """
        (hhk,) = argv

        rv = False
        if self.window_hooks.get(hhk):
            self.window_hooks.pop(hhk)
            rv = True
        return rv

    @apihook("MsgWaitForMultipleObjects", argc=5)
    def MsgWaitForMultipleObjects(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD MsgWaitForMultipleObjects(
            DWORD nCount,
            const HANDLE *pHandles,
            BOOL fWaitAll,
            DWORD dwMilliseconds,
            DWORD dwWakeMask
        );
        """
        return 0

    @apihook("GetMessage", argc=4)
    def GetMessage(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetMessage(
            LPMSG lpMsg,
            HWND hWnd,
            UINT wMsgFilterMin,
            UINT wMsgFilterMax
        );

        When no posted message matches the filter, GetMessage gives a timer message or a synthetic keyboard event,
        and does not apply the filter to it. An empty queue exposes one bounded idle wakeup as WM_NULL without
        reporting WM_QUIT; the following empty call ends the run with a gui_message_wait error.
        """
        lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax = argv

        thread = emu.get_current_thread()
        queued = self.get_posted_message(emu, hWnd, wMsgFilterMin, wMsgFilterMax, remove=True)
        if queued is None:
            timers = getattr(self, "timers", ())
            if timers:
                next_timer = getattr(self, "next_timer", 0)
                hwnd, tid, proc = timers[next_timer % len(timers)]
                self.next_timer = next_timer + 1
                queued = QueuedWindowMessage(
                    hwnd=hwnd,
                    message=u32defs.WM_TIMER,
                    wparam=tid,
                    lparam=proc,
                )
            elif getattr(self, "timer_count", 0) > 0:
                queued = QueuedWindowMessage(hwnd=hWnd, message=u32defs.WM_TIMER)
            else:
                synthetic = self.emit_synthetic_keyboard_hook_event(emu, argv)
                if synthetic is not None:
                    wparam, vkey = synthetic
                    queued = QueuedWindowMessage(
                        hwnd=hWnd,
                        message=wparam,
                        wparam=vkey,
                    )
                else:
                    if not thread.message_queue.idle_policy.allow_idle_wakeup():
                        error = emu.get_error_info(
                            "gui_message_wait",
                            emu.get_pc(),
                        )
                        emu.curr_run.error = error
                        emu.on_run_complete()
                        return True
                    # GetMessage blocks in Win32 when the queue is empty. Expose
                    # one bounded idle wakeup without falsely reporting WM_QUIT.
                    queued = QueuedWindowMessage(
                        hwnd=hWnd,
                        message=u32defs.WM_NULL,
                    )

        if lpMsg:
            self.write_queued_message(emu, lpMsg, queued)

        return queued.message != u32defs.WM_QUIT

    @apihook("TranslateMessage", argc=1)
    def TranslateMessage(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL TranslateMessage(
            const MSG *lpMsg
        );
        """
        return True

    @apihook("DispatchMessage", argc=1)
    def DispatchMessage(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LRESULT DispatchMessage(
            const MSG *lpMsg
        );

        A WM_TIMER with a timer procedure goes to that procedure; every other
        message goes to the window procedure that the SessionManager records for
        its window (a per-window override, else the class procedure).
        """
        (lpMsg,) = argv

        if not lpMsg:
            return 0

        msg = u32defs.MSG(self.get_ptr_size())
        msg = self.mem_cast(msg, lpMsg)

        if msg.message == u32defs.WM_TIMER and msg.lParam:
            self.setup_callback(
                msg.lParam,
                (msg.hwnd, msg.message, msg.wParam, msg.time),
                caller_argv=argv,
                complete=lambda result: result,
            )
            return 0
        if msg.hwnd:
            wndproc = self.sessman.get_window_proc(msg.hwnd)
            if wndproc:
                self.setup_callback(
                    wndproc,
                    (msg.hwnd, msg.message, msg.wParam, msg.lParam),
                    caller_argv=argv,
                    complete=lambda result: result,
                )

        return 0

    @apihook("GetForegroundWindow", argc=0)
    def GetForegroundWindow(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetForegroundWindow();
        """
        if not self.foreground_window:
            explorer = next((p for p in emu.get_processes() if p.name.lower() == "explorer"), None)
            self.foreground_window = self.sessman.create_window(
                window_name="Program Manager",
                class_name="Progman",
                thread_id=emu.handle_allocator.allocate_kernel_object_id(),
                process_id=explorer.pid if explorer else 0,
            )
        return self.foreground_window

    @apihook("LoadCursor", argc=2)
    def LoadCursor(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HCURSOR LoadCursor(
            HINSTANCE hInstance,
            LPCTSTR lpCursorName
        );
        """
        hInstance, lpCursorName = argv
        self.read_res_identifier(emu, ctx, "lpCursorName", _char_width(self, ctx), lpCursorName)
        return emu.handle_allocator.allocate_handle()

    @apihook("FindWindow", argc=2)
    def FindWindow(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND FindWindow(
            LPCTSTR lpClassName,
            LPCTSTR lpWindowName
        );
        """
        lpClassName, lpWindowName = argv
        cw = _char_width(self, ctx)
        if lpClassName > 0xFFFF:
            cn = self.read_mem_string(lpClassName, cw)
            _set_arg_display(ctx, "lpClassName", cn)
        if lpWindowName:
            wn = self.read_mem_string(lpWindowName, cw)
            _set_arg_display(ctx, "lpWindowName", wn)
        return 0

    @apihook("FindWindowEx", argc=4)
    def FindWindowEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND FindWindowEx(
            HWND hWndParent,
            HWND hWndChildAfter,
            LPCTSTR lpszClass,
            LPCTSTR lpszWindow
        );
        """
        hWndParent, hWndChildAfter, lpszClass, lpszWindow = argv
        cw = _char_width(self, ctx)
        if lpszClass > 0xFFFF:
            _set_arg_display(ctx, "lpszClass", self.read_mem_string(lpszClass, cw))
        if lpszWindow:
            _set_arg_display(ctx, "lpszWindow", self.read_mem_string(lpszWindow, cw))
        return 0

    @apihook("GetWindowText", argc=3)
    def GetWindowText(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int GetWindowText(
            HWND hWnd,
            LPTSTR lpString,
            int nMaxCount
        );
        """
        hWnd, lpString, nMaxCount = argv

        cw = _char_width(self, ctx)
        win_text = "speakeasy window"
        if not lpString or not 0 < nMaxCount <= 0x7FFFFFFF:
            return 0
        win_text = win_text[: nMaxCount - 1]
        self.write_mem_string(win_text, lpString, cw)

        return len(win_text)

    @apihook("PaintDesktop", argc=1)
    def PaintDesktop(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL PaintDesktop(
            HDC hdc
        );
        """
        return 0

    @apihook("wvsprintf", argc=3)
    def wvsprintf(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int wvsprintf(
            LPTSTR lpOutput,
            LPCTSTR lpFmt,
            va_list arglist
        );
        """
        lpOutput, lpFmt, arglist = argv
        cw = _char_width(self, ctx)
        fmt_str = self.read_mem_string(lpFmt, cw)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        vargs = self.va_args(arglist, fmt_cnt)
        fin = self.do_str_format(fmt_str, vargs, wide=cw == 2)
        self.write_mem_string(fin, lpOutput, cw)
        _replace_args(ctx, fin, fmt_str)
        return len(fin)

    @apihook("ReleaseDC", argc=2)
    def ReleaseDC(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int ReleaseDC(
            HWND hWnd,
            HDC hDC
        );
        """
        hWnd, hDC = argv
        return int(hDC == self.sessman.get_device_context())

    @apihook("CharNext", argc=1)
    def CharNext(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPTSTR CharNext(
            LPCTSTR lpsz
        );
        """
        (lpsz,) = argv
        rv = lpsz
        cw = _char_width(self, ctx)
        if lpsz and int.from_bytes(self.mem_read(lpsz, cw), "little"):
            rv = lpsz + cw
        return rv

    @apihook("CharPrev", argc=2)
    def CharPrev(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPTSTR CharPrev(
            LPCTSTR lpszStart,
            LPCTSTR lpszCurrent
        );
        """
        """
        Got this from wine.          
        https://github.com/wine-mirror/wine/blob/a8c1d5c108fc57e4d78e9db126f395c89083a83d/dlls/kernelbase/string.c
        """
        lpszStart, lpszCurrent = argv
        cw = _char_width(self, ctx)
        while lpszStart < lpszCurrent:
            n = lpszStart + cw
            if n >= lpszCurrent:
                break
            lpszStart = n

        return lpszStart

    @apihook("EnumWindows", argc=2)
    def EnumWindows(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EnumWindows(
            WNDENUMPROC lpEnumFunc,
            LPARAM lParam
        );
        """
        lpEnumFunc, lParam = argv
        desktop = self.sessman.get_current_desktop().desktop_window.get_handle()
        hwnds = [hnd for hnd, w in self.sessman.windows.items() if isinstance(hnd, int) and w.parent in (0, desktop)]
        for hnd in hwnds:
            if not (yield GuestCall(lpEnumFunc, (hnd, lParam))) & 0xFFFFFFFF:
                return 0
        return 1

    @apihook("GetSysColor", argc=1)
    def GetSysColor(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetSysColor(
            int nIndex
        );
        """
        (nIndex,) = argv
        return SYS_COLORS.get(nIndex, 0)

    @apihook("GetParent", argc=1)
    def GetParent(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetParent(
            HWND hWnd
        );
        """
        (hWnd,) = argv
        window = self.sessman.get_window(hWnd)
        if not window:
            if hWnd != self.sessman.get_current_desktop().desktop_window.get_handle():
                emu.set_last_error(windefs.ERROR_INVALID_WINDOW_HANDLE)
            return 0
        if window.style & (WS_POPUP | WS_CHILD):
            return window.parent
        return 0

    def get_prop_key(self, lpString: int, ctx: api.ApiContext) -> int | str:
        if lpString <= 0xFFFF:
            return lpString
        name = self.read_mem_string(lpString, _char_width(self, ctx))
        _set_arg_display(ctx, "lpString", name)
        return name.upper()

    def get_prop_window(self, emu, hnd):
        window = self.sessman.get_window(hnd)
        if not window:
            emu.set_last_error(windefs.ERROR_INVALID_WINDOW_HANDLE)
        return window

    @apihook("SetProp", argc=3)
    def SetProp(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetProp(
            HWND hWnd,
            LPCTSTR lpString,
            HANDLE hData
        );
        """
        hWnd, lpString, hData = argv
        key = self.get_prop_key(lpString, ctx)
        window = self.get_prop_window(emu, hWnd)
        if not window:
            return False
        window.props[key] = hData
        return True

    @apihook("GetProp", argc=2)
    def GetProp(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE GetProp(
            HWND hWnd,
            LPCTSTR lpString
        );
        """
        hWnd, lpString = argv
        key = self.get_prop_key(lpString, ctx)
        window = self.get_prop_window(emu, hWnd)
        if not window:
            return 0
        return window.props.get(key, 0)

    @apihook("RemoveProp", argc=2)
    def RemoveProp(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE RemoveProp(
            HWND hWnd,
            LPCTSTR lpString
        );
        """
        hWnd, lpString = argv
        key = self.get_prop_key(lpString, ctx)
        window = self.get_prop_window(emu, hWnd)
        if not window:
            return 0
        return window.props.pop(key, 0)

    @apihook("GetWindowThreadProcessId", argc=2)
    def GetWindowThreadProcessId(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetWindowThreadProcessId(
            HWND hWnd,
            LPDWORD lpdwProcessId
        );
        """
        hWnd, lpdwProcessId = argv
        desktop_window = self.sessman.get_current_desktop().desktop_window
        if hWnd == desktop_window.get_handle():
            window = desktop_window
            if not window.thread_id:
                csrss = next((p for p in emu.get_processes() if p.name.lower() == "csrss"), None)
                window.process_id = csrss.pid if csrss else 0
                window.thread_id = emu.handle_allocator.allocate_kernel_object_id()
        else:
            window = self.sessman.get_window(hWnd)
            if not window:
                emu.set_last_error(windefs.ERROR_INVALID_WINDOW_HANDLE)
                return 0
            if window.process_id and not window.thread_id:
                # The console window reports the first thread of the process that owns the console
                owner = next((p for p in emu.get_processes() if p.pid == window.process_id), None)
                if owner and owner.threads:
                    window.thread_id = owner.threads[0].tid
        if lpdwProcessId:
            self.write_dword(lpdwProcessId, window.process_id)
        return window.thread_id

    @apihook("GetSysColorBrush", argc=1)
    def GetSysColorBrush(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HBRUSH GetSysColorBrush(
            int nIndex
        );
        """
        (nIndex,) = argv
        rv = 1

        return rv

    def _window_proc_value(self, hWnd: int) -> int:
        """Current window procedure for ``hWnd`` as an integer (0 if unknown).

        The SessionManager is the single source of truth for ``GWL_WNDPROC``:
        a window's own procedure overrides its class procedure, and a handle
        that does not identify a window has no procedure.
        """
        return int(self.sessman.get_window_proc(hWnd) or 0)

    def _window_for_long(self, emu, hWnd: int):
        """
        Get the window of ``hWnd``, else set ERROR_INVALID_WINDOW_HANDLE and return None.

        Windows validates the HWND of GetWindowLong and SetWindowLong, so a
        handle that the SessionManager does not know fails the call instead of
        reading or storing an attribute for it.
        """
        window = self.sessman.get_window(hWnd)
        if window is None:
            emu.set_last_error(ERROR_INVALID_WINDOW_HANDLE)
        return window

    def _get_window_long(self, emu, hWnd: int, nIndex: int, value_size: int) -> int:
        """Read one window long attribute.

        Args:
            emu: the emulator, for the error of an unknown handle.
            hWnd: window handle. An unknown handle sets
                ERROR_INVALID_WINDOW_HANDLE and reads as 0.
            nIndex: ``GWL_*`` selector; 32-bit and 64-bit sign-extended forms
                address the same attribute.
            value_size: result width in bytes (4 for ``LONG``, pointer size for
                ``LONG_PTR``).

        Returns:
            The stored value truncated to ``value_size``. ``GWL_WNDPROC``
            returns the SessionManager window procedure, ``GWL_STYLE`` returns
            the window style, and an attribute that was never set returns 0.
            No placeholder value is fabricated.
        """
        if self._window_for_long(emu, hWnd) is None:
            return 0
        index = canonical_window_long_index(nIndex)
        if index == canonical_window_long_index(GWL_WNDPROC):
            value = self._window_proc_value(hWnd)
        elif index == canonical_window_long_index(GWL_STYLE):
            value = self.sessman.get_window(hWnd).style
        else:
            value = self.window_state.get(hWnd, index)
        return mask_window_long_value(value, value_size)

    def _set_window_long(self, emu, hWnd: int, nIndex: int, dwNewLong: int, value_size: int) -> int:
        """Store one window long attribute and return the previous value.

        ``GWL_WNDPROC`` is routed exclusively through
        ``SessionManager.set_window_proc`` so the stored procedure and message
        dispatch stay consistent; the procedure itself is pointer-sized.
        ``GWL_STYLE`` updates the style that the SessionManager window carries.
        Other selectors are stored in ``WindowState`` keyed by
        ``(hWnd, canonical nIndex)``. An unknown handle sets
        ERROR_INVALID_WINDOW_HANDLE and cannot acquire procedure, style or
        attribute state.

        Returns:
            The previous value truncated to ``value_size`` (0 when unset).
        """
        if self._window_for_long(emu, hWnd) is None:
            return 0
        index = canonical_window_long_index(nIndex)
        if index == canonical_window_long_index(GWL_WNDPROC):
            old = self._window_proc_value(hWnd)
            new_proc = mask_window_long_value(dwNewLong, self.get_ptr_size())
            self.sessman.set_window_proc(hWnd, new_proc)
        elif index == canonical_window_long_index(GWL_STYLE):
            window = self.sessman.get_window(hWnd)
            old = window.style
            window.style = mask_window_long_value(dwNewLong, 4)
        else:
            old = self.window_state.get(hWnd, index)
            self.window_state.set(hWnd, index, mask_window_long_value(dwNewLong, value_size))
        return mask_window_long_value(old, value_size)

    @apihook("GetWindowLong", argc=2)
    def GetWindowLong(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG GetWindowLongA/W(
            HWND hWnd,
            int  nIndex
        );

        Returns the stored window long value, or 0 when it was never set.
        ``GWL_WNDPROC`` reflects the SessionManager window procedure and
        ``GWL_STYLE`` the window style. An unknown handle fails with
        ERROR_INVALID_WINDOW_HANDLE.
        """
        hWnd, nIndex = argv
        return self._get_window_long(emu, hWnd, nIndex, 4)

    @apihook("GetWindowLongPtr", argc=2)
    def GetWindowLongPtr(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG_PTR GetWindowLongPtrA/W(
            HWND hWnd,
            int  nIndex
        );

        Pointer-width variant of GetWindowLong, used by 64-bit guests. Shares
        the same attribute storage; values are truncated to the pointer size.
        """
        hWnd, nIndex = argv
        return self._get_window_long(emu, hWnd, nIndex, self.get_ptr_size())

    @apihook("SetWindowLong", argc=3)
    def SetWindowLong(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG SetWindowLongA/W(
          HWND hWnd,
          int  nIndex,
          LONG dwNewLong
        );

        Stores ``dwNewLong`` and returns the previous value (0 when unset).
        ``GWL_WNDPROC`` (-4) additionally updates the window procedure used for
        message dispatch, and ``GWL_STYLE`` (-16) updates the window style. An
        unknown handle fails with ERROR_INVALID_WINDOW_HANDLE.
        """
        hWnd, nIndex, dwNewLong = argv
        return self._set_window_long(emu, hWnd, nIndex, dwNewLong, 4)

    @apihook("SetWindowLongPtr", argc=3)
    def SetWindowLongPtr(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG_PTR SetWindowLongPtrA/W(
          HWND    hWnd,
          int     nIndex,
          LONG_PTR dwNewLong
        );

        Pointer-width variant of SetWindowLong, used by 64-bit guests. Shares
        the same attribute storage; ``GWL_WNDPROC`` updates the window procedure.
        """
        hWnd, nIndex, dwNewLong = argv
        return self._set_window_long(emu, hWnd, nIndex, dwNewLong, self.get_ptr_size())

    @apihook("DialogBoxParam", argc=5)
    def DialogBoxParam(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        INT_PTR DialogBoxParam(
            HINSTANCE hInstance,
            LPCTSTR lpTemplateName,
            HWND hWndParent,
            DLGPROC lpDialogFunc,
            LPARAM dwInitParam
        );

        ``lpTemplateName`` is overloaded: it may be a string pointer or a
        MAKEINTRESOURCE identifier whose value is the low-order word. Treating a
        small identifier as an address aborts otherwise valid runs.
        """
        hInstance, lpTemplateName, hWndParent, lpDialogFunc, dwInitParam = argv
        cw = _char_width(self, ctx)
        if lpTemplateName and lpTemplateName > 0xFFFF:
            if not emu.is_address_valid(lpTemplateName):
                return 0
            tname = self.read_mem_string(lpTemplateName, cw)
            _set_arg_display(ctx, "lpTemplateName", tname)

        if getattr(self, "sessman", None) is None:
            # Handler contract tests construct the handler without a session
            # manager and provide the dialog handle through ``get_handle``.
            getter = getattr(self, "get_handle", None)
            return getter() if callable(getter) else 0
        if not lpDialogFunc:
            return IDCANCEL
        return self.run_dialog(self.new_window_handle(), lpDialogFunc, dwInitParam)

    def run_dialog(self, hdlg, func, param):
        # No user input arrives, so the dialog ends when the procedure calls EndDialog
        # during WM_INITDIALOG, or else as if the user closed it
        yield GuestCall(func, (hdlg, u32defs.WM_INITDIALOG, 0, param))
        return self.dialog_results.pop(hdlg, IDCANCEL)

    @apihook("EndDialog", argc=2)
    def EndDialog(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EndDialog(
            HWND hDlg,
            INT_PTR nResult
        );
        """
        hDlg, nResult = argv
        self.dialog_results[hDlg] = nResult
        return 1

    @apihook("CreateDialogIndirectParam", argc=5)
    def CreateDialogIndirectParam(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND CreateDialogIndirectParam(
            HINSTANCE hInstance,
            LPCDLGTEMPLATE lpTemplate,
            HWND hWndParent,
            DLGPROC lpDialogFunc,
            LPARAM dwInitParam
        );
        """
        (
            hInstance,
            lpTemplate,
            hWndParent,
            lpDialogFunc,
            dwInitParam,
        ) = argv

        hdlg = self.new_window_handle()
        cb_args = (hdlg, u32defs.WM_INITDIALOG, 0, dwInitParam)
        self.setup_callback(lpDialogFunc, cb_args)
        return hdlg

    @apihook("GetMenuInfo", argc=2)
    def GetMenuInfo(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetMenuInfo(
            HMENU hmenu,
            LPMENUINFO lpcmi
        );
        """
        return 1

    @apihook("GetProcessWindowStation", argc=0)
    def GetProcessWindowStation(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWINSTA GetProcessWindowStation();
        """
        sta = self.sessman.get_current_station()
        return sta.get_handle()

    @apihook("LoadAccelerators", argc=2)
    def LoadAccelerators(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HACCEL LoadAccelerators(
            HINSTANCE hInstance,
            LPCTSTR lpTableName
        );
        """
        hInstance, lpTableName = argv
        self.read_res_identifier(emu, ctx, "lpTableName", _char_width(self, ctx), lpTableName)
        return emu.handle_allocator.allocate_handle()

    @apihook("IsWindowVisible", argc=1)
    def IsWindowVisible(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL IsWindowVisible(
            HWND hWnd
        );
        """
        return True

    @apihook("IsZoomed", argc=1)
    def IsZoomed(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL IsZoomed(
            HWND hWnd
        );

        Nonzero only while the window is maximized. The maximize state is
        maintained by CreateWindowEx (WS_MAXIMIZE) and ShowWindow
        (SW_MAXIMIZE / restore commands); an unknown HWND is not zoomed and
        sets ERROR_INVALID_WINDOW_HANDLE, matching the documented predicate
        contract instead of an unconditional TRUE signature fallback.
        """
        hWnd = argv[0]
        window = self.sessman.get_window(hWnd)
        if window is None:
            emu.set_last_error(ERROR_INVALID_WINDOW_HANDLE)
            _attach_scatter_observation(
                ctx,
                lambda: api_diagnostics.observe_is_zoomed(
                    emu,
                    hWnd,
                    0,
                    emu.get_last_error(),
                    window_known=False,
                    api_name=_ctx_func_name(ctx),
                ),
            )
            return 0
        rv = 1 if self.window_placement.is_maximized(hWnd) else 0
        _attach_scatter_observation(
            ctx,
            lambda: api_diagnostics.observe_is_zoomed(
                emu,
                hWnd,
                rv,
                emu.get_last_error(),
                window_known=True,
                api_name=_ctx_func_name(ctx),
            ),
        )
        return rv

    @apihook("BeginPaint", argc=2)
    def BeginPaint(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HDC BeginPaint(
            HWND hWnd,
            LPPAINTSTRUCT lpPaint
        );
        """
        return emu.handle_allocator.allocate_handle()

    @apihook("LookupIconIdFromDirectory", argc=2)
    def LookupIconIdFromDirectory(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int LookupIconIdFromDirectory(
            PBYTE presbits,
            BOOL fIcon
        );
        """
        return 1

    @apihook("GetActiveWindow", argc=0)
    def GetActiveWindow(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetActiveWindow();
        """
        return self.new_window_handle()

    @apihook("GetLastActivePopup", argc=1)
    def GetLastActivePopup(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetLastActivePopup(
            HWND hWnd
        );
        """
        (hWnd,) = argv
        return self.new_window_handle()

    @apihook("GetUserObjectInformation", argc=5)
    def GetUserObjectInformation(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetUserObjectInformation(
            HANDLE hObj,
            int nIndex,
            PVOID pvInfo,
            DWORD nLength,
            LPDWORD lpnLengthNeeded
        );
        """
        hObj, nIndex, pvInfo, nLength, lpnLengthNeeded = argv

        if nIndex == UOI_FLAGS:
            uoi = u32defs.USEROBJECTFLAGS(emu.get_ptr_size())
            uoi.fInherit = 1
            uoi.dwFlags = 1

            if pvInfo:
                self.mem_write(pvInfo, uoi.get_bytes())

        return True

    @apihook("LoadIcon", argc=2)
    def LoadIcon(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HICON LoadIcon(
            HINSTANCE hInstance,
            LPCTSTR lpIconName
        );
        """
        (
            hInstance,
            lpIconName,
        ) = argv
        self.read_res_identifier(emu, ctx, "lpIconName", _char_width(self, ctx), lpIconName)

        if lpIconName not in (
            IDI_APPLICATION,
            IDI_ASTERISK,
            IDI_ERROR,
            IDI_EXCLAMATION,
            IDI_HAND,
            IDI_INFORMATION,
            IDI_QUESTION,
            IDI_SHIELD,
            IDI_WARNING,
            IDI_WINLOGO,
        ):
            return 0
        return 1

    @apihook("GetRawInputDeviceList", argc=3)
    def GetRawInputDeviceList(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT GetRawInputDeviceList(
            PRAWINPUTDEVICELIST pRawInputDeviceList,
            PUINT puiNumDevices,
            UINT cbSize
        );
        """
        pRawInputDeviceList, puiNumDevices, cbSize = argv
        types = (u32defs.RIM_TYPEKEYBOARD, u32defs.RIM_TYPEMOUSE, u32defs.RIM_TYPEHID, u32defs.RIM_TYPEHID)
        num_devices = len(types)
        if not pRawInputDeviceList:
            self.write_dword(puiNumDevices, num_devices)
            return 0

        if self.read_dword(puiNumDevices) < num_devices:
            self.write_dword(puiNumDevices, num_devices)
            emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)
            return 0xFFFFFFFF

        ptr_size = self.get_ptr_size()
        for i, dev_type in enumerate(types):
            hnd = emu.handle_allocator.allocate_handle()
            entry = hnd.to_bytes(ptr_size, "little") + dev_type.to_bytes(ptr_size, "little")
            self.mem_write(pRawInputDeviceList + i * 2 * ptr_size, entry)
        return num_devices

    @apihook("GetNextDlgTabItem", argc=3)
    def GetNextDlgTabItem(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetNextDlgTabItem(
            HWND hDlg,
            HWND hCtl,
            BOOL bPrevious
        );
        """
        return 0

    @apihook("GetCaretPos", argc=1)
    def GetCaretPos(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetCaretPos(
            LPPOINT lpPoint
        );
        """
        (lpPoint,) = argv
        point = windef.POINT(emu.get_ptr_size())
        point.x = 0
        point.y = 0
        self.mem_write(lpPoint, self.get_bytes(point))
        return 1

    @apihook("GetMonitorInfo", argc=2)
    def GetMonitorInfo(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetMonitorInfo(
            HMONITOR hMonitor,
            LPMONITORINFO lpmi
        );
        """
        hMonitor, lpmi = argv
        mi = windef.MONITORINFO(emu.get_ptr_size())
        mi = self.mem_cast(mi, lpmi)
        # just a stub for now
        self.mem_write(lpmi, self.get_bytes(mi))
        return 1

    @apihook("EndPaint", argc=2)
    def EndPaint(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EndPaint(
            HWND hWnd,
            const PAINTSTRUCT *lpPaint
        );
        """
        return 1

    @apihook("GetDlgCtrlID", argc=1)
    def GetDlgCtrlID(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int GetDlgCtrlID(
            HWND hWnd
        );
        """
        return 1

    @apihook("GetUpdateRect", argc=3)
    def GetUpdateRect(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetUpdateRect(
            HWND hWnd,
            LPRECT lpRect,
            BOOL bErase
        );
        """
        return 0

    @apihook("GetAltTabInfo", argc=5)
    def GetAltTabInfo(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetAltTabInfo(
            HWND hwnd,
            int iItem,
            PALTTABINFO pati,
            LPTSTR pszItemText,
            UINT cchItemText
        );
        """
        return 0

    @apihook("GetUpdateRgn", argc=3)
    def GetUpdateRgn(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int GetUpdateRgn(
            HWND hWnd,
            HRGN hRgn,
            BOOL bErase
        );
        """
        return 0

    @apihook("FlashWindow", argc=2)
    def FlashWindow(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL FlashWindow(
            HWND hWnd,
            BOOL bInvert
        );
        """
        return 1

    @apihook("IsClipboardFormatAvailable", argc=1)
    def IsClipboardFormatAvailable(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL IsClipboardFormatAvailable(
            UINT format
        );
        """
        return 0

    @apihook("GetClipboardData", argc=1)
    def GetClipboardData(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE GetClipboardData(
            UINT uFormat
        );
        """
        return 0

    @apihook("IsWindow", argc=1)
    def IsWindow(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL IsWindow(
            HWND hWnd
        );
        """
        (hWnd,) = argv

        return True

    @apihook("EnableWindow", argc=2)
    def EnableWindow(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EnableWindow(
            HWND hWnd,
            BOOL bEnable
        );
        """
        hWnd, bEnable = argv

        return False

    @apihook("CharLowerBuff", argc=2)
    def CharLowerBuff(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD CharLowerBuff(
            LPTSTR lpsz,
            DWORD cchLength
        );
        """
        lpsz, cchLength = argv
        cw = _char_width(self, ctx)
        if not cchLength:
            return 0
        raw = self.mem_read(lpsz, cchLength * cw)
        _set_arg_display(ctx, "lpsz", self.decode_string(raw, cw).replace("\x00", ""))
        self.mem_write(lpsz, map_char_case(raw, cw, upper=False))
        return cchLength

    @apihook("CharUpperBuff", argc=2)
    def CharUpperBuff(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD CharUpperBuff(
            LPTSTR lpsz,
            DWORD cchLength
        );
        """
        lpsz, cchLength = argv
        cw = _char_width(self, ctx)
        if not cchLength:
            return 0
        raw = self.mem_read(lpsz, cchLength * cw)
        _set_arg_display(ctx, "lpsz", self.decode_string(raw, cw).replace("\x00", ""))
        self.mem_write(lpsz, map_char_case(raw, cw, upper=True))
        return cchLength

    @apihook("CharLower", argc=1)
    def CharLower(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPTSTR CharLower(
            LPTSTR lpsz
        );
        """
        (lpsz,) = argv
        cw = _char_width(self, ctx)
        bits = lpsz.bit_length()
        if bits <= 16:
            if cw == 1 and lpsz > 0xFF:
                return lpsz
            val = map_char_case(lpsz.to_bytes(cw, "little"), cw, upper=False)
            return int.from_bytes(val, byteorder="little")
        raw = self.mem_read(lpsz, self.mem_string_len(lpsz, cw) * cw)
        self.mem_write(lpsz, map_char_case(raw, cw, upper=False))
        return lpsz

    @apihook("CharUpper", argc=1)
    def CharUpper(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPTSTR CharUpper(
            LPTSTR lpsz
        );
        """
        (lpsz,) = argv
        cw = _char_width(self, ctx)
        bits = lpsz.bit_length()
        if bits <= 16:
            if cw == 1 and lpsz > 0xFF:
                return lpsz
            val = map_char_case(lpsz.to_bytes(cw, "little"), cw, upper=True)
            return int.from_bytes(val, byteorder="little")
        raw = self.mem_read(lpsz, self.mem_string_len(lpsz, cw) * cw)
        self.mem_write(lpsz, map_char_case(raw, cw, upper=True))
        return lpsz

    @apihook("SetTimer", argc=4)
    def SetTimer(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT_PTR SetTimer(
            HWND hWnd,
            UINT_PTR nIDEvent,
            UINT uElapse,
            TIMERPROC lpTimerFunc
        );
        """
        hWnd, nIDEvent, uElapse, lpTimerFunc = argv
        if hWnd:
            self.timers = [t for t in self.timers if t[:2] != (hWnd, nIDEvent)]
            self.timers.append((hWnd, nIDEvent, lpTimerFunc))
            self.timer_count = len(self.timers)
            return nIDEvent
        tid = emu.handle_allocator.allocate_handle()
        self.timers.append((0, tid, lpTimerFunc))
        self.timer_count = len(self.timers)
        return tid

    @apihook("KillTimer", argc=2)
    def KillTimer(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL KillTimer(
            HWND hWnd,
            UINT_PTR uIDEvent
        );
        """
        hWnd, uIDEvent = argv
        self.timers = [t for t in self.timers if t[:2] != (hWnd, uIDEvent)]
        self.timer_count = len(self.timers)
        return True

    @apihook("OpenDesktop", argc=4)
    def OpenDesktop(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HDESK OpenDesktop(
            LPCTSTR lpszDesktop,
            DWORD dwFlags,
            BOOL fInherit,
            ACCESS_MASK dwDesiredAccess
        );
        """
        lpszDesktop, dwFlags, fInherit, dwDesiredAccess = argv
        cw = _char_width(self, ctx)
        desktop = self.read_mem_string(lpszDesktop, cw)
        _set_arg_display(ctx, "lpszDesktop", desktop)
        return emu.handle_allocator.allocate_handle()

    @apihook("SetThreadDesktop", argc=1)
    def SetThreadDesktop(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetThreadDesktop(
            HDESK hDesktop
        );
        """
        return 0

    @apihook("GetKeyboardLayoutList", argc=2)
    def GetKeyboardLayoutList(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int GetKeyboardLayoutList(
            int nBuff,
            HKL *lpList
        );
        """
        nBuff, lpList = argv
        if not nBuff:
            # number of items
            return 1
        hkl = 0x04090409  # English - United States
        self.write_ptr(lpList, hkl)

        return 1

    @apihook("GetKBCodePage", argc=0)
    def GetKBCodePage(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT GetKBCodePage();
        """
        # >>> ctypes.windll.user32.GetKBCodePage()
        # 437
        # https://docs.microsoft.com/en-us/windows/win32/intl/code-page-identifiers
        return 437  # OEM United States

    @apihook("GetClipboardViewer", argc=0)
    def GetClipboardViewer(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetClipboardViewer();
        """
        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("GetClipboardOwner", argc=0)
    def GetClipboardOwner(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetClipboardOwner();
        """
        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("GetMenuCheckMarkDimensions", argc=0)
    def GetMenuCheckMarkDimensions(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG GetMenuCheckMarkDimensions();
        """
        # >>> ctypes.windll.user32.GetMenuCheckMarkDimensions()
        # 983055
        return 983055

    @apihook("GetOpenClipboardWindow", argc=0)
    def GetOpenClipboardWindow(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetOpenClipboardWindow();
        """
        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("GetFocus", argc=0)
    def GetFocus(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetFocus();
        """
        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("GetCursor", argc=0)
    def GetCursor(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HCURSOR GetCursor();
        """
        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("GetClipboardSequenceNumber", argc=0)
    def GetClipboardSequenceNumber(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetClipboardSequenceNumber();
        """
        # >>> ctypes.windll.user32.GetClipboardSequenceNumber()
        # 295
        return 295

    @apihook("GetCaretBlinkTime", argc=0)
    def GetCaretBlinkTime(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT GetCaretBlinkTime();
        """
        # >>> ctypes.windll.user32.GetCaretBlinkTime()
        # 530
        return 530

    @apihook("GetDoubleClickTime", argc=0)
    def GetDoubleClickTime(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT GetDoubleClickTime();
        """
        # >>> ctypes.windll.user32.GetDoubleClickTime()
        # 500
        return 500

    @apihook("RegisterClipboardFormatA", argc=1)
    def RegisterClipboardFormatA(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT RegisterClipboardFormatA(
            LPCSTR lpszFormat
        );
        """
        # Return a fake clipboard format ID.
        # Clipboard format IDs start at 0xC000 for custom formats.
        return 0xC000

    @apihook("SystemParametersInfoA", argc=4)
    def SystemParametersInfoA(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SystemParametersInfoA(
            UINT uiAction,
            UINT uiParam,
            PVOID pvParam,
            UINT fWinIni
        );
        """
        uiAction, uiParam, pvParam, fWinIni = argv

        # Many callers expect pvParam to be filled with something.
        # We return success without writing anything unless needed.
        return 1

    @apihook("GetKeyboardLayout", argc=1)
    def GetKeyboardLayout(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HKL GetKeyboardLayout(
            DWORD idThread
        );
        """
        # Return a fake HKL (keyboard layout handle).
        # Real HKLs are typically like 0x04090409 (LANG + device id).
        return 0x04090409

    @apihook("EnumDisplayMonitors", argc=4)
    def EnumDisplayMonitors(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EnumDisplayMonitors(
            HDC hdc,
            LPCRECT lprcClip,
            MONITORENUMPROC lpfnEnum,
            LPARAM dwData
        );
        """
        hdc, lprcClip, lpfnEnum, dwData = argv

        # Most callers expect TRUE to indicate success.
        # We do not invoke the callback — Speakeasy doesn't emulate monitor enumeration.
        return 1

    @apihook("EnumDisplayDevices", argc=4)
    def EnumDisplayDevices(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EnumDisplayDevices(
            LPCTSTR lpDevice,
            DWORD iDevNum,
            PDISPLAY_DEVICE lpDisplayDevice,
            DWORD dwFlags
        );

        Older callers set cb to the size of the struct without DeviceID and DeviceKey, so the handler writes only
        cb bytes.
        """
        lpDevice, iDevNum, lpDisplayDevice, dwFlags = argv

        cw = _char_width(self, ctx)
        parent = self.read_mem_string(lpDevice, cw).upper() if lpDevice else None
        if iDevNum or not lpDisplayDevice or parent not in DISPLAY_DEVICES:
            return 0

        dd = u32defs.DISPLAY_DEVICE(emu.get_ptr_size(), cw)
        cb = self.read_dword(lpDisplayDevice)
        if cb < dd.get_cstruct().DeviceID.offset:
            return 0

        name, text, flags, device_id, key = DISPLAY_DEVICES[parent]
        dd.cb = cb
        dd.DeviceName = self.encode_string(name, cw)
        dd.DeviceString = self.encode_string(text, cw)
        dd.StateFlags = flags
        dd.DeviceID = self.encode_string(device_id, cw)
        dd.DeviceKey = self.encode_string(key, cw)
        self.mem_write(lpDisplayDevice, dd.get_bytes()[:cb])
        return 1

    @apihook("OemToCharA", argc=2)
    def OemToCharA(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL OemToCharA(
            LPCSTR pSrc,
            LPSTR pDst
        );
        """
        pSrc, pDst = argv

        # If destination buffer exists, copy source bytes into it.
        if pSrc and pDst:
            data = emu.mem_read(pSrc, self.mem_string_len(pSrc, 1) + 1)
            emu.mem_write(pDst, data)

        # Return TRUE
        return 1

    @apihook("CharPrevW", argc=2)
    def CharPrevW(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPWSTR CharPrevW(
            LPCWSTR lpszStart,
            LPCWSTR lpszCurrent
        );
        """
        lpszStart, lpszCurrent = argv

        # If current > start, return current - 2 (one WCHAR back)
        try:
            if lpszCurrent and lpszStart and lpszCurrent > lpszStart:
                return lpszCurrent - 2
        except Exception:
            pass

        # Otherwise return start
        return lpszStart
