# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from speakeasy.windows.handles import HandleTable

if TYPE_CHECKING:
    from speakeasy.windows.objman import HandleAllocator


class GuiObject:
    """Base class for all GUI objects."""

    def __init__(self, handles: HandleTable):
        self.handles: HandleTable = handles
        self.handle: int = handles.new_handle(self)

    def get_handle(self):
        return self.handle


class Session(GuiObject):
    """Represents a Windows session."""

    def __init__(self, handles: HandleTable, windows: dict[int | str, Window], sess_id):
        super().__init__(handles)
        self.windows: dict[int | str, Window] = windows
        self.id: int = sess_id
        self.stations: dict[int, Station] = {}

    def new_station(self, name="WinSta0"):
        stat = Station(self.handles, self.windows, name=name)
        self.stations.update({stat.get_handle(): stat})
        return stat


class Station(GuiObject):
    """Represents a window station."""

    def __init__(self, handles: HandleTable, windows: dict[int | str, Window], name=""):
        super().__init__(handles)
        self.windows: dict[int | str, Window] = windows
        self.name: str = name
        self.desktops: dict[int, Desktop] = {}

    def new_desktop(self, name=""):
        desk = Desktop(self.handles, self.windows, name=name)
        self.desktops.update({desk.get_handle(): desk})
        return desk


class Desktop(GuiObject):
    """
    Represents a desktop.

    The windows of all desktops are in the one window store of the session manager. The desktop
    window is not in the store, because EnumWindows does not give it.
    """

    def __init__(self, handles: HandleTable, windows: dict[int | str, Window], name=""):
        super().__init__(handles)
        self.windows: dict[int | str, Window] = windows
        self.desktop_window: Window = Window(handles)
        self.name: str = name

    def new_window(
        self,
        window_name=None,
        class_name=None,
        style=0,
        parent=0,
        thread_id=0,
        process_id=0,
        *,
        class_atom: int | None = None,
        wndproc: int | None = None,
    ) -> Window:
        window = Window(
            self.handles,
            window_name,
            class_name,
            style,
            parent,
            thread_id,
            process_id,
            class_atom=class_atom,
            wndproc=wndproc,
        )
        self.windows.update({window.get_handle(): window})
        if window_name:
            self.windows.update({window_name: window})
        return window


@dataclass
class ListViewColumn:
    fmt: int
    cx: int
    text: str
    sub_item: int


class Window(GuiObject):
    """Represents a GUI window."""

    def __init__(
        self,
        handles: HandleTable,
        name=None,
        class_name=None,
        style=0,
        parent=0,
        thread_id=0,
        process_id=0,
        *,
        class_atom: int | None = None,
        wndproc: int | None = None,
    ):
        super().__init__(handles)
        self.name: str | None = name
        self.class_name: str | None = class_name
        self.style: int = style
        self.parent: int = parent
        self.thread_id: int = thread_id
        self.process_id: int = process_id
        self.props: dict[int | str, int] = {}
        self.lv_columns: list[ListViewColumn] = []
        self.class_atom: int | None = class_atom
        self.wndproc: int | None = wndproc


class WindowClass(GuiObject):
    """Represents a GUI window class."""

    def __init__(self, handles: HandleTable, wclass, name):
        super().__init__(handles)
        self.wclass: Any = wclass
        self.name: str = name

    @property
    def wndproc(self) -> int | None:
        return int(self.wclass.lpfnWndProc or 0) or None


class SessionManager:
    """
    Keep the sessions, window stations, desktops, windows and window classes of the emulator.

    USER objects, such as windows, desktops and window classes, belong to the session on Windows, not
    to a process, so their handles are in a table of the manager.
    """

    def __init__(self, config, allocator: HandleAllocator):
        super().__init__()
        self.handles: HandleTable = HandleTable(allocator, release=lambda obj: None)
        self.sessions: dict[int, Session] = {}
        self.window_classes: dict[int | str, WindowClass] = {}
        self.windows: dict[int | str, Window] = {}
        self.curr_session: Session | None = None
        self.curr_station: Station | None = None
        self.curr_desktop: Desktop | None = None
        self.config: Any = config
        self.dev_ctx: int = allocator.allocate_handle()

        self.curr_session = Session(self.handles, self.windows, sess_id=0)
        self.curr_station = self.curr_session.new_station(name="WinSta0")
        self.curr_station.new_desktop("Winlogon")
        default = self.curr_station.new_desktop("Default")
        self.curr_station.new_desktop("Disconnect")
        self.curr_desktop = default

    def create_window_class(self, class_obj, class_name=None):
        wc = WindowClass(self.handles, class_obj, class_name)
        atom = wc.get_handle()
        self.window_classes.update({atom: wc})
        if class_name:
            self.window_classes.update({class_name: wc})
        return atom

    def create_window(
        self,
        window_name=None,
        class_name=None,
        style=0,
        parent=0,
        thread_id=0,
        process_id=0,
        *,
        class_atom: int | None = None,
        wndproc: int | None = None,
    ):
        window_class = self.get_window_class(
            class_atom if class_atom is not None else class_name
        )
        resolved_class_name = class_name
        if window_class is not None:
            resolved_class_name = resolved_class_name or window_class.name
            class_atom = window_class.get_handle()
            if wndproc is None:
                wndproc = window_class.wndproc

        desk = self.get_current_desktop()
        return desk.new_window(
            window_name,
            resolved_class_name,
            style,
            parent,
            thread_id,
            process_id,
            class_atom=class_atom,
            wndproc=wndproc,
        ).get_handle()

    def get_window_class(self, atom_or_name):
        return self.window_classes.get(atom_or_name)

    def get_window(self, handle) -> Window | None:
        """Get the window of a window handle, else None."""
        return self.handles.get(handle, Window)

    def get_window_proc(self, handle) -> int | None:
        window = self.get_window(handle)
        if not isinstance(window, Window):
            return None
        if window.wndproc is not None:
            return window.wndproc
        window_class = self.get_window_class(window.class_atom)
        if isinstance(window_class, WindowClass):
            return window_class.wndproc
        return None

    def set_window_proc(self, handle, wndproc: int | None) -> bool:
        window = self.get_window(handle)
        if not isinstance(window, Window):
            return False
        window.wndproc = int(wndproc or 0) or None
        return True

    def destroy_window(self, handle) -> bool:
        window = self.get_window(handle)
        if not isinstance(window, Window):
            return False

        aliases = [key for key, value in self.windows.items() if value is window]
        if not aliases:
            return False
        for key in aliases:
            self.windows.pop(key, None)
        self.handles.close(window.get_handle())
        return True

    def unregister_window_class(self, atom_or_name) -> bool:
        window_class = self.get_window_class(atom_or_name)
        if not isinstance(window_class, WindowClass):
            return False
        class_atom = window_class.get_handle()
        if any(
            isinstance(window, Window) and window.class_atom == class_atom
            for window in set(self.windows.values())
        ):
            return False

        self.window_classes.pop(class_atom, None)
        for key, value in list(self.window_classes.items()):
            if value is window_class:
                self.window_classes.pop(key, None)
        self.handles.close(class_atom)
        return True

    def get_device_context(self):
        return self.dev_ctx

    def get_current_desktop(self):
        return self.curr_desktop

    def get_current_station(self):
        return self.curr_station
