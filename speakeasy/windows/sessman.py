# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from speakeasy.windows.objman import HandleAllocator


class GuiObject:
    """
    Base class for all GUI objects
    """

    def __init__(self, allocator: HandleAllocator):
        self.allocator = allocator
        self.handle = self._alloc_handle()

    def _alloc_handle(self):
        return self.allocator.allocate_gui_object_handle()

    def get_handle(self):
        return self.handle


class Session(GuiObject):
    """
    Represents a windows Session
    """

    def __init__(self, allocator: HandleAllocator, sess_id):
        super().__init__(allocator)
        self.id: int = sess_id
        self.stations: dict[int, Station] = {}

    def new_station(self, name="WinSta0"):
        stat = Station(self.allocator, name=name)
        self.stations.update({stat.get_handle(): stat})
        return stat


class Station(GuiObject):
    """
    Represents a window station
    """

    def __init__(self, allocator: HandleAllocator, name=""):
        super().__init__(allocator)
        self.name: str = name
        self.desktops: dict[int, Desktop] = {}

    def new_desktop(self, name=""):
        desk = Desktop(self.allocator, name=name)
        self.desktops.update({desk.get_handle(): desk})
        return desk


class Desktop(GuiObject):
    """
    Represents a Desktop object
    """

    def __init__(self, allocator: HandleAllocator, name=""):
        super().__init__(allocator)
        self.windows: dict[int, Window] = {}
        self.desktop_window: Window = self.new_window()
        self.name: str = name

    def new_window(self):
        window = Window(self.allocator)
        self.windows.update({window.get_handle(): window})
        return window


class Window(GuiObject):
    """
    Represents a GUI window
    """

    def __init__(
        self,
        allocator: HandleAllocator,
        name=None,
        class_name=None,
        class_atom: int | None = None,
        wndproc: int | None = None,
    ):
        super().__init__(allocator)
        self.name: str | None = name
        self.class_name: str | None = class_name
        self.class_atom: int | None = class_atom
        self.wndproc: int | None = wndproc


class WindowClass(GuiObject):
    """
    Represents a GUI window class
    """

    def __init__(self, allocator: HandleAllocator, wclass, name):
        super().__init__(allocator)
        self.wclass: Any = wclass
        self.name: str = name

    @property
    def wndproc(self) -> int | None:
        return int(self.wclass.lpfnWndProc or 0) or None


class SessionManager:
    """
    The session manager for the emulator. This will manage things like desktops,
    windows, and session isolation
    """

    def __init__(self, config, allocator: HandleAllocator):
        super().__init__()
        self.sessions: dict[int, Session] = {}
        self.window_classes: dict[int | str, WindowClass] = {}
        self.windows: dict[int | str, Window] = {}
        self.curr_session: Session | None = None
        self.curr_station: Station | None = None
        self.curr_desktop: Desktop | None = None
        self.config: Any = config
        self.allocator = allocator
        self.dev_ctx: int = allocator.allocate_gui_object_handle()

        # create a session 0
        self.curr_session = Session(allocator, sess_id=0)

        # create WinSta0
        self.curr_station = self.curr_session.new_station(name="WinSta0")

        # Create a desktop
        self.curr_station.new_desktop("Winlogon")
        default = self.curr_station.new_desktop("Default")
        self.curr_station.new_desktop("Disconnect")

        # For now lets default to the Default desktop
        self.curr_desktop = default

    def create_window_class(self, class_obj, class_name=None):
        wc = WindowClass(self.allocator, class_obj, class_name)
        atom = wc.get_handle()
        self.window_classes.update({atom: wc})
        if class_name:
            self.window_classes.update({class_name: wc})
        return atom

    def create_window(
        self,
        window_name=None,
        class_name=None,
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

        window = Window(
            self.allocator,
            window_name,
            resolved_class_name,
            class_atom=class_atom,
            wndproc=wndproc,
        )
        hnd = window.get_handle()
        self.windows.update({hnd: window})
        if window_name:
            self.windows.update({window_name: window})
        return hnd

    def get_window_class(self, atom_or_name):
        return self.window_classes.get(atom_or_name)

    def get_window(self, handle):
        return self.windows.get(handle)

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

        self.windows.pop(window.get_handle(), None)
        for key, value in list(self.windows.items()):
            if value is window:
                self.windows.pop(key, None)
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
        return True

    def get_device_context(self):
        return self.dev_ctx

    def get_current_desktop(self):
        return self.curr_desktop

    def get_current_station(self):
        return self.curr_station

    def get_gui_object(self, handle):
        for hsess, sess in self.sessions.items():
            if hsess == handle:
                return sess
            for hstat, stat in sess.stations.items():
                if hstat == handle:
                    return stat
                for hdesk, desk in stat.desktops.items():
                    if hdesk == handle:
                        return desk
