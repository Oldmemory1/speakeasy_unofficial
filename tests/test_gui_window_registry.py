from __future__ import annotations

from types import SimpleNamespace

from speakeasy.profiler import ApiCallbackFrame
from speakeasy.windows.sessman import SessionManager
from speakeasy.winenv.api.usermode.user32 import User32
from speakeasy.winenv.defs.windows import user32 as user32_defs


class _Allocator:
    def __init__(self) -> None:
        self.value = 0x100

    def allocate_gui_object_handle(self) -> int:
        self.value += 4
        return self.value


def _manager() -> SessionManager:
    return SessionManager(config=None, allocator=_Allocator())


def test_window_creation_inherits_registered_wndproc():
    manager = _manager()
    wndproc = 0x401000
    atom = manager.create_window_class(
        SimpleNamespace(lpfnWndProc=wndproc),
        "MainWindow",
    )

    hwnd = manager.create_window("caption", "MainWindow")

    window = manager.get_window(hwnd)
    assert window is not None
    assert window.class_atom == atom
    assert window.class_name == "MainWindow"
    assert manager.get_window_proc(hwnd) == wndproc


def test_window_proc_override_and_destruction_are_explicit():
    manager = _manager()
    atom = manager.create_window_class(
        SimpleNamespace(lpfnWndProc=0x401000),
        "MainWindow",
    )
    hwnd = manager.create_window(class_atom=atom)

    assert manager.set_window_proc(hwnd, 0x402000)
    assert manager.get_window_proc(hwnd) == 0x402000
    assert not manager.unregister_window_class(atom)
    assert manager.destroy_window(hwnd)
    assert manager.get_window(hwnd) is None
    assert manager.unregister_window_class(atom)


class _RecordingUser32(User32):
    def __init__(self, manager: SessionManager) -> None:
        self.sessman = manager
        self.callback = None

    def setup_callback(
        self,
        func,
        args,
        caller_argv=None,
        *,
        return_value=None,
        complete=None,
    ):
        self.callback = {
            "func": func,
            "args": args,
            "caller_argv": tuple(caller_argv or ()),
            "return_value": return_value,
            "complete": complete,
        }


def test_create_window_dispatches_wm_create_with_window_identity():
    manager = _manager()
    atom = manager.create_window_class(
        SimpleNamespace(lpfnWndProc=0x401000),
        "MainWindow",
    )
    handler = _RecordingUser32(manager)
    argv = [0, atom, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xABCD]

    hwnd = handler.CreateWindowEx(
        None,
        argv,
        {"func_name": "user32.CreateWindowExA"},
    )

    assert hwnd != 0
    assert handler.callback is not None
    assert handler.callback["func"] == 0x401000
    assert handler.callback["args"] == (
        hwnd,
        user32_defs.WM_CREATE,
        0,
        0xABCD,
    )
    assert handler.callback["complete"](0) == hwnd
    assert manager.get_window_proc(hwnd) == 0x401000


def test_wm_create_failure_destroys_window_and_returns_null():
    manager = _manager()
    atom = manager.create_window_class(
        SimpleNamespace(lpfnWndProc=0x401000),
        "MainWindow",
    )
    handler = _RecordingUser32(manager)
    hwnd = handler.CreateWindowEx(
        None,
        [0, atom, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        {"func_name": "user32.CreateWindowExA"},
    )

    assert handler.callback["complete"](0xFFFFFFFF) == 0
    assert manager.get_window(hwnd) is None


def test_send_message_dispatches_window_proc_and_preserves_lresult():
    manager = _manager()
    atom = manager.create_window_class(
        SimpleNamespace(lpfnWndProc=0x401000),
        "MainWindow",
    )
    hwnd = manager.create_window(class_atom=atom)
    handler = _RecordingUser32(manager)

    result = handler.SendMessage(
        None,
        [hwnd, 0x0111, 0x37, 0x1234],
        {"func_name": "user32.SendMessageA"},
    )

    assert result == 0
    assert handler.callback is not None
    assert handler.callback["func"] == 0x401000
    assert handler.callback["args"] == (hwnd, 0x0111, 0x37, 0x1234)
    assert handler.callback["complete"](0xCAFE) == 0xCAFE


def test_send_message_without_window_proc_returns_zero():
    manager = _manager()
    handler = _RecordingUser32(manager)

    result = handler.SendMessage(
        None,
        [0xDEAD, 0x0111, 0, 0],
        {"func_name": "user32.SendMessageA"},
    )

    assert result == 0
    assert handler.callback is None


def test_callback_frame_preserves_explicit_api_return_value():
    frame = ApiCallbackFrame(
        ret_addr=0x401234,
        function=0x401000,
        cleanup_argc=12,
        caller_argv=(),
        return_value=0x1234,
    )

    assert frame.resolve_api_return(0) == 0x1234


__all__ = []
