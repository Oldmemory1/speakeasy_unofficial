from __future__ import annotations

from types import SimpleNamespace

import pytest

from speakeasy.profiler import ApiCallbackFrame
from speakeasy.windows.sessman import SessionManager
from speakeasy.winenv.api.usermode.user32 import User32
from speakeasy.winenv.defs.windows import user32 as user32_defs


class _Allocator:
    """Minimal C4 shared handle allocator used by ``SessionManager``/``HandleTable``.

    v2.1.0 routed GUI handles through the one emulator-wide allocator; the old
    ``allocate_gui_object_handle`` stub method no longer exists. Mirror
    ``HandleAllocator``'s interface and its 4-byte handle stride.
    """

    def __init__(self) -> None:
        self.value = 0x100

    def allocate_handle(self) -> int:
        self.value += 4
        return self.value

    def free_handle(self, handle: int) -> None:
        # The shared allocator does not reuse closed handles.
        return None


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
        self.ptr_size = 4
        self.callback = None
        self.message = None

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

    def mem_cast(self, msg, address):
        assert address == 0x5000
        return self.message


class _CreateWindowEmu:
    """Minimal emulator double for the CreateWindowEx generator handler.

    v2.1.0 ``CreateWindowEx`` yields ``GuestCall`` objects for WM_NCCREATE and
    WM_CREATE instead of calling ``setup_callback``; the handler only needs the
    guest stack for the CREATESTRUCT alloca and the pointer size.
    """

    def __init__(self) -> None:
        frame = SimpleNamespace(stack_pointer=0x8000, handler=SimpleNamespace(scratch=0))
        self.run = SimpleNamespace(guest_callbacks=[frame])
        self.writes: list[tuple[int, bytes]] = []

    def get_ptr_size(self) -> int:
        return 4

    def get_current_thread(self):
        return None

    def get_current_process(self):
        return None

    def get_current_run(self):
        return self.run

    def mem_write(self, address: int, data: bytes) -> None:
        self.writes.append((address, bytes(data)))


def _start_create_window(handler, argv):
    """Drive CreateWindowEx up to its first yield: the WM_NCCREATE guest call."""
    emu = _CreateWindowEmu()
    generator = handler.CreateWindowEx(emu, argv, {"func_name": "user32.CreateWindowExA"})
    first = next(generator)
    return generator, first, emu


def test_create_window_dispatches_wm_create_with_window_identity():
    manager = _manager()
    atom = manager.create_window_class(
        SimpleNamespace(lpfnWndProc=0x401000),
        "MainWindow",
    )
    handler = _RecordingUser32(manager)
    argv = [0, atom, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xABCD]

    generator, first, emu = _start_create_window(handler, argv)
    assert first.function == 0x401000
    hwnd, message, _, lparam = first.args
    assert message == user32_defs.WM_NCCREATE
    assert hwnd != 0

    second = generator.send(1)  # WM_NCCREATE returns TRUE
    assert second.function == 0x401000
    assert second.args == (hwnd, user32_defs.WM_CREATE, 0, lparam)
    # Both messages carry one CREATESTRUCT of the arguments; lpCreateParams is
    # the last CreateWindowEx argument (0xABCD).
    assert len(emu.writes) == 1 and emu.writes[0][0] == lparam
    assert int.from_bytes(emu.writes[0][1][:4], "little") == 0xABCD

    with pytest.raises(StopIteration) as done:
        generator.send(0)  # WM_CREATE returns 0: the window is made
    assert done.value.value == hwnd
    assert manager.get_window_proc(hwnd) == 0x401000


def test_wm_create_failure_destroys_window_and_returns_null():
    manager = _manager()
    atom = manager.create_window_class(
        SimpleNamespace(lpfnWndProc=0x401000),
        "MainWindow",
    )
    handler = _RecordingUser32(manager)
    generator, first, _ = _start_create_window(handler, [0, atom, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    hwnd = first.args[0]

    generator.send(1)  # WM_NCCREATE returns TRUE
    with pytest.raises(StopIteration) as done:
        generator.send(0xFFFFFFFF)  # WM_CREATE returns -1
    assert done.value.value == 0
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


def test_dispatch_message_calls_bound_window_proc_and_preserves_lresult():
    manager = _manager()
    atom = manager.create_window_class(
        SimpleNamespace(lpfnWndProc=0x401000),
        "MainWindow",
    )
    hwnd = manager.create_window(class_atom=atom)
    handler = _RecordingUser32(manager)
    handler.message = SimpleNamespace(
        hwnd=hwnd,
        message=0x0111,
        wParam=0x37,
        lParam=0x1234,
    )

    emu = SimpleNamespace(get_ptr_size=lambda: 4)
    result = handler.DispatchMessage(
        emu,
        [0x5000],
        {"func_name": "user32.DispatchMessageA"},
    )

    assert result == 0
    assert handler.callback is not None
    assert handler.callback["func"] == 0x401000
    assert handler.callback["args"] == (
        hwnd,
        0x0111,
        0x37,
        0x1234,
    )
    assert handler.callback["caller_argv"] == (0x5000,)
    assert handler.callback["complete"](0xCAFE) == 0xCAFE


def test_dispatch_message_without_window_returns_zero():
    manager = _manager()
    handler = _RecordingUser32(manager)
    handler.message = SimpleNamespace(
        hwnd=0xDEAD,
        message=0x0111,
        wParam=0,
        lParam=0,
    )

    emu = SimpleNamespace(get_ptr_size=lambda: 4)
    result = handler.DispatchMessage(
        emu,
        [0x5000],
        {"func_name": "user32.DispatchMessageA"},
    )

    assert result == 0
    assert handler.callback is None


def test_dispatch_message_without_message_pointer_returns_zero():
    manager = _manager()
    handler = _RecordingUser32(manager)

    result = handler.DispatchMessage(
        SimpleNamespace(get_ptr_size=lambda: 4),
        [0],
        {"func_name": "user32.DispatchMessageA"},
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
