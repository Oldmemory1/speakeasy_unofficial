from __future__ import annotations

from speakeasy.windows.gui_messages import WindowsMessageQueue
from speakeasy.winenv.api.usermode.user32 import User32
from speakeasy.winenv.defs.windows import user32 as user32_defs


class _Thread:
    def __init__(self) -> None:
        self.message_queue = WindowsMessageQueue()


class _Emulator:
    def __init__(self) -> None:
        self.thread = _Thread()

    def get_current_thread(self) -> _Thread:
        return self.thread

    def get_ptr_size(self) -> int:
        return 4


class _MessageUser32(User32):
    def __init__(self) -> None:
        self.timer_count = 0
        self.messages: list[bytes] = []

    def mem_write(self, address: int, data: bytes) -> None:
        assert address == 0x1000
        self.messages.append(bytes(data))

    def emit_synthetic_keyboard_hook_event(self, emu, caller_argv):
        return None


def _native_message(data: bytes):
    msg = user32_defs.MSG(4)
    msg.cast(data)
    return msg


def test_message_queue_preserves_fifo_order():
    queue = WindowsMessageQueue()
    queue.post(0x200, user32_defs.WM_NULL)
    queue.post_quit(7)

    first = queue.pop()
    quit_message = queue.pop()

    assert first is not None
    assert first.message == user32_defs.WM_NULL
    assert quit_message is not None
    assert quit_message.message == user32_defs.WM_QUIT
    assert quit_message.wparam == 7
    assert queue.pop() is None


def test_post_quit_message_is_only_dequeued_once():
    emu = _Emulator()
    handler = _MessageUser32()

    handler.PostQuitMessage(emu, [9], {"func_name": "user32.PostQuitMessage"})
    first_result = handler.GetMessage(
        emu,
        [0x1000, 0, 0, 0],
        {"func_name": "user32.GetMessageA"},
    )
    second_result = handler.GetMessage(
        emu,
        [0x1000, 0, 0, 0],
        {"func_name": "user32.GetMessageA"},
    )

    assert first_result is False
    quit_record = _native_message(handler.messages[0])
    assert quit_record.message == user32_defs.WM_QUIT
    assert quit_record.wParam == 9
    assert second_result is True
    idle_record = _native_message(handler.messages[1])
    assert idle_record.message == user32_defs.WM_NULL


def test_non_quit_message_returns_true():
    emu = _Emulator()
    handler = _MessageUser32()
    emu.thread.message_queue.post(0x200, user32_defs.WM_CREATE, 1, 2)

    result = handler.GetMessage(
        emu,
        [0x1000, 0x200, 0, 0],
        {"func_name": "user32.GetMessageA"},
    )

    assert result is True
    record = _native_message(handler.messages[0])
    assert record.hwnd == 0x200
    assert record.message == user32_defs.WM_CREATE
    assert record.wParam == 1
    assert record.lParam == 2


__all__ = []
