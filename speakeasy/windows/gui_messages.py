"""Thread-local Win32 GUI message queue primitives."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any

from speakeasy.winenv.defs.windows import user32 as user32_defs


@dataclass(frozen=True)
class QueuedWindowMessage:
    """One message waiting in an emulated thread's GUI queue."""

    hwnd: int = 0
    message: int = user32_defs.WM_NULL
    wparam: int = 0
    lparam: int = 0
    time: int = 0
    point_x: int = 0
    point_y: int = 0
    private: int = 0

    @classmethod
    def from_native(cls, msg: Any) -> QueuedWindowMessage:
        return cls(
            hwnd=int(msg.hwnd or 0),
            message=int(msg.message or 0),
            wparam=int(msg.wParam or 0),
            lparam=int(msg.lParam or 0),
            time=int(msg.time or 0),
            point_x=int(msg.pt_x or 0),
            point_y=int(msg.pt_y or 0),
            private=int(msg.lPrivate or 0),
        )

    def to_native(self, ptr_size: int) -> Any:
        msg = user32_defs.MSG(ptr_size)
        msg.hwnd = self.hwnd
        msg.message = self.message
        msg.wParam = self.wparam
        msg.lParam = self.lparam
        msg.time = self.time
        msg.pt_x = self.point_x
        msg.pt_y = self.point_y
        msg.lPrivate = self.private
        return msg


class WindowsMessageQueue:
    """FIFO queue for messages delivered to one emulated Windows thread."""

    def __init__(self) -> None:
        self._messages: deque[QueuedWindowMessage] = deque()

    def __len__(self) -> int:
        return len(self._messages)

    def append(self, msg: Any) -> None:
        """Append a native MSG structure or an explicit queued message."""
        if isinstance(msg, QueuedWindowMessage):
            queued = msg
        else:
            queued = QueuedWindowMessage.from_native(msg)
        self._messages.append(queued)

    def post(
        self,
        hwnd: int,
        message: int,
        wparam: int = 0,
        lparam: int = 0,
    ) -> QueuedWindowMessage:
        queued = QueuedWindowMessage(
            hwnd=int(hwnd or 0),
            message=int(message),
            wparam=int(wparam or 0),
            lparam=int(lparam or 0),
        )
        self._messages.append(queued)
        return queued

    def post_quit(self, exit_code: int) -> QueuedWindowMessage:
        """Post WM_QUIT with the documented thread-queue semantics."""
        return self.post(
            hwnd=0,
            message=user32_defs.WM_QUIT,
            wparam=int(exit_code or 0),
        )

    def peek(self) -> QueuedWindowMessage | None:
        return self._messages[0] if self._messages else None

    def pop(
        self,
        *,
        hwnd: int = 0,
        message_min: int = 0,
        message_max: int = 0,
    ) -> QueuedWindowMessage | None:
        """Remove and return the first message matching GetMessage filters."""
        if not self._messages:
            return None

        for index, queued in enumerate(self._messages):
            if queued.message == user32_defs.WM_QUIT:
                break
            if hwnd and queued.hwnd != hwnd:
                continue
            if message_min and queued.message < message_min:
                continue
            if message_max and queued.message > message_max:
                continue
            break
        else:
            return None

        if index == 0:
            return self._messages.popleft()
        del self._messages[index]
        return queued
