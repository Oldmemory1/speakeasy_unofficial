from __future__ import annotations

from types import SimpleNamespace

from speakeasy.windows.win32 import Win32Emulator


class ModuleDataHarness(Win32Emulator):
    """Expose module-data lookup with an explicit file-manager stub."""

    def __init__(self, data: object | None) -> None:
        """Create a file manager returning one emulated file."""

        self.fileman = SimpleNamespace(
            get_file_from_path=lambda _path: SimpleNamespace(data=data)
        )

    def does_file_exist(self, path: str) -> bool:
        """Report the supplied path as present without host filesystem access."""

        return path == r"C:\Windows\CTS.exe"


def test_module_data_lookup_rejects_file_without_backing_bytes() -> None:
    """A writable file with no retained bytes is not a loadable PE."""

    harness = ModuleDataHarness(None)

    assert harness.get_module_data_from_emu_file(r"C:\Windows\CTS.exe") is None


def test_module_data_lookup_returns_snapshot_without_moving_pointer() -> None:
    """BytesIO-backed files retain their current file pointer."""

    from io import BytesIO

    stream = BytesIO(b"MZpayload")
    stream.seek(2)
    harness = ModuleDataHarness(stream)

    assert harness.get_module_data_from_emu_file(r"C:\Windows\CTS.exe") == (
        b"MZpayload"
    )
    assert stream.tell() == 2
