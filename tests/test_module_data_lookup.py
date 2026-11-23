from __future__ import annotations

from speakeasy.windows.win32 import Win32Emulator


class _EmuFile:
    """File double with the ``File.get_contents()`` contract.

    v2.1.0 resolves module data through ``FileManager.get_file_by_path()`` and
    reads it with ``File.get_contents()``, which keeps the guest file pointer.
    """

    def __init__(self, data: object | None) -> None:
        self.data = data

    def get_contents(self):
        if self.data is None:
            return None
        return self.data.getvalue()


class _FileManagerStub:
    """Minimal file manager: one emulated file, no host filesystem access."""

    def __init__(self, data: object | None) -> None:
        self.data = data

    def get_file_from_path(self, _path: str):
        return _EmuFile(self.data)

    def get_file_by_path(self, path: str):
        # Mirror FileManager.get_file_by_path: resolve the emulated file by path.
        return self.get_file_from_path(path)


class ModuleDataHarness(Win32Emulator):
    """Expose module-data lookup with an explicit file-manager stub."""

    def __init__(self, data: object | None) -> None:
        """Create a file manager returning one emulated file."""

        self.fileman = _FileManagerStub(data)

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
