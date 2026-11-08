from __future__ import annotations

import pytest

from speakeasy import Speakeasy
from speakeasy.errors import SpeakeasyError
from speakeasy.windows.pe_compat import (
    IMAGE_FILE_MACHINE_AMD64,
    IMAGE_FILE_MACHINE_I386,
    InvalidZeroMachineError,
    normalize_zero_machine,
)


def _image_with_zero_machine(image: bytes) -> bytes:
    pe_offset = int.from_bytes(image[0x3C:0x40], "little")
    patched = bytearray(image)
    patched[pe_offset + 4 : pe_offset + 6] = b"\x00\x00"
    return bytes(patched)


@pytest.mark.parametrize(
    ("fixture_name", "expected_machine", "reason"),
    [
        (
            "argv_test_x86.exe.xz",
            IMAGE_FILE_MACHINE_I386,
            "inferred_i386_from_pe32_optional_header",
        ),
        (
            "argv_test_x64.exe.xz",
            IMAGE_FILE_MACHINE_AMD64,
            "inferred_amd64_from_pe32_plus_optional_header",
        ),
    ],
)
def test_zero_machine_is_inferred_from_optional_header(
    load_test_bin,
    fixture_name,
    expected_machine,
    reason,
):
    original = load_test_bin(fixture_name)
    zero_machine_image = _image_with_zero_machine(original)
    result = normalize_zero_machine(zero_machine_image)

    assert result.changed
    assert result.image != zero_machine_image
    assert result.original_machine == 0
    assert result.normalized_machine == expected_machine
    assert result.reason == reason
    assert result.image[0x3C:0x40] == original[0x3C:0x40]


def test_present_machine_is_left_unchanged(load_test_bin):
    original = load_test_bin("argv_test_x86.exe.xz")
    result = normalize_zero_machine(original)

    assert not result.changed
    assert result.image == original
    assert result.diagnostic() is None


def test_zero_machine_with_invalid_optional_header_is_rejected(load_test_bin):
    image = bytearray(_image_with_zero_machine(load_test_bin("argv_test_x86.exe.xz")))
    pe_offset = int.from_bytes(image[0x3C:0x40], "little")
    optional_offset = pe_offset + 24
    image[optional_offset : optional_offset + 2] = b"\x34\x12"

    with pytest.raises(InvalidZeroMachineError, match="optional-header magic"):
        normalize_zero_machine(bytes(image))


def test_speakeasy_loads_zero_machine_without_modifying_disk(
    config,
    load_test_bin,
    tmp_path,
):
    image = _image_with_zero_machine(load_test_bin("argv_test_x86.exe.xz"))
    sample = tmp_path / "machine-zero.exe"
    sample.write_bytes(image)

    emulator = Speakeasy(config=config)
    try:
        module = emulator.load_module(str(sample))
        metadata = module.get_pe_metadata()

        assert metadata is not None
        assert metadata.machine == IMAGE_FILE_MACHINE_I386
        assert emulator.pe_machine_normalization == {
            "original_machine": 0,
            "normalized_machine": IMAGE_FILE_MACHINE_I386,
            "reason": "inferred_i386_from_pe32_optional_header",
        }
        assert sample.read_bytes() == image
    finally:
        emulator.shutdown()


def test_speakeasy_rejects_ambiguous_zero_machine(
    config,
    load_test_bin,
    tmp_path,
):
    image = bytearray(_image_with_zero_machine(load_test_bin("argv_test_x86.exe.xz")))
    pe_offset = int.from_bytes(image[0x3C:0x40], "little")
    optional_offset = pe_offset + 24
    image[optional_offset : optional_offset + 2] = b"\x34\x12"
    sample = tmp_path / "ambiguous.exe"
    sample.write_bytes(image)

    emulator = Speakeasy(config=config)
    try:
        with pytest.raises(SpeakeasyError, match="cannot be normalized"):
            emulator.load_module(str(sample))
    finally:
        emulator.shutdown()


__all__ = []
