"""Compatibility handling for structurally valid PE files with missing metadata."""

from __future__ import annotations

from dataclasses import dataclass

IMAGE_DOS_SIGNATURE = b"MZ"
IMAGE_NT_SIGNATURE = b"PE\x00\x00"
IMAGE_FILE_MACHINE_I386 = 0x14C
IMAGE_FILE_MACHINE_AMD64 = 0x8664

_PE_SIGNATURE_OFFSET = 0x3C
_COFF_HEADER_SIZE = 20
_OPTIONAL_HEADER_OFFSET_FROM_SIGNATURE = 4 + _COFF_HEADER_SIZE
_MACHINE_OFFSET_FROM_SIGNATURE = 4
_OPTIONAL_MAGIC_PE32 = 0x10B
_OPTIONAL_MAGIC_PE32_PLUS = 0x20B


class InvalidZeroMachineError(ValueError):
    """Raised when Machine=0 cannot be safely resolved from the optional header."""


@dataclass(frozen=True)
class PeMachineNormalization:
    """Result of the narrow Machine=0 compatibility normalization."""

    image: bytes
    original_machine: int | None
    normalized_machine: int | None
    reason: str

    @property
    def changed(self) -> bool:
        return self.normalized_machine is not None

    def diagnostic(self) -> dict[str, int | str] | None:
        if self.original_machine != 0:
            return None
        return {
            "original_machine": self.original_machine,
            "normalized_machine": self.normalized_machine,
            "reason": self.reason,
        }


def normalize_zero_machine(data: bytes) -> PeMachineNormalization:
    """Restore a zero COFF Machine field from an otherwise valid optional header.

    The normalization is deliberately narrow: it only changes a zero Machine
    field when the PE signature, COFF layout, and PE32/PE32+ optional-header
    magic are all structurally valid. The original bytes are never written back
    to disk.

    Args:
        data: Raw PE image.

    Returns:
        The possibly patched image and provenance metadata.

    Raises:
        InvalidZeroMachineError: Machine is zero but the image cannot be
            unambiguously classified as PE32 x86 or PE32+ x64.
    """
    image = bytes(data)
    if len(image) < _PE_SIGNATURE_OFFSET + 4 or image[:2] != IMAGE_DOS_SIGNATURE:
        return PeMachineNormalization(image, None, None, "not_a_pe_image")

    pe_offset = int.from_bytes(
        image[_PE_SIGNATURE_OFFSET : _PE_SIGNATURE_OFFSET + 4],
        "little",
    )
    machine_offset = pe_offset + _MACHINE_OFFSET_FROM_SIGNATURE
    if len(image) < machine_offset + 2:
        return PeMachineNormalization(image, None, None, "truncated_coff_header")
    if image[pe_offset : pe_offset + 4] != IMAGE_NT_SIGNATURE:
        return PeMachineNormalization(image, None, None, "invalid_pe_signature")

    original_machine = int.from_bytes(
        image[machine_offset : machine_offset + 2],
        "little",
    )
    if original_machine != 0:
        return PeMachineNormalization(
            image,
            original_machine,
            None,
            "machine_already_present",
        )

    section_count_offset = pe_offset + 4 + 2
    optional_size_offset = pe_offset + 4 + 16
    optional_offset = pe_offset + _OPTIONAL_HEADER_OFFSET_FROM_SIGNATURE
    if len(image) < optional_offset + 2 or section_count_offset + 2 > len(image):
        raise InvalidZeroMachineError("truncated PE header")

    section_count = int.from_bytes(
        image[section_count_offset : section_count_offset + 2],
        "little",
    )
    optional_size = int.from_bytes(
        image[optional_size_offset : optional_size_offset + 2],
        "little",
    )
    if section_count == 0 or optional_size < 2:
        raise InvalidZeroMachineError(
            "zero Machine field lacks a usable COFF/optional header"
        )
    if optional_offset + optional_size > len(image):
        raise InvalidZeroMachineError("optional header extends beyond image")

    optional_magic = int.from_bytes(
        image[optional_offset : optional_offset + 2],
        "little",
    )
    if optional_magic == _OPTIONAL_MAGIC_PE32:
        normalized_machine = IMAGE_FILE_MACHINE_I386
        reason = "inferred_i386_from_pe32_optional_header"
    elif optional_magic == _OPTIONAL_MAGIC_PE32_PLUS:
        normalized_machine = IMAGE_FILE_MACHINE_AMD64
        reason = "inferred_amd64_from_pe32_plus_optional_header"
    else:
        raise InvalidZeroMachineError(
            f"unsupported optional-header magic: 0x{optional_magic:x}"
        )

    patched = bytearray(image)
    patched[machine_offset : machine_offset + 2] = (
        normalized_machine.to_bytes(2, "little")
    )
    return PeMachineNormalization(
        bytes(patched),
        original_machine,
        normalized_machine,
        reason,
    )


__all__ = [
    "IMAGE_FILE_MACHINE_AMD64",
    "IMAGE_FILE_MACHINE_I386",
    "InvalidZeroMachineError",
    "PeMachineNormalization",
    "normalize_zero_machine",
]
