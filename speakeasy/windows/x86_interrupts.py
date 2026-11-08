"""Semantic helpers for x86 software interrupt instructions."""

from __future__ import annotations

from enum import Enum

X86_EFLAGS_OVERFLOW = 0x00000800
X86_INTO_OPCODE = 0xCE


class OverflowTrapKind(str, Enum):
    """How an overflow-vector interrupt should be interpreted."""

    INTO_TAKEN = "into_taken"
    INTO_NOT_TAKEN = "into_not_taken"
    EXPLICIT_INT4 = "explicit_int4"
    UNKNOWN = "unknown"


def classify_overflow_trap(
    opcode_prefix: bytes,
    *,
    eflags: int,
) -> OverflowTrapKind:
    """Classify the instruction that raised interrupt vector 4.

    Args:
        opcode_prefix: Bytes beginning at the trapping instruction.
        eflags: x86 EFLAGS value captured by the interrupt hook.

    Returns:
        ``INTO_TAKEN`` or ``INTO_NOT_TAKEN`` for opcode ``0xCE``,
        ``EXPLICIT_INT4`` for ``CD 04``, and ``UNKNOWN`` otherwise.

    Side effects:
        None.
    """

    if opcode_prefix.startswith(b"\xCE"):
        if eflags & X86_EFLAGS_OVERFLOW:
            return OverflowTrapKind.INTO_TAKEN
        return OverflowTrapKind.INTO_NOT_TAKEN
    if opcode_prefix.startswith(b"\xCD\x04"):
        return OverflowTrapKind.EXPLICIT_INT4
    return OverflowTrapKind.UNKNOWN


__all__ = [
    "OverflowTrapKind",
    "X86_EFLAGS_OVERFLOW",
    "X86_INTO_OPCODE",
    "classify_overflow_trap",
]
