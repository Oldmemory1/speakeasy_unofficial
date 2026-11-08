"""Read-time code shape for import hook sentinels.

Guest programs sometimes inspect the bytes behind an imported function pointer
before calling it. Speakeasy normally leaves the sentinel page zero-filled
because calls are intercepted from the unmapped page. Returning a canonical
Windows function prologue for data reads preserves that call interception while
avoiding a false anti-hook branch based solely on the zero page.
"""

from __future__ import annotations

from collections.abc import Mapping

from speakeasy.winenv import arch

_X86_PROLOGUE = b"\x8b\xff"  # mov edi, edi
_AMD64_PROLOGUE = b"\x48\x8b\xc4"  # mov rax, rsp


def import_probe_prefix(machine_arch: int) -> bytes:
    """Return a read-only function prologue for the emulated architecture."""
    if machine_arch == arch.ARCH_X86:
        return _X86_PROLOGUE
    if machine_arch == arch.ARCH_AMD64:
        return _AMD64_PROLOGUE
    return b""


def find_import_sentinel(
    import_table: Mapping[int, object],
    address: int,
    size: int,
    pointer_size: int,
) -> int | None:
    """Return an import sentinel overlapped by a guest data read, if any."""
    read_end = address + max(size, 0)
    for sentinel in import_table:
        if sentinel <= address < sentinel + pointer_size:
            return sentinel
        if address < sentinel < read_end:
            return sentinel
    return None


__all__ = ["find_import_sentinel", "import_probe_prefix"]
