"""Image-level Data Execution Prevention (DEP) policy.

A PE image encodes its DEP/NX compatibility in the Optional Header
``DllCharacteristics`` field:

* ``IMAGE_DLLCHARACTERISTICS_NX_COMPAT`` (0x0100) set: the image is
  NX-compatible, so normal DEP applies.
* The bit clear (notably ``DllCharacteristics == 0``): the image explicitly
  opted out of DEP.

Windows/Wine derive the process execution policy from the loaded image.
Wine's loader calls ``NtSetInformationProcess(ProcessExecuteFlags,
MEM_EXECUTE_OPTION_ENABLE)`` when a module lacks NXCOMPAT
(``dlls/ntdll/loader.c:1585-1591``); with that flag set, ``mprotect_exec``
adds ``PROT_EXEC`` to protections that carry ``PROT_READ``
(``dlls/ntdll/unix/virtual.c:1647-1659``) and new ``VirtualAlloc`` views are
mapped executable (``virtual.c:4940-4966``).  The guest therefore may execute
pages that the Win32 ``PAGE_*`` value alone would keep non-executable.

This module only describes the policy.  The Windows emulator decides where to
apply it; the emulator deliberately relaxes execution only for writable pages,
so read-only image sections (``.rdata``/resources) keep their protections.

The policy is architecture independent: the field sits at the same Optional
Header offset (0x46) in PE32 and PE32+.
"""

from __future__ import annotations

from dataclasses import dataclass

#: ``IMAGE_DLLCHARACTERISTICS_NX_COMPAT`` from winnt.h.
IMAGE_DLLCHARACTERISTICS_NX_COMPAT: int = 0x0100

_DLL_CHARACTERISTICS_MASK: int = 0xFFFF


@dataclass(frozen=True)
class ImageDepPolicy:
    """DEP policy parsed from a PE image's Optional Header.

    Attributes:
        dll_characteristics: Raw 16-bit ``DllCharacteristics`` value.
    """

    dll_characteristics: int

    @property
    def nx_compat(self) -> bool:
        """True when the image sets ``IMAGE_DLLCHARACTERISTICS_NX_COMPAT``."""
        return bool(self.dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)

    @property
    def dep_disabled(self) -> bool:
        """True when the image explicitly opted out of DEP (NXCOMPAT clear)."""
        return not self.nx_compat


def policy_from_dll_characteristics(value: int | None) -> ImageDepPolicy | None:
    """Build an :class:`ImageDepPolicy` from a ``DllCharacteristics`` value.

    Args:
        value: ``OPTIONAL_HEADER.DllCharacteristics`` from a PE image, or
            ``None`` when the image has no PE Optional Header (shellcode,
            synthesized API modules, decoys).

    Returns:
        An :class:`ImageDepPolicy` for a real PE header, or ``None`` when the
        field is unavailable.  ``None`` means "policy unknown" and callers
        must keep the existing DEP-enabled behaviour.

    Unknown inputs: the value is masked to the 16-bit field width; other bits
    are ignored because only NXCOMPAT affects execution permission.
    """
    if value is None:
        return None
    return ImageDepPolicy(dll_characteristics=int(value) & _DLL_CHARACTERISTICS_MASK)


def dep_opt_out(policy: ImageDepPolicy | None) -> bool:
    """Return True only for an explicit image DEP opt-out.

    Args:
        policy: Policy from the process image, or ``None`` when unknown.

    Returns:
        True when the image's NXCOMPAT bit is clear.  ``None`` (unknown
        policy) returns False so non-PE runners keep the current DEP-enabled
        semantics.
    """
    return policy is not None and policy.dep_disabled
