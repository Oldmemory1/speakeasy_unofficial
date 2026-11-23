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
apply it; the emulator deliberately relaxes execution only for writable pages
(``VirtualAlloc`` views and writable image sections), so read-only image
sections (``.rdata``/resources) keep their protections.

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


def image_page_exec_allowed(
    policy: ImageDepPolicy | None,
    *,
    is_image_page: bool,
    page_readable: bool,
    page_writable: bool,
) -> bool:
    """Return True when the image DEP opt-out relaxes an image-page fetch.

    Wine disables no-exec enforcement for a process whose image lacks
    NXCOMPAT (``dlls/ntdll/loader.c:1585-1591``) and ``mprotect_exec`` then
    adds ``PROT_EXEC`` to readable views
    (``dlls/ntdll/unix/virtual.c:1647-1659``).  The emulator applies that
    relaxation only to writable image pages, the class packed samples decrypt
    code into: a ``PAGE_WRITECOPY`` image page that carries read and write
    permission may be executed.  Read-only image sections (``.rdata``,
    resources), no-access pages and non-image mappings keep their protections.

    Args:
        policy: DEP policy of the process image, or ``None`` when unknown.
        is_image_page: True when the faulting page belongs to a PE image view.
        page_readable: True when the page's effective permissions carry read.
        page_writable: True when the page's effective permissions carry write.

    Returns:
        True only for an explicit DEP opt-out (NXCOMPAT clear) on a readable,
        writable image page.  A ``None`` policy (unknown header) and every
        other page class return False, so DEP-enabled semantics are preserved.

    Architecture: independent of PE32/PE32+; the NXCOMPAT bit sits at the same
    Optional Header offset in both formats.
    """
    if not dep_opt_out(policy):
        return False
    return bool(is_image_page and page_readable and page_writable)
