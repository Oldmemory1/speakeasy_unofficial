"""Synthesis of known-but-unmodelled Windows system DLLs (FX-014).

Speakeasy models many system DLLs with API handlers (``kernel32``, ``mpr``,
``version``, ...) and loads the configured user-module inventory at startup.
A Windows/Wine host also ships DLLs that are not modelled at all (``msjava``,
``sechost``, ...).  ``LoadLibrary`` used to return NULL for those names even
though the host can load them; packers and installers treat that NULL as a
hostile or incomplete environment and abort.

This module builds a deterministic decoy module image -- a small PE with a
real export table -- for names explicitly listed in
``modules.synthesized_system_modules``.  The list is engine configuration, not
sample data: matching never depends on a sample name, hash or address.  Names
outside the list are not synthesized and callers keep returning NULL for them,
matching Windows semantics for genuinely unknown DLLs.

The decoy has no API handlers.  ``GetProcAddress`` on it resolves through the
engine's existing non-EXE sentinel path, so this module does not change export
semantics (that work belongs to FX-013).
"""

from __future__ import annotations

import fnmatch
import ntpath
import os
from collections.abc import Iterable, Sequence

import speakeasy.common as common
from speakeasy.windows.common import EXPORTED_FUNCTION, JitPeFile
from speakeasy.windows.loaders import (
    ExportEntry,
    LoadedImage,
    MemoryRegion,
    PeMetadata,
    SectionEntry,
    perms_from_section_chars,
)


def module_basename(name: str) -> str:
    """Return the lowercase DLL stem for a module name or path.

    ``"C:\\Windows\\system32\\MSJAVA.DLL" -> "msjava"``.  An empty or
    separator-only name yields an empty string and never matches a pattern.
    """
    if not name:
        return ""
    stem, _ = os.path.splitext(ntpath.basename(name))
    return stem.lower()


def is_synthesizable_system_module(name: str, patterns: Iterable[str]) -> bool:
    """Return True when *name* matches a configured known-system-module pattern.

    Matching is case-insensitive fnmatch against the DLL stem, e.g. ``"msvcr*"``
    matches ``msvcr71.dll``.  Unknown names return False; callers must keep
    returning NULL for them instead of fabricating a module.
    """
    base = module_basename(name)
    if not base:
        return False
    return any(fnmatch.fnmatchcase(base, str(pattern).lower()) for pattern in patterns)


def default_decoy_exports(name: str) -> tuple[str, ...]:
    """Return the synthetic export names for a decoy module.

    A decoy must be a structurally valid DLL, which requires an export table.
    The single export is named after the DLL stem; it is a structural
    placeholder, not an impersonated real API.  Callers that need a different
    export set can pass ``export_names`` to :class:`SystemModuleDecoyLoader`.
    """
    base = module_basename(name)
    return (base,) if base else ()


class SystemModuleDecoyLoader:
    """Build a decoy PE with an export table for a configured system module.

    Parameters:
        name: Module stem as it should appear in the module table (``msjava``).
        arch: Emulated architecture (``speakeasy.winenv.arch`` value).
        base: Requested image base; the caller may rebuild at a free base.
        emu_path: Guest-visible module path (``C:\\Windows\\system32\\msjava.dll``).
        export_names: Optional explicit export names; defaults to
            :func:`default_decoy_exports`.

    The produced :class:`LoadedImage` is a non-EXE module with one memory
    region, an export directory, and ``visible_in_peb=True`` so
    ``GetModuleHandle``/PEB walkers see it after a successful load.

    Raises:
        ValueError: if *arch* is not a supported x86/x86-64 emulation target.
    """

    def __init__(
        self,
        *,
        name: str,
        arch: int,
        base: int,
        emu_path: str,
        export_names: Sequence[str] | None = None,
    ) -> None:
        if arch not in EXPORTED_FUNCTION:
            raise ValueError(f"unsupported architecture for system module decoy: {arch}")
        self._name = name
        self._arch = arch
        self._base = base
        self._emu_path = emu_path
        self._export_names = tuple(export_names) if export_names else default_decoy_exports(name)

    def make_image(self) -> LoadedImage:
        jit = JitPeFile(self._arch, base=self._base, mod_name=self._name, exports=list(self._export_names))
        img_data = bytes(jit.basepe.get_memory_mapped_image(max_virtual_address=0xF0000000))
        image_size = jit.basepe.OPTIONAL_HEADER.SizeOfImage

        text_sect = jit.get_section_by_name(jit.basepe, ".text")
        text_va = text_sect.VirtualAddress if text_sect is not None else 0
        stub_size = len(EXPORTED_FUNCTION[self._arch])
        exports = [
            ExportEntry(
                name=export_name,
                address=self._base + text_va + index * stub_size,
                ordinal=index + 1,
                execution_mode="intercepted",
            )
            for index, export_name in enumerate(self._export_names)
        ]

        sections = []
        for sect in jit.basepe.sections:
            sect_name = sect.Name.decode("utf-8", errors="ignore").rstrip("\x00")
            sections.append(
                SectionEntry(
                    name=sect_name,
                    virtual_address=sect.VirtualAddress,
                    virtual_size=sect.Misc_VirtualSize,
                    perms=perms_from_section_chars(sect.Characteristics),
                )
            )

        region = MemoryRegion(
            base=self._base,
            data=img_data,
            name="system_module_decoy",
            perms=common.PERM_MEM_RWX,
        )

        pe_metadata = PeMetadata(
            subsystem=jit.basepe.OPTIONAL_HEADER.Subsystem,
            timestamp=jit.basepe.FILE_HEADER.TimeDateStamp,
            machine=jit.basepe.FILE_HEADER.Machine,
            magic=jit.basepe.OPTIONAL_HEADER.Magic,
        )

        return LoadedImage(
            arch=self._arch,
            module_type="dll",
            name=self._name,
            emu_path=self._emu_path,
            image_base=self._base,
            image_size=image_size,
            regions=[region],
            imports=[],
            exports=exports,
            default_export_mode="intercepted",
            entry_points=[],
            visible_in_peb=True,
            loader=self,
            sections=sections,
            pe_metadata=pe_metadata,
        )


__all__ = [
    "SystemModuleDecoyLoader",
    "default_decoy_exports",
    "is_synthesizable_system_module",
    "module_basename",
]
