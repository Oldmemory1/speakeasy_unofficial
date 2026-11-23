# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import datetime
import hashlib
import os
from collections import namedtuple
from enum import IntFlag

import pefile

import speakeasy.winenv.arch as _arch
from speakeasy.struct import Enum
from speakeasy.winenv.defs.nt import ddk

# Access bits and flags of the GDT descriptors that the emulator builds for protected mode.
GDT_ACCESS_BITS = Enum()
GDT_ACCESS_BITS.ProtMode32 = 0x4
GDT_ACCESS_BITS.PresentBit = 0x80
GDT_ACCESS_BITS.Ring3 = 0x60
GDT_ACCESS_BITS.Ring0 = 0
GDT_ACCESS_BITS.DataWritable = 0x2
GDT_ACCESS_BITS.CodeReadable = 0x2
GDT_ACCESS_BITS.DirectionConformingBit = 0x4
GDT_ACCESS_BITS.Code = 0x18
GDT_ACCESS_BITS.Data = 0x10

GDT_FLAGS = Enum()
GDT_FLAGS.Ring3 = 0x3
GDT_FLAGS.Ring0 = 0

DEFAULT_LOAD_ADDR = 0x40000

# Local extension: page size used when the decoy PE builder grows SizeOfImage.
PAGE_SIZE = 0x1000

# The machine setup allocates memory from this base, so that the input image can use its preferred base.
# On x86, the container image must fit between this base and TEB_ADDRESS.
MACHINE_BASE = 0x7D000000
# The user mode addresses of the first TEB and the first PEB in 32-bit Windows.
# x64 uses them too, because the GS base comes from a 32-bit GDT descriptor.
TEB_ADDRESS = 0x7FFDE000
PEB_ADDRESS = 0x7FFDF000

EMU_RESERVED = 0xFEEDF000
EMU_RESERVE_SIZE = 0x4000

# Local extension: reserved sub-ranges inside EMU_RESERVED, used by the
# emulator for dynamic import, callback and syscall bookkeeping.
DYM_IMP_RESERVE = EMU_RESERVED + 0x1000
EMU_CALLBACK_RESERVE = DYM_IMP_RESERVE + 0x1000
EMU_SYSCALL_RESERVE = EMU_CALLBACK_RESERVE + 0x1000

EMU_RESERVED_END = EMU_RESERVED + EMU_RESERVE_SIZE
EMU_RETURN_ADDR = EMU_RESERVED
EXIT_RETURN_ADDR = EMU_RETURN_ADDR + 1

# Local extension: sentinels for SEH unwinding, guest callbacks and import hooks.
# ``API_CALLBACK_HANDLER_ADDR`` is the pre-merge local name of upstream's
# ``GUEST_CALLBACK_RETURN_ADDR``; both names are kept because local-only
# modules (guest_call, winenv/api/api, tests) still import the old one.
SEH_RETURN_ADDR = EMU_RETURN_ADDR + 4
GUEST_CALLBACK_RETURN_ADDR = EMU_RETURN_ADDR + 8
API_CALLBACK_HANDLER_ADDR = EMU_RETURN_ADDR + 8
# The pre-merge local file assigned this constant twice (0xFEEDFACE, then
# EMU_RETURN_ADDR + 12); only the final value was ever observable. Define it
# once, with the value the emulator actually used.
IMPORT_HOOK_ADDR = EMU_RETURN_ADDR + 12

# The emulated system booted one day before emulation starts.
START_TICK_COUNT = 24 * 60 * 60 * 1000

FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
FILETIME_UNIX_EPOCH = 116444736000000000

# Common blank DOS header
DOS_HEADER = (
    b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00"
    b"\x00\x00\x00\x00@"
    + (b"\x00" * 35)
    + b"\xb0\x00\x00\x00\x0e\x1f\xba\x0e\x00\xb4\t\xcd!\xb8\x01L\xcd!This program "
    b"cannot be run in DOS mode.\r\r\n$" + (b"\x00" * 39) + b"Rich\xbeL\x1c\x41\x00\x00\x00\x00\x00\x00\x00\x00"
)

# Blank header used for a 32-bit PE header
EMPTY_PE_32 = (
    DOS_HEADER + b"PE\x00\x00L\x01\x00\x00ABCD\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\xe0\x00\x03\x01\x0b\x01\x08\x00\x04\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd0\x01\x00\x00\xd4\x01"
    b"\x00\x00\x00\x00@\x00\x01\x00\x00\x00\x01\x00\x00\x00\x04\x00"
    b"\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\xd4"
    b"\x01\x00\x00\xd0\x01\x00\x00\x00\x00\x00\x00\x02\x00\x00\x04"
    b"\x00\x00\x10\x00\x00\x10\x00\x00\x00\x00\x10\x00\x00\x10\x00"
    b"\x00\x00\x00\x00\x00\x10" + (b"\x00" * 131)
)

# Blank header used for a 64-bit PE header
EMPTY_PE_64 = (
    DOS_HEADER + b"PE\x00\x00d\x86\x00\x00ABCD\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\xf0\x00\x03\x10\x0b\x02\x08\x00\x04\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@"
    b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x06\x00"
    b"\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xb8"
    b"\x01\x00\x00\x00\x00\x00\x00AAAA\x02\x00\x00\x04\x00\x00\x10"
    b"\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x10\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x10" + (b"\x00" * 131)
)

# a 16-byte-aligned code used to implement exported functions in a 32-bit decoy module
X86_EXPORTED_FUNCTION = (
    b"\x8b\xff"  # mov edi, edi
    b"\x55"  # push ebp
    b"\x8b\xec"  # mov ebp, esp
    b"\xb8\x00\x00\x00\x00"  # mov eax, 0
    b"\x8b\xe5"  # mov esp, ebp
    b"\x5d"  # pop ebp
    b"\xc3"  # ret
    b"\xcc"  # int3
    b"\xcc"  # int3
    b"\xcc"  # int3
)

# a 16-byte-aligned code used to implement exported functions in a 64-bit decoy module
X64_EXPORTED_FUNCTION = (
    b"\x48\x89\xff"  # mov rdi, rdi
    b"\x90"  # nop
    b"\x48\xc7\xc0\x00\x00\x00\x00"  # mov rax, 0
    b"\xc3"  # ret
    b"\xcc"  # int3
    b"\xcc"  # int3
    b"\xcc"  # int3
    b"\xcc"  # int3
)

EXPORTED_FUNCTION = {_arch.ARCH_X86: X86_EXPORTED_FUNCTION, _arch.ARCH_AMD64: X64_EXPORTED_FUNCTION}


class ImageSectionCharacteristics(IntFlag):
    IMAGE_SCN_TYPE_NO_PAD = 0x00000008

    IMAGE_SCN_CNT_CODE = 0x00000020
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080

    IMAGE_SCN_LNK_OTHER = 0x00000100
    IMAGE_SCN_LNK_INFO = 0x00000200
    IMAGE_SCN_LNK_REMOVE = 0x00000800
    IMAGE_SCN_LNK_COMDAT = 0x00001000
    IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000

    IMAGE_SCN_GPREL = 0x00008000

    IMAGE_SCN_MEM_PURGEABLE = 0x00020000
    IMAGE_SCN_MEM_16BIT = 0x00020000  # IMAGE_SCN_MEM_PURGEABLE alias
    IMAGE_SCN_MEM_LOCKED = 0x00040000
    IMAGE_SCN_MEM_PRELOAD = 0x00080000

    # Alignment (object files only)
    IMAGE_SCN_ALIGN_1BYTES = 0x00100000
    IMAGE_SCN_ALIGN_2BYTES = 0x00200000
    IMAGE_SCN_ALIGN_4BYTES = 0x00300000
    IMAGE_SCN_ALIGN_8BYTES = 0x00400000
    IMAGE_SCN_ALIGN_16BYTES = 0x00500000
    IMAGE_SCN_ALIGN_32BYTES = 0x00600000
    IMAGE_SCN_ALIGN_64BYTES = 0x00700000
    IMAGE_SCN_ALIGN_128BYTES = 0x00800000
    IMAGE_SCN_ALIGN_256BYTES = 0x00900000
    IMAGE_SCN_ALIGN_512BYTES = 0x00A00000
    IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000
    IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000
    IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000
    IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000

    # Memory flags
    IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
    IMAGE_SCN_MEM_NOT_CACHED = 0x04000000
    IMAGE_SCN_MEM_NOT_PAGED = 0x08000000
    IMAGE_SCN_MEM_SHARED = 0x10000000
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_READ = 0x40000000
    IMAGE_SCN_MEM_WRITE = 0x80000000


def get_filetime(when: datetime.datetime) -> int:
    """Return a time with a time zone as a FILETIME value, in 100 ns units since 1601."""
    return (when - FILETIME_EPOCH) // datetime.timedelta(microseconds=1) * 10


def get_datetime_from_filetime(filetime: int) -> datetime.datetime:
    """Return a FILETIME value as a time in UTC."""
    return FILETIME_EPOCH + datetime.timedelta(microseconds=filetime // 10)


# DLL and API set name prefixes, and the modules that have handlers for their functions.
# ``get_dll_hosts`` uses the first prefix that matches. When the functions of a set are in
# more than one module, the main module is first.
#
# Local behavior folded into the upstream table:
# * ``crtdll`` is a VC4/VC5-era CRT (old MSVCRT); folding it into ``msvcrt``
#   resolves its imports (_XcptFilter, _initterm, malloc, ...) to real handlers.
# * ``api-ms-win-security`` resolves to ``advapi32``, which implements the
#   security API-set functions used by the samples (AllocateAndInitializeSid,
#   GetTokenInformation, EqualSid, FreeSid, CheckTokenMembership).
DLL_HOSTS: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (
        ("api-ms-win-crt", "api-ms-win-core-crt", "vcruntime", "ucrtbased", "ucrtbase", "msvcr", "msvcp", "crtdll"),
        ("msvcrt",),
    ),
    (("winsock", "wsock32"), ("ws2_32",)),
    (("shfolder",), ("shell32",)),
    (("icmp",), ("iphlpapi",)),
    (
        ("ext-ms-win-ntuser", "ext-ms-win-rtcore-ntuser", "api-ms-win-rtcore-ntuser", "api-ms-win-ntuser-"),
        ("user32",),
    ),
    (("ext-ms-win-gdi", "ext-ms-win-rtcore-gdi"), ("gdi32",)),
    (("api-ms-win-eventing", "api-ms-win-service", "api-ms-win-security"), ("advapi32",)),
    (("api-ms-win-shell-", "api-ms-win-core-commandlinetoargv", "ext-ms-win-shell32-"), ("shell32",)),
    (("api-ms-win-shcore-obsolete",), ("shell32", "shlwapi")),
    (("api-ms-win-core-shlwapi",), ("shlwapi",)),
    (("api-ms-win-core-com-l", "ext-ms-win-com-ole32", "ext-ms-win-ole32-"), ("ole32",)),
    (("api-ms-win-core-winrt",), ("combase",)),
    (("api-ms-win-core-string-l2",), ("user32",)),
    (("api-ms-win-mm-",), ("winmm",)),
    (("api-ms-win-core-version",), ("version",)),
    (("api-ms-win-core-processthreads",), ("kernel32", "advapi32")),
    (("api-ms-win-core-libraryloader", "api-ms-win-core-stringansi"), ("kernel32", "user32")),
    (("api-ms-win-core", "api-ms-win-appmodel-"), ("kernel32",)),
    (("ext-ms-win-session-wtsapi32",), ("wtsapi32",)),
    (("ext-ms-win-setupapi-",), ("setupapi",)),
    (("sspicli",), ("secur32",)),
    (("kernelbase",), ("kernelbase", "kernel32")),
    (("ntoskrnl",), ("ntoskrnl", "msvcrt")),
)


def get_dll_hosts(name: str) -> tuple[str, ...]:
    """
    Get the modules that have handlers for the functions of a DLL or API set.

    A DLL that is not in ``DLL_HOSTS`` has its own handlers.
    """
    lower = name.lower()
    for prefixes, hosts in DLL_HOSTS:
        if lower.startswith(prefixes):
            return hosts
    return (name,)


def normalize_dll_name(name: str) -> str:
    """Get the main module that has handlers for a DLL or API set."""
    return get_dll_hosts(name)[0]


class PeParseException(Exception):
    """Local extension: parse failure surfaced by the pre-merge PE loader.

    Local-only callers (``winemu``) still catch this exception alongside
    ``pefile.PEFormatError`` and ``ValueError``, so the name is kept.
    """

    pass


class _PeParser(pefile.PE):
    """A pefile PE with the mapped image and the imports that the loaders read."""

    def __init__(self, path=None, data=None, imp_id=IMPORT_HOOK_ADDR, imp_step=4, emu_path="", fast_load=False):
        # Local extension: an explicit byte buffer must take precedence over a
        # path. pefile otherwise reads the on-disk file and silently discards
        # normalized in-memory headers supplied by the loader.
        parse_path = None if data is not None else path
        super().__init__(name=parse_path, data=data, fast_load=fast_load)

        if self.OPTIONAL_HEADER.ImageBase == 0:
            self.relocate_image(DEFAULT_LOAD_ADDR)
            super().__init__(name=None, data=self.write())

        # Local extension: import-sentinel allocation state (see _patch_imports).
        self.imp_id = imp_id
        self.imp_step = imp_step

        self.file_size: int = 0
        self.base: int = self.OPTIONAL_HEADER.ImageBase
        self.hash: str = self._hash_pe(path=path, data=data)
        self.imports: dict[int, tuple[str, str]] = self._get_pe_imports()
        # Windows rounds SizeOfImage up to SectionAlignment, and a section can end in the rounded part.
        alignment = self.OPTIONAL_HEADER.SectionAlignment or 1
        self.image_size: int = -(-self.OPTIONAL_HEADER.SizeOfImage // alignment) * alignment
        self.mapped_image: bytes = self.get_mapped_image()
        self.ep: int = self.OPTIONAL_HEADER.AddressOfEntryPoint
        self.stack_commit: int = self.OPTIONAL_HEADER.SizeOfStackCommit
        self.path: str = ""
        self.name: str = ""
        if path:
            self.path = os.path.abspath(path)
        self.emu_path: str = emu_path
        self.arch: int = self._get_architecture()
        if self.arch == _arch.ARCH_X86:
            self.ptr_size: int = 4
        else:
            self.ptr_size = 8

        # Local extensions: decoy/synthesized module and import-hook contracts.
        self.exports: list = self._get_pe_exports()
        self.import_table: dict[int, tuple[str, str]] = {}
        self.is_mapped = True
        self.pe_sections = self._get_pe_sections()
        self._patch_imports()

    def get_tls_callbacks(self):
        """
        Get the TLS callbacks for a PE (if any)
        """
        max_tls_callbacks = 100
        callbacks = []
        if hasattr(self, "DIRECTORY_ENTRY_TLS"):
            rva = self.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - self.OPTIONAL_HEADER.ImageBase

            for i in range(max_tls_callbacks):
                ptr = self.get_data(rva + self.ptr_size * i, self.ptr_size)
                ptr = int.from_bytes(ptr, "little")
                if ptr == 0:
                    break
                callbacks.append(ptr)
        return callbacks

    def get_resource_dir_rva(self):
        res_dir_rva = 0
        for dd in self.OPTIONAL_HEADER.DATA_DIRECTORY:
            if dd.name == "IMAGE_DIRECTORY_ENTRY_RESOURCE":
                res_dir_rva = dd.VirtualAddress
                break

        return res_dir_rva

    def _hash_pe(self, path=None, data=None):
        hasher = hashlib.sha256()
        buf = b""
        if path:
            with open(path, "rb") as f:
                buf = f.read()
        elif data:
            buf = data

        hasher.update(buf)
        self.file_size = len(buf)
        return hasher.hexdigest()

    def _get_pe_imports(self):
        pe = self
        imports: dict[int, tuple[str, str]] = {}

        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return imports

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll
            dll = dll.decode("utf-8")
            dll = os.path.splitext(dll)[0]
            for imp in entry.imports:
                if imp.import_by_ordinal:
                    func_name = f"ordinal_{imp.ordinal}"
                    imports.update({imp.address: (dll, func_name)})
                else:
                    func_name = imp.name.decode("utf-8")
                    imports.update({imp.address: (dll, func_name)})
        return imports

    def get_exports(self):
        self.exports = self._get_pe_exports()

        return self.exports

    def _get_pe_exports(self):
        pe = self
        exports: list = []
        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            return exports

        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            entry = namedtuple("export", ["name", "address", "forwarder", "ordinal"])  # type: ignore[name-match]  # legacy: namedtuple name differs from var
            entry.name = exp.name
            entry.address = exp.address + pe.base
            entry.forwarder = exp.forwarder
            entry.ordinal = exp.ordinal
            if entry.name:
                entry.name = entry.name.decode("utf-8")
            exports.append(entry)
        return exports

    def _get_pe_sections(self):
        pe = self
        sections = []
        for section in pe.sections:
            sect = (section.Name, section.VirtualAddress, section.Misc_VirtualSize, section.SizeOfRawData)
            sections.append(sect)
        return sections

    def get_section_by_name(self, name):
        sect = [s for s in self.sections if s.Name.decode("utf-8").strip("\x00") == name]
        if sect:
            return sect[0]

    def _get_architecture(self):
        # 0x010b: PE32, 0x020b: PE32+ (64 bit)
        magic = self.OPTIONAL_HEADER.Magic
        if magic & ddk.PE32_BIT:
            return _arch.ARCH_X86
        if magic & ddk.PE32_PLUS_BIT:
            return _arch.ARCH_AMD64
        raise ValueError(f"Unsupported architecture: 0x{magic:x}")

    def _patch_imports(self):
        """
        Imports are patched with invalid memory addresses. When the API is called
        by the emulated binary, the invalid memory fetch callback will trigger,
        allowing us to handle the Windows API within the emulator
        """
        if not self.imports:
            return

        if not self.mapped_image:
            raise ValueError("PE image has not been mapped yet")

        # Local extension: the pre-merge implementation copied the whole image
        # once per import (O(imports * SizeOfImage), which timed out on large
        # images). One bytearray, written back after the loop, is equivalent.
        tmp = bytearray(self.mapped_image)
        for addr, imp in self.imports.items():
            offset = addr - self.base
            tmp[offset : offset + self.ptr_size] = self.imp_id.to_bytes(self.ptr_size, "little")

            self.import_table.update({self.imp_id: imp})
            self.imp_id += self.imp_step
        self.mapped_image = bytes(tmp)

    def get_export_by_name(self, name):
        for exp in self.get_exports():
            if name == exp.name:
                return exp.address

    def get_raw_data(self):
        return self.get_memory_mapped_image()

    def find_bytes(self, pattern, offset=0):
        return self.get_raw_data().find(pattern, offset)

    def set_bytes(self, offset, pattern):
        self.set_bytes_at_offset(offset, pattern)

    def get_base_name(self):
        fn = os.path.basename(self.path)
        return os.path.splitext(fn)[0]

    def is_decoy(self):
        return False

    def is_driver(self):
        rv = super().is_driver()
        if rv:
            return rv

        system_DLLs = set((b"ntoskrnl.exe", b"hal.dll", b"ndis.sys", b"bootvid.dll", b"kdcom.dll", b"win32k.sys"))

        if hasattr(self, "DIRECTORY_ENTRY_IMPORT"):
            if system_DLLs.intersection([imp.dll.lower() for imp in self.DIRECTORY_ENTRY_IMPORT]):
                return True

        if self.OPTIONAL_HEADER.Subsystem == pefile.SUBSYSTEM_TYPE["IMAGE_SUBSYSTEM_NATIVE"] and self.ep == 0:
            return True

    def is_dotnet(self):
        """Test whether the PE imports a .NET entry point or has a CLR header (data directory 14)."""
        for dll, func in self.imports.values():
            if dll == "mscoree" and func in ["_CorExeMain", "_CorDllMain"]:
                return True
        directories = self.OPTIONAL_HEADER.DATA_DIRECTORY
        return len(directories) > 14 and bool(directories[14].VirtualAddress and directories[14].Size)

    def has_reloc_table(self):
        return len(self.OPTIONAL_HEADER.DATA_DIRECTORY) >= 6 and self.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size > 0

    def get_mapped_image(self) -> bytes:
        """
        Return the image with each section at its virtual address.

        pefile ``get_memory_mapped_image`` leaves out a section whose raw data goes past the end of the
        file. Windows maps the bytes that the file has and fills the rest with zeros, so this method
        keeps the bytes that the file has.

        pefile ``PE.header`` stops at the end of the section table when the raw data of a section starts
        in the header. Windows maps the first SizeOfHeaders bytes of the file, so this method starts the
        image with these bytes.
        """
        data = self.__data__
        alignment = self.OPTIONAL_HEADER.SectionAlignment
        file_alignment = self.OPTIONAL_HEADER.FileAlignment
        mapped = bytearray(data[: self.OPTIONAL_HEADER.SizeOfHeaders])
        for section in self.sections:
            if section.Misc_VirtualSize == 0 and section.SizeOfRawData == 0:
                continue
            offset = self.adjust_PointerToRawData(section.PointerToRawData)
            address = self.adjust_SectionAlignment(section.VirtualAddress, alignment, file_alignment)
            if offset > len(data) or address >= 0xF0000000:
                continue
            if address > len(mapped):
                mapped.extend(bytes(address - len(mapped)))
            else:
                del mapped[address:]
            mapped += section.get_data()
        return bytes(mapped[: self.image_size])

    def rebase(self, to):
        self.relocate_image(to)

        self.base = to
        self.ep = self.OPTIONAL_HEADER.AddressOfEntryPoint

        self.mapped_image = self.get_mapped_image()

        # Local extensions: refresh the parsed views and re-patch the import
        # slots at the new base, as the pre-merge implementation did.
        self.pe_sections = self._get_pe_sections()
        self.imports = self._get_pe_imports()
        self.exports = self._get_pe_exports()
        self._patch_imports()


class JitPeFile:
    """
    Class used to rapidly assemble a decoy PE that will only contain an export table
    so malware can parse it.
    """

    def __init__(self, arch, base=0, *, mod_name="", exports=()):
        if arch == _arch.ARCH_X86:
            husk = EMPTY_PE_32
        else:
            husk = EMPTY_PE_64

        self.arch = arch

        self.basepe = pefile.PE(data=husk, fast_load=True)

        self.basepe.OPTIONAL_HEADER.FileAlignment = 0x200
        self.basepe.OPTIONAL_HEADER.SectionAlignment = 0x1000

        if base > 0:
            self.basepe.OPTIONAL_HEADER.ImageBase = base

        if exports:
            self._build_decoy_pe(mod_name, exports)

    def get_section_by_name(self, pe, name):
        """
        Get a PE section by name
        """
        for sect in pe.sections:
            if sect.Name.decode("utf-8").strip("\x00") == name.strip("\x00"):
                return self.cast_section(sect.get_file_offset())

    def get_raw_pe(self):
        """
        Get the raw data associated with a decoy PE
        """
        return self.basepe.__data__

    def update(self):
        """
        Update the raw data associated with a decoy PE
        """
        self.basepe = pefile.PE(None, self.basepe.write(), fast_load=True)
        self.update_image_size()

    def cast_section(self, offset=None):
        """
        Get a section from a given offset
        """
        if offset is None:
            offset = self.get_current_offset()
            data = pefile.Structure(self.basepe.__IMAGE_SECTION_HEADER_format__).sizeof() * b"\x00"
        else:
            data = self.basepe.get_data(offset, pefile.Structure(self.basepe.__IMAGE_SECTION_HEADER_format__).sizeof())  # noqa

        sect = self.basepe.__unpack_data__(self.basepe.__IMAGE_SECTION_HEADER_format__, data, offset)
        return sect

    def update_image_size(self):
        """
        Update the size of the image within the optional header
        """
        self.basepe.OPTIONAL_HEADER.SizeOfImage = len(self.basepe.get_memory_mapped_image()) + PAGE_SIZE

    def add_section(self, name, chars=0x40000040):
        """
        Add a section to the decoy PE
        """
        new_sect = self.cast_section()
        new_sect.Name = name.encode("utf-8")
        new_sect.Characteristics = chars

        hdr_size = pefile.Structure(self.basepe.__IMAGE_SECTION_HEADER_format__).sizeof()

        self.basepe.OPTIONAL_HEADER.SizeOfHeaders += hdr_size
        self.basepe.OPTIONAL_HEADER.SizeOfImage += hdr_size
        self.basepe.FILE_HEADER.NumberOfSections += 1

        self.update()
        return new_sect

    def get_current_offset(self):
        """
        Get the current offset (or size) of the PE
        """
        return len(self.basepe.__data__)

    def append_data(self, data):
        """
        Append data to the decoy PE
        """
        self.basepe.__data__ += data

    def get_exports_size(self, name, exports_info):
        """
        Get the total size of the export directory
        """
        # Get the total size needed for the new export section
        exp_size = pefile.Structure(self.basepe.__IMAGE_EXPORT_DIRECTORY_format__).sizeof()

        exp_size += len(name) + 1

        for _, exp in exports_info:
            exp_size += len(exp) + 1
            exp_size += 0x4 + 0x4 + 0x4

        return exp_size

    def pad_file(self):
        cur_offset = self.get_current_offset()
        fa = self.basepe.OPTIONAL_HEADER.FileAlignment
        aligned_offset = (cur_offset + fa - 1) & ~(fa - 1)
        padding = b"\x00" * (aligned_offset - cur_offset)
        self.append_data(padding)

    def _build_decoy_pe(self, mod_name, exports):
        text_chars = (
            ImageSectionCharacteristics.IMAGE_SCN_MEM_READ
            | ImageSectionCharacteristics.IMAGE_SCN_MEM_EXECUTE
            | ImageSectionCharacteristics.IMAGE_SCN_CNT_CODE
        )

        edata_chars = (
            ImageSectionCharacteristics.IMAGE_SCN_MEM_READ | ImageSectionCharacteristics.IMAGE_SCN_CNT_INITIALIZED_DATA
        )

        self.add_section(name=".text", chars=int(text_chars))
        self.add_section(name=".edata", chars=int(edata_chars))
        self.pad_file()

        exports_info = self.init_text_section(exports)
        self.pad_file()

        # update header size
        text_sect = self.get_section_by_name(self.basepe, ".text")
        self.basepe.OPTIONAL_HEADER.SizeOfHeaders = text_sect.PointerToRawData

        self.init_export_section(mod_name.encode("utf-8"), exports_info)
        self.update_image_size()
        return self.get_raw_pe()

    def init_export_section(self, name, exports_info):
        """
        Initialize and add the export table to the PE
        """
        exports_size = self.get_exports_size(name, exports_info)

        dest_exp_sect = self.get_section_by_name(self.basepe, ".edata")

        cur_offset = self.get_current_offset()
        sa = self.basepe.OPTIONAL_HEADER.SectionAlignment
        text_sect = self.get_section_by_name(self.basepe, ".text")
        text_aligned_size = (text_sect.Misc_VirtualSize + sa - 1) & ~(sa - 1)
        sec_rva = text_sect.VirtualAddress + text_aligned_size

        dest_exp_sect.Misc_VirtualSize = exports_size
        dest_exp_sect.Misc_PhysicalAddress = 0
        dest_exp_sect.VirtualAddress = sec_rva
        dest_exp_sect.SizeOfRawData = exports_size
        dest_exp_sect.PointerToRawData = cur_offset

        self.basepe.OPTIONAL_HEADER.SizeOfInitializedData += exports_size

        export_dir = self.basepe.OPTIONAL_HEADER.DATA_DIRECTORY[0]

        export_dir.VirtualAddress = dest_exp_sect.VirtualAddress
        export_dir.Size = exports_size

        offset = self.get_current_offset()
        rva = sec_rva
        self.append_data(b"\x00" * exports_size)

        dest_export_dir = self.basepe.__unpack_data__(
            self.basepe.__IMAGE_EXPORT_DIRECTORY_format__,  # noqa
            pefile.Structure(self.basepe.__IMAGE_EXPORT_DIRECTORY_format__).sizeof() * b"\x00",  # noqa
            offset,
        )
        offset += pefile.Structure(self.basepe.__IMAGE_EXPORT_DIRECTORY_format__).sizeof()
        rva += pefile.Structure(self.basepe.__IMAGE_EXPORT_DIRECTORY_format__).sizeof()

        dest_export_dir.Characteristics = 0
        dest_export_dir.TimeDateStamp = 0xD1234567
        dest_export_dir.MajorVersion = 0
        dest_export_dir.MinorVersion = 0
        dest_export_dir.Base = 1
        dest_export_dir.NumberOfFunctions = len(exports_info)
        dest_export_dir.NumberOfNames = len(exports_info)

        # Set the address of functions array
        num_funcs = dest_export_dir.NumberOfFunctions
        funcs_rva = rva
        names_rva = funcs_rva + (4 * num_funcs)
        ord_rva = names_rva + (4 * num_funcs)
        strings_rva = ord_rva + (2 * num_funcs)

        dest_export_dir.Name = strings_rva
        dest_export_dir.AddressOfFunctions = funcs_rva
        dest_export_dir.AddressOfNames = names_rva
        dest_export_dir.AddressOfNameOrdinals = ord_rva
        self.update()

        # Set the export name
        self.basepe.set_bytes_at_rva(strings_rva, name)
        strings_rva += len(name) + 1

        for i, (rva, exp) in enumerate(exports_info):
            exp = exp.encode("utf-8")

            # Add fluff to pass forwarded export checks
            self.append_data(b"\x00" * len(exports_info))

            # Add the function addresses
            self.basepe.set_dword_at_rva(funcs_rva, rva)
            funcs_rva += 4
            if funcs_rva > sec_rva + exports_size:
                raise Exception("Functions offset exceeds total PE size")

            # Add the ordinals
            self.basepe.set_word_at_rva(ord_rva, (i + 1) - dest_export_dir.Base)
            ord_rva += 2
            if ord_rva > sec_rva + exports_size:
                raise Exception("Ordinals offset exceeds total PE size")

            # Add the function names in
            if strings_rva > sec_rva + exports_size:
                raise Exception("Export string offset exceeds total PE size")
            self.basepe.set_dword_at_rva(names_rva, strings_rva)
            names_rva += 4
            self.basepe.set_bytes_at_rva(strings_rva, exp)
            strings_rva += len(exp) + 1

        if strings_rva:
            strings_offset = self.basepe.get_offset_from_rva(strings_rva)
            self.basepe.__data__ = self.basepe.__data__[:strings_offset]
            edata = self.get_section_by_name(self.basepe, ".edata")
            actual_size = strings_offset - edata.PointerToRawData
            edata.Misc_VirtualSize = actual_size
            edata.SizeOfRawData = actual_size
        self.update()

    def init_text_section(self, names):
        """
        Initialize and add the text section to the PE
        """
        pattern = b""
        exports_info = list()

        sect = self.get_section_by_name(self.basepe, ".text")
        cur_offset = self.get_current_offset()
        sa = self.basepe.OPTIONAL_HEADER.SectionAlignment
        sec_rva = (cur_offset + sa - 1) & ~(sa - 1)

        # Add placeholder code in case emulated samples want to hook the function
        for i, func_name in enumerate(names):
            exports_info.append((sec_rva + len(pattern), func_name))
            # Using i + 1 to avoid using 0, since the Win32 convention is to return TRUE when the function succeeds
            pattern += EXPORTED_FUNCTION[self.arch].replace(b"\x00\x00\x00\x00", (i + 1).to_bytes(4, "little"))

        if pattern:
            sect.VirtualAddress = sec_rva
            sect.Misc_VirtualSize = len(pattern)
            sect.Misc_PhysicalAddress = 0
            sect.SizeOfRawData = len(pattern)
            sect.PointerToRawData = cur_offset
            self.basepe.OPTIONAL_HEADER.AddressOfEntryPoint = sect.VirtualAddress
            self.append_data(pattern)
        self.update()
        return exports_info
