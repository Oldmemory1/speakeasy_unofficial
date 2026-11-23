"""Import slots, export tables and procedure resolvers agree on mapped API entries."""

import struct

import pefile
import pytest
import unicorn as uc

from speakeasy.windows.api_image import ApiExportSpec, build_api_image
from speakeasy.windows.common import EMU_RESERVED, EMU_RESERVED_END
from tests.handler_harness import alloc, call, load_emu

TEST_BINS = {4: "dll_test_x86.dll.xz", 8: "dll_test_x64.dll.xz"}


@pytest.fixture(params=["dll_emu", "dll64_emu"])
def api_emu(request):
    return request.getfixturevalue(request.param)


@pytest.fixture
def placeholder_emu(config, load_test_bin):
    config["modules"]["stubs"] = True
    yield from load_emu(config, load_test_bin(TEST_BINS[4]))


def module_handle(se, name):
    handle, _ = call(se, "kernel32", "GetModuleHandleA", [alloc(se, name.encode() + b"\0")])
    assert handle
    return handle


def get_proc_address(se, handle, name):
    result, _ = call(se, "kernel32", "GetProcAddress", [handle, alloc(se, name.encode() + b"\0")])
    return result


def mapped_pe(se, base):
    size = pefile.PE(data=se.mem_read(base, 0x1000), fast_load=True).OPTIONAL_HEADER.SizeOfImage
    return pefile.PE(data=se.mem_read(base, size))


def permissions_at(se, address):
    return next(perms for start, end, perms in se.emu.get_mem_regions() if start <= address <= end)


def test_iat_slots_match_get_proc_address(api_emu, load_test_bin):
    ptr = api_emu.get_ptr_size()
    pe = pefile.PE(data=load_test_bin(TEST_BINS[ptr]))
    base = api_emu.emu.modules[0].base
    checked = 0
    for descriptor in pe.DIRECTORY_ENTRY_IMPORT:
        handle = module_handle(api_emu, descriptor.dll.decode())
        for imp in descriptor.imports:
            slot = base + imp.address - pe.OPTIONAL_HEADER.ImageBase
            address = int.from_bytes(api_emu.mem_read(slot, ptr), "little")
            assert address == get_proc_address(api_emu, handle, imp.name.decode())
            # FX-013 (authoritative): imports of handler-backed modules bind to
            # unmapped dispatch sentinels in the reserved range. Dispatch happens
            # on the guest fetch, so a data read at the sentinel is not valid.
            assert EMU_RESERVED <= address < EMU_RESERVED_END
            checked += 1
    assert checked >= 26


def test_eat_and_resolvers_share_one_entry(api_emu):
    ptr = api_emu.get_ptr_size()
    kernel32 = module_handle(api_emu, "kernel32.dll")
    export = next(e for e in mapped_pe(api_emu, kernel32).DIRECTORY_ENTRY_EXPORT.symbols if e.name == b"MoveFileExW")
    address = kernel32 + export.address
    # FX-013 sentinel model (authoritative): a name lookup in a handler-backed
    # module returns an unmapped dispatch sentinel, not the mapped EAT stub.
    sentinel = get_proc_address(api_emu, kernel32, "MoveFileExW")
    assert EMU_RESERVED <= sentinel < EMU_RESERVED_END
    assert api_emu.emu.get_address_map(sentinel) is None
    # The ordinal lookup and the ntdll loader resolver keep the upstream
    # mapped-entry behavior, so they still share the EAT entry with each other.
    by_ordinal, _ = call(api_emu, "kernel32", "GetProcAddress", [kernel32, export.ordinal])
    assert by_ordinal == address
    name = alloc(api_emu, b"MoveFileExW\0")
    padding = b"\0" * 4 if ptr == 8 else b""
    ansi = alloc(api_emu, struct.pack("<HH", 11, 12) + padding + name.to_bytes(ptr, "little"))
    output = alloc(api_emu, b"\0" * ptr)
    status, _ = call(api_emu, "ntdll", "LdrGetProcedureAddress", [kernel32, ansi, 0, output])
    assert status == 0
    assert int.from_bytes(api_emu.mem_read(output, ptr), "little") == address
    assert api_emu.mem_read(address, 2) == (b"\x8b\xff" if ptr == 4 else b"\x66\x90")
    assert permissions_at(api_emu, address) & uc.UC_PROT_EXEC
    assert api_emu.get_symbol_from_address(address + 2).endswith("MoveFileExW+0x2")


def test_missing_known_export_fails_both_resolvers(dll_emu):
    kernel32 = module_handle(dll_emu, "kernel32.dll")
    # Adapted to the authoritative FX-013 sentinel policy: a missing name in a
    # loaded non-EXE module (kernel32) returns a nonzero dispatch sentinel in
    # the EMU_RESERVED range, not Windows' NULL; only the ntdll loader resolver
    # still fails. (The name keeps its upstream spelling for traceability.)
    sentinel = get_proc_address(dll_emu, kernel32, "NotARealKernel32Export")
    assert sentinel != 0
    assert EMU_RESERVED <= sentinel < EMU_RESERVED_END
    output = alloc(dll_emu, b"\0" * 4)
    status, _ = call(dll_emu, "ntdll", "LdrGetProcedureAddress", [kernel32, 0, 65535, output])
    assert status != 0
    assert dll_emu.mem_read(output, 4) == b"\0" * 4


def test_unknown_module_entries_are_stable_and_leave_pe_unchanged(placeholder_emu):
    se = placeholder_emu
    handle, _ = call(se, "kernel32", "LoadLibraryA", [alloc(se, b"unknown_vendor.dll\0")])
    assert handle
    before = mapped_pe(se, handle)
    headers = before.OPTIONAL_HEADER.SizeOfHeaders
    address = get_proc_address(se, handle, "UnknownFunction")
    assert address
    assert get_proc_address(se, handle, "UnknownFunction") == address
    assert get_proc_address(se, handle, "AnotherFunction") not in (0, address)
    assert se.mem_read(handle, headers) == before.__data__[:headers]
    assert handle <= address < handle + before.OPTIONAL_HEADER.SizeOfImage
    perms = permissions_at(se, address)
    assert perms & uc.UC_PROT_EXEC
    assert not perms & uc.UC_PROT_WRITE


def test_forwarders_resolve_to_destination_and_keep_eat_strings(dll_emu):
    # Reported product gap (not adapted): GetProcAddress on a forwarding export
    # of a synthetic module returns a sentinel keyed to the forwarding module
    # itself (``forwarding_test!Tick``) instead of following the forwarder to
    # the destination handler (``kernel32!GetTickCount``). ``resolve_export``
    # already follows synthetic forwarders; ``resolve_module_export``, used by
    # GetProcAddress for non-PeLoader modules, ignores ``ExportEntry.forwarder``.
    # The assertions stay unchanged until the product follows forwarders.
    emu = dll_emu.emu
    base, _ = emu.get_valid_ranges(0x20000, addr=0x63000000)
    module = dll_emu.load_image(
        build_api_image(
            name="forwarding_test",
            arch=emu.arch,
            base=base,
            emu_path="forwarding_test.dll",
            exports=[
                ApiExportSpec("Tick", forwarder="kernel32.GetTickCount"),
                ApiExportSpec("Variable", forwarder="msvcrt._acmdln"),
                ApiExportSpec("Cycle", forwarder="forwarding_test.Cycle"),
                ApiExportSpec("Missing", forwarder="kernel32.NotARealExport"),
            ],
        )
    )
    before = dll_emu.mem_read(module.base, module.image_size)
    kernel32 = module_handle(dll_emu, "kernel32.dll")
    msvcrt = module_handle(dll_emu, "msvcrt.dll")
    assert get_proc_address(dll_emu, module.base, "Tick") == get_proc_address(dll_emu, kernel32, "GetTickCount")
    assert get_proc_address(dll_emu, module.base, "Variable") == get_proc_address(dll_emu, msvcrt, "_acmdln")
    assert get_proc_address(dll_emu, module.base, "Cycle") == 0
    assert get_proc_address(dll_emu, module.base, "Missing") == 0
    assert dll_emu.mem_read(module.base, module.image_size) == before


def test_dynamic_arena_holds_2048_entries_then_refuses_without_moving_them(dll_emu):
    # Reported product gap (not adapted): the 2048-slot ``.dyn`` arena still
    # caps a synthetic module's dynamic entries, but once it is exhausted
    # ``get_proc`` falls back to ``_alloc_import_sentinel`` and reports a
    # sentinel instead of refusing with 0. The sentinel allocator itself has no
    # capacity/refusal contract, so the upstream "refuse without moving them"
    # invariant is lost. The assertions stay unchanged until the product fixes
    # the exhaustion path.
    emu = dll_emu.emu
    emu.load_module_by_name("capacity_vendor")
    addresses = [emu.get_proc("capacity_vendor", f"Dynamic{index}") for index in range(2048)]
    assert len(set(addresses)) == 2048
    assert all(addresses)
    first_bytes = emu.mem_read(addresses[0], 16)
    last_bytes = emu.mem_read(addresses[-1], 16)

    assert emu.get_proc("capacity_vendor", "Overflow") == 0
    assert emu.get_proc("capacity_vendor", 7) == 0

    assert emu.get_proc("capacity_vendor", "Dynamic0") == addresses[0]
    assert emu.get_proc("capacity_vendor", "Dynamic2047") == addresses[-1]
    assert emu.mem_read(addresses[0], 16) == first_bytes
    assert emu.mem_read(addresses[-1], 16) == last_bytes
