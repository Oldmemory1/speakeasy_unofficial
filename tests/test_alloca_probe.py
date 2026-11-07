"""Regression tests for the x86 ntdll._alloca_probe ABI."""

import pytest

from speakeasy.config import SpeakeasyConfig
from speakeasy.errors import ApiEmuError
from speakeasy.windows.win32 import Win32Emulator
from speakeasy.winenv import arch as e_arch
from speakeasy.winenv.api.usermode.ntdll import Ntdll

STACK_SIZE = 0x12000
RET_ADDR = 0x402137


@pytest.fixture
def x86_emu(config):
    return _make_emu(config, e_arch.ARCH_X86, e_arch.BITS_32)


@pytest.fixture
def x64_emu(config):
    return _make_emu(config, e_arch.ARCH_AMD64, e_arch.BITS_64)


def _make_emu(config, arch, bits):
    cfg = SpeakeasyConfig(**config)
    emu = Win32Emulator(cfg)
    emu.arch = arch
    emu.set_ptr_size(arch)
    emu.emu_eng.init_engine(e_arch.ARCH_X86, bits)
    base, _ = emu.alloc_stack(STACK_SIZE)
    emu.stack_base = base
    return emu


def _alloca_handler(emu):
    handler = Ntdll(emu)
    entry = handler.get_func_handler("_alloca_probe")
    assert entry is not None
    _, func, argc, conv, _ = entry
    assert argc == 0
    assert conv == e_arch.CALL_CONV_CDECL
    return handler, func


@pytest.mark.parametrize("byte_count", [0, 1, 3, 4, 0x14, 0x24, 0x84])
def test_alloca_probe_lowers_esp_and_preserves_return_address(x86_emu, byte_count):
    handler, func = _alloca_handler(x86_emu)
    x86_emu.set_func_args(x86_emu.stack_base, RET_ADDR, conv=e_arch.CALL_CONV_CDECL)
    x86_emu.reg_write(e_arch.X86_REG_EAX, byte_count)
    x86_emu.reg_write(e_arch.X86_REG_ECX, 0xDEADBEEF)

    sp_at_entry = x86_emu.get_stack_ptr()
    assert x86_emu.get_ret_address() == RET_ADDR

    return_value = func(handler, x86_emu, [], {"func_name": "ntdll._alloca_probe"})

    new_sp = sp_at_entry - byte_count
    assert x86_emu.get_stack_ptr() == new_sp
    assert x86_emu.get_ret_address() == RET_ADDR
    assert x86_emu.reg_read(e_arch.X86_REG_ECX) == 0xDEADBEEF
    assert int.from_bytes(x86_emu.mem_read(new_sp, 4), "little") == RET_ADDR
    assert return_value == RET_ADDR

    # Model the common import return path after the handler.
    x86_emu.do_call_return(
        0,
        ret_addr=x86_emu.get_ret_address(),
        ret_value=return_value,
        conv=e_arch.CALL_CONV_CDECL,
    )

    assert x86_emu.get_stack_ptr() == sp_at_entry + 4 - byte_count
    assert x86_emu.reg_read(e_arch.X86_REG_EAX) == RET_ADDR
    assert x86_emu.get_pc() == RET_ADDR


def test_alloca_probe_rejects_stack_underflow(x86_emu):
    handler, func = _alloca_handler(x86_emu)
    x86_emu.set_func_args(x86_emu.stack_base, RET_ADDR, conv=e_arch.CALL_CONV_CDECL)
    x86_emu.reg_write(e_arch.X86_REG_EAX, x86_emu.get_stack_ptr())

    with pytest.raises(ApiEmuError, match="stack allocation is out of range"):
        func(handler, x86_emu, [], {"func_name": "ntdll._alloca_probe"})


def test_alloca_probe_rejects_destination_outside_stack_mapping(x86_emu):
    handler, func = _alloca_handler(x86_emu)
    x86_emu.set_func_args(x86_emu.stack_base, RET_ADDR, conv=e_arch.CALL_CONV_CDECL)
    stack_pointer = x86_emu.get_stack_ptr()
    stack_map = x86_emu.get_address_map(stack_pointer)
    byte_count = stack_pointer - stack_map.base + 1
    x86_emu.reg_write(e_arch.X86_REG_EAX, byte_count)

    with pytest.raises(ApiEmuError, match="stack allocation is out of range"):
        func(handler, x86_emu, [], {"func_name": "ntdll._alloca_probe"})


def test_alloca_probe_rejects_non_x86(x64_emu):
    handler = Ntdll(x64_emu)
    entry = handler.get_func_handler("_alloca_probe")
    assert entry is not None
    _, func, _, _, _ = entry

    with pytest.raises(ApiEmuError, match="only supported on x86"):
        func(handler, x64_emu, [], {"func_name": "ntdll._alloca_probe"})
