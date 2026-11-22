"""Contract tests for FX-019 `Loader / initial_thread_context`.

The top-level EXE's ``module_entry`` run must start with the Windows loader
entry convention:

* x86: ``EAX = entry``, ``EBX = PEB``;
* x64: ``RCX = entry``, ``RDX = PEB``.

The PEB must therefore be reachable through the register the guest expects
(``[EBX+0xc]`` / ``[RDX+0xc]`` is ``PEB->Ldr``).  The rule is scoped to the
top-level EXE entry run only: DLL entry runs, shellcode runs, and
``create_process()`` child thread contexts keep their existing semantics.

Synthetic PE images are built by ``tests/synthetic_pe.py``; the tests run the
real engine, no batch sample runs.
"""

from __future__ import annotations

import lzma
from pathlib import Path

import pytest

import speakeasy.winenv.arch as e_arch
from speakeasy import Speakeasy
from tests.synthetic_pe import (
    DATA_RVA,
    CodeBuffer,
    apply_patches,
    build_pe,
)

BINS = Path(__file__).resolve().parent / "bins"


def _bin(name: str) -> bytes:
    with lzma.open(BINS / name) as fh:
        return fh.read()


def _read_u32(emu, addr: int) -> int:
    return int.from_bytes(emu.mem_read(addr, 4), "little")


def test_x86_top_level_entry_context_matches_windows_loader(config):
    """x86 module_entry starts with EAX=entry and EBX=PEB."""
    code = CodeBuffer()
    code.mov_ptr_abs_eax("out_a")
    code.mov_ptr_abs_ebx("out_b")
    code.ret()

    data = build_pe(e_arch.ARCH_X86, bytes(code.buf))
    se = Speakeasy(config=config, argv=[])
    try:
        module = se.load_module(data=data)
        emu = se.emu
        entry = module.base + module.ep
        out_a = module.base + DATA_RVA
        out_b = module.base + DATA_RVA + 4
        apply_patches(emu, module, code.patches, {"out_a": out_a, "out_b": out_b})

        se.run_module(module)
        report = se.get_report()
        peb = emu.get_current_process().peb.address
        captured_eax = _read_u32(emu, out_a)
        captured_ebx = _read_u32(emu, out_b)
        entry_run = next(r for r in emu.runs if r.type == "module_entry")
        entry_context = getattr(entry_run, "entry_context", None)
    finally:
        se.shutdown()

    assert report.entry_points[0].error is None
    assert captured_eax == entry
    assert captured_ebx == peb
    assert entry_context is not None
    assert entry_context.entry == entry
    assert entry_context.peb == peb


def test_x64_top_level_entry_context_matches_windows_loader(config):
    """x64 module_entry starts with RCX=entry and RDX=PEB."""
    code = CodeBuffer()
    code.mov_ptr_abs_ecx_x64("out_a")
    code.mov_ptr_abs_edx_x64("out_b")
    code.ret()

    data = build_pe(e_arch.ARCH_AMD64, bytes(code.buf))
    se = Speakeasy(config=config, argv=[])
    observed: dict[str, int] = {}
    try:
        module = se.load_module(data=data)
        emu = se.emu
        entry = module.base + module.ep
        out_a = module.base + DATA_RVA
        out_b = module.base + DATA_RVA + 4
        apply_patches(emu, module, code.patches, {"out_a": out_a, "out_b": out_b})

        def entry_hook(uc, addr, size):
            if addr == entry and "rcx" not in observed:
                observed["rcx"] = emu.reg_read(e_arch.AMD64_REG_RCX)
                observed["rdx"] = emu.reg_read(e_arch.AMD64_REG_RDX)

        se.emu.add_code_hook(cb=entry_hook, begin=entry, end=entry + 1)
        se.run_module(module)
        report = se.get_report()
        peb = emu.get_current_process().peb.address
        captured_ecx = _read_u32(emu, out_a)
        captured_edx = _read_u32(emu, out_b)
        entry_context = getattr(emu.runs[0], "entry_context", None)
    finally:
        se.shutdown()

    assert report.entry_points[0].error is None
    assert observed["rcx"] == entry
    assert observed["rdx"] == peb
    assert captured_ecx == entry & 0xFFFFFFFF
    assert captured_edx == peb & 0xFFFFFFFF
    assert entry_context is not None
    assert entry_context.entry == entry
    assert entry_context.peb == peb


def test_x86_entry_ebx_reads_peb_ldr(config):
    """The 5c4cae64 mechanism: [EBX+0xc] must read PEB->Ldr without faulting."""
    code = CodeBuffer()
    code.mov_ecx_ptr_ebx_disp8(0xC)
    code.mov_ptr_abs_ecx("out_a")
    code.ret()

    data = build_pe(e_arch.ARCH_X86, bytes(code.buf))
    se = Speakeasy(config=config, argv=[])
    try:
        module = se.load_module(data=data)
        emu = se.emu
        out_a = module.base + DATA_RVA
        apply_patches(emu, module, code.patches, {"out_a": out_a})

        se.run_module(module)
        report = se.get_report()
        peb = emu.get_current_process().peb.address
        peb_ldr = _read_u32(emu, peb + 0xC)
        captured = _read_u32(emu, out_a)
    finally:
        se.shutdown()

    assert report.entry_points[0].error is None
    assert captured == peb_ldr
    assert peb_ldr != 0


@pytest.mark.parametrize("bin_file", ["dll_test_x86.dll.xz"])
def test_dll_entry_run_has_no_process_entry_context(config, load_test_bin, bin_file):
    """DLL entry runs must not receive the top-level EXE entry context."""
    data = load_test_bin(bin_file)
    se = Speakeasy(config=config, argv=[])
    try:
        module = se.load_module(data=data)
        se.run_module(module)
        runs = list(se.emu.runs)
        dll_runs = [r for r in runs if isinstance(r.type, str) and r.type.startswith("dll_entry.")]
    finally:
        se.shutdown()

    assert dll_runs, "expected a DLL entry run"
    for run in runs:
        assert getattr(run, "entry_context", None) is None


def test_shellcode_run_has_no_process_entry_context(config):
    """Shellcode runs keep zeroed entry registers and no entry context."""
    config["max_instructions"] = 2
    se = Speakeasy(config=config, argv=[])
    observed: dict[str, int] = {}
    try:
        sc_addr = se.load_shellcode(data=b"\x90\x90", arch="x86")
        emu = se.emu

        def entry_hook(uc, addr, size):
            if addr == sc_addr and "eax" not in observed:
                observed["eax"] = emu.reg_read(e_arch.X86_REG_EAX)
                observed["ebx"] = emu.reg_read(e_arch.X86_REG_EBX)

        emu.add_code_hook(cb=entry_hook, begin=sc_addr, end=sc_addr + 1)
        se.run_shellcode(sc_addr)
        shellcode_runs = [r for r in emu.runs if r.type == "shellcode"]
    finally:
        se.shutdown()

    assert observed["eax"] == 0
    assert observed["ebx"] == 0
    assert shellcode_runs
    for run in shellcode_runs:
        assert getattr(run, "entry_context", None) is None


@pytest.mark.parametrize(
    "arch,entry_reg,peb_reg,pc_reg",
    [
        (e_arch.ARCH_X86, e_arch.X86_REG_EAX, e_arch.X86_REG_EBX, e_arch.X86_REG_EIP),
        (e_arch.ARCH_AMD64, e_arch.AMD64_REG_RCX, e_arch.AMD64_REG_RDX, e_arch.AMD64_REG_RIP),
    ],
)
def test_create_process_thread_context_uses_entry_rule(config, arch, entry_reg, peb_reg, pc_reg):
    """create_process() child contexts keep the arch entry rule and PC=0.

    The parent's live CPU registers must not change when a child process
    object is created.
    """
    code = CodeBuffer()
    code.ret()
    data = build_pe(arch, bytes(code.buf))
    se = Speakeasy(config=config, argv=[])
    try:
        module = se.load_module(data=data)
        emu = se.emu
        se.run_module(module)
        if arch == e_arch.ARCH_X86:
            tracked = (
                e_arch.X86_REG_EAX,
                e_arch.X86_REG_EBX,
                e_arch.X86_REG_ECX,
                e_arch.X86_REG_EDX,
                e_arch.X86_REG_EIP,
                e_arch.X86_REG_ESP,
            )
        else:
            tracked = (
                e_arch.AMD64_REG_RAX,
                e_arch.AMD64_REG_RBX,
                e_arch.AMD64_REG_RCX,
                e_arch.AMD64_REG_RDX,
                e_arch.AMD64_REG_RIP,
                e_arch.AMD64_REG_RSP,
            )
        parent_before = {reg: emu.reg_read(reg) for reg in tracked}

        child = emu.create_process(path=r"C:\Windows\system32\cmd.exe", child=True)
        thread = child.threads[0]
        child_entry = child.pe.base + child.pe.ep
        child_ctx_entry = getattr(thread.ctx, "Eax" if arch == e_arch.ARCH_X86 else "Rcx")
        child_ctx_peb = getattr(thread.ctx, "Ebx" if arch == e_arch.ARCH_X86 else "Rdx")
        child_ctx_pc = getattr(thread.ctx, "Eip" if arch == e_arch.ARCH_X86 else "Rip")
        parent_after = {reg: emu.reg_read(reg) for reg in tracked}
    finally:
        se.shutdown()

    assert child_ctx_entry == child_entry
    assert child_ctx_peb == child.peb.address
    assert child_ctx_pc == 0
    assert parent_after == parent_before
    assert emu.reg_read(entry_reg) == parent_before[entry_reg]
    assert emu.reg_read(peb_reg) == parent_before[peb_reg]
    assert emu.reg_read(pc_reg) == parent_before[pc_reg]
