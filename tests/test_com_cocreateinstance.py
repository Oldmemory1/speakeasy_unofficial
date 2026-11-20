"""Contract tests for CoCreateInstance COM failure semantics (FX-005).

``COM / cocreateinstance_fake_success``: the handler used to initialize
``rv = S_OK`` and only changed ``*ppv`` on the success path, so an unregistered
CLSID or an unsupported IID was reported as success while ``*ppv`` stayed NULL.

The COM/HRESULT contract mirrors Wine's combase (read-only reference tree,
Wine 11.22, ``dlls/combase/combase.c``):

* NULL ``ppv`` -> ``E_POINTER`` (combase.c:1703-1704) and no fake success;
* the interface result is zeroed before class lookup, so every failure path
  leaves ``*ppv = NULL`` (combase.c:1908 ``init_multi_qi``);
* unregistered CLSID -> ``REGDB_E_CLASSNOTREG``;
* registered CLSID but unsupported IID -> ``E_NOINTERFACE``.

The tests drive the real ``ole32.CoCreateInstance`` handler from x86 shellcode
loaded by the engine; no batch sample is executed.
"""

from __future__ import annotations

import struct
import uuid

from speakeasy import Speakeasy

REGDB_E_CLASSNOTREG = 0x80040154
E_NOINTERFACE = 0x80004002
E_POINTER = 0x80004003
S_OK = 0

# Guest GUID memory layout is little-endian (uuid.UUID.bytes_le); the handler
# converts it back with convert_guid_bytes_to_str() and matches com.py strings.
CLSID_UNKNOWN = uuid.UUID("{3EFB1800-C2A1-11CF-960C-0080C7C2BA87}").bytes_le
IID_IUNKNOWN = uuid.UUID("{00000001-0000-0000-C000-000000000046}").bytes_le
CLSID_WBEM_LOCATOR = uuid.UUID("{4590F811-1D3A-11D0-891F-00AA004B2E24}").bytes_le
IID_IWBEM_LOCATOR = uuid.UUID("{DC12A687-737F-11CF-884D-00AA004B2E24}").bytes_le
IID_UNKNOWN = uuid.UUID("{DEADBEEF-CAFE-BABE-0123-456789ABCDEF}").bytes_le

S_CLSID = 0x00
S_IID = 0x10
S_PPV = 0x20
S_RV = 0x24
S_PPV_OUT = 0x28
DATA_SIZE = 0x40

SENTINEL = 0xDEADBEEF


class _Asm:
    """Small x86 emitter with absolute fixups resolved after loading."""

    def __init__(self) -> None:
        self.buf = bytearray()
        self.patches: list[list] = []

    def imm32(self, key: str, addend: int = 0) -> None:
        offset = len(self.buf)
        self.buf += b"\x00\x00\x00\x00"
        self.patches.append([offset, key, addend])

    def push_imm32(self, value: int) -> None:
        self.buf += b"\x68" + struct.pack("<I", value & 0xFFFFFFFF)

    def push_abs(self, key: str, addend: int = 0) -> None:
        self.buf += b"\x68"
        self.imm32(key, addend)

    def mov_eax_abs(self, key: str, addend: int = 0) -> None:
        self.buf += b"\xb8"
        self.imm32(key, addend)

    def mov_eax_ptr_abs(self, key: str, addend: int = 0) -> None:
        self.buf += b"\x8b\x05"
        self.imm32(key, addend)

    def mov_ptr_abs_eax(self, key: str, addend: int = 0) -> None:
        self.buf += b"\x89\x05"
        self.imm32(key, addend)

    def mov_ptr_abs_imm32(self, key: str, value: int, addend: int = 0) -> None:
        self.buf += b"\xc7\x05"
        self.imm32(key, addend)
        self.buf += struct.pack("<I", value & 0xFFFFFFFF)

    def call_eax(self) -> None:
        self.buf += b"\xff\xd0"

    def ret(self) -> None:
        self.buf += b"\xc3"


def _run_com_call(
    config,
    clsid: bytes,
    iid: bytes,
    *,
    null_ppv: bool = False,
    api: str = "CoCreateInstance",
):
    """Call a COM class/interface API from shellcode and return ``(rv, *ppv)``.

    ``api`` selects ``CoCreateInstance`` (rclsid, pUnkOuter, dwClsContext,
    riid, ppv) or ``CoGetClassObject`` (rclsid, dwClsContext, pServerInfo,
    riid, ppv).  ``*ppv`` is prefilled with ``SENTINEL`` before the call so a
    failure path that forgets to clear it is observable.
    """
    asm = _Asm()

    if null_ppv:
        asm.push_imm32(0)  # ppv = NULL
    else:
        asm.mov_ptr_abs_imm32("data", SENTINEL, S_PPV)
        asm.push_abs("data", S_PPV)
    asm.push_abs("data", S_IID)
    if api == "CoGetClassObject":
        asm.push_imm32(0)  # pServerInfo
        asm.push_imm32(7)  # dwClsContext
    else:
        asm.push_imm32(7)  # dwClsContext (CLSCTX_SERVER | CLSCTX_INPROC_HANDLER)
        asm.push_imm32(0)  # pUnkOuter
    asm.push_abs("data", S_CLSID)
    asm.mov_eax_abs("comcall")
    asm.call_eax()
    asm.mov_ptr_abs_eax("data", S_RV)
    if not null_ppv:
        asm.mov_eax_ptr_abs("data", S_PPV)
        asm.mov_ptr_abs_eax("data", S_PPV_OUT)
    asm.ret()

    code = bytes(asm.buf)
    data_offset = len(code)
    code += b"\x00" * DATA_SIZE

    se = Speakeasy(config=config)
    try:
        sc_addr = se.load_shellcode(data=code, arch="x86")
        emu = se.emu
        values = {
            "sc": sc_addr,
            "data": sc_addr + data_offset,
            "comcall": emu.get_proc("ole32", api),
        }
        assert all(values.values())

        for offset, key, addend in asm.patches:
            emu.mem_write(
                sc_addr + offset,
                struct.pack("<I", (values[key] + addend) & 0xFFFFFFFF),
            )

        data_addr = sc_addr + data_offset
        emu.mem_write(data_addr + S_CLSID, clsid)
        emu.mem_write(data_addr + S_IID, iid)

        se.run_shellcode(sc_addr)
        report = se.get_report()
        entry = report.entry_points[0]
        assert entry.error is None, entry.error

        rv = int.from_bytes(emu.mem_read(data_addr + S_RV, 4), "little")
        ppv_value = None
        if not null_ppv:
            ppv_value = int.from_bytes(emu.mem_read(data_addr + S_PPV_OUT, 4), "little")
        return rv, ppv_value
    finally:
        se.shutdown()


def test_unknown_clsid_returns_regdb_e_classnotreg_and_clears_ppv(config):
    rv, ppv_value = _run_com_call(config, CLSID_UNKNOWN, IID_IUNKNOWN)

    assert rv == REGDB_E_CLASSNOTREG
    assert ppv_value == 0


def test_known_clsid_unknown_iid_returns_e_nointerface_and_clears_ppv(config):
    rv, ppv_value = _run_com_call(config, CLSID_WBEM_LOCATOR, IID_UNKNOWN)

    assert rv == E_NOINTERFACE
    assert ppv_value == 0


def test_known_clsid_known_iid_still_succeeds(config):
    rv, ppv_value = _run_com_call(config, CLSID_WBEM_LOCATOR, IID_IWBEM_LOCATOR)

    assert rv == S_OK
    assert ppv_value != 0


def test_null_ppv_returns_e_pointer(config):
    rv, _ = _run_com_call(config, CLSID_WBEM_LOCATOR, IID_IWBEM_LOCATOR, null_ppv=True)

    assert rv == E_POINTER


def test_get_class_object_unknown_clsid_returns_regdb_e_classnotreg_and_clears_ppv(config):
    # The representative sample calls the ole32 IAT slot that is in fact
    # CoGetClassObject (objdump: 0x401dbe `call DWORD PTR ds:0x401108`), so the
    # same unknown-CLSID contract must hold on this entry point too.
    rv, ppv_value = _run_com_call(
        config, CLSID_UNKNOWN, IID_IUNKNOWN, api="CoGetClassObject"
    )

    assert rv == REGDB_E_CLASSNOTREG
    assert ppv_value == 0


def test_get_class_object_known_clsid_returns_e_nointerface_and_clears_ppv(config):
    # Speakeasy models COM interfaces, not IClassFactory implementations, so a
    # registered CLSID has no class object to return: the handler must fail
    # explicitly instead of pretending success with a NULL pointer.
    rv, ppv_value = _run_com_call(
        config, CLSID_WBEM_LOCATOR, IID_IWBEM_LOCATOR, api="CoGetClassObject"
    )

    assert rv == E_NOINTERFACE
    assert ppv_value == 0


def test_get_class_object_null_ppv_returns_e_pointer(config):
    rv, _ = _run_com_call(
        config,
        CLSID_WBEM_LOCATOR,
        IID_IWBEM_LOCATOR,
        null_ppv=True,
        api="CoGetClassObject",
    )

    assert rv == E_POINTER
