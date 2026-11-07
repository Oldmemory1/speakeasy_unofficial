from __future__ import annotations

from types import SimpleNamespace

import pytest

import speakeasy.winenv.arch as _arch
from speakeasy.winenv.api.usermode.msacm32 import (
    ACMSTREAMHEADER_STATUSF_DONE,
    ACMSTREAMHEADER_STATUSF_PREPARED,
    MMSYSERR_INVALHANDLE,
    MMSYSERR_INVALPARAM,
    MMSYSERR_NOERROR,
    AcmStreamHeader,
    AcmStreamHeaderLayout,
    Msacm32,
)


class _Memory:
    def __init__(self) -> None:
        self.data: dict[int, int] = {}

    def mem_read(self, address: int, size: int) -> bytes:
        return bytes(
            self.data.get(address + offset, 0)
            for offset in range(size)
        )

    def mem_write(self, address: int, data: bytes) -> None:
        for offset, value in enumerate(data):
            self.data[address + offset] = value

    def write(self, address: int, data: bytes) -> None:
        self.mem_write(address, data)


def _handler(pointer_size: int = 4) -> tuple[Msacm32, _Memory]:
    memory = _Memory()
    emu = SimpleNamespace(
        mem_read=memory.mem_read,
        mem_write=memory.mem_write,
        get_arch=lambda: (
            _arch.ARCH_X86 if pointer_size == 4 else _arch.ARCH_AMD64
        ),
        get_ptr_size=lambda: pointer_size,
    )
    return Msacm32(emu), memory


@pytest.mark.parametrize(
    ("pointer_size", "size", "status", "src_used", "dst_used", "dw_dst_user"),
    [
        (4, 84, 4, 20, 36, 40),
        (8, 128, 4, 28, 52, 56),
    ],
)
def test_acm_stream_header_layout(
    pointer_size: int,
    size: int,
    status: int,
    src_used: int,
    dst_used: int,
    dw_dst_user: int,
) -> None:
    layout = AcmStreamHeaderLayout.for_pointer_size(pointer_size)

    assert layout.size == size
    assert layout.fdw_status == status
    assert layout.cb_src_length_used == src_used
    assert layout.cb_dst_length_used == dst_used
    assert layout.dw_dst_user == dw_dst_user
    assert layout.dw_dst_user % pointer_size == 0


@pytest.mark.parametrize("pointer_size", [4, 8])
def test_acm_stream_header_round_trip(pointer_size: int) -> None:
    layout = AcmStreamHeaderLayout.for_pointer_size(pointer_size)
    header = AcmStreamHeader(
        layout=layout,
        cb_struct=layout.size,
        fdw_status=ACMSTREAMHEADER_STATUSF_PREPARED,
        dw_user=0x11,
        pb_src=0x1000,
        cb_src_length=16,
        cb_src_length_used=4,
        dw_src_user=0x22,
        pb_dst=0x2000,
        cb_dst_length=32,
        cb_dst_length_used=5,
        dw_dst_user=0x33,
        reserved_driver=tuple(range(layout.reserved_driver_count)),
    )

    decoded = AcmStreamHeader.from_bytes(header.to_bytes(), pointer_size)

    assert decoded == header


def test_convert_rejects_invalid_stream_before_touching_header() -> None:
    handler, memory = _handler()

    result = handler.acmStreamConvert(
        handler.emu,
        [0x40301E, 0, 0],
        None,
    )

    assert result == MMSYSERR_INVALHANDLE
    assert memory.data == {}


def test_convert_rejects_null_header_for_valid_stream() -> None:
    handler, _memory = _handler()
    result_pointer = 0x3000
    result = handler.acmStreamOpen(
        handler.emu,
        [result_pointer, 0x1000, 0x2000, 0, 0, 0, 0, 0],
        None,
    )
    assert result == MMSYSERR_NOERROR
    stream_handle = int.from_bytes(
        bytes(_memory.data[result_pointer + i] for i in range(4)),
        "little",
    )

    assert handler.acmStreamConvert(
        handler.emu, [stream_handle, 0, 0], None
    ) == MMSYSERR_INVALPARAM


def test_prepare_and_convert_write_back_documented_outputs() -> None:
    pointer_size = 4
    handler, memory = _handler(pointer_size)
    stream_out = 0x3000
    header_address = 0x4000
    source = b"acm!"
    destination = 0x5000

    assert handler.acmStreamOpen(
        handler.emu,
        [stream_out, 0x1000, 0x2000, 0, 0, 0, 0, 0],
        None,
    ) == MMSYSERR_NOERROR
    stream_handle = int.from_bytes(
        memory.mem_read(stream_out, pointer_size), "little"
    )
    layout = AcmStreamHeaderLayout.for_pointer_size(pointer_size)
    header = AcmStreamHeader(
        layout=layout,
        cb_struct=layout.size,
        pb_src=0x6000,
        cb_src_length=len(source),
        pb_dst=destination,
        cb_dst_length=len(source),
    )
    memory.write(header_address, header.to_bytes())
    memory.write(header.pb_src, source)

    assert handler.acmStreamPrepareHeader(
        handler.emu, [stream_handle, header_address, 0], None
    ) == MMSYSERR_NOERROR
    prepared = AcmStreamHeader.from_bytes(
        memory.mem_read(header_address, layout.size), pointer_size
    )
    assert prepared.fdw_status & ACMSTREAMHEADER_STATUSF_PREPARED

    assert handler.acmStreamConvert(
        handler.emu, [stream_handle, header_address, 0], None
    ) == MMSYSERR_NOERROR
    converted = AcmStreamHeader.from_bytes(
        memory.mem_read(header_address, layout.size), pointer_size
    )
    assert converted.fdw_status & ACMSTREAMHEADER_STATUSF_DONE
    assert converted.cb_src_length_used == len(source)
    assert converted.cb_dst_length_used == len(source)
    assert memory.mem_read(destination, len(source)) == source


def test_header_size_mismatch_is_invalid_parameter() -> None:
    handler, memory = _handler()
    stream_out = 0x3000
    header_address = 0x4000
    assert handler.acmStreamOpen(
        handler.emu,
        [stream_out, 0x1000, 0x2000, 0, 0, 0, 0, 0],
        None,
    ) == MMSYSERR_NOERROR
    stream_handle = int.from_bytes(memory.mem_read(stream_out, 4), "little")
    layout = AcmStreamHeaderLayout.for_pointer_size(4)
    malformed = AcmStreamHeader(
        layout=layout,
        cb_struct=layout.size - 4,
    )
    memory.write(header_address, malformed.to_bytes())

    assert handler.acmStreamPrepareHeader(
        handler.emu, [stream_handle, header_address, 0], None
    ) == MMSYSERR_INVALPARAM
