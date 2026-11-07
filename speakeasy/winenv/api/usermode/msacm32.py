# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

"""Minimal, deterministic emulation of the Windows ACM stream API.

The ACM API transfers audio headers by pointer and uses architecture-specific
``ACMSTREAMHEADER`` layouts.  Treating those pointers as scalar arguments and
returning success can make a caller consume uninitialized or attacker-chosen
values as output.  This module keeps handle validation and header
serialization explicit so unsupported or invalid requests fail with documented
ACM result codes instead.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass

from .. import api

logger = logging.getLogger(__name__)

MMSYSERR_NOERROR = 0
MMSYSERR_INVALHANDLE = 5
MMSYSERR_INVALPARAM = 11

ACMSTREAMHEADER_STATUSF_DONE = 0x00000001
ACMSTREAMHEADER_STATUSF_PREPARED = 0x00010000
ACMSTREAMHEADER_STATUSF_INQUEUE = 0x00020000

_HANDLE_BASE = 0xA0C00000
_HANDLE_STRIDE = 8
_POINTER_ALIGNMENT = {4: 4, 8: 8}


@dataclass(frozen=True)
class AcmStreamHeaderLayout:
    """Byte layout of the public x86/x64 ``ACMSTREAMHEADER`` structure."""

    pointer_size: int
    size: int
    cb_struct: int
    fdw_status: int
    dw_user: int
    pb_src: int
    cb_src_length: int
    cb_src_length_used: int
    dw_src_user: int
    pb_dst: int
    cb_dst_length: int
    cb_dst_length_used: int
    dw_dst_user: int
    reserved_driver: int
    reserved_driver_count: int

    @classmethod
    def for_pointer_size(cls, pointer_size: int) -> AcmStreamHeaderLayout:
        if pointer_size not in _POINTER_ALIGNMENT:
            raise ValueError(f"unsupported pointer size: {pointer_size}")

        alignment = _POINTER_ALIGNMENT[pointer_size]
        cb_struct = 0
        fdw_status = 4
        dw_user = (8 + alignment - 1) & ~(alignment - 1)
        pb_src = dw_user + pointer_size
        cb_src_length = pb_src + pointer_size
        cb_src_length_used = cb_src_length + 4
        dw_src_user = cb_src_length_used + 4
        pb_dst = dw_src_user + pointer_size
        cb_dst_length = pb_dst + pointer_size
        cb_dst_length_used = cb_dst_length + 4
        dw_dst_user = cb_dst_length_used + 4
        reserved_driver = dw_dst_user + pointer_size
        reserved_driver_count = 10 if pointer_size == 4 else 15
        unaligned_size = reserved_driver + reserved_driver_count * 4
        size = (unaligned_size + alignment - 1) & ~(alignment - 1)

        return cls(
            pointer_size=pointer_size,
            size=size,
            cb_struct=cb_struct,
            fdw_status=fdw_status,
            dw_user=dw_user,
            pb_src=pb_src,
            cb_src_length=cb_src_length,
            cb_src_length_used=cb_src_length_used,
            dw_src_user=dw_src_user,
            pb_dst=pb_dst,
            cb_dst_length=cb_dst_length,
            cb_dst_length_used=cb_dst_length_used,
            dw_dst_user=dw_dst_user,
            reserved_driver=reserved_driver,
            reserved_driver_count=reserved_driver_count,
        )


@dataclass
class AcmStreamHeader:
    """Decoded fields of an ``ACMSTREAMHEADER`` structure."""

    layout: AcmStreamHeaderLayout
    cb_struct: int = 0
    fdw_status: int = 0
    dw_user: int = 0
    pb_src: int = 0
    cb_src_length: int = 0
    cb_src_length_used: int = 0
    dw_src_user: int = 0
    pb_dst: int = 0
    cb_dst_length: int = 0
    cb_dst_length_used: int = 0
    dw_dst_user: int = 0
    reserved_driver: tuple[int, ...] = ()

    @classmethod
    def from_bytes(cls, data: bytes, pointer_size: int) -> AcmStreamHeader:
        layout = AcmStreamHeaderLayout.for_pointer_size(pointer_size)
        if len(data) < layout.size:
            raise ValueError(
                f"ACMSTREAMHEADER requires {layout.size} bytes, got {len(data)}"
            )

        def read_u32(offset: int) -> int:
            return struct.unpack_from("<I", data, offset)[0]

        def read_ptr(offset: int) -> int:
            fmt = "<I" if pointer_size == 4 else "<Q"
            return struct.unpack_from(fmt, data, offset)[0]

        reserved = tuple(
            read_u32(layout.reserved_driver + index * 4)
            for index in range(layout.reserved_driver_count)
        )
        return cls(
            layout=layout,
            cb_struct=read_u32(layout.cb_struct),
            fdw_status=read_u32(layout.fdw_status),
            dw_user=read_ptr(layout.dw_user),
            pb_src=read_ptr(layout.pb_src),
            cb_src_length=read_u32(layout.cb_src_length),
            cb_src_length_used=read_u32(layout.cb_src_length_used),
            dw_src_user=read_ptr(layout.dw_src_user),
            pb_dst=read_ptr(layout.pb_dst),
            cb_dst_length=read_u32(layout.cb_dst_length),
            cb_dst_length_used=read_u32(layout.cb_dst_length_used),
            dw_dst_user=read_ptr(layout.dw_dst_user),
            reserved_driver=reserved,
        )

    def to_bytes(self) -> bytes:
        layout = self.layout
        data = bytearray(layout.size)

        def write_u32(offset: int, value: int) -> None:
            struct.pack_into("<I", data, offset, value & 0xFFFFFFFF)

        def write_ptr(offset: int, value: int) -> None:
            mask = 0xFFFFFFFF if layout.pointer_size == 4 else 0xFFFFFFFFFFFFFFFF
            fmt = "<I" if layout.pointer_size == 4 else "<Q"
            struct.pack_into(fmt, data, offset, value & mask)

        write_u32(layout.cb_struct, self.cb_struct)
        write_u32(layout.fdw_status, self.fdw_status)
        write_ptr(layout.dw_user, self.dw_user)
        write_ptr(layout.pb_src, self.pb_src)
        write_u32(layout.cb_src_length, self.cb_src_length)
        write_u32(layout.cb_src_length_used, self.cb_src_length_used)
        write_ptr(layout.dw_src_user, self.dw_src_user)
        write_ptr(layout.pb_dst, self.pb_dst)
        write_u32(layout.cb_dst_length, self.cb_dst_length)
        write_u32(layout.cb_dst_length_used, self.cb_dst_length_used)
        write_ptr(layout.dw_dst_user, self.dw_dst_user)
        reserved = list(self.reserved_driver)
        reserved.extend([0] * (layout.reserved_driver_count - len(reserved)))
        for index, value in enumerate(reserved[: layout.reserved_driver_count]):
            write_u32(layout.reserved_driver + index * 4, value)
        return bytes(data)


@dataclass
class _AcmStream:
    handle: int
    source_format: int
    destination_format: int
    filter: int


class Msacm32(api.ApiHandler):
    """Emulates the subset of ``msacm32.dll`` needed for stream headers."""

    name = "msacm32"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        self._next_handle = _HANDLE_BASE
        self._streams: dict[int, _AcmStream] = {}
        super().__get_hook_attrs__(self)

    def _allocate_handle(self) -> int:
        handle = self._next_handle
        self._next_handle += _HANDLE_STRIDE
        return handle

    def _stream(self, handle: int) -> _AcmStream | None:
        return self._streams.get(handle)

    def _read_u32(self, address: int) -> int | None:
        if not address:
            return None
        try:
            return int.from_bytes(self.emu.mem_read(address, 4), "little")
        except Exception:
            logger.debug("failed to read ACM u32 at 0x%x", address, exc_info=True)
            return None

    def _read_header(self, address: int) -> AcmStreamHeader | None:
        if not address:
            return None
        layout = AcmStreamHeaderLayout.for_pointer_size(self.emu.get_ptr_size())
        try:
            data = self.emu.mem_read(address, layout.size)
            return AcmStreamHeader.from_bytes(data, layout.pointer_size)
        except Exception:
            logger.debug(
                "failed to read ACMSTREAMHEADER at 0x%x", address, exc_info=True
            )
            return None

    def _write_header(self, address: int, header: AcmStreamHeader) -> bool:
        try:
            self.emu.mem_write(address, header.to_bytes())
            return True
        except Exception:
            logger.debug(
                "failed to write ACMSTREAMHEADER at 0x%x", address, exc_info=True
            )
            return False

    @apihook("acmStreamOpen", argc=8)
    def acmStreamOpen(self, emu, argv, ctx: api.ApiContext = None):
        """MMRESULT acmStreamOpen(...);"""
        out_stream, source_format, destination_format, audio_filter = argv[:4]
        if not out_stream or not source_format or not destination_format:
            return MMSYSERR_INVALPARAM

        handle = self._allocate_handle()
        self._streams[handle] = _AcmStream(
            handle=handle,
            source_format=source_format,
            destination_format=destination_format,
            filter=audio_filter,
        )
        try:
            emu.mem_write(
                out_stream,
                handle.to_bytes(self.emu.get_ptr_size(), "little"),
            )
        except Exception:
            logger.debug(
                "failed to write ACM stream handle at 0x%x",
                out_stream,
                exc_info=True,
            )
            del self._streams[handle]
            return MMSYSERR_INVALPARAM
        return MMSYSERR_NOERROR

    @apihook("acmStreamPrepareHeader", argc=3)
    def acmStreamPrepareHeader(self, emu, argv, ctx: api.ApiContext = None):
        """MMRESULT acmStreamPrepareHeader(HACMSTREAM, LPACMSTREAMHEADER, DWORD);"""
        stream_handle, header_address, _flags = argv
        if self._stream(stream_handle) is None:
            return MMSYSERR_INVALHANDLE
        header = self._read_header(header_address)
        if header is None or header.cb_struct != header.layout.size:
            return MMSYSERR_INVALPARAM

        header.fdw_status |= ACMSTREAMHEADER_STATUSF_PREPARED
        header.fdw_status &= ~ACMSTREAMHEADER_STATUSF_INQUEUE
        if not self._write_header(header_address, header):
            return MMSYSERR_INVALPARAM
        return MMSYSERR_NOERROR

    @apihook("acmStreamConvert", argc=3)
    def acmStreamConvert(self, emu, argv, ctx: api.ApiContext = None):
        """MMRESULT acmStreamConvert(HACMSTREAM, LPACMSTREAMHEADER, DWORD);"""
        stream_handle, header_address, _flags = argv
        if self._stream(stream_handle) is None:
            return MMSYSERR_INVALHANDLE
        header = self._read_header(header_address)
        if header is None or header.cb_struct != header.layout.size:
            return MMSYSERR_INVALPARAM
        if not (header.fdw_status & ACMSTREAMHEADER_STATUSF_PREPARED):
            return MMSYSERR_INVALPARAM
        if header.fdw_status & ACMSTREAMHEADER_STATUSF_INQUEUE:
            return MMSYSERR_INVALPARAM

        transfer_size = min(header.cb_src_length, header.cb_dst_length)
        if transfer_size and (not header.pb_src or not header.pb_dst):
            return MMSYSERR_INVALPARAM
        if transfer_size:
            try:
                source = emu.mem_read(header.pb_src, transfer_size)
                emu.mem_write(header.pb_dst, source)
            except Exception:
                logger.debug("ACM identity transfer failed", exc_info=True)
                return MMSYSERR_INVALPARAM

        header.cb_src_length_used = transfer_size
        header.cb_dst_length_used = transfer_size
        header.fdw_status |= ACMSTREAMHEADER_STATUSF_DONE
        if not self._write_header(header_address, header):
            return MMSYSERR_INVALPARAM
        return MMSYSERR_NOERROR

    @apihook("acmStreamUnprepareHeader", argc=3)
    def acmStreamUnprepareHeader(self, emu, argv, ctx: api.ApiContext = None):
        """MMRESULT acmStreamUnprepareHeader(HACMSTREAM, LPACMSTREAMHEADER, DWORD);"""
        stream_handle, header_address, _flags = argv
        if self._stream(stream_handle) is None:
            return MMSYSERR_INVALHANDLE
        header = self._read_header(header_address)
        if header is None or header.cb_struct != header.layout.size:
            return MMSYSERR_INVALPARAM
        if not (header.fdw_status & ACMSTREAMHEADER_STATUSF_PREPARED):
            return MMSYSERR_INVALPARAM
        if header.fdw_status & ACMSTREAMHEADER_STATUSF_INQUEUE:
            return MMSYSERR_INVALPARAM

        header.fdw_status &= ~(
            ACMSTREAMHEADER_STATUSF_PREPARED
            | ACMSTREAMHEADER_STATUSF_INQUEUE
            | ACMSTREAMHEADER_STATUSF_DONE
        )
        if not self._write_header(header_address, header):
            return MMSYSERR_INVALPARAM
        return MMSYSERR_NOERROR

    @apihook("acmStreamClose", argc=2)
    def acmStreamClose(self, emu, argv, ctx: api.ApiContext = None):
        """MMRESULT acmStreamClose(HACMSTREAM, DWORD);"""
        stream_handle, _flags = argv
        if self._stream(stream_handle) is None:
            return MMSYSERR_INVALHANDLE
        del self._streams[stream_handle]
        return MMSYSERR_NOERROR
