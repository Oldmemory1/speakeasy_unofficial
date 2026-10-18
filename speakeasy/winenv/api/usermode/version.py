# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
"""version.dll —— 只实现语料里高频出现的版本查询函数（fixN）。

扫描 1204 语料的导入表：301 个样本导入 version.dll，887 次导入，Top：
GetFileVersionInfoA 168 / GetFileVersionInfoSizeA 165 / VerQueryValueA 164 /
VerQueryValueW 135 / GetFileVersionInfoW 125 / GetFileVersionInfoSizeW 124。

旧行为（无 handler）：`GetFileVersionInfoSize*` 走签名模拟返回 u32=0 →
样本认为"没有版本信息"，常直接跳过后续分支。这里给一个最小的、格式合法的
VS_FIXEDFILEINFO（52 字节），让版本查询链路能走通。
"""

import struct

from .. import api

# VS_FIXEDFILEINFO（52 bytes），版本 10.0.19041.0
_FIXED_FILE_INFO = struct.pack(
    "<13I",
    0xFEEF04BD,  # dwSignature
    0x00010000,  # dwStrucVersion
    0x000A0000,  # dwFileVersionMS (10.0)
    0x00004A61,  # dwFileVersionLS (19041.0)
    0x000A0000,  # dwProductVersionMS
    0x00004A61,  # dwProductVersionLS
    0x3F,        # dwFileFlagsMask
    0x0,         # dwFileFlags
    0x40004,     # dwFileOS (VOS_NT_WINDOWS32)
    0x1,         # dwFileType (VFT_APP)
    0x0,         # dwFileSubtype
    0x0,         # dwFileDateMS
    0x0,         # dwFileDateLS
)


class Version(api.ApiHandler):
    """version.dll"""

    name = "version"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        super().__get_hook_attrs__(self)

    @apihook("GetFileVersionInfoSizeA", argc=2)
    def GetFileVersionInfoSizeA(self, emu, argv, ctx: api.ApiContext = None):
        """DWORD GetFileVersionInfoSizeA(LPCSTR, LPDWORD);"""
        handle_ptr = argv[1]
        if handle_ptr:
            self.mem_write(handle_ptr, b"\x00\x00\x00\x00")
        return len(_FIXED_FILE_INFO)

    @apihook("GetFileVersionInfoSizeW", argc=2)
    def GetFileVersionInfoSizeW(self, emu, argv, ctx: api.ApiContext = None):
        """DWORD GetFileVersionInfoSizeW(LPCWSTR, LPDWORD);"""
        handle_ptr = argv[1]
        if handle_ptr:
            self.mem_write(handle_ptr, b"\x00\x00\x00\x00")
        return len(_FIXED_FILE_INFO)

    @apihook("GetFileVersionInfoA", argc=4)
    def GetFileVersionInfoA(self, emu, argv, ctx: api.ApiContext = None):
        """BOOL GetFileVersionInfoA(LPCSTR, DWORD, DWORD, LPVOID);"""
        data = argv[3]
        if data:
            self.mem_write(data, _FIXED_FILE_INFO)
        return 1

    @apihook("GetFileVersionInfoW", argc=4)
    def GetFileVersionInfoW(self, emu, argv, ctx: api.ApiContext = None):
        """BOOL GetFileVersionInfoW(LPCWSTR, DWORD, DWORD, LPVOID);"""
        data = argv[3]
        if data:
            self.mem_write(data, _FIXED_FILE_INFO)
        return 1

    def _query_value(self, argv, wide: bool):
        """VerQueryValue(A/W)(hBlock, lpSubBlock, lplpBuffer, puLen)

        只支持根查询 "\\\\"（VS_FIXEDFILEINFO）：分配 52 字节并回填指针与长度；
        其它子块返回 FALSE（与"查不到"一致）。
        """
        sub_block, pp_buffer, p_len = argv[1], argv[2], argv[3]
        sub = ""
        if sub_block:
            try:
                sub = self.read_mem_string(sub_block, 2 if wide else 1)
            except Exception:
                sub = ""
        if sub.strip("\\").strip("\x00") != "":
            return 0
        if pp_buffer:
            ptr = self.mem_alloc(len(_FIXED_FILE_INFO), tag="api.version.fixedfileinfo")
            self.mem_write(ptr, _FIXED_FILE_INFO)
            self.mem_write(pp_buffer, ptr.to_bytes(self.get_ptr_size(), "little"))
        if p_len:
            self.mem_write(p_len, len(_FIXED_FILE_INFO).to_bytes(4, "little"))
        return 1

    @apihook("VerQueryValueA", argc=4)
    def VerQueryValueA(self, emu, argv, ctx: api.ApiContext = None):
        return self._query_value(argv, wide=False)

    @apihook("VerQueryValueW", argc=4)
    def VerQueryValueW(self, emu, argv, ctx: api.ApiContext = None):
        return self._query_value(argv, wide=True)
