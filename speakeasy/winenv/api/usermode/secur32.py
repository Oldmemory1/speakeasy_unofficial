# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.windows.secur32 as sec32defs

from .. import api


class Secur32(api.ApiHandler):
    name = "secur32"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        super().__get_hook_attrs__(self)

    @apihook("GetUserNameEx", argc=3, conv=_arch.CALL_CONV_STDCALL)
    def GetUserNameEx(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOLEAN SEC_ENTRY GetUserNameExA(
          EXTENDED_NAME_FORMAT NameFormat,
          LPSTR                lpNameBuffer,
          PULONG               nSize
        );
        """
        ctx = ctx or {}
        NameFormat, lpNameBuffer, nSize = argv

        cw = self.get_char_width(ctx)

        name_format = sec32defs.get_define(NameFormat, prefix="Name")
        if name_format:
            argv[0] = name_format

        user_name = emu.config.user.name
        user_name_len = len(user_name) + 1

        argv[1] = user_name
        argv[2] = user_name_len

        if not nSize or not emu.is_address_valid(nSize):
            return 0

        current_size = int.from_bytes(self.mem_read(nSize, 4), "little")
        self.mem_write(nSize, user_name_len.to_bytes(4, "little"))
        if not lpNameBuffer or current_size < user_name_len:
            emu.set_last_error(122)  # ERROR_INSUFFICIENT_BUFFER
            return 0

        self.write_mem_string(user_name, lpNameBuffer, cw)
        return 1

    @apihook("EncryptMessage", argc=4)
    def EncryptMessage(self, emu, argv, ctx: api.ApiContext = None):
        """
        SECURITY_STATUS SEC_ENTRY EncryptMessage(
        PCtxtHandle    phContext,
        unsigned long  fQOP,
        PSecBufferDesc pMessage,
        unsigned long  MessageSeqNo
        );
        """

        PCtxtHandle, fQOP, pMessage, MessageSeqNo = argv

        return sec32defs.SEC_E_INVALID_HANDLE
