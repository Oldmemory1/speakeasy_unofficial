# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import speakeasy.common as common
import speakeasy.winenv.arch as _arch

from .. import api


class Cygwin(api.ApiHandler):
    """
    Minimal Cygwin/MSYS runtime ABI support.

    ``cygwin_internal`` is an implementation-detail entry point used by the
    Cygwin and MSYS CRT startup code.  Its first argument is a command from
    ``cygwin_getinfo_types``; the command values are zero based.
    """

    name = "cygwin1"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    CW_LOCK_PINFO = 0
    CW_UNLOCK_PINFO = 1
    CW_USER_DATA = 8

    # The caller treats the CW_USER_DATA result as a writable runtime
    # structure.  Current Cygwin x64 startup code accesses fields up to
    # +0x148, while older MSYS x86 startup code writes fields around +0xa8.
    # Allocate a full page so both ABIs have room for their runtime layout.
    USER_DATA_SIZE = 0x1000

    def __init__(self, emu):
        super().__init__(emu)
        self._user_data = 0
        super().__get_hook_attrs__(self)

    def _get_user_data(self) -> int:
        if not self._user_data:
            self._user_data = self.emu.mem_map(
                self.USER_DATA_SIZE,
                perms=common.PERM_MEM_RW,
                tag="emu.cygwin.user_data",
            )
        return self._user_data

    @apihook("cygwin_internal", argc=_arch.VAR_ARGS, conv=_arch.CALL_CONV_CDECL)
    def Cygwin_internal(self, emu, argv, ctx: api.ApiContext = None):
        """
        uintptr_t cygwin_internal(cygwin_getinfo_types command, ...);

        Only the first argument is decoded here.  The variadic arguments are
        command-specific, so handlers must fetch them explicitly when adding
        support for a new command.
        """
        command_argv = emu.get_func_argv(_arch.CALL_CONV_CDECL, 1)
        if not command_argv:
            return self.get_max_int()

        command = command_argv[0]
        if command in (self.CW_LOCK_PINFO, self.CW_UNLOCK_PINFO):
            return 1
        if command == self.CW_USER_DATA:
            return self._get_user_data()

        # Cygwin initializes its return value to (uintptr_t)-1 and leaves it
        # there for unsupported commands.  Returning NULL here is unsafe: CRT
        # startup callers may treat a successful return as a structure pointer.
        return self.get_max_int()


class Msys(Cygwin):
    """MSYS 1.0 exports the same cygwin_internal ABI from msys-1.dll."""

    name = "msys-1"


class Msys2(Cygwin):
    """MSYS2's cygwin runtime exports the same ABI from msys-2.0.dll."""

    name = "msys-2.0"


class Msys2Short(Cygwin):
    """PE import parsing may preserve msys-2.0.dll as the module name msys-2."""

    name = "msys-2"
