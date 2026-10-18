# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
"""userenv.dll —— 只实现语料里的高频函数（fixN）。

导入扫描：138 个样本、477 次导入，Top：
LoadUserProfileW 122 / CreateEnvironmentBlock 119 / UnloadUserProfile 114 /
DestroyEnvironmentBlock 112 / GetProfilesDirectoryA 5。

这几个 API 被服务/提权类样本用来"切换到用户环境"。旧行为走签名模拟
（BOOL→1、指针→0），`CreateEnvironmentBlock` 返回 0 会让样本直接放弃。
这里给出合法返回值与环境块指针。
"""

from .. import api


class UserEnv(api.ApiHandler):
    """userenv.dll"""

    name = "userenv"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        super().__get_hook_attrs__(self)

    @apihook("LoadUserProfileA", argc=2)
    def LoadUserProfileA(self, emu, argv, ctx: api.ApiContext = None):
        """BOOL LoadUserProfileA(HANDLE, LPPROFILEINFOA);"""
        return 1

    @apihook("LoadUserProfileW", argc=2)
    def LoadUserProfileW(self, emu, argv, ctx: api.ApiContext = None):
        """BOOL LoadUserProfileW(HANDLE, LPPROFILEINFOW);"""
        return 1

    @apihook("UnloadUserProfile", argc=2)
    def UnloadUserProfile(self, emu, argv, ctx: api.ApiContext = None):
        """BOOL UnloadUserProfile(HANDLE, HANDLE);"""
        return 1

    @apihook("CreateEnvironmentBlock", argc=3)
    def CreateEnvironmentBlock(self, emu, argv, ctx: api.ApiContext = None):
        """BOOL CreateEnvironmentBlock(LPVOID *lpEnvironment, HANDLE hToken, BOOL bInherit);

        写一个双 NUL 结尾的环境块，并把指针回填到 *lpEnvironment。
        """
        pp_env = argv[0]
        enc = "utf-16le"
        parts = [f"{k}={v}\x00".encode(enc) for k, v in (emu.get_env() or {}).items()]
        block = b"".join(parts) + b"\x00\x00"
        ptr = self.mem_alloc(len(block), tag="api.userenv.environment")
        self.mem_write(ptr, block)
        if pp_env:
            self.mem_write(pp_env, ptr.to_bytes(self.get_ptr_size(), "little"))
        return 1

    @apihook("DestroyEnvironmentBlock", argc=1)
    def DestroyEnvironmentBlock(self, emu, argv, ctx: api.ApiContext = None):
        """BOOL DestroyEnvironmentBlock(LPVOID);"""
        return 1

    @apihook("GetProfilesDirectoryA", argc=2)
    def GetProfilesDirectoryA(self, emu, argv, ctx: api.ApiContext = None):
        """BOOL GetProfilesDirectoryA(LPSTR lpProfileDir, LPDWORD lpcchSize);"""
        buf, p_size = argv[0], argv[1]
        path = "C:\\Users"
        if buf:
            self.write_mem_string(path, buf)
        if p_size:
            self.mem_write(p_size, (len(path) + 1).to_bytes(4, "little"))
        return 1

    @apihook("GetProfilesDirectoryW", argc=2)
    def GetProfilesDirectoryW(self, emu, argv, ctx: api.ApiContext = None):
        """BOOL GetProfilesDirectoryW(LPWSTR lpProfileDir, LPDWORD lpcchSize);"""
        buf, p_size = argv[0], argv[1]
        path = "C:\\Users"
        if buf:
            self.mem_write(buf, (path + "\x00").encode("utf-16le"))
        if p_size:
            self.mem_write(p_size, (len(path) + 1).to_bytes(4, "little"))
        return 1

    @apihook("GetUserProfileDirectoryA", argc=3)
    def GetUserProfileDirectoryA(self, emu, argv, ctx: api.ApiContext = None):
        """BOOL GetUserProfileDirectoryA(HANDLE, LPSTR, LPDWORD);"""
        buf, p_size = argv[1], argv[2]
        path = "C:\\Users\\user"
        if buf:
            self.write_mem_string(path, buf)
        if p_size:
            self.mem_write(p_size, (len(path) + 1).to_bytes(4, "little"))
        return 1

    @apihook("GetUserProfileDirectoryW", argc=3)
    def GetUserProfileDirectoryW(self, emu, argv, ctx: api.ApiContext = None):
        """BOOL GetUserProfileDirectoryW(HANDLE, LPWSTR, LPDWORD);"""
        buf, p_size = argv[1], argv[2]
        path = "C:\\Users\\user"
        if buf:
            self.mem_write(buf, (path + "\x00").encode("utf-16le"))
        if p_size:
            self.mem_write(p_size, (len(path) + 1).to_bytes(4, "little"))
        return 1
