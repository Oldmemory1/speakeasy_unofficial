# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
"""uxtheme.dll —— 只实现语料里的高频函数（fixN）。

导入扫描：111 个样本、293 次导入，Top：
IsThemeActive 92 / GetCurrentThemeName 19 / GetThemeFont 18 / CloseThemeData 18 /
DrawThemeBackground 18 / GetThemeInt 18 / DrawThemeEdge 18 / GetThemeSysBool 18。

这些 API 用于"是否有主题/主题参数"的环境探测；给出"有主题、参数为 0"的
一致结果，避免样本因为拿到 0 句柄而走异常分支。
"""

from .. import api

_THEME_PATH = "C:\\Windows\\resources\\themes\\Aero\\Aero.msstyles"
_FAKE_THEME = 0x00A70000


class UxTheme(api.ApiHandler):
    """uxtheme.dll"""

    name = "uxtheme"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        super().__get_hook_attrs__(self)

    @apihook("IsThemeActive", argc=0)
    def IsThemeActive(self, emu, argv, ctx: api.ApiContext = None):
        """BOOL IsThemeActive();"""
        return 1

    @apihook("IsAppThemed", argc=0)
    def IsAppThemed(self, emu, argv, ctx: api.ApiContext = None):
        """BOOL IsAppThemed();"""
        return 1

    @apihook("OpenThemeData", argc=2)
    def OpenThemeData(self, emu, argv, ctx: api.ApiContext = None):
        """HTHEME OpenThemeData(HWND hwnd, LPCWSTR pszClassList);"""
        return _FAKE_THEME

    @apihook("CloseThemeData", argc=1)
    def CloseThemeData(self, emu, argv, ctx: api.ApiContext = None):
        """HRESULT CloseThemeData(HTHEME hTheme);"""
        return 0

    @apihook("GetCurrentThemeName", argc=6)
    def GetCurrentThemeName(self, emu, argv, ctx: api.ApiContext = None):
        """HRESULT GetCurrentThemeName(LPWSTR, int, LPWSTR, int, LPWSTR, int);"""
        name_buf, _cch_name, _color_buf, _cch_color, _size_buf, _cch_size = argv
        if name_buf:
            self.mem_write(name_buf, (_THEME_PATH + "\x00").encode("utf-16le"))
        return 0

    @apihook("GetThemeInt", argc=5)
    def GetThemeInt(self, emu, argv, ctx: api.ApiContext = None):
        """HRESULT GetThemeInt(HTHEME, int, int, int, int *piVal);"""
        pi_val = argv[4]
        if pi_val:
            self.mem_write(pi_val, b"\x00\x00\x00\x00")
        return 0

    @apihook("GetThemeSysBool", argc=2)
    def GetThemeSysBool(self, emu, argv, ctx: api.ApiContext = None):
        """BOOL GetThemeSysBool(HTHEME hTheme, int iBoolId);"""
        return 1

    @apihook("GetThemeFont", argc=6)
    def GetThemeFont(self, emu, argv, ctx: api.ApiContext = None):
        """HRESULT GetThemeFont(HTHEME, HDC, int, int, int, LOGFONTW *);"""
        font_ptr = argv[5]
        if font_ptr:
            # LOGFONTW 至少 92 字节；清零即可（样本通常只检查返回值）
            self.mem_write(font_ptr, b"\x00" * 92)
        return 0

    @apihook("DrawThemeBackground", argc=6)
    def DrawThemeBackground(self, emu, argv, ctx: api.ApiContext = None):
        """HRESULT DrawThemeBackground(HTHEME, HDC, int, int, const RECT *, const RECT *);"""
        return 0

    @apihook("DrawThemeEdge", argc=8)
    def DrawThemeEdge(self, emu, argv, ctx: api.ApiContext = None):
        """HRESULT DrawThemeEdge(HTHEME, HDC, int, int, const RECT *, UINT, UINT, RECT *);"""
        return 0
