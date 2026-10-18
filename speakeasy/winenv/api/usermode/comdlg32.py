# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
"""comdlg32.dll —— 只实现语料里的高频函数（fixN）。

导入扫描：192 个样本、402 次导入，Top：
GetSaveFileNameW 120 / GetOpenFileNameW 118 / GetFileTitleA 44 /
GetOpenFileNameA 40 / GetSaveFileNameA 39 / ChooseColorA 18。

对话框类 API 在无人交互的沙箱里返回 0（用户取消）是合理语义；
`GetFileTitle*` 只做文件名提取，给样本一个真实的结果。
"""

import ntpath

from .. import api


class ComDlg32(api.ApiHandler):
    """comdlg32.dll"""

    name = "comdlg32"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        super().__get_hook_attrs__(self)

    @apihook("GetOpenFileNameA", argc=1)
    def GetOpenFileNameA(self, emu, argv, ctx: api.ApiContext = None):
        """BOOL GetOpenFileNameA(LPOPENFILENAMEA);"""
        return 0

    @apihook("GetOpenFileNameW", argc=1)
    def GetOpenFileNameW(self, emu, argv, ctx: api.ApiContext = None):
        """BOOL GetOpenFileNameW(LPOPENFILENAMEW);"""
        return 0

    @apihook("GetSaveFileNameA", argc=1)
    def GetSaveFileNameA(self, emu, argv, ctx: api.ApiContext = None):
        """BOOL GetSaveFileNameA(LPOPENFILENAMEA);"""
        return 0

    @apihook("GetSaveFileNameW", argc=1)
    def GetSaveFileNameW(self, emu, argv, ctx: api.ApiContext = None):
        """BOOL GetSaveFileNameW(LPOPENFILENAMEW);"""
        return 0

    def _file_title(self, argv, wide: bool):
        """GetFileTitle(A/W)(lpFile, lpTitle, cbBuf) —— 返回标题长度（不含 NUL）。"""
        file_ptr, title_ptr, cb_buf = argv[0], argv[1], argv[2]
        if not file_ptr or not title_ptr:
            return -1
        try:
            path = self.read_mem_string(file_ptr, 2 if wide else 1)
        except Exception:
            return -1
        title = ntpath.basename(path)
        if cb_buf and len(title) + 1 > cb_buf:
            return -1
        if wide:
            self.mem_write(title_ptr, (title + "\x00").encode("utf-16le"))
        else:
            self.write_mem_string(title, title_ptr)
        return len(title)

    @apihook("GetFileTitleA", argc=3)
    def GetFileTitleA(self, emu, argv, ctx: api.ApiContext = None):
        return self._file_title(argv, wide=False)

    @apihook("GetFileTitleW", argc=3)
    def GetFileTitleW(self, emu, argv, ctx: api.ApiContext = None):
        return self._file_title(argv, wide=True)

    @apihook("ChooseColorA", argc=1)
    def ChooseColorA(self, emu, argv, ctx: api.ApiContext = None):
        """BOOL ChooseColorA(LPCHOOSECOLORA);"""
        return 0

    @apihook("ChooseColorW", argc=1)
    def ChooseColorW(self, emu, argv, ctx: api.ApiContext = None):
        """BOOL ChooseColorW(LPCHOOSECOLORW);"""
        return 0

    @apihook("PrintDlgA", argc=1)
    def PrintDlgA(self, emu, argv, ctx: api.ApiContext = None):
        """BOOL PrintDlgA(LPPRINTDLGA);"""
        return 0

    @apihook("PrintDlgW", argc=1)
    def PrintDlgW(self, emu, argv, ctx: api.ApiContext = None):
        """BOOL PrintDlgW(LPPRINTDLGW);"""
        return 0
