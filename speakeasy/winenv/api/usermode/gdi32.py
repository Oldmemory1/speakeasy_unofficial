# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from .. import api


class GDI32(api.ApiHandler):
    """
    Implements exported functions from gdi32.dll
    """

    # GET_STOCK_OBJECT_FLAGS values. Value 9 is not defined and invalid stock
    # object identifiers must fail rather than aliasing another object.
    STOCK_OBJECT_TYPES = frozenset(
        {
            0,  # WHITE_BRUSH
            1,  # LTGRAY_BRUSH
            2,  # GRAY_BRUSH
            3,  # DKGRAY_BRUSH
            4,  # BLACK_BRUSH
            5,  # NULL_BRUSH / HOLLOW_BRUSH
            6,  # WHITE_PEN
            7,  # BLACK_PEN
            8,  # NULL_PEN
            10,  # OEM_FIXED_FONT
            11,  # ANSI_FIXED_FONT
            12,  # ANSI_VAR_FONT
            13,  # SYSTEM_FONT
            14,  # DEVICE_DEFAULT_FONT
            15,  # DEFAULT_PALETTE
            16,  # SYSTEM_FIXED_FONT
            17,  # DEFAULT_GUI_FONT
            18,  # DC_BRUSH
            19,  # DC_PEN
        }
    )
    STOCK_OBJECT_HANDLE_BASE = 0x7000

    name = "gdi32"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)

        self.funcs = {}
        self.data = {}
        self.handle = 0
        self.count = 0
        self.stock_objects: dict[int, int] = {}
        super().__get_hook_attrs__(self)

    def get_handle(self):
        self.handle += 4
        hnd = self.handle
        return hnd

    def get_stock_object_handle(self, stock_object: int) -> int:
        """Return a stable pseudo-handle for a valid GDI stock object."""
        if stock_object not in self.STOCK_OBJECT_TYPES:
            return 0

        handle = self.stock_objects.get(stock_object)
        if handle is None:
            handle = self.STOCK_OBJECT_HANDLE_BASE + stock_object * 4
            self.stock_objects[stock_object] = handle
        return handle

    @apihook("CreateBitmap", argc=5)
    def CreateBitmap(self, emu, argv, ctx: api.ApiContext = None):
        """
        HBITMAP CreateBitmap(
            int        nWidth,
            int        nHeight,
            UINT       nPlanes,
            UINT       nBitCount,
            const VOID *lpBits
        );
        """
        return self.get_handle()

    @apihook("MoveToEx", argc=4)
    def MoveToEx(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL MoveToEx(
          HDC     hdc,
          int     x,
          int     y,
          LPPOINT lppt
        );
        """
        return 1

    @apihook("LineTo", argc=3)
    def LineTo(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL LineTo(
          HDC hdc,
          int x,
          int y
        )
        """
        return 1

    @apihook("GetStockObject", argc=1)
    def GetStockObject(self, emu, argv, ctx: api.ApiContext = None):
        """
        HGDIOBJ GetStockObject(
            int i
        );
        """
        return self.get_stock_object_handle(argv[0])

    @apihook("GetMapMode", argc=1)
    def GetMapMode(self, emu, argv, ctx: api.ApiContext = None):
        """
        int GetMapMode(
            HDC hdc
        );
        """
        return 1

    @apihook("GetDeviceCaps", argc=2)
    def GetDeviceCaps(self, emu, argv, ctx: api.ApiContext = None):
        """
        int GetDeviceCaps(
            HDC hdc,
            int index
        );
        """
        return 16

    @apihook("GdiSetBatchLimit", argc=1)
    def GdiSetBatchLimit(self, emu, argv, ctx: api.ApiContext = None):
        """
        DWORD GdiSetBatchLimit(
          DWORD dw
        );
        """
        return 0

    @apihook("MaskBlt", argc=12)
    def MaskBlt(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL MaskBlt(
          HDC     hdcDest,
          int     xDest,
          int     yDest,
          int     width,
          int     height,
          HDC     hdcSrc,
          int     xSrc,
          int     ySrc,
          HBITMAP hbmMask,
          int     xMask,
          int     yMask,
          DWORD   rop
        );
        """
        return 1

    @apihook("BitBlt", argc=9)
    def BitBlt(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL BitBlt(
        HDC   hdc,
        int   x,
        int   y,
        int   cx,
        int   cy,
        HDC   hdcSrc,
        int   x1,
        int   y1,
        DWORD rop
        """
        return 1

    @apihook("DeleteDC", argc=1)
    def DeleteDC(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL DeleteDC(
        HDC hdc
        );
        """
        return 1

    @apihook("SelectObject", argc=2)
    def SelectObject(self, emu, argv, ctx: api.ApiContext = None):
        """
        HGDIOBJ SelectObject(
          HDC     hdc,
          HGDIOBJ h
        );
        """
        return 0

    @apihook("DeleteObject", argc=1)
    def DeleteObject(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL DeleteObject(
        HGDIOBJ ho
        );
        """
        return 1

    @apihook("CreateCompatibleBitmap", argc=3)
    def CreateCompatibleBitmap(self, emu, argv, ctx: api.ApiContext = None):
        """
        HBITMAP CreateCompatibleBitmap(
        HDC hdc,
        int cx,
        int cy
        );
        """
        return 0

    @apihook("CreateCompatibleDC", argc=1)
    def CreateCompatibleDC(self, emu, argv, ctx: api.ApiContext = None):
        """
        HDC CreateCompatibleDC(
        HDC hdc
        );
        """
        return 0

    @apihook("GetDIBits", argc=7)
    def GetDIBits(self, emu, argv, ctx: api.ApiContext = None):
        """
        int GetDIBits(
        HDC          hdc,
        HBITMAP      hbm,
        UINT         start,
        UINT         cLines,
        LPVOID       lpvBits,
        LPBITMAPINFO lpbmi,
        UINT         usage
        );
        """
        return 0

    @apihook("CreateDIBSection", argc=6)
    def CreateDIBSection(self, emu, argv, ctx: api.ApiContext = None):
        """
        HBITMAP CreateDIBSection(
          [in]  HDC              hdc,
          [in]  const BITMAPINFO *pbmi,
          [in]  UINT             usage,
          [out] VOID             **ppvBits,
          [in]  HANDLE           hSection,
          [in]  DWORD            offset
        );
        """
        return 0

    @apihook("CreateDCA", argc=4)
    def CreateDCA(self, emu, argv, ctx: api.ApiContext = None):
        """
        HDC CreateDCA(
        LPCSTR         pwszDriver,
        LPCSTR         pwszDevice,
        LPCSTR         pszPort,
        const DEVMODEA *pdm
        );
        """
        return 0

    @apihook("GetTextCharacterExtra", argc=1)
    def GetTextCharacterExtra(self, emu, argv, ctx: api.ApiContext = None):
        """
        int GetTextCharacterExtra(
          HDC hdc
        );
        """
        return 0x8000000

    @apihook("StretchBlt", argc=11)
    def StretchBlt(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL StretchBlt(
          HDC   hdcDest,
          int   xDest,
          int   yDest,
          int   wDest,
          int   hDest,
          HDC   hdcSrc,
          int   xSrc,
          int   ySrc,
          int   wSrc,
          int   hSrc,
          DWORD rop
        );
        """
        return 0

    @apihook("CreateFontIndirectA", argc=1)
    def CreateFontIndirectA(self, emu, argv, ctx: api.ApiContext = None):
        """
        HFONT CreateFontIndirectA(
            const LOGFONTA *lplf
        );
        """
        # Return a fake HFONT handle.
        # Any non-zero value is treated as success.
        return 0x6000

    @apihook("GetObjectA", argc=3)
    def GetObjectA(self, emu, argv, ctx: api.ApiContext = None):
        """
        int GetObjectA(
            HANDLE h,
            int    c,
            LPVOID pv
        );
        """
        h, c, pv = argv

        # If caller provided a buffer, fill it with zeros.
        if pv and c:
            try:
                data = b"\x00" * c
                try:
                    emu.mem_write(pv, data)
                except Exception:
                    base_addr = pv & ~0xFFF
                    emu.mem_map(base_addr, 0x1000)
                    emu.mem_write(pv, data)
            except Exception:
                pass

        # Return number of bytes "written"
        return c

    @apihook("WidenPath", argc=1)
    def WidenPath(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL WidenPath(
            HDC hdc
        );
        """
        # We don't emulate actual path widening; just report success.
        return 1
