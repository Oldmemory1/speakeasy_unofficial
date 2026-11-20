# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import logging

import speakeasy.winenv.defs.windows.com as com
import speakeasy.winenv.defs.windows.windows as windefs

from .. import api

logger = logging.getLogger(__name__)


class Ole32(api.ApiHandler):
    name = "ole32"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    # Clipboard formats that carry a GDI object handle instead of an HGLOBAL.
    # Wine duplicates these with CopyEnhMetaFileW/CopyMetaFileW/CreatePalette/
    # CreateBitmapIndirect (ole32/ole2.c:3094). Speakeasy does not model those
    # GDI objects for this API, so they fail with NULL rather than returning a
    # fabricated handle of the wrong kind.
    GDI_CLIPBOARD_FORMATS = frozenset(
        {
            2,  # CF_BITMAP
            3,  # CF_METAFILEPICT
            9,  # CF_PALETTE
            14,  # CF_ENHMETAFILE
        }
    )

    def __init__(self, emu):
        super().__init__(emu)
        self.funcs = {}
        self.data = {}
        super().__get_hook_attrs__(self)
        self.netman = emu.get_network_manager()
        self.names = {}

    @apihook("OleInitialize", argc=1)
    def OleInitialize(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT OleInitialize(
            IN LPVOID pvReserved
        );
        """

        rv = windefs.S_OK

        return rv

    @apihook("CoInitialize", argc=1)
    def CoInitialize(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT CoInitialize(
          LPVOID pvReserved
        );
        """

        rv = windefs.S_OK

        return rv

    @apihook("CoInitializeEx", argc=2)
    def CoInitializeEx(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT CoInitializeEx(
          LPVOID pvReserved,
          DWORD  dwCoInit
        );
        """

        rv = windefs.S_OK

        return rv

    @apihook("CoUninitialize", argc=0)
    def CoUninitialize(self, emu, argv, ctx: api.ApiContext = None):
        """
        void CoUninitialize();
        """

    @apihook("CoInitializeSecurity", argc=9)
    def CoInitializeSecurity(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT CoInitializeSecurity(
          PSECURITY_DESCRIPTOR        pSecDesc,
          LONG                        cAuthSvc,
          SOLE_AUTHENTICATION_SERVICE *asAuthSvc,
          void                        *pReserved1,
          DWORD                       dwAuthnLevel,
          DWORD                       dwImpLevel,
          void                        *pAuthList,
          DWORD                       dwCapabilities,
          void                        *pReserved3
        );
        """

        rv = windefs.S_OK

        authn_level = com.get_define_int(argv[4])
        if authn_level:
            argv[4] = authn_level

        imp_level = com.get_define_int(argv[5])
        if imp_level:
            argv[5] = imp_level

        return rv

    def _zero_com_out_pointer(self, ppv, ptr_size):
        """Zero *ppv so that no COM failure path can leave a stale pointer."""
        self.mem_write(ppv, b"\x00" * ptr_size)

    def _read_clsid(self, rclsid) -> tuple[str, str | None]:
        """Resolve a guest REFCLSID to (clsid_str, registered CLSID name or None)."""
        clsid_bytes = self.mem_read(rclsid, self.sizeof(windefs.GUID()))
        clsid_str = com.convert_guid_bytes_to_str(clsid_bytes)
        return clsid_str, com.get_clsid(clsid_str)

    def _read_iid(self, riid) -> tuple[str, str | None]:
        """Resolve a guest REFIID to (riid_str, registered IID name or None)."""
        riid_bytes = self.mem_read(riid, self.sizeof(windefs.GUID()))
        riid_str = com.convert_guid_bytes_to_str(riid_bytes)
        return riid_str, com.get_iid(riid_str)

    @apihook("CoCreateInstance", argc=5)
    def CoCreateInstance(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT CoCreateInstance(
          REFCLSID  rclsid,
          LPUNKNOWN pUnkOuter,
          DWORD     dwClsContext,
          REFIID    riid,
          LPVOID    *ppv
        );

        COM contract (same as Wine combase CoCreateInstance/CoCreateInstanceEx):
        *ppv is NULL on every failure path, and unsupported classes/interfaces
        return an explicit failure HRESULT. Only the success path allocates an
        interface and writes *ppv.
        """
        rclsid, pUnkOuter, dwClsContext, riid, ppv = argv
        ptr_size = emu.get_ptr_size()

        if not ppv:
            # Wine combase.c:1695-1704 returns E_POINTER when obj is NULL.
            return com.E_POINTER

        # Wine zeroes the interface result before class lookup (combase.c:1908
        # init_multi_qi), so no failure path can leave a stale pointer behind.
        self._zero_com_out_pointer(ppv, ptr_size)

        clsid_str, clsid_name = self._read_clsid(rclsid)
        if not clsid_name:
            logger.info("Unsupported COM CLSID %s", clsid_str)
            return com.REGDB_E_CLASSNOTREG

        argv[0] = clsid_name
        riid_str, iid_name = self._read_iid(riid)
        if not iid_name:
            logger.info("Unsupported COM IID %s", riid_str)
            return com.E_NOINTERFACE

        argv[3] = iid_name
        ci = emu.com.get_interface(emu, ptr_size, iid_name.replace("IID_", ""))
        pv = self.mem_alloc(ptr_size, tag=f"emu.COM.pv_{iid_name}")
        self.mem_write(pv, ci.address.to_bytes(ptr_size, "little"))
        self.mem_write(ppv, pv.to_bytes(ptr_size, "little"))

        return windefs.S_OK

    @apihook("CoGetClassObject", argc=5)
    def CoGetClassObject(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT CoGetClassObject(
          REFCLSID       rclsid,
          DWORD          dwClsContext,
          COSERVERINFO   *pServerInfo,
          REFIID         riid,
          LPVOID         *ppv
        );

        Same COM failure contract as CoCreateInstance: *ppv is NULL on failure
        and an unregistered CLSID returns REGDB_E_CLASSNOTREG (Wine combase.c
        com_get_class_object). Speakeasy models COM interfaces but not
        IClassFactory implementations, so a registered CLSID currently has no
        class object to hand out: return E_NOINTERFACE instead of the previous
        signature-default S_OK with *ppv left NULL.
        """
        rclsid, dwClsContext, pServerInfo, riid, ppv = argv
        ptr_size = emu.get_ptr_size()

        if not ppv:
            return com.E_POINTER

        self._zero_com_out_pointer(ppv, ptr_size)

        clsid_str, clsid_name = self._read_clsid(rclsid)
        if not clsid_name:
            logger.info("Unsupported COM CLSID %s", clsid_str)
            return com.REGDB_E_CLASSNOTREG

        argv[0] = clsid_name
        riid_str, iid_name = self._read_iid(riid)
        if iid_name:
            argv[3] = iid_name
        logger.info("No COM class object for CLSID %s (IID %s)", clsid_name, riid_str)
        return com.E_NOINTERFACE

    @apihook("OleDuplicateData", argc=3)
    def OleDuplicateData(self, emu, argv, ctx: api.ApiContext = None):
        """
        HGLOBAL OleDuplicateData(
          HGLOBAL   hSrc,
          CLIPFORMAT cfFormat,
          UINT      uiFlags
        );

        Duplicate a clipboard data handle. Wine (ole32/ole2.c:3094) routes the
        GDI-object formats through their GDI copy functions and every other
        format through GlobalSize/GlobalAlloc/memcpy. Speakeasy models an
        HGLOBAL as a mapped block, so:

        * NULL source -> NULL (Wine's GlobalSize(NULL) is 0);
        * GDI-object formats -> NULL (no GDI object duplication model; a kernel
          handle is not an HBITMAP/HPALETTE/HMETAFILE);
        * other formats -> a new mapped block with the source contents, or NULL
          when the source is not a mapped HGLOBAL.

        ``uiFlags`` selects GMEM_* flags in Windows; Speakeasy HGLOBALs are
        plain mapped addresses, so the flags are accepted and ignored.
        """
        hsrc, cf_format, _ui_flags = argv
        cf_format = int(cf_format) & 0xFFFF

        if not hsrc:
            return 0
        if cf_format in self.GDI_CLIPBOARD_FORMATS:
            logger.info("OleDuplicateData: unsupported GDI clipboard format %#x", cf_format)
            return 0

        size = self._source_global_size(hsrc)
        if not size:
            logger.info("OleDuplicateData: source %#x is not a mapped HGLOBAL", hsrc)
            return 0

        try:
            source = self.mem_read(hsrc, size)
        except Exception:
            logger.debug("OleDuplicateData: cannot read source %#x (%#x bytes)", hsrc, size, exc_info=True)
            return 0

        dest = self.mem_alloc(size, tag="api.OleDuplicateData")
        try:
            self.mem_write(dest, source)
        except Exception:
            logger.debug("OleDuplicateData: cannot write duplicate at %#x (%#x bytes)", dest, size, exc_info=True)
            self.mem_free(dest)
            return 0

        return dest

    def _source_global_size(self, hsrc: int) -> int:
        """Size of the mapped HGLOBAL block whose base is ``hsrc`` (0 if none)."""
        mm = self.emu.get_address_map(hsrc)
        if mm is None or mm.base != hsrc or mm.free:
            return 0
        return mm.size

    @apihook("CoSetProxyBlanket", argc=8)
    def CoSetProxyBlanket(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT CoSetProxyBlanket(
            IUnknown                 *pProxy,
            DWORD                    dwAuthnSvc,
            DWORD                    dwAuthzSvc,
            OLECHAR                  *pServerPrincName,
            DWORD                    dwAuthnLevel,
            DWORD                    dwImpLevel,
            RPC_AUTH_IDENTITY_HANDLE pAuthInfo,
            DWORD                    dwCapabilities
        );
        """
        return 1

    @apihook("StringFromCLSID", argc=2)
    def StringFromCLSID(self, emu, argv, ctx: api.ApiContext = None):
        """
        HRESULT StringFromCLSID(
        REFCLSID rclsid,
        LPOLESTR *lplpsz
        );
        """

        rclsid, lplpsz = argv
        rv = windefs.S_OK

        guid = self.mem_read(rclsid, self.sizeof(windefs.GUID()))
        u = com.convert_guid_bytes_to_str(guid)
        argv[1] = u
        u = (u + "\x00").encode("utf-16le")

        ptr = self.mem_alloc(len(u), tag="api.StringFromCLSID")

        if lplpsz:
            self.mem_write(lplpsz, ptr.to_bytes(emu.get_ptr_size(), "little"))

        return rv

    @apihook("CoCreateGuid", argc=1)
    def CoCreateGuid(self, emu, argv, ctx: api.ApiContext = None):
        pguid = argv[0]
        guid_bytes = b"\xde\xad\xc0\xde\xbe\xef\xca\xfe\xba\xbe\x01\x23\x45\x67\x89\xab"
        if pguid:
            try:
                self.emu.mem_write(pguid, guid_bytes)
            except Exception:
                self.emu.mem_map(pguid & ~0xFFF, 0x1000)
                self.emu.mem_write(pguid, guid_bytes)
        return 0
