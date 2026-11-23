# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import logging
import uuid
from typing import TYPE_CHECKING

import speakeasy.common as common
import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.winenv.defs.enums import RPC_C_AUTHN_LEVEL, RPC_C_IMP_LEVEL
from speakeasy.winenv.defs.lookup import decode
from speakeasy.winenv.defs.windows import com as comdefs

from .. import api

if TYPE_CHECKING:
    from speakeasy.windows.netman import NetworkManager
    from speakeasy.windows.win32 import Win32Emulator

logger = logging.getLogger(__name__)


class Ole32(api.ApiHandler):
    name = "ole32"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    # Largest CoTaskMemAlloc request that is backed with real emulator memory.
    # This is an emulator policy bound: mapping multi-GB ranges is not a
    # faithful allocation success and can hang Unicorn. It is not a Windows
    # semantic; larger requests fail with NULL like an out-of-memory malloc.
    MAX_TASK_ALLOC = 0x10000000

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
        self.netman: NetworkManager = emu.get_network_manager()
        self.com_init: dict[int, tuple[int, int]] = {}
        # Explicit ownership tracking for the COM task allocator: block base ->
        # requested cb. CoTaskMemFree/CoTaskMemRealloc only touch these blocks;
        # image pages and mappings owned by other APIs are never released.
        self._task_allocs: dict[int, int] = {}

    def co_initialize(self, emu, model):
        tid = emu.get_current_thread().id
        count, current = self.com_init.get(tid, (0, None))
        if count and current != model:
            return comdefs.RPC_E_CHANGED_MODE
        self.com_init[tid] = (count + 1, model)
        return comdefs.S_FALSE if count else windefs.S_OK

    def co_uninitialize(self, emu):
        tid = emu.get_current_thread().id
        count, model = self.com_init.get(tid, (0, 0))
        if count > 1:
            self.com_init[tid] = (count - 1, model)
        else:
            self.com_init.pop(tid, None)

    @apihook("OleInitialize", argc=1)
    def OleInitialize(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT OleInitialize(
            LPVOID pvReserved
        );
        """
        return self.co_initialize(emu, comdefs.COINIT_APARTMENTTHREADED)

    @apihook("OleUninitialize", argc=0)
    def OleUninitialize(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void OleUninitialize();
        """
        self.co_uninitialize(emu)

    @apihook("CoInitialize", argc=1)
    def CoInitialize(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT CoInitialize(
            LPVOID pvReserved
        );
        """
        return self.co_initialize(emu, comdefs.COINIT_APARTMENTTHREADED)

    @apihook("CoInitializeEx", argc=2)
    def CoInitializeEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT CoInitializeEx(
            LPVOID pvReserved,
            DWORD dwCoInit
        );
        """
        pvReserved, dwCoInit = argv
        return self.co_initialize(emu, dwCoInit & comdefs.COINIT_APARTMENTTHREADED)

    @apihook("CoUninitialize", argc=0)
    def CoUninitialize(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void CoUninitialize();
        """
        self.co_uninitialize(emu)

    @apihook("CoInitializeSecurity", argc=9)
    def CoInitializeSecurity(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT CoInitializeSecurity(
            PSECURITY_DESCRIPTOR pSecDesc,
            LONG cAuthSvc,
            SOLE_AUTHENTICATION_SERVICE *asAuthSvc,
            void *pReserved1,
            DWORD dwAuthnLevel,
            DWORD dwImpLevel,
            void *pAuthList,
            DWORD dwCapabilities,
            void *pReserved3
        );
        """
        rv = windefs.S_OK

        ctx.args["dwAuthnLevel"].display = decode(RPC_C_AUTHN_LEVEL, argv[4])
        ctx.args["dwImpLevel"].display = decode(RPC_C_IMP_LEVEL, argv[5])

        return rv

    def _zero_com_out_pointer(self, ppv, ptr_size):
        """Zero *ppv so that no COM failure path can leave a stale pointer."""
        self.mem_write(ppv, b"\x00" * ptr_size)

    def _read_clsid(self, rclsid) -> tuple[str, str | None]:
        """Resolve a guest REFCLSID to (clsid_str, registered CLSID name or None)."""
        clsid_bytes = self.mem_read(rclsid, self.sizeof(windefs.GUID()))
        clsid_str = comdefs.convert_guid_bytes_to_str(clsid_bytes)
        return clsid_str, comdefs.get_clsid(clsid_str)

    def _read_iid(self, riid) -> tuple[str, str | None]:
        """Resolve a guest REFIID to (riid_str, registered IID name or None)."""
        riid_bytes = self.mem_read(riid, self.sizeof(windefs.GUID()))
        riid_str = comdefs.convert_guid_bytes_to_str(riid_bytes)
        return riid_str, comdefs.get_iid(riid_str)

    @apihook("CoCreateInstance", argc=5)
    def CoCreateInstance(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT CoCreateInstance(
            REFCLSID rclsid,
            LPUNKNOWN pUnkOuter,
            DWORD dwClsContext,
            REFIID riid,
            LPVOID *ppv
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
            return comdefs.E_POINTER

        # Wine zeroes the interface result before class lookup (combase.c:1908
        # init_multi_qi), so no failure path can leave a stale pointer behind.
        self._zero_com_out_pointer(ppv, ptr_size)

        clsid_str, clsid_name = self._read_clsid(rclsid)
        if not clsid_name:
            logger.info("Unsupported COM CLSID %s", clsid_str)
            return comdefs.REGDB_E_CLASSNOTREG

        ctx.args["rclsid"].display = clsid_name
        riid_str, iid_name = self._read_iid(riid)
        if not iid_name:
            logger.info("Unsupported COM IID %s", riid_str)
            return comdefs.E_NOINTERFACE

        ctx.args["riid"].display = iid_name
        ci = emu.com.get_interface(emu, ptr_size, iid_name.replace("IID_", ""))
        pv = self.mem_alloc(ptr_size, tag=f"emu.COM.pv_{iid_name}")
        self.write_ptr(pv, ci.address)
        self.write_ptr(ppv, pv)

        return windefs.S_OK

    @apihook("CoGetClassObject", argc=5)
    def CoGetClassObject(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT CoGetClassObject(
            REFCLSID rclsid,
            DWORD dwClsContext,
            COSERVERINFO *pServerInfo,
            REFIID riid,
            LPVOID *ppv
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
            return comdefs.E_POINTER

        self._zero_com_out_pointer(ppv, ptr_size)

        clsid_str, clsid_name = self._read_clsid(rclsid)
        if not clsid_name:
            logger.info("Unsupported COM CLSID %s", clsid_str)
            return comdefs.REGDB_E_CLASSNOTREG

        ctx.args["rclsid"].display = clsid_name
        riid_str, iid_name = self._read_iid(riid)
        if iid_name:
            ctx.args["riid"].display = iid_name
        logger.info("No COM class object for CLSID %s (IID %s)", clsid_name, riid_str)
        return comdefs.E_NOINTERFACE

    @apihook("CoGetObject", argc=4)
    def CoGetObject(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT CoGetObject(
            LPCWSTR pszName,
            BIND_OPTS *pBindOptions,
            REFIID riid,
            void **ppv
        );

        No moniker names are modeled, so every name fails to parse.
        """
        pszName, pBindOptions, riid, ppv = argv

        if pszName:
            ctx.args["pszName"].display = self.read_mem_string(pszName, 2)
        if ppv:
            self.mem_write(ppv, b"\x00" * emu.get_ptr_size())
        return comdefs.MK_E_SYNTAX

    @apihook("OleDuplicateData", argc=3)
    def OleDuplicateData(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
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
    def CoSetProxyBlanket(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT CoSetProxyBlanket(
            IUnknown *pProxy,
            DWORD dwAuthnSvc,
            DWORD dwAuthzSvc,
            OLECHAR *pServerPrincName,
            DWORD dwAuthnLevel,
            DWORD dwImpLevel,
            RPC_AUTH_IDENTITY_HANDLE pAuthInfo,
            DWORD dwCapabilities
        );
        """
        return windefs.S_OK

    @apihook("StringFromCLSID", argc=2)
    def StringFromCLSID(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT StringFromCLSID(
            REFCLSID rclsid,
            LPOLESTR *lplpsz
        );
        """
        rclsid, lplpsz = argv
        rv = windefs.S_OK

        guid = self.mem_read(rclsid, self.sizeof(windefs.GUID()))
        u = comdefs.convert_guid_bytes_to_str(guid)
        ctx.args["lplpsz"].display = u
        u = (u + "\x00").encode("utf-16le")

        ptr = self.mem_alloc(len(u), tag="api.StringFromCLSID")
        self.mem_write(ptr, u)

        if lplpsz:
            self.write_ptr(lplpsz, ptr)

        return rv

    @apihook("CLSIDFromProgID", argc=2)
    def CLSIDFromProgID(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT CLSIDFromProgID(
            LPCOLESTR lpszProgID,
            LPCLSID lpclsid
        );
        """
        lpszProgID, lpclsid = argv

        progid = self.read_mem_string(lpszProgID, 2) if lpszProgID else ""
        clsid = comdefs.PROGID_CLSIDS.get(progid.lower())
        if clsid is None:
            self.mem_write(lpclsid, b"\x00" * 16)
            return comdefs.CO_E_CLASSSTRING

        self.mem_write(lpclsid, uuid.UUID(clsid).bytes_le)
        ctx.args["lpclsid"].display = clsid
        return windefs.S_OK

    @apihook("CLSIDFromProgIDEx", argc=2)
    def CLSIDFromProgIDEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT CLSIDFromProgIDEx(
            LPCOLESTR lpszProgID,
            LPCLSID lpclsid
        );
        """
        return self.CLSIDFromProgID(emu, argv, ctx)

    @apihook("StringFromGUID2", argc=3)
    def StringFromGUID2(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int StringFromGUID2(
            REFGUID rguid,
            LPOLESTR lpsz,
            int cchMax
        );
        """
        rguid, lpsz, cchMax = argv

        guid = self.mem_read(rguid, self.sizeof(windefs.GUID()))
        u = comdefs.convert_guid_bytes_to_str(guid) + "\x00"
        if cchMax < len(u):
            return 0

        self.write_mem_string(u, lpsz, 2)
        ctx.args["lpsz"].display = u[:-1]
        return len(u)

    @apihook("CoTaskMemAlloc", argc=1)
    def CoTaskMemAlloc(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void *CoTaskMemAlloc(SIZE_T cb);

        Allocate a writable block of ``cb`` bytes and return its address, or
        NULL when the request is too large for the emulator or the underlying
        mapping fails. This is the COM task allocator's documented contract,
        not a generic ``ret=p`` rule: a successful call returns a page-aligned,
        guest-readable/writable block, and the block is recorded in
        ``_task_allocs`` so that only this handler's own memory can be freed.
        """
        (cb,) = argv
        return self._task_alloc(cb)

    @apihook("CoTaskMemFree", argc=1)
    def CoTaskMemFree(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void CoTaskMemFree(LPVOID pv);

        Release a block previously returned by this handler. Untracked
        pointers (image pages, mappings owned by other APIs, NULL, or a second
        free) are ignored: the task allocator must never unmap memory it does
        not own.
        """
        (pv,) = argv
        self._task_free(pv)

    @apihook("CoTaskMemRealloc", argc=2)
    def CoTaskMemRealloc(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void *CoTaskMemRealloc(LPVOID pv, SIZE_T cb);

        Reallocate a tracked task-allocator block. ``pv == NULL`` behaves like
        ``CoTaskMemAlloc(cb)``; ``cb == 0`` frees the block and returns NULL.
        An untracked pointer returns NULL without touching the caller's
        memory. On success the old contents are copied up to
        ``min(old_cb, cb)`` bytes before the old block is released.
        """
        pv, cb = argv
        pv = int(pv)
        cb = int(cb)

        if not pv:
            return self._task_alloc(cb)
        if cb == 0:
            self._task_free(pv)
            return 0

        old_cb = self._task_allocs.get(pv)
        if old_cb is None:
            logger.debug("CoTaskMemRealloc: ignoring untracked pointer %#x", pv)
            return 0

        new_addr = self._task_alloc(cb)
        if not new_addr:
            # Allocation failure leaves the original block valid and tracked,
            # matching the C realloc contract.
            return 0

        copy_len = min(old_cb, cb)
        if copy_len:
            self.mem_copy(new_addr, pv, copy_len)

        self._task_free(pv)
        return new_addr

    @apihook("CoCreateGuid", argc=1)
    def CoCreateGuid(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT CoCreateGuid(
            GUID *pguid
        );
        """
        (pguid,) = argv
        if not pguid:
            return windefs.E_INVALIDARG
        self.mem_write(pguid, uuid.UUID(bytes=emu.rng.randbytes(16), version=4).bytes_le)
        return windefs.S_OK

    def _task_alloc(self, cb: int) -> int:
        """Map and track a task-allocator block for ``cb`` bytes (0 on failure)."""
        if cb < 0 or cb > self.MAX_TASK_ALLOC:
            logger.debug("CoTaskMemAlloc: refusing oversized request %#x", cb)
            return 0

        page_size = int(self.emu.page_size)
        size = max(int(cb), 1)
        size = (size + page_size - 1) & ~(page_size - 1)

        try:
            addr = self.mem_alloc(size, tag="api.CoTaskMemAlloc", perms=common.PERM_MEM_RW)
        except Exception:
            logger.debug("CoTaskMemAlloc: could not map %#x bytes", size, exc_info=True)
            return 0
        if not addr:
            return 0

        self._task_allocs[addr] = int(cb)
        return addr

    def _task_free(self, pv: int) -> None:
        """Release an owned task-allocator block; untracked pointers are ignored."""
        pv = int(pv)
        if not pv:
            return
        if self._task_allocs.pop(pv, None) is None:
            logger.debug("CoTaskMemFree: ignoring untracked pointer %#x", pv)
            return
        self.mem_free(pv)
