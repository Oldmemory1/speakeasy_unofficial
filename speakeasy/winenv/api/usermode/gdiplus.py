"""Minimal stateful emulation for GDI+ lifecycle APIs."""

from __future__ import annotations

from .. import api

GDI_PLUS_OK = 0
GDI_PLUS_GENERIC_ERROR = 1
GDI_PLUS_INVALID_PARAMETER = 2


class Gdiplus(api.ApiHandler):
    """Emulate the deterministic lifecycle subset used during process startup."""

    name = "gdiplus"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    _TOKEN_BASE = 0x6D000000
    _TOKEN_STRIDE = 4

    def __init__(self, emu):
        super().__init__(emu)
        self._next_token = self._TOKEN_BASE
        self._tokens: set[int] = set()
        super().__get_hook_attrs__(self)

    @apihook("GdiplusStartup", argc=3)
    def GdiplusStartup(self, emu, argv, ctx: api.ApiContext = None):
        """GdiplusStartup(ULONG_PTR *token, const GdiplusStartupInput *input, ...)."""
        token_address, input_address, _output_address = argv
        if not token_address or not input_address:
            return GDI_PLUS_INVALID_PARAMETER

        token = self._next_token
        self._next_token += self._TOKEN_STRIDE
        self._tokens.add(token)
        try:
            emu.mem_write(
                token_address,
                token.to_bytes(emu.get_ptr_size(), "little"),
            )
        except Exception:
            self._tokens.discard(token)
            return GDI_PLUS_GENERIC_ERROR
        return GDI_PLUS_OK

    @apihook("GdiplusShutdown", argc=1)
    def GdiplusShutdown(self, emu, argv, ctx: api.ApiContext = None):
        """GdiplusShutdown(ULONG_PTR token); this function has no return value."""
        token = int(argv[0])
        if token not in self._tokens:
            # GdiplusShutdown is void. A stale token cannot be made into a
            # useful status code, so leave lifecycle cleanup idempotent.
            return None
        self._tokens.remove(token)
        return None
