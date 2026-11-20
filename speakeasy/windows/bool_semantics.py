# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

"""Return-value policy for BOOL APIs emulated from the Win32 signature database.

The signature database records only that an API returns ``b``/``B`` (a BOOL).
It does not record which question the BOOL answers, and the two classes have
different safe defaults:

* ``predicate_bool`` asks "is this condition true?" (``IsZoomed``,
  ``IsWindow``). With no emulated state behind the condition, the honest
  answer is FALSE. Returning TRUE sends the guest down a branch that trusts
  state the emulator never produced.
* ``status_bool`` asks "did this operation succeed?" (``AdjustTokenGroups``,
  ``MoveFileExW``). The emulator has not performed the state change, so the
  honest answer is FALSE plus a real error in GetLastError. Returning TRUE
  fabricates a completed operation.

:func:`speakeasy.winenv.api.sigdb.bool_return_semantics` classifies the API;
this module turns that classification into the guest-visible result. Both
classes return 0 - the distinction is the LastError side effect. No caller can
receive a fabricated TRUE from the signature fallback.

Applies to x86 and x64 alike: a BOOL is one guest register in both cases.
Unknown inputs never raise; see ``bool_return_semantics`` for the fallback
classification.
"""

from __future__ import annotations

import speakeasy.winenv.api.sigdb as sigdb

# WinError.h: "This function is not supported on this system." It is the
# truthful failure for a state change the emulator cannot perform, as opposed
# to a fabricated success or a misleading parameter-level error.
ERROR_CALL_NOT_IMPLEMENTED = 120


def default_bool_return(sig: sigdb.FuncSig) -> int:
    """Return the guest-visible value for a signature-emulated BOOL API.

    Both semantic classes answer FALSE: neither a condition nor a state change
    may be claimed when the emulator has no evidence for it.

    Args:
        sig: The API's signature (used for documentation symmetry; every BOOL
            classification returns the same value).

    Returns:
        Always 0 (FALSE).
    """
    return 0


def last_error_for_default(sig: sigdb.FuncSig) -> int | None:
    """Return the GetLastError value to set after the default BOOL result.

    Args:
        sig: The API's signature.

    Returns:
        ``ERROR_CALL_NOT_IMPLEMENTED`` for ``status_bool`` APIs (the state
        change did not happen), and ``None`` for ``predicate_bool`` APIs (a
        false condition is not an error; LastError is left untouched).
        Non-BOOL signatures also return ``None``; the engine keeps its
        previous non-BOOL LastError handling.
    """
    if sig.ret_kind not in sigdb.BOOL_KINDS:
        return None
    if sigdb.bool_return_semantics(sig.dll, sig.name, sig) == sigdb.BOOL_SEMANTICS_STATUS:
        return ERROR_CALL_NOT_IMPLEMENTED
    return None
