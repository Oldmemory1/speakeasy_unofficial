"""Explicit guest-call chaining for Win32 API handlers.

Some APIs are specified in terms of guest functions that the API must invoke
before it returns: CRT initializer tables (``_initterm``/``_initterm_e``),
window procedures, thread entry points, and similar callbacks. Handlers run in
Python while Unicorn is executing the guest, so a handler cannot simply call a
guest function and read back its result. The engine already supports *one*
guest callback per handler through
``speakeasy.profiler.ApiCallbackFrame`` and the reserved
``API_CALLBACK_HANDLER_ADDR`` sentinel; this module adds an explicit,
ordered chain of such callbacks that resumes inside the engine.

A ``GuestCallChain`` is stored in ``run.api_callbacks``. Starting a chain arms
the first guest function:

* the API call site is saved (``ret_addr = [SP]``, ``base_sp = SP``);
* ``SP`` is reset to ``base_sp`` and a call frame is pushed with
  ``API_CALLBACK_HANDLER_ADDR`` as the return address (on x64 the 32-byte
  home space is included below ``base_sp``);
* ``PC`` is set to the guest function entry.

When the guest function returns, the engine traps on the sentinel and calls
``GuestCallChain.advance``. The chain reads the function's 32-bit ``int``
result from EAX/RAX, restores ``base_sp`` (undoing the x64 home-space offset so
the chain never accumulates stack drift), and either arms the next function or
tells the engine to complete the intercepted API call with
``do_call_return``. Because every function executes as ordinary guest code,
initializers may themselves call imported APIs, raise exceptions handled by
SEH/VEH, and consume the normal instruction/API budgets.

Concurrency/state: a chain is scoped to one ``Run`` and is driven only by that
run's callback completion path. Chains nest LIFO like any other callback frame,
so an initializer that calls another chain-based API works without special
handling.

Calling convention: guest functions are invoked with no arguments (the CRT
initializer types ``_PVFV``/``_PIFV`` take none). ``conv`` is the convention
used to finish the intercepted API call, not the initializer call.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

import speakeasy.winenv.arch as e_arch
from speakeasy.errors import WindowsEmuError
from speakeasy.windows.common import API_CALLBACK_HANDLER_ADDR

#: Mask for the 32-bit ``int`` returned by ``_PIFV`` initializers on both x86
#: and x64 (the x64 ABI leaves the upper 32 bits of RAX unspecified).
_INT32_MASK = 0xFFFFFFFF


@dataclass
class GuestCallChain:
    """Ordered sequence of zero-argument guest calls issued by one API handler.

    Attributes:
        functions: Guest function entry points, called in order.
        base_sp: Stack pointer at the API call site (points at the API return
            address). Reset before every call so the chain restores the guest
            stack exactly once.
        ret_addr: Return address of the intercepted API call.
        conv: Calling convention used when completing the API call
            (``CALL_CONV_CDECL`` for ``_initterm``/``_initterm_e``).
        cleanup_argc: Argument slot count for ``do_call_return`` cleanup. Only
            meaningful for stack-cleaning conventions; cdecl uses 0 because
            the guest caller removes its own arguments.
        stop_on_nonzero: When true, the first non-zero ``int`` result stops the
            chain and becomes the API return value (``_initterm_e``). When
            false, results are ignored (``_initterm``).
        cursor: Index of the next function to arm.
        final_value: API return value once the chain has completed.
    """

    functions: tuple[int, ...]
    base_sp: int
    ret_addr: int
    conv: int
    cleanup_argc: int = 0
    stop_on_nonzero: bool = False
    cursor: int = 0
    final_value: int = field(default=0, init=False)

    def _enter_next(self, emu: Any) -> None:
        """Arm the guest call for ``functions[cursor]``.

        Resets SP to the API call site so each call starts from the same stack
        posture, pushes the callback sentinel, and points PC at the function.
        """
        emu.set_stack_ptr(self.base_sp)
        emu.set_func_args(
            self.base_sp,
            API_CALLBACK_HANDLER_ADDR,
            conv=e_arch.CALL_CONV_CDECL,
        )
        emu.set_pc(self.functions[self.cursor])

    def advance(self, emu: Any, callback_result: int) -> bool:
        """Record one completed guest call and arm the next one if needed.

        Args:
            emu: The active ``WindowsEmulator`` (provides stack/PC access).
            callback_result: Value of EAX (x86) / RAX (x64) when the guest
                function returned to ``API_CALLBACK_HANDLER_ADDR``.

        Returns:
            ``True`` when another function was armed and guest execution must
            continue at that function. ``False`` when the chain is finished;
            the caller must complete the API call with
            ``do_call_return(cleanup_argc, ret_addr, api_return(), conv=conv)``.
        """
        result = int(callback_result) & _INT32_MASK
        self.cursor += 1

        if self.stop_on_nonzero and result != 0:
            self.final_value = result
            self._restore_stack(emu)
            return False

        if self.cursor >= len(self.functions):
            self.final_value = 0
            self._restore_stack(emu)
            return False

        self._enter_next(emu)
        return True

    def _restore_stack(self, emu: Any) -> None:
        """Restore SP to the API call site before completing the API call."""
        emu.set_stack_ptr(self.base_sp)

    def api_return(self) -> int:
        """Return value of the intercepted API call once the chain is done."""
        return self.final_value


def start_guest_call_chain(
    emu: Any,
    functions: Iterable[int],
    *,
    conv: int,
    stop_on_nonzero: bool = False,
    cleanup_argc: int = 0,
) -> GuestCallChain | None:
    """Start an ordered chain of guest calls for the active API handler.

    The handler must return immediately after calling this function; the engine
    resumes the guest at the first function and drives the rest of the chain
    through ``GuestCallChain.advance`` when each function returns.

    Args:
        emu: The active ``WindowsEmulator``.
        functions: Guest function entry points in call order. NULL entries must
            already be filtered out by the caller. An empty iterable is a
            no-op and returns ``None`` (the API returns the handler's value).
        conv: Calling convention of the intercepted API call, used when the
            chain completes the call.
        stop_on_nonzero: Stop at the first non-zero ``int`` result and return
            it (``_initterm_e``).
        cleanup_argc: Argument slots cleaned by ``do_call_return`` for
            stack-cleaning conventions; 0 for cdecl.

    Returns:
        The chain stored on ``run.api_callbacks``, or ``None`` when there is
        nothing to call.

    Raises:
        WindowsEmuError: If no run is active, the function list contains a
            zero entry, or the architecture cannot supply a return register
            (the caller validates entries; this is a programming error).
    """
    entries = tuple(int(fn) for fn in functions)
    if 0 in entries:
        raise WindowsEmuError("guest call chain entries must be non-NULL")
    if not entries:
        return None

    run = emu.get_current_run()
    if run is None:
        raise WindowsEmuError("guest call chain requires an active run")

    chain = GuestCallChain(
        functions=entries,
        base_sp=emu.get_stack_ptr(),
        ret_addr=emu.get_ret_address(),
        conv=conv,
        cleanup_argc=cleanup_argc,
        stop_on_nonzero=stop_on_nonzero,
    )
    run.api_callbacks.append(chain)
    chain._enter_next(emu)
    return chain
