"""Guest vectored-exception-handler (VEH) registry and dispatch bookkeeping.

Windows ``AddVectoredExceptionHandler(First, Handler)`` inserts First-chance
handlers at the front of the dispatch list and last-chance handlers at the
end; the dispatcher walks that list in order before the SEH chain.  The
emulator stores the registrations here so the ordering survives, and keeps the
per-fault state needed while a guest VEH handler is being executed (the handler
runs as normal guest code and returns through a reserved sentinel address).

This module deliberately has no engine imports: it only owns the registration
order and a small immutable snapshot of the fault that started a VEH dispatch.
The emulator (``speakeasy.windows.winemu.WinEmulator``) performs the actual
context/control transfer and interprets the handler return value.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any


def coerce_handler_address(handler: int | Sequence[int]) -> int:
    """Normalize a guest VEH handler identifier to a single address.

    ``kernel32!RemoveVectoredExceptionHandler`` receives the handler pointer as
    its only argument, but the emulated API wrapper forwards the whole ``argv``
    list.  Accept both spellings explicitly here instead of failing on
    ``int(list)`` (or silently ignoring the list).

    Args:
        handler: Handler address, or a one-element sequence holding it (the
            emulated ``argv`` list).

    Returns:
        The handler address truncated to pointer width.

    Raises:
        ValueError: The sequence does not hold exactly one handler address.
        TypeError: The value is neither an integer nor a one-element sequence.

    Unknown input behaviour: any integer address, including 0, is accepted as
    supplied; the registry stores/removes it verbatim.
    """
    if isinstance(handler, (list, tuple)):
        if len(handler) != 1:
            raise ValueError(
                f"expected exactly one vectored exception handler address, got {len(handler)}"
            )
        handler = handler[0]
    if isinstance(handler, bool) or not isinstance(handler, int):
        raise TypeError(
            "vectored exception handler must be an integer address "
            f"or a one-element sequence, got {type(handler).__name__}"
        )
    return handler & 0xFFFFFFFFFFFFFFFF


@dataclass(frozen=True)
class VectoredExceptionHandler:
    """One guest VEH registration.

    Attributes:
        address: Guest virtual address of the handler function.
        first: True for ``AddVectoredExceptionHandler(First=1, ...)``.
    """

    address: int
    first: bool


class VectoredExceptionRegistry:
    """Ordered registry of guest VEH registrations.

    Dispatch order follows Windows ``AddVectoredExceptionHandler`` semantics:
    First-chance handlers run in reverse registration order, followed by
    last-chance handlers in registration order.  As with the previous
    emulator behaviour, registering an address that is already present
    replaces the existing entry (and therefore its ordering).

    Unknown input behaviour: any integer handler address, including 0, is
    stored as supplied.  The dispatcher, not the registry, decides whether the
    address is executable in the guest.
    """

    def __init__(self) -> None:
        # Kept in dispatch order: First entries inserted at the front, last
        # chance entries appended.
        self._entries: list[VectoredExceptionHandler] = []

    def __len__(self) -> int:
        return len(self._entries)

    def __bool__(self) -> bool:
        return bool(self._entries)

    def add(self, first: bool, handler: int) -> None:
        """Register ``handler`` as a First-chance or last-chance VEH.

        Args:
            first: Nonzero/True selects First-chance dispatch order.
            handler: Guest VA of the handler function.

        Returns:
            None.  Re-registering an address replaces its previous entry.
        """
        address = coerce_handler_address(handler)
        self.remove(address)
        entry = VectoredExceptionHandler(address=address, first=bool(first))
        if entry.first:
            self._entries.insert(0, entry)
        else:
            self._entries.append(entry)

    def remove(self, handler: int | Sequence[int]) -> None:
        """Remove every registration for ``handler`` (no-op when absent).

        Args:
            handler: Handler address, or a one-element sequence holding it
                (the emulated ``argv`` list used by the API wrappers).

        Returns:
            None.  An address that is not registered is ignored.

        Raises:
            ValueError: A sequence did not hold exactly one handler address.
            TypeError: The value is neither an integer nor a one-element
                sequence.  Malformed input is rejected explicitly rather than
                silently ignored.
        """
        address = coerce_handler_address(handler)
        self._entries = [entry for entry in self._entries if entry.address != address]

    def dispatch_order(self) -> list[int]:
        """Return registered handler addresses in Windows dispatch order."""
        return [entry.address for entry in self._entries]


@dataclass
class VehDispatchState:
    """Snapshot of the fault that is currently being delivered to VEH handlers.

    Applicable architecture: x86 (the emulator's VEH dispatch is wired to the
    x86 CONTEXT/SEH path; AMD64 keeps the pre-existing unhandled behaviour).

    Attributes:
        except_code: NTSTATUS exception code passed to each handler.
        fault_pc: Guest PC of the faulting instruction at dispatch time.
        faulting_address: Faulting memory address for access violations, or
            None when the exception has no associated address.
        stack_ptr: Guest stack pointer captured before the first handler call;
            each handler invocation rebuilds its frame from this value so
            handler returns cannot accumulate stack residue.
        context: Pre-fault CONTEXT object (Python copy; guest edits do not
            mutate it).
        context_address: Guest VA of the CONTEXT written into EXCEPTION_POINTERS.
        exception_ptrs: Guest VA of the EXCEPTION_POINTERS structure.
        record_address: Guest VA of the EXCEPTION_RECORD structure.
        handlers: Handler addresses in dispatch order.
        next_index: Index of the next handler to invoke.
        deferred_fault: Engine-owned snapshot of a protected read/fetch fault
            whose exception dispatch was deferred (opaque to this module).  It
            is ``None`` for faults dispatched directly from the memory-error
            path.  When set, the emulator finalizes the original fatal error
            instead of resuming the faulting instruction if every handler
            declines.
    """

    except_code: int
    fault_pc: int
    faulting_address: int | None
    stack_ptr: int
    context: Any
    context_address: int
    exception_ptrs: int
    record_address: int
    handlers: tuple[int, ...]
    next_index: int = 0
    deferred_fault: Any | None = None
