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

from dataclasses import dataclass
from typing import Any


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
        address = int(handler) & 0xFFFFFFFFFFFFFFFF
        self.remove(address)
        entry = VectoredExceptionHandler(address=address, first=bool(first))
        if entry.first:
            self._entries.insert(0, entry)
        else:
            self._entries.append(entry)

    def remove(self, handler: int) -> None:
        """Remove every registration for ``handler`` (no-op when absent)."""
        address = int(handler) & 0xFFFFFFFFFFFFFFFF
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
