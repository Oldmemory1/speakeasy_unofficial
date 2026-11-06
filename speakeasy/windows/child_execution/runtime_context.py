"""Own child runtime context switching and one-shot entry observation.

The context manager uses an injected backend to capture and restore public
process/thread/run handles. The entry observer uses the emulator's registered
code-hook interface rather than patching engine objects or private state.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from types import TracebackType
from typing import Protocol, runtime_checkable

from .models import (
    ChildEventOwnership,
    ChildFailureKind,
    ChildLaunchRequest,
    ChildProcessContext,
    EmulatedProcessProtocol,
    EmulatedRunProtocol,
    EmulatedThreadProtocol,
    LoadedChildImage,
)


class ChildRuntimeContextError(RuntimeError):
    """Expected context activation or restoration failure.

    Args:
        message: Human-readable failure detail.

    The error belongs to one child run and must be converted to a child result
    by its scheduler or runner.
    """

    kind = ChildFailureKind.CONTEXT


class ChildEntrypointObservationError(RuntimeError):
    """Invalid one-shot entry observation setup.

    Args:
        message: Human-readable failure detail.
    """

    kind = ChildFailureKind.CONTEXT


@dataclass(frozen=True)
class ParentRuntimeContext:
    """Opaque parent handles captured before activating a child.

    Args:
        process: Parent process active before child activation.
        thread: Parent thread active before child activation.
        run: Parent run active before child activation.

    ``None`` represents the absence of that handle. The backing context
    backend owns interpretation and restoration; callers must not mutate these
    engine objects through this record.
    """

    process: EmulatedProcessProtocol | None
    thread: EmulatedThreadProtocol | None
    run: EmulatedRunProtocol | None


@runtime_checkable
class ChildRuntimeContextBackend(Protocol):
    """Capture, activate, and restore an emulator's child runtime context."""

    def capture_parent(self) -> ParentRuntimeContext:
        """Capture the handles that must be restored after child execution.

        Returns:
            Immutable parent process, thread, and run handles.

        Side effects:
            None. The backend must not switch context or alter metadata.
        """
        ...

    def activate(
        self,
        request: ChildLaunchRequest,
        image: LoadedChildImage,
        ownership: ChildEventOwnership,
    ) -> ChildProcessContext:
        """Switch the emulator to one child's runtime context.

        Args:
            request: Child launch identity and parent correlation.
            image: Already loaded non-primary child image.
            ownership: Stable event ownership for the child.

        Returns:
            Active child process, thread, module, run, and ownership handles.

        Side effects:
            Switches process and thread context inside the existing emulator.
            It must not replace root metadata, create another process, queue a
            run, or execute child code.
        """
        ...

    def restore_parent(self, parent: ParentRuntimeContext) -> None:
        """Restore a previously captured parent runtime context.

        Args:
            parent: Immutable snapshot returned by :meth:`capture_parent`.

        Returns:
            ``None``.

        Side effects:
            Restores process, thread, and run handles. This operation must be
            idempotent because cleanup can run after partial activation.
        """
        ...


@runtime_checkable
class ChildCodeHook(Protocol):
    """Minimal lifecycle surface for an explicitly registered code hook."""

    def disable(self) -> None:
        """Disable the hook without inventing entry-point evidence."""
        ...


@runtime_checkable
class ChildEntrypointHookBackend(Protocol):
    """Register an address-scoped code hook through a public engine API."""

    def add_code_hook(
        self,
        callback: Callable[[object, int, int], bool],
        *,
        begin: int,
        end: int,
    ) -> ChildCodeHook:
        """Register one code-range callback.

        Args:
            callback: Receives ``(engine, address, size)`` when code executes.
            begin: Inclusive beginning of the watched child entry address.
            end: Exclusive end of the watched range.

        Returns:
            Hook handle exposing an idempotent ``disable`` operation.

        Side effects:
            Registers exactly one callback with the emulator. It must not
            execute code or alter process/thread state.
        """
        ...


class ChildContextSession(AbstractContextManager[ChildProcessContext]):
    """Activate one child context and restore its parent on every exit path.

    Args:
        backend: Explicit public context-switching implementation.
        parent: Parent handles captured when the session was created.
        request: Child launch identity.
        image: Non-primary image loaded for the launch.
        ownership: Expected child event ownership.

    A session is single-use. The backend owns context switching; this class
    owns ordering, validation, and guaranteed restoration.
    """

    def __init__(
        self,
        backend: ChildRuntimeContextBackend,
        parent: ParentRuntimeContext,
        request: ChildLaunchRequest,
        image: LoadedChildImage,
        ownership: ChildEventOwnership,
    ) -> None:
        self._backend = backend
        self._parent = parent
        self._request = request
        self._image = image
        self._ownership = ownership
        self._entered = False
        self._exited = False

    def __enter__(self) -> ChildProcessContext:
        """Activate and validate the child runtime context.

        Returns:
            The active child process context.

        Side effects:
            Switches process/thread/run context through the injected backend.
            If activation or validation fails, restores the parent immediately.

        Raises:
            ChildRuntimeContextError: If activation, validation, or rollback
                fails, or if a ``with`` block is unavailable at this point.
        """

        if self._entered or self._exited:
            raise ChildRuntimeContextError("child context session is single-use")
        self._entered = True

        context: ChildProcessContext | None = None
        try:
            context = self._backend.activate(
                self._request,
                self._image,
                self._ownership,
            )
            self._validate_context(context)
        except Exception as exc:
            try:
                self._backend.restore_parent(self._parent)
            except Exception as restore_exc:
                raise ChildRuntimeContextError(
                    "child activation failed and parent restoration also failed"
                ) from restore_exc
            if isinstance(exc, ChildRuntimeContextError):
                raise
            raise ChildRuntimeContextError(
                f"cannot activate child context: {type(exc).__name__}: {exc}"
            ) from exc

        return context

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        """Restore the parent context and preserve any body exception.

        Args:
            exc_type: Exception type raised by the ``with`` body, if any.
            exc_value: Exception instance raised by the body, if any.
            traceback: Body exception traceback, if any.

        Returns:
            ``False`` so child exceptions continue to their owning runner.

        Side effects:
            Restores the captured parent context exactly once, including on
            exception paths.

        Raises:
            ChildRuntimeContextError: If parent restoration fails and the body
                did not already raise. A body exception is preserved and a
                restoration note is attached when cleanup also fails.
        """

        if self._exited:
            return False
        self._exited = True

        try:
            self._backend.restore_parent(self._parent)
        except Exception as restore_exc:
            restore_error = ChildRuntimeContextError(
                f"cannot restore parent context: {type(restore_exc).__name__}: "
                f"{restore_exc}"
            )
            if exc_value is not None:
                exc_value.add_note(str(restore_error))
                return False
            raise restore_error from restore_exc
        return False

    def _validate_context(self, context: ChildProcessContext) -> None:
        """Verify that an activated context belongs to the requested child.

        Args:
            context: Backend result about to be yielded.

        Returns:
            ``None`` when all identity and ownership handles match.

        Side effects:
            None.

        Raises:
            ChildRuntimeContextError: If launch, image, process, thread, or run
                identity does not match.
        """

        if context.ownership != self._ownership:
            raise ChildRuntimeContextError(
                "child context ownership does not match the selected launch"
            )
        if context.module is not self._image.module:
            raise ChildRuntimeContextError(
                "child context module does not match the loaded image"
            )
        if context.process.pid != self._ownership.child_pid:
            raise ChildRuntimeContextError(
                "child process pid does not match event ownership"
            )
        if context.run.process_context is not context.process:
            raise ChildRuntimeContextError(
                "child run is not bound to the activated process"
            )
        if context.run.thread is not context.thread:
            raise ChildRuntimeContextError(
                "child run is not bound to the activated thread"
            )


class ChildRuntimeContextManager:
    """Create single-use child context sessions.

    Args:
        backend: Explicit public context-switching implementation.
    """

    def __init__(self, backend: ChildRuntimeContextBackend) -> None:
        self._backend = backend

    def enter(
        self,
        request: ChildLaunchRequest,
        image: LoadedChildImage,
        ownership: ChildEventOwnership,
    ) -> AbstractContextManager[ChildProcessContext]:
        """Capture the parent and return a single-use child context session.

        Args:
            request: Child launch identity.
            image: Loaded non-primary child image.
            ownership: Stable child event ownership.

        Returns:
            A context manager that activates the child on entry and restores
            the captured parent on every exit path.

        Side effects:
            Captures parent process/thread/run handles through the injected
            backend. It does not activate the child until the returned manager
            is entered.
        """

        if image.request_launch_id != request.launch_id:
            raise ChildRuntimeContextError(
                "loaded image belongs to a different launch"
            )
        if ownership.launch_id != request.launch_id:
            raise ChildRuntimeContextError(
                "event ownership belongs to a different launch"
            )
        parent = self._backend.capture_parent()
        return ChildContextSession(
            self._backend,
            parent,
            request,
            image,
            ownership,
        )


class OneShotChildEntrypointObserver:
    """Record one-shot entry evidence from explicitly registered code hooks.

    Args:
        hook_backend: Emulator object exposing the public code-hook API.

    The observer owns only pending hook handles and launch IDs whose entry
    points actually fired. It never infers entry from process existence, queue
    state, or a run object's presence.
    """

    def __init__(self, hook_backend: ChildEntrypointHookBackend) -> None:
        self._hook_backend = hook_backend
        self._active_launch_id: str | None = None
        self._active_hook: ChildCodeHook | None = None
        self._reached_launch_ids: set[str] = set()

    def arm(self, context: ChildProcessContext) -> None:
        """Register one address-scoped hook for the child entry point.

        Args:
            context: Child context whose run start address is the entry point.

        Returns:
            ``None``.

        Side effects:
            Disarms any previous pending hook and registers exactly one
            callback for the active launch. It does not mark the entry point as
            reached.

        Raises:
            ChildEntrypointObservationError: If the context has no usable
                entry address or the same launch was already observed.
        """

        launch_id = context.ownership.launch_id
        entrypoint = context.run.start_addr
        if not isinstance(entrypoint, int) or entrypoint <= 0:
            raise ChildEntrypointObservationError(
                "child context has no valid entry-point address"
            )
        if launch_id in self._reached_launch_ids:
            raise ChildEntrypointObservationError(
                f"child entry point was already observed for {launch_id}"
            )

        if self._active_launch_id is not None:
            self.disarm(self._active_launch_id)

        hook_ref: list[ChildCodeHook] = []

        def on_code(_engine: object, address: int, _size: int) -> bool:
            if address != entrypoint:
                return True
            if launch_id not in self._reached_launch_ids:
                self._reached_launch_ids.add(launch_id)
            if hook_ref:
                hook_ref[0].disable()
            if self._active_launch_id == launch_id:
                self._active_launch_id = None
                self._active_hook = None
            return True

        hook = self._hook_backend.add_code_hook(
            on_code,
            begin=entrypoint,
            end=entrypoint + 1,
        )
        hook_ref.append(hook)
        self._active_launch_id = launch_id
        self._active_hook = hook

    def disarm(self, launch_id: str) -> None:
        """Disable and forget a pending entry hook for one child.

        Args:
            launch_id: Stable child launch identifier.

        Returns:
            ``None``.

        Side effects:
            Disables at most one pending hook. Previously recorded reached
            evidence is retained. Repeated calls are safe.
        """

        if launch_id != self._active_launch_id:
            return
        hook = self._active_hook
        self._active_launch_id = None
        self._active_hook = None
        if hook is not None:
            hook.disable()

    def reached(self, launch_id: str) -> bool:
        """Return whether the registered entry hook actually fired.

        Args:
            launch_id: Stable child launch identifier.

        Returns:
            ``True`` only after this observer's callback fired for the launch.

        Side effects:
            None.
        """

        return launch_id in self._reached_launch_ids


__all__ = [
    "ChildCodeHook",
    "ChildContextSession",
    "ChildEntrypointHookBackend",
    "ChildEntrypointObservationError",
    "ChildRuntimeContextBackend",
    "ChildRuntimeContextError",
    "ChildRuntimeContextManager",
    "OneShotChildEntrypointObserver",
    "ParentRuntimeContext",
]
