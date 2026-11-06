"""Load resolved child bytes as non-primary emulation images.

The loader separates byte-to-image construction from engine image mapping.
Both dependencies are injected explicitly, so the module can validate and test
the complete load boundary without patching the emulator or depending on its
private state.
"""

from __future__ import annotations

import hashlib
import ntpath
from dataclasses import replace
from typing import Protocol, runtime_checkable

from speakeasy.windows.loaders import LoadedImage, PeLoader

from .models import (
    ChildFailureKind,
    ChildLaunchRequest,
    ChildTerminationReason,
    EmulatedModuleProtocol,
    LoadedChildImage,
    ResolvedChildTarget,
)


class ChildImageLoadError(RuntimeError):
    """Expected failure while validating or loading a child image.

    Args:
        message: Human-readable reason for the load failure.
        termination_reason: Stable child termination classification.

    The consuming scheduler or runner converts this exception into a child
    result. It must not escape as a parent simulation error.
    """

    kind = ChildFailureKind.LOAD

    def __init__(
        self,
        message: str,
        *,
        termination_reason: ChildTerminationReason = ChildTerminationReason.LOAD_ERROR,
    ) -> None:
        super().__init__(message)
        self.termination_reason = termination_reason


@runtime_checkable
class ChildImageMaterializer(Protocol):
    """Construct one engine image object from exact child bytes."""

    def materialize(
        self,
        data: bytes,
        *,
        emu_path: str,
        display_name: str,
    ) -> LoadedImage:
        """Create a PE image without mapping or executing it.

        Args:
            data: Complete, already validated child executable bytes.
            emu_path: Windows-style path used by the child process.
            display_name: Module name without path.

        Returns:
            An unmapped engine ``LoadedImage`` whose bytes and metadata
            correspond to the supplied payload.

        Side effects:
            Parses bytes in memory. It must not map emulator memory, mutate
            root metadata, create a process, or execute child code.
        """
        ...


@runtime_checkable
class ChildImageBaseAllocator(Protocol):
    """Choose a non-conflicting image base before child materialization."""

    def allocate(
        self,
        *,
        preferred_base: int,
        image_size: int,
    ) -> int:
        """Return a page-aligned image base for one child image.

        Args:
            preferred_base: PE preferred base reported by the first parse.
            image_size: Mapped image size including aligned virtual regions.

        Returns:
            A page-aligned base for the child image. It may equal
            ``preferred_base`` only when that range is known to be available.

        Side effects:
            May query emulator-owned address maps. It must not map the image or
            modify root metadata.
        """
        ...


@runtime_checkable
class ChildImageMapper(Protocol):
    """Map one image object into emulator memory as a non-primary module."""

    def map_child_image(
        self,
        image: LoadedImage,
        *,
        request: ChildLaunchRequest,
    ) -> EmulatedModuleProtocol:
        """Map one child image and return the resulting runtime module.

        Args:
            image: Parsed image created from the request's trusted bytes.
            request: Launch identity used for correlation and diagnostics.

        Returns:
            The mapped child module with a stable base and image size.

        Side effects:
            Maps child regions into the existing emulator. It must not replace
            root input metadata, install root profiler state, create a child
            process context, queue a run, or execute child code.
        """
        ...


@runtime_checkable
class ChildImageEngine(Protocol):
    """Minimal public emulator surface required by the default image mapper."""

    def load_image(self, image: LoadedImage) -> EmulatedModuleProtocol:
        """Map a parsed image and return its runtime module."""
        ...

    def mem_protect(self, base: int, size: int, perms: int) -> None:
        """Apply section permissions to an already mapped region."""
        ...

    def get_valid_ranges(
        self,
        size: int,
        addr: int | None = None,
    ) -> tuple[int, int]:
        """Return an unoccupied page-aligned emulator address range."""
        ...


class EngineChildImageBaseAllocator:
    """Allocate child image bases from the emulator's public memory map.

    Args:
        engine: Emulator exposing ``get_valid_ranges``.
        preferred_search_base: Optional deterministic search start. ``None``
            uses the emulator's normal low-address search.
    """

    def __init__(
        self,
        engine: ChildImageEngine,
        *,
        preferred_search_base: int | None = None,
    ) -> None:
        self._engine = engine
        self._preferred_search_base = preferred_search_base

    def allocate(
        self,
        *,
        preferred_base: int,
        image_size: int,
    ) -> int:
        """Choose a fresh non-conflicting base for one child image.

        Args:
            preferred_base: PE preferred base; retained for diagnostics and
                allocator implementations that can test it cheaply.
            image_size: Complete mapped image size.

        Returns:
            The page-aligned base returned by ``get_valid_ranges``.

        Side effects:
            Reads emulator-owned address maps only. Mapping remains the
            mapper's responsibility.

        Raises:
            ChildImageLoadError: If no address range can satisfy the image.
        """

        del preferred_base
        try:
            base, _size = self._engine.get_valid_ranges(
                image_size,
                addr=self._preferred_search_base,
            )
        except Exception as exc:
            raise ChildImageLoadError(
                f"cannot allocate child image base: {type(exc).__name__}: {exc}"
            ) from exc
        return base


class PeChildImageMaterializer:
    """Parse child bytes with the engine's PE loader without mapping them.

    Args:
        base_allocator: Explicit allocator for a non-conflicting address range.
            The PE is parsed once for its image size, a base is selected, and
            the image is rebuilt with that base override when it differs.

    The class owns no mapped image state and is safe to inject into one runtime
    loader. All metadata comes from the supplied ``ResolvedChildTarget``.
    """

    def __init__(self, base_allocator: ChildImageBaseAllocator) -> None:
        self._base_allocator = base_allocator

    def materialize(
        self,
        data: bytes,
        *,
        emu_path: str,
        display_name: str,
    ) -> LoadedImage:
        """Parse exact child bytes into an unmapped PE image.

        Args:
            data: Complete PE bytes validated by :class:`ChildRuntimeLoader`.
            emu_path: Windows-style child module path.
            display_name: Module name visible in diagnostics.

        Returns:
            An unmapped ``LoadedImage`` produced by ``PeLoader``.

        Side effects:
            Parses bytes in memory only. It does not call engine mapping or
            execution methods.

        Raises:
            ChildImageLoadError: If PE parsing fails.
        """

        image = self._parse(data, emu_path=emu_path)
        image_base = self._base_allocator.allocate(
            preferred_base=image.image_base,
            image_size=image.image_size,
        )
        if image_base != image.image_base:
            image = self._parse(
                data,
                emu_path=emu_path,
                base_override=image_base,
            )
        image.name = display_name
        image.emu_path = emu_path
        return image

    @staticmethod
    def _parse(
        data: bytes,
        *,
        emu_path: str,
        base_override: int | None = None,
    ) -> LoadedImage:
        """Parse exact bytes into an unmapped PE image.

        Args:
            data: Complete PE bytes.
            emu_path: Windows-style child module path.
            base_override: Optional explicitly selected image base.

        Returns:
            Unmapped image produced by ``PeLoader``.

        Side effects:
            Parses bytes in memory only.

        Raises:
            ChildImageLoadError: If PE parsing or rebasing fails.
        """

        try:
            return PeLoader(
                data=data,
                emu_path=emu_path,
                base_override=base_override,
            ).make_image()
        except Exception as exc:
            raise ChildImageLoadError(
                f"cannot parse child PE: {type(exc).__name__}: {exc}"
            ) from exc


class EngineChildImageMapper:
    """Map child images through the emulator's public image-loading surface.

    Args:
        engine: Emulator exposing ``load_image`` and ``mem_protect``.

    The mapper removes the PE loader marker before calling ``load_image``. That
    makes the engine's existing primary/non-primary branch choose its
    non-primary path without patching or replacing engine methods. Section
    permissions are then restored through the public memory-protection API.
    """

    def __init__(self, engine: ChildImageEngine) -> None:
        self._engine = engine

    def map_child_image(
        self,
        image: LoadedImage,
        *,
        request: ChildLaunchRequest,
    ) -> EmulatedModuleProtocol:
        """Map one parsed image as a non-primary child module.

        Args:
            image: Parsed child image from :class:`PeChildImageMaterializer`.
            request: Launch identity associated with the mapped bytes.

        Returns:
            Runtime module returned by the emulator.

        Side effects:
            Maps child bytes into emulator memory and applies child section
            permissions. It does not alter root input metadata or execute code.

        Raises:
            ChildImageLoadError: If engine mapping fails.
        """

        non_primary_image = replace(image, loader=None)
        try:
            module = self._engine.load_image(non_primary_image)
        except Exception as exc:
            raise ChildImageLoadError(
                f"cannot map child image for {request.launch_id}: "
                f"{type(exc).__name__}: {exc}"
            ) from exc

        self._restore_section_permissions(non_primary_image, module)
        return module

    def _restore_section_permissions(
        self,
        image: LoadedImage,
        module: EmulatedModuleProtocol,
    ) -> None:
        """Restore parsed PE section permissions after non-primary mapping.

        Args:
            image: Mapped image whose runtime base may have been assigned by
                the engine.
            module: Mapping result containing the final runtime base.

        Returns:
            ``None``.

        Side effects:
            Applies page-aligned section permissions through the emulator's
            public ``mem_protect`` method. Mapping failures remain load errors;
            individual protection failures preserve the engine's existing
            best-effort behavior and are not converted into parent failures.
        """

        page_size = 0x1000
        page_permissions: dict[int, int] = {}
        for section in image.sections:
            section_base = module.base + section.virtual_address
            aligned_base = section_base & ~(page_size - 1)
            section_end = section_base + section.virtual_size
            aligned_end = (section_end + page_size - 1) & ~(page_size - 1)
            for page in range(aligned_base, aligned_end, page_size):
                page_permissions[page] = (
                    page_permissions.get(page, 0) | section.perms
                )

        for page, perms in sorted(page_permissions.items()):
            try:
                self._engine.mem_protect(page, page_size, perms)
            except Exception:
                continue


class ChildImageRuntimeLoader:
    """Validate and load one resolved child target as a non-primary image.

    Args:
        materializer: Converts exact bytes into an unmapped PE image.
        image_mapper: Maps that image without selecting the primary-image path.

    The loader owns no target bytes, processes, runs, or parent context. It
    validates target identity, materializes the image, and returns an immutable
    :class:`LoadedChildImage`.
    """

    def __init__(
        self,
        materializer: ChildImageMaterializer,
        image_mapper: ChildImageMapper,
    ) -> None:
        self._materializer = materializer
        self._image_mapper = image_mapper

    def load(
        self,
        request: ChildLaunchRequest,
        target: ResolvedChildTarget,
    ) -> LoadedChildImage:
        """Load one trusted child target without executing it.

        Args:
            request: Immutable launch identity and command information.
            target: Resolution evidence containing trusted PE bytes.

        Returns:
            The mapped non-primary image, runtime base, and absolute entry
            point. ``primary`` is always ``False``.

        Side effects:
            Parses and maps child bytes into the emulator. It does not create a
            process context, queue a run, call a child entry point, or modify
            root metadata.

        Raises:
            ChildImageLoadError: If the target is incomplete, not an executable
                PE, its bytes do not match recorded evidence, or mapping fails.
        """

        data = self._validate_target(target)
        display_name = ntpath.basename(target.normalized_path)
        display_name = ntpath.splitext(display_name)[0] or request.launch_id

        image = self._materializer.materialize(
            data,
            emu_path=target.normalized_path,
            display_name=display_name,
        )
        module = self._image_mapper.map_child_image(image, request=request)
        entrypoint_address = module.base + target.entrypoint_rva
        if entrypoint_address <= module.base:
            raise ChildImageLoadError(
                "child entry point is missing",
                termination_reason=ChildTerminationReason.ENTRYPOINT_MISSING,
            )
        if target.entrypoint_rva >= module.image_size:
            raise ChildImageLoadError(
                "child entry point is outside the mapped image",
                termination_reason=ChildTerminationReason.ENTRYPOINT_OUT_OF_RANGE,
            )

        return LoadedChildImage(
            request_launch_id=request.launch_id,
            module=module,
            image_base=module.base,
            entrypoint_address=entrypoint_address,
            primary=False,
        )

    @staticmethod
    def _validate_target(target: ResolvedChildTarget) -> bytes:
        """Return exact trusted bytes after validating target evidence.

        Args:
            target: Resolver output for one child request.

        Returns:
            A fresh immutable byte snapshot for materialization.

        Side effects:
            None.

        Raises:
            ChildImageLoadError: If resolution, format, type, entry point, or
                digest evidence does not permit loading.
        """

        if not target.resolved or target.payload_ref is None:
            raise ChildImageLoadError(
                "child target bytes are unavailable",
                termination_reason=ChildTerminationReason.TARGET_UNAVAILABLE,
            )
        if target.file_format.lower() != "pe":
            raise ChildImageLoadError(
                "child target is not a PE image",
                termination_reason=ChildTerminationReason.TARGET_NOT_PE,
            )
        if target.module_type.lower() != "exe":
            raise ChildImageLoadError(
                "child target is not an executable image",
                termination_reason=ChildTerminationReason.LOAD_ERROR,
            )
        if target.entrypoint_rva <= 0:
            raise ChildImageLoadError(
                "child entry point is missing",
                termination_reason=ChildTerminationReason.ENTRYPOINT_MISSING,
            )

        payload = target.payload_ref.data
        if payload is None:
            raise ChildImageLoadError(
                "child target bytes are unavailable",
                termination_reason=ChildTerminationReason.TARGET_UNAVAILABLE,
            )
        data = bytes(payload)
        if len(data) != target.size or len(data) != target.payload_ref.size:
            raise ChildImageLoadError("child target size does not match evidence")

        actual_sha256 = hashlib.sha256(data).hexdigest()
        expected_digests = {
            digest.lower()
            for digest in (target.sha256, target.payload_ref.sha256)
            if digest
        }
        if any(digest != actual_sha256 for digest in expected_digests):
            raise ChildImageLoadError("child target digest does not match evidence")
        return data


__all__ = [
    "ChildImageBaseAllocator",
    "ChildImageEngine",
    "ChildImageLoadError",
    "ChildImageMapper",
    "ChildImageMaterializer",
    "ChildImageRuntimeLoader",
    "EngineChildImageBaseAllocator",
    "EngineChildImageMapper",
    "PeChildImageMaterializer",
]
