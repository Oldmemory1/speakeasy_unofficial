from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

import speakeasy.common as common
from speakeasy.windows.child_execution.interfaces import ChildRuntimeLoader
from speakeasy.windows.child_execution.models import (
    ChildLaunchRequest,
    ChildTargetSource,
    ExecutionBudget,
    ResolvedChildTarget,
    TargetPayloadRef,
)
from speakeasy.windows.child_execution.runtime_loader import (
    ChildImageLoadError,
    ChildImageRuntimeLoader,
    EngineChildImageBaseAllocator,
    EngineChildImageMapper,
    PeChildImageMaterializer,
)
from speakeasy.windows.loaders import (
    LoadedImage,
    MemoryRegion,
    PeLoader,
    SectionEntry,
)


class ExplicitModule:
    """Runtime module stub exposing only the public child module contract."""

    def __init__(self, base: int = 0x500000) -> None:
        self.base = base
        self.image_size = 0x5000
        self.emu_path = r"C:\fixtures\child.exe"


class ExplicitEngine:
    """Engine stub that records image mapping and memory protections."""

    def __init__(self) -> None:
        self.images: list[LoadedImage] = []
        self.protections: list[tuple[int, int, int]] = []

    def load_image(self, image: LoadedImage) -> ExplicitModule:
        """Record the mapped image and return a deterministic module."""

        self.images.append(image)
        return ExplicitModule()

    def mem_protect(self, base: int, size: int, perms: int) -> None:
        """Record one public memory-protection request."""

        self.protections.append((base, size, perms))

    def get_valid_ranges(
        self,
        size: int,
        addr: int | None = None,
    ) -> tuple[int, int]:
        """Return a deterministic child image allocation range."""

        return (addr or 0x600000, size)


class ExplicitBaseAllocator:
    """Return one configured runtime base and record its inputs."""

    def __init__(self, base: int) -> None:
        self.base = base
        self.calls: list[tuple[int, int]] = []

    def allocate(
        self,
        *,
        preferred_base: int,
        image_size: int,
    ) -> int:
        """Record preferred metadata and return the configured base."""

        self.calls.append((preferred_base, image_size))
        return self.base


class ExplicitMaterializer:
    """Record materialization inputs and return a supplied image."""

    def __init__(self, image: LoadedImage) -> None:
        self.image = image
        self.calls: list[tuple[bytes, str, str]] = []

    def materialize(
        self,
        data: bytes,
        *,
        emu_path: str,
        display_name: str,
    ) -> LoadedImage:
        """Return the configured image after recording exact arguments."""

        self.calls.append((data, emu_path, display_name))
        return self.image


class ExplicitMapper:
    """Record mapper inputs and return a deterministic runtime module."""

    def __init__(self, module: ExplicitModule) -> None:
        self.module = module
        self.calls: list[tuple[LoadedImage, ChildLaunchRequest]] = []

    def map_child_image(
        self,
        image: LoadedImage,
        *,
        request: ChildLaunchRequest,
    ) -> ExplicitModule:
        """Return the configured module after recording exact arguments."""

        self.calls.append((image, request))
        return self.module


def _image() -> LoadedImage:
    return LoadedImage(
        arch=0,
        module_type="exe",
        name="child",
        emu_path=r"C:\fixtures\child.exe",
        image_base=0x500000,
        image_size=0x5000,
        regions=[
            MemoryRegion(
                base=0x500000,
                data=b"MZ",
                name="pe_image",
                perms=common.PERM_MEM_RWX,
            )
        ],
        imports=[],
        exports=[],
        default_export_mode="intercepted",
        entry_points=[0x501000],
        loader=PeLoader(data=b"MZ", emu_path=r"C:\fixtures\child.exe"),
        sections=[
            SectionEntry(
                name=".text",
                virtual_address=0x1000,
                virtual_size=0x200,
                perms=common.PERM_MEM_READ | common.PERM_MEM_EXEC,
            )
        ],
    )


def _request(data: bytes = b"MZ") -> ChildLaunchRequest:
    return ChildLaunchRequest(
        launch_id="child-000001",
        root_sample_sha256="1" * 64,
        parent_launch_id=None,
        source_api="CreateProcess",
        parent_pid=100,
        parent_tid=101,
        depth=1,
        target=r"C:\fixtures\child.exe",
        normalized_target=r"C:\fixtures\child.exe",
        working_directory=r"C:\fixtures",
        command_line=r'"C:\fixtures\child.exe"',
        command_sha256=hashlib.sha256(b"command").hexdigest(),
        parent_budget=ExecutionBudget(
            timeout_seconds=30.0,
            max_api_count=100,
            max_instructions=10_000,
        ),
    )


def _target(data: bytes = b"MZ") -> ResolvedChildTarget:
    digest = hashlib.sha256(data).hexdigest()
    return ResolvedChildTarget(
        source=ChildTargetSource.FIXTURE,
        normalized_path=r"C:\fixtures\child.exe",
        payload_ref=TargetPayloadRef(
            source=ChildTargetSource.FIXTURE,
            sha256=digest,
            size=len(data),
            emu_path=r"C:\fixtures\child.exe",
            data=data,
        ),
        sha256=digest,
        size=len(data),
        file_format="pe",
        arch="x86",
        module_type="exe",
        entrypoint_rva=0x1000,
        resolved=True,
        reason=None,
    )


def test_concrete_loader_implements_frozen_loader_protocol() -> None:
    loader = ChildImageRuntimeLoader(
        ExplicitMaterializer(_image()),
        ExplicitMapper(ExplicitModule()),
    )

    assert isinstance(loader, ChildRuntimeLoader)


def test_loader_uses_exact_target_bytes_and_returns_non_primary_image() -> None:
    data = b"MZ" + b"\x00" * 30
    image = _image()
    materializer = ExplicitMaterializer(image)
    mapper = ExplicitMapper(ExplicitModule())
    loader = ChildImageRuntimeLoader(materializer, mapper)
    request = _request(data)
    target = _target(data)

    loaded = loader.load(request, target)

    assert materializer.calls == [
        (data, r"C:\fixtures\child.exe", "child"),
    ]
    assert mapper.calls == [(image, request)]
    assert loaded.request_launch_id == request.launch_id
    assert loaded.image_base == 0x500000
    assert loaded.entrypoint_address == 0x501000
    assert loaded.primary is False


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"resolved": False}, "unavailable"),
        ({"file_format": "non_pe"}, "not a PE"),
        ({"module_type": "dll"}, "not an executable"),
        ({"entrypoint_rva": 0}, "entry point is missing"),
    ],
)
def test_loader_rejects_invalid_targets_before_materialization(
    change: dict[str, object],
    message: str,
) -> None:
    image = _image()
    materializer = ExplicitMaterializer(image)
    mapper = ExplicitMapper(ExplicitModule())
    target = ResolvedChildTarget(
        **{
            **vars(_target()),
            **change,
        }
    )

    with pytest.raises(ChildImageLoadError, match=message):
        ChildImageRuntimeLoader(materializer, mapper).load(
            _request(),
            target,
        )

    assert materializer.calls == []
    assert mapper.calls == []


def test_loader_rejects_digest_mismatch_before_engine_mapping() -> None:
    image = _image()
    materializer = ExplicitMaterializer(image)
    mapper = ExplicitMapper(ExplicitModule())
    target = _target(b"MZ")
    mismatched = ResolvedChildTarget(
        source=target.source,
        normalized_path=target.normalized_path,
        payload_ref=target.payload_ref,
        sha256="0" * 64,
        size=target.size,
        file_format=target.file_format,
        arch=target.arch,
        module_type=target.module_type,
        entrypoint_rva=target.entrypoint_rva,
        resolved=True,
        reason=None,
    )

    with pytest.raises(ChildImageLoadError, match="digest"):
        ChildImageRuntimeLoader(materializer, mapper).load(
            _request(),
            mismatched,
        )

    assert materializer.calls == []
    assert mapper.calls == []


def test_engine_mapper_selects_non_primary_branch_and_restores_sections() -> None:
    engine = ExplicitEngine()
    mapper = EngineChildImageMapper(engine)
    image = _image()

    module = mapper.map_child_image(image, request=_request())

    assert module.base == 0x500000
    assert len(engine.images) == 1
    assert engine.images[0].loader is None
    assert engine.images[0].regions == image.regions
    assert engine.images[0].image_base == image.image_base
    assert engine.protections == [
        (
            0x501000,
            0x1000,
            common.PERM_MEM_READ | common.PERM_MEM_EXEC,
        )
    ]


def test_materializer_applies_explicit_non_conflicting_base() -> None:
    fixture = Path(__file__).parents[1] / (
        "speakeasy/winenv/decoys/x86/default_exe.exe"
    )
    data = fixture.read_bytes()
    allocator = ExplicitBaseAllocator(0x300000)

    image = PeChildImageMaterializer(allocator).materialize(
        data,
        emu_path=r"C:\fixtures\child.exe",
        display_name="child",
    )

    assert len(allocator.calls) == 1
    preferred_base, requested_size = allocator.calls[0]
    assert preferred_base != 0x300000
    assert requested_size == image.image_size
    assert image.image_base == 0x300000
    assert image.name == "child"
    assert image.emu_path == r"C:\fixtures\child.exe"
    assert image.loader is not None


def test_engine_base_allocator_uses_public_valid_range_search() -> None:
    engine = ExplicitEngine()
    allocator = EngineChildImageBaseAllocator(
        engine,
        preferred_search_base=0x700000,
    )

    base = allocator.allocate(preferred_base=0x500000, image_size=0x5000)

    assert base == 0x700000


def test_pe_materializer_reports_parse_failures_as_child_load_errors() -> None:
    with pytest.raises(ChildImageLoadError, match="cannot parse child PE"):
        PeChildImageMaterializer(ExplicitBaseAllocator(0x300000)).materialize(
            b"not a PE",
            emu_path=r"C:\fixtures\bad.exe",
            display_name="bad",
        )
