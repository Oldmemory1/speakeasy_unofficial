"""Resolve child targets from emulation-owned byte sources.

Resolution only reads root, fixture, or dropped-file bytes and describes the
resulting PE metadata. It never creates a process, admits a request, queues
work, or executes child code.
"""

from __future__ import annotations

import hashlib
import ntpath
import re
import shlex
from typing import Any

import speakeasy.winenv.arch as _arch

from .models import ChildTargetSource, ResolvedChildTarget, TargetPayloadRef


class ChildTargetResolver:
    """Resolve child target bytes from approved emulation-owned sources.

    Args:
        emu: Emulator context exposing root metadata, architecture, cwd, env,
            and optional dropped-file manager. It is read only.
        fixtures: Optional normalized path-to-bytes mappings supplied by the
            caller for explicit tests or replay.
    """

    def __init__(
        self,
        emu: Any,
        fixtures: dict[str, bytes] | None = None,
    ) -> None:
        self.emu = emu
        self.fixtures = {
            self._normalize_fixture_key(path): bytes(data)
            for path, data in (fixtures or {}).items()
        }

    @property
    def root_sample_sha256(self) -> str:
        """Return the lower-case root sample digest, or an empty string.

        Returns:
            Digest copied from explicit emulator metadata or root input.

        Side effects:
            None.
        """

        value = getattr(self.emu, "_root_sample_sha256", None)
        if value:
            return str(value).lower()
        input_meta = getattr(self.emu, "input", None) or {}
        return str(input_meta.get("sha256") or "").lower()

    @staticmethod
    def command_target(command_line: str) -> str:
        """Return the executable token from a command line.

        Args:
            command_line: Command line that may begin with a quoted path.

        Returns:
            The first token with surrounding quotes removed, or ``""``.

        Side effects:
            None.
        """

        if not command_line:
            return ""
        try:
            tokens = shlex.split(command_line, posix=False)
        except ValueError:
            tokens = command_line.split()
        if not tokens:
            return ""
        return tokens[0].strip().strip('"')

    def register_fixture(self, path: str, data: bytes) -> None:
        """Register target bytes for an explicit fixture path.

        Args:
            path: Windows-style fixture path.
            data: Exact immutable byte snapshot to register.

        Returns:
            ``None``.

        Side effects:
            Replaces this resolver's fixture entry for ``path``. Admission
            history and engine state are unchanged.
        """

        self.fixtures[self._normalize_fixture_key(path)] = bytes(data)

    def resolve(
        self,
        path: str | None,
        command_line: str | None = None,
        cwd: str | None = None,
    ) -> ResolvedChildTarget:
        """Resolve one target and describe its bytes.

        Args:
            path: Explicit application path, if supplied by the API.
            command_line: Command line used to derive a target when ``path`` is
                empty.
            cwd: Emulated working directory for relative path normalization.

        Returns:
            Immutable target evidence. ``resolved`` is true whenever complete
            bytes were found; PE validity and execution eligibility are
            reported separately through ``reason``.

        Side effects:
            May read emulation-owned root, fixture, or dropped-file bytes.
            Never creates or executes a child.
        """

        command_line = command_line or ""
        requested = (path or "").strip().strip('"')
        if not requested:
            requested = self.command_target(command_line)

        normalized = self.normalize_path(requested, cwd=cwd)
        if not requested:
            return self._unavailable("", "empty_target")
        if re.match(r"^[a-z][a-z0-9+.-]*://", requested, re.IGNORECASE):
            return ResolvedChildTarget(
                source=ChildTargetSource.UNAVAILABLE,
                normalized_path=normalized,
                payload_ref=None,
                sha256=None,
                size=0,
                file_format="uri",
                arch="unknown",
                module_type="unknown",
                entrypoint_rva=0,
                resolved=False,
                reason="non_pe_target",
            )

        root_data = getattr(self.emu, "_root_pe_data", None)
        if root_data and self._is_self_target(normalized):
            return self._describe_bytes(
                ChildTargetSource.SELF,
                normalized,
                bytes(root_data),
            )

        fixture_data = self._fixture_bytes(normalized)
        if fixture_data is not None:
            return self._describe_bytes(
                ChildTargetSource.FIXTURE,
                normalized,
                fixture_data,
            )

        dropped = self._dropped_file_bytes(normalized)
        if dropped is not None:
            return self._describe_bytes(
                ChildTargetSource.DROPPED_FILE,
                normalized,
                dropped,
            )

        return self._unavailable(normalized, "target_unavailable")

    def normalize_path(self, path: str, cwd: str | None = None) -> str:
        """Expand emulated environment variables and normalize a path.

        Args:
            path: Windows-style path or URI.
            cwd: Optional working directory for relative paths.

        Returns:
            Normalized path, or the original URI form.

        Side effects:
            None.
        """

        path = path.strip().strip('"')
        if not path:
            return ""

        env = getattr(self.emu, "env", {}) or {}

        def replace_env(match: re.Match[str]) -> str:
            name = match.group(1).lower()
            return str(env.get(name, match.group(0)))

        path = re.sub(r"%([^%]+)%", replace_env, path)
        if re.match(r"^[a-z][a-z0-9+.-]*://", path, re.IGNORECASE):
            return path

        if not ntpath.isabs(path):
            base = (
                cwd
                or getattr(self.emu, "cd", "")
                or getattr(
                    getattr(self.emu, "config", None),
                    "current_dir",
                    "",
                )
            )
            if base:
                path = ntpath.join(base, path)
        return ntpath.normpath(path)

    def _is_self_target(self, target: str) -> bool:
        """Return whether ``target`` names the loaded root sample.

        Args:
            target: Normalized Windows path.

        Returns:
            ``True`` for the root file name, stem, or root digest.

        Side effects:
            None.
        """

        target_name = ntpath.basename(target).lower()
        target_stem = ntpath.splitext(target_name)[0]
        root_path = getattr(self.emu, "_root_emu_path", "")
        root_name = ntpath.basename(root_path).lower()
        root_stem = ntpath.splitext(root_name)[0]
        candidates = {
            name
            for name in (root_name, root_stem, self.root_sample_sha256)
            if name
        }
        return target_name in candidates or target_stem in candidates

    def _fixture_bytes(self, normalized: str) -> bytes | None:
        """Return registered fixture bytes for a normalized path.

        Args:
            normalized: Normalized fixture path.

        Returns:
            Immutable fixture bytes, or ``None``.

        Side effects:
            None.
        """

        return self.fixtures.get(self._normalize_fixture_key(normalized))

    def _dropped_file_bytes(self, normalized: str) -> bytes | None:
        """Return bytes for a dropped file owned by the emulator.

        Args:
            normalized: Normalized Windows target path.

        Returns:
            Immutable dropped-file bytes, or ``None`` when the path is absent,
            not recognized as a dropped file, or unreadable.

        Side effects:
            Reads the emulator-owned file manager. It does not mutate file
            manager state beyond the existing ``get_data`` API contract.
        """

        fileman = getattr(self.emu, "fileman", None)
        if fileman is None:
            return None
        try:
            target_file = fileman.get_file_from_path(normalized)
            dropped_files = fileman.get_dropped_files()
        except Exception:
            return None
        if target_file is None or target_file not in dropped_files:
            return None
        try:
            data = target_file.get_data(reset_pointer=True)
        except Exception:
            return None
        return bytes(data) if data else None

    def _describe_bytes(
        self,
        source: ChildTargetSource,
        normalized: str,
        data: bytes,
    ) -> ResolvedChildTarget:
        """Describe target bytes and validate PE execution properties.

        Args:
            source: Approved origin of ``data``.
            normalized: Normalized Windows target path.
            data: Complete target bytes to inspect.

        Returns:
            Immutable target evidence with digest, size, PE format, module
            type, architecture, entry point, and optional rejection reason.

        Side effects:
            None.
        """

        sha256 = hashlib.sha256(data).hexdigest()
        payload = TargetPayloadRef(
            source=source,
            sha256=sha256,
            size=len(data),
            emu_path=normalized,
            data=data,
        )
        try:
            from speakeasy.windows.common import _PeParser

            pe = _PeParser(data=data, fast_load=True)
        except Exception:
            return ResolvedChildTarget(
                source=source,
                normalized_path=normalized,
                payload_ref=payload,
                sha256=sha256,
                size=len(data),
                file_format="non_pe",
                arch="unknown",
                module_type="unknown",
                entrypoint_rva=0,
                resolved=True,
                reason="target_not_pe",
            )

        arch = "unknown"
        if pe.arch == _arch.ARCH_X86:
            arch = "x86"
        elif pe.arch == _arch.ARCH_AMD64:
            arch = "x64"

        module_type = "unknown"
        if pe.is_driver():
            module_type = "driver"
        elif pe.is_dll():
            module_type = "dll"
        elif pe.is_exe():
            module_type = "exe"

        entrypoint_rva = int(getattr(pe, "ep", 0) or 0)
        reason: str | None = None
        if module_type != "exe":
            reason = "target_not_executable"
        elif entrypoint_rva <= 0:
            reason = "entrypoint_missing"
        elif entrypoint_rva >= int(getattr(pe, "image_size", 0) or 0):
            reason = "entrypoint_out_of_range"
        else:
            try:
                engine_arch = self.emu.get_arch()
            except Exception:
                engine_arch = None
            if engine_arch and pe.arch != engine_arch:
                reason = "arch_mismatch"

        return ResolvedChildTarget(
            source=source,
            normalized_path=normalized,
            payload_ref=payload,
            sha256=sha256,
            size=len(data),
            file_format="pe",
            arch=arch,
            module_type=module_type,
            entrypoint_rva=entrypoint_rva,
            resolved=True,
            reason=reason,
        )

    @staticmethod
    def _unavailable(normalized: str, reason: str) -> ResolvedChildTarget:
        """Build target evidence for an unresolved path.

        Args:
            normalized: Normalized path when one was available.
            reason: Machine-readable resolution or skip reason.

        Returns:
            Immutable unresolved target evidence.

        Side effects:
            None.
        """

        return ResolvedChildTarget(
            source=ChildTargetSource.UNAVAILABLE,
            normalized_path=normalized,
            payload_ref=None,
            sha256=None,
            size=0,
            file_format="unknown",
            arch="unknown",
            module_type="unknown",
            entrypoint_rva=0,
            resolved=False,
            reason=reason,
        )

    @staticmethod
    def _normalize_fixture_key(path: str) -> str:
        """Normalize a fixture path for exact case-insensitive lookup.

        Args:
            path: Windows-style fixture path.

        Returns:
            Normalized lower-case path key.

        Side effects:
            None.
        """

        return ntpath.normpath(path).lower()


__all__ = ["ChildTargetResolver"]
