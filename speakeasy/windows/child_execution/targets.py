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
        path = self._canonical_path(path)

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
        elif path.startswith("\\") and not path.startswith("\\\\"):
            base = (
                cwd
                or getattr(self.emu, "cd", "")
                or getattr(
                    getattr(self.emu, "config", None),
                    "current_dir",
                    "",
                )
            )
            drive, _ = ntpath.splitdrive(str(base or ""))
            if drive:
                path = drive + path
        return self._canonical_path(path)

    @staticmethod
    def _canonical_path(path: str) -> str:
        """Normalize separators and remove Windows device-path prefixes.

        Args:
            path: Windows-style path that may use a device namespace such as
                ``\\\\?\\C:\\Temp\\child.exe`` or ``\\??\\C:\\Temp\\child.exe``.

        Returns:
            A normalized Win32-style path with forward slashes converted to
            backslashes and a drive or UNC device prefix removed.

        Side effects:
            None.
        """

        value = str(path or "").strip().strip('"').replace("/", "\\")
        upper = value.upper()
        unc_prefixes = ("\\\\?\\UNC\\", "\\??\\UNC\\", "\\\\??\\UNC\\")
        for prefix in unc_prefixes:
            if upper.startswith(prefix.upper()):
                value = "\\\\" + value[len(prefix) :]
                break
        else:
            prefixes = ("\\\\?\\", "\\??\\", "\\\\??\\")
            for prefix in prefixes:
                if upper.startswith(prefix.upper()):
                    value = value[len(prefix) :]
                    break
        return ntpath.normpath(value) if value else ""

    def _is_self_target(self, target: str) -> bool:
        """Return whether ``target`` names the loaded root sample.

        Args:
            target: Normalized Windows path.

        Returns:
            ``True`` for the root file name, stem, root digest, or the
            one-character-truncated 64-character root filename alias observed
            from ``ShellExecute``. The alias may have an ``.exe`` extension or
            no extension.

        Side effects:
            None.
        """

        target_name = ntpath.basename(target).lower()
        target_stem = ntpath.splitext(target_name)[0]
        target_suffix = ntpath.splitext(target_name)[1]
        root_path = getattr(self.emu, "_root_emu_path", "")
        root_name = ntpath.basename(root_path).lower()
        root_stem = ntpath.splitext(root_name)[0]
        root_sha256 = self.root_sample_sha256
        candidates = {
            name
            for name in (root_name, root_stem, root_sha256)
            if name
        }
        if target_name in candidates or target_stem in candidates:
            return True

        # Some ShellExecute samples derive their path from the 64-character
        # root filename but omit the final filename character and the
        # executable extension. The filename need not equal the content SHA.
        # Match only the exact root stem minus one character; accepting
        # shorter prefixes would make unrelated executables resolve as root.
        return (
            len(root_stem) == 64
            and all(character in "0123456789abcdef" for character in root_stem)
            and len(target_stem) == 63
            and target_suffix in {"", ".exe"}
            and target_stem == root_stem[:-1]
        )

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
            A complete, immutable snapshot of the uniquely path-matched
            dropped file, or ``None`` when the path is absent, ambiguous,
            incomplete, or unreadable.

        Side effects:
            Reads the emulator-owned file manager. The snapshot is obtained
            through ``File.duplicate`` so the live file's cursor is unchanged.
        """

        fileman = getattr(self.emu, "fileman", None)
        if fileman is None:
            return None
        try:
            dropped_files = fileman.get_dropped_files()
        except Exception:
            return None
        target_file = self._exact_dropped_file(dropped_files, normalized)
        if target_file is None:
            return None

        data = self._snapshot_file_bytes(target_file)
        if data is None:
            return None
        try:
            expected_size = int(target_file.get_size())
        except Exception:
            return None
        if len(data) != expected_size:
            return None
        return data

    @staticmethod
    def _exact_dropped_file(dropped_files: Any, normalized: str) -> Any | None:
        """Return the sole dropped file whose full path equals the target.

        Args:
            dropped_files: Iterable of file-manager objects that are fully
                written and eligible to be treated as dropped artifacts.
            normalized: Normalized Windows target path from the launch request.

        Returns:
            The unique object with an exactly matching normalized path, or
            ``None`` when no such object or more than one object matches.

        Side effects:
            None. The file-manager collection and file objects are read only.
        """

        target_path = ChildTargetResolver._canonical_path(normalized).casefold()
        matches: list[Any] = []
        seen: set[int] = set()
        for candidate in dropped_files:
            candidate_path = getattr(candidate, "path", None)
            if not candidate_path:
                continue
            try:
                candidate_key = ChildTargetResolver._canonical_path(
                    str(candidate_path)
                ).casefold()
            except (TypeError, ValueError):
                continue
            if candidate_key != target_path or id(candidate) in seen:
                continue
            seen.add(id(candidate))
            matches.append(candidate)
        return matches[0] if len(matches) == 1 else None

    @staticmethod
    def _snapshot_file_bytes(target_file: Any) -> bytes | None:
        """Return a detached full-byte snapshot of a completed dropped file.

        Args:
            target_file: Fully written file-manager object selected by exact
                normalized path.

        Returns:
            Complete immutable file bytes, or ``None`` when the object cannot
            provide a detached snapshot.

        Side effects:
            None on ``target_file``. ``File.duplicate`` creates a separate
            in-memory file object whose cursor can be reset safely.
        """

        try:
            snapshot = target_file.duplicate()
            data = snapshot.get_data(reset_pointer=True)
        except Exception:
            return None
        if data is None:
            return None
        return bytes(data)

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

        return ChildTargetResolver._canonical_path(path).casefold()


__all__ = ["ChildTargetResolver"]
