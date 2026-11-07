"""Windows-version capabilities that affect exposed API behavior."""

from __future__ import annotations

from dataclasses import dataclass

PF_FASTFAIL_AVAILABLE = 23


@dataclass(frozen=True)
class WindowsOsVersion:
    """Minimal immutable Windows version used for capability decisions."""

    major: int | None
    minor: int | None

    def at_least(self, major: int, minor: int) -> bool:
        """Return whether the version is known and meets the inclusive bound."""
        if self.major is None or self.minor is None:
            return False
        return (self.major, self.minor) >= (major, minor)


def processor_feature_override(
    feature_id: int,
    os_version: WindowsOsVersion,
) -> int | None:
    """Return an OS-dependent processor-feature result.

    ``None`` means the caller should use its architecture-independent default.
    Windows 8 introduced the ``__fastfail`` intrinsic, so Windows 7 must not
    advertise ``PF_FASTFAIL_AVAILABLE``.
    """
    if feature_id == PF_FASTFAIL_AVAILABLE:
        return int(os_version.at_least(6, 2))
    return None

