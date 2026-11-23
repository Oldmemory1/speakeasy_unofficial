"""Read-only runtime API-name resolution diagnostics for FX-005.

The FX-005 work item (``Loader / getprocaddress``, diagnostic mode) covers
samples whose self-decrypting code resolves undecorated API names
(``GetUserName``, ``GetSystemDirectory``, ...) at runtime.  The report currently
shows only ``ApiEmuError: Failed to get character width ...`` and the final
``invalid_protect_fetch``; it cannot show *which* lookup matched the undecorated
name to a handler, what ``GetProcAddress`` returned, or which A/W spelling the
engine would have picked.

This module adds *evidence*, never behaviour.  ``ApiHandler.get_char_width``
calls :func:`observe_char_width` before returning a width or raising its
existing ``ApiEmuError``.  The observation records:

* the requested module/function spelling and its A/W suffix analysis;
* how the engine handler table matched it (exact undecorated handler, A/W
  folding, ordinal, or no handler);
* whether the loaded module's export table exposes the exact spelling and its
  A/W aliases (the synthetic export table is why an undecorated lookup can
  succeed where Windows would return NULL);
* signature-database availability for the exact and A/W spellings;
* the dispatch provenance (import-table sentinel -> module/function target, or
  a direct handler call).

Observation contract
--------------------
* Every observation is a JSON-safe ``dict`` with
  ``kind="api_name_resolution_diagnostic"`` and ``schema_version=SCHEMA_VERSION``.
* Observations are stored in ``ctx["_api_observation"]`` (the existing
  ``ApiEvent.observation`` report field, merged into
  ``ErrorInfo.diagnostics["api_observation"]`` on the handler-error path).  A
  pre-existing non-FX-005 observation is preserved and the trace is nested under
  ``MERGE_KEY``.
* All helpers are read-only and best effort; diagnostic failures are logged at
  debug level and never raise into a handler.  No handler return value, page
  permission, exception dispatch or control flow is changed.
* Bounded: no guest memory reads; module-export and signature lookups are
  limited to the exact spelling plus one A/W variant.
* No sample/address/family special cases, no environment variables, no
  configuration switches, no monkey patches.

Applicable architecture: pointer-size independent; PC/return-address rendering
uses the emulator's public accessors on x86/AMD64.  Unknown inputs produce
explicit fields (``available=False``, ``module_found=False``, ``None``) rather
than guesses.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import speakeasy.winenv.arch as _arch
from speakeasy.winenv.api import sigdb

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
OBSERVATION_KIND = "api_name_resolution_diagnostic"
MERGE_KEY = "api_name_resolution_trace"

MAX_TEXT_CHARS = 256


def _hex_value(value: Any) -> str | None:
    """Render an integer as a hex string, else ``None``."""
    if isinstance(value, bool):
        return f"0x{int(value):x}"
    if isinstance(value, int):
        return f"0x{value:x}"
    return None


def _int_value(value: Any) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    return None


def _bounded_text(value: Any, limit: int = MAX_TEXT_CHARS) -> str | None:
    """Render a value as a bounded, JSON-safe string (``None`` stays ``None``)."""
    if value is None:
        return None
    try:
        text = str(value).replace("\x00", "")
        text = text.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    except Exception:
        return None
    return text[:limit]


def _split_api_name(function_name: str) -> tuple[str | None, str]:
    """Split ``module.function`` at the last dot; a bare name has no module."""
    if "." in function_name:
        module_name, _, name = function_name.rpartition(".")
        if name:
            return module_name, name
    return None, function_name


def _suffix(name: str) -> str | None:
    """Return the engine's A/W suffix rule spelling, if any."""
    if name.endswith("A"):
        return "A"
    if name.endswith("W"):
        return "W"
    return None


def _handler_entry(funcs: dict, name: str) -> Any:
    """Look up a handler entry by name or ``ordinal_<n>`` spelling."""
    if not isinstance(funcs, dict):
        return None
    try:
        entry = funcs.get(name)
    except Exception:
        return None
    if entry is not None:
        return entry
    if isinstance(name, str) and name.startswith("ordinal_"):
        try:
            ordinal = int(name.split("_", 1)[1])
        except (IndexError, ValueError):
            return None
        try:
            return funcs.get(ordinal)
        except Exception:
            return None
    return None


def _entry_fields(entry: Any) -> tuple[str | None, int | None]:
    """Extract ``(registered_name, argc)`` from an ``ApiHandler.funcs`` value."""
    if not isinstance(entry, (tuple, list)) or not entry:
        return None, None
    name = entry[0] if isinstance(entry[0], str) else None
    argc = entry[2] if len(entry) > 2 and isinstance(entry[2], int) else None
    return name, argc


def handler_resolution(handler: Any, function_name: str) -> dict[str, Any]:
    """Describe how the engine handler table matches *function_name*.

    Read-only.  ``resolution_path`` is one of ``exact_handler``,
    ``aw_folded_handler``, ``ordinal_handler`` or ``unregistered_handler``.
    """
    result: dict[str, Any] = {
        "available": False,
        "resolution_path": "unregistered_handler",
        "handler_impname": None,
        "handler_argc": None,
        "handler_registration": None,
        "exact_registered": False,
        "aw_folded_registered": False,
        "aw_aliases_registered": [],
    }
    funcs = getattr(handler, "funcs", None)
    if not isinstance(funcs, dict):
        return result

    result["available"] = True
    suffix = _suffix(function_name)
    folded_name = function_name[:-1] if suffix else None

    exact = _handler_entry(funcs, function_name)
    folded = _handler_entry(funcs, folded_name) if folded_name else None
    alias_names: list[str] = []
    if suffix is None:
        alias_names = [alias for alias in (function_name + "A", function_name + "W") if _handler_entry(funcs, alias)]
    elif folded is not None:
        alias_names = [folded_name]

    entry = exact if exact is not None else folded
    name, argc = _entry_fields(entry)
    result["exact_registered"] = exact is not None
    result["aw_folded_registered"] = folded is not None
    result["handler_impname"] = name
    result["handler_argc"] = argc
    result["aw_aliases_registered"] = alias_names

    if exact is not None:
        result["resolution_path"] = "ordinal_handler" if function_name.startswith("ordinal_") else "exact_handler"
    elif folded is not None:
        result["resolution_path"] = "aw_folded_handler"

    if name is not None:
        result["handler_registration"] = "decorated" if name.endswith(("A", "W")) else "undecorated"
    return result


def _module_base_name(module: Any) -> str | None:
    getter = getattr(module, "get_base_name", None)
    if callable(getter):
        try:
            return _bounded_text(getter())
        except Exception:
            pass
    return _bounded_text(getattr(module, "name", None))


def module_export_membership(
    handler: Any,
    module_name: str | None,
    function_name: str,
) -> dict[str, Any]:
    """Record the exact/A/W spellings in the loaded module's export table."""
    result: dict[str, Any] = {
        "module_found": False,
        "module_query": _bounded_text(module_name),
        "module_name": None,
        "module_base": None,
        "loader": None,
        "names": {},
        "exact_present": False,
        "aliases_present": [],
    }
    emu = getattr(handler, "emu", None)
    if emu is None or not module_name:
        return result
    getter = getattr(emu, "get_mod_by_name", None)
    if not callable(getter):
        return result
    try:
        module = getter(module_name)
    except Exception:
        module = None
    if module is None:
        return result

    loader = getattr(module, "loader", None)
    result.update(
        {
            "module_found": True,
            "module_name": _module_base_name(module),
            "module_base": _hex_value(_int_value(getattr(module, "base", None))),
            "loader": type(loader).__name__ if loader is not None else None,
        }
    )

    suffix = _suffix(function_name)
    spellings = [function_name]
    if suffix is None:
        spellings.extend([function_name + "A", function_name + "W"])
    else:
        spellings.append(function_name[:-1])

    names: dict[str, Any] = {}
    for spelling in spellings:
        entry = None
        lookup = getattr(module, "get_export_by_name", None)
        if callable(lookup):
            try:
                entry = lookup(spelling)
            except Exception:
                entry = None
        names[spelling] = {
            "present": entry is not None,
            "address": _hex_value(_int_value(getattr(entry, "address", None))) if entry is not None else None,
            "ordinal": _int_value(getattr(entry, "ordinal", None)) if entry is not None else None,
        }
    result["names"] = names
    result["exact_present"] = bool(names.get(function_name, {}).get("present"))
    result["aliases_present"] = sorted(
        spelling for spelling in names if spelling != function_name and names[spelling]["present"]
    )
    return result


def _signature_view(sig: Any) -> dict[str, Any] | None:
    if sig is None:
        return None
    try:
        return {
            "name": _bounded_text(getattr(sig, "name", None)),
            "dll": _bounded_text(getattr(sig, "dll", None)),
            "source": _bounded_text(getattr(sig, "source", None)),
            "ret_kind": _bounded_text(getattr(sig, "ret_kind", None)),
            "param_count": len(getattr(sig, "params", ()) or ()),
            "variadic": bool(getattr(sig, "variadic", False)),
        }
    except Exception:
        logger.debug("api name resolution diagnostic: signature render failed", exc_info=True)
        return None


def signature_resolution(
    handler: Any,
    module_name: str | None,
    function_name: str,
) -> dict[str, Any]:
    """Record signature-database availability for the exact/A/W spellings.

    Uses the engine's public ``get_signature_db`` accessor and the public
    :func:`sigdb.lookup_name_variants` helper; the database is never modified.
    """
    result: dict[str, Any] = {
        "available": False,
        "module": _bounded_text(module_name),
        "arch": None,
        "exact": None,
        "aliases": {},
    }
    emu = getattr(handler, "emu", None)
    if emu is None or not module_name:
        return result

    getter = getattr(emu, "get_signature_db", None)
    try:
        database = getter() if callable(getter) else None
    except Exception:
        database = None
    if database is None or not getattr(database, "available", False):
        return result

    arch_getter = getattr(emu, "get_arch", None)
    try:
        arch_value = arch_getter() if callable(arch_getter) else None
    except Exception:
        arch_value = None
    if arch_value == _arch.ARCH_X86:
        arch = sigdb.ARCH_X86
    elif arch_value == _arch.ARCH_AMD64:
        arch = sigdb.ARCH_X64
    else:
        return result

    try:
        variants = sigdb.lookup_name_variants(database, module_name, function_name, arch)
    except Exception:
        logger.debug("api name resolution diagnostic: signature variants failed", exc_info=True)
        return result

    result["available"] = True
    result["arch"] = arch
    result["exact"] = _signature_view(variants.get(function_name))
    result["aliases"] = {
        name: _signature_view(sig) for name, sig in variants.items() if name != function_name
    }
    return result


def _safe_call(emu: Any, method: str) -> int | None:
    getter = getattr(emu, method, None)
    if not callable(getter):
        return None
    try:
        return _int_value(getter())
    except Exception:
        logger.debug("api name resolution diagnostic: %s unavailable", method, exc_info=True)
        return None


def dispatch_provenance(handler: Any) -> dict[str, Any]:
    """Record the dispatch sentinel behind the current handler call, if any.

    During ``handle_import_func`` the guest PC still addresses the import-table
    sentinel that ``GetProcAddress`` returned, so ``import_table[pc]`` recovers
    the resolved ``(module, function)`` target.  Direct handler calls have no
    sentinel and report ``dispatch_kind="direct_handler_call"``.
    """
    result: dict[str, Any] = {
        "dispatch_kind": "unknown",
        "pc": None,
        "sentinel": None,
        "sentinel_target": None,
        "return_address": None,
        "pc_mapping_tag": None,
    }
    emu = getattr(handler, "emu", None)
    if emu is None:
        return result

    pc = _safe_call(emu, "get_pc")
    result["pc"] = _hex_value(pc)
    if pc is not None:
        table = getattr(emu, "import_table", None)
        target = None
        if isinstance(table, dict):
            try:
                target = table.get(pc)
            except Exception:
                target = None
        if isinstance(target, (tuple, list)) and len(target) >= 2:
            result["dispatch_kind"] = "import_table_sentinel"
            result["sentinel"] = _hex_value(pc)
            result["sentinel_target"] = {
                "module": _bounded_text(target[0]),
                "function": _bounded_text(target[1]),
            }
        else:
            result["dispatch_kind"] = "direct_handler_call"

        getter = getattr(emu, "get_address_map", None)
        if callable(getter):
            try:
                mapping = getter(pc)
            except Exception:
                mapping = None
            result["pc_mapping_tag"] = _bounded_text(getattr(mapping, "tag", None))

    result["return_address"] = _hex_value(_safe_call(emu, "get_ret_address"))
    return result


def windows_semantics(
    function_name: str,
    resolution: dict[str, Any],
    membership: dict[str, Any],
    signatures: dict[str, Any],
) -> dict[str, Any]:
    """Summarize the Windows expectation explicit in the CSV expected behaviour.

    ``GetProcAddress`` would return NULL only when the signature database (the
    Windows API metadata) does not know the exact undecorated spelling but does
    know an A/W variant.  Engine-only aliases (synthetic module exports, handler
    registration) are recorded separately because they explain why the *engine*
    resolves the name; by themselves they are weaker evidence about Windows.
    Unknown spellings stay ``unknown`` instead of guessing.
    """
    suffix = _suffix(function_name)
    aliases = set(resolution.get("aw_aliases_registered") or ())
    aliases.update(membership.get("aliases_present") or ())
    aliases.update(
        name for name, view in (signatures.get("aliases") or {}).items() if view is not None
    )
    undecorated_with_aliases = suffix is None and bool(aliases)

    signature_available = bool(signatures.get("available"))
    exact_signature_known: bool | None = None
    decorated_signature_known: bool | None = None
    if signature_available:
        exact_signature_known = signatures.get("exact") is not None
        decorated_signature_known = any(
            view is not None for view in (signatures.get("aliases") or {}).values()
        )

    expected = "unknown"
    if suffix is None and exact_signature_known is False and decorated_signature_known is True:
        expected = "NULL"

    note = None
    if expected == "NULL":
        note = (
            "undecorated spelling is absent from the Windows signature metadata while A/W variants exist; "
            "Windows exports these APIs under the decorated names, so GetProcAddress would return NULL "
            "for this spelling"
        )
    elif undecorated_with_aliases:
        note = (
            "undecorated spelling also has A/W aliases in the engine handler/export/signature tables; "
            "the engine resolution itself does not prove the Windows export spelling"
        )
    return {
        "undecorated_name_with_aw_aliases": undecorated_with_aliases,
        "char_width_policy": "requires_A_or_W_suffix",
        "expected_get_proc_address": expected,
        "exact_signature_known": exact_signature_known,
        "decorated_signature_known": decorated_signature_known,
        "note": note,
    }


def char_width_selection(function_name: str, char_width: int | None, failure: str | None) -> dict[str, Any]:
    """Record the suffix-derived width or the explicit failure reason."""
    suffix = _suffix(function_name)
    return {
        "suffix": suffix,
        "width": char_width,
        "derived": suffix is not None and char_width is not None,
        "failure": failure,
    }


def _log_observation(observation: dict[str, Any]) -> None:
    if not logger.isEnabledFor(logging.INFO):
        return
    try:
        logger.info(
            "api-name-resolution-diagnostic %s",
            json.dumps(observation, ensure_ascii=False, sort_keys=True),
        )
    except Exception:
        logger.debug("api name resolution diagnostic: observation not serializable", exc_info=True)


def attach(ctx: dict[str, Any] | None, observation: dict[str, Any] | None) -> None:
    """Attach one observation without affecting handler behaviour.

    A pre-existing observation with a different ``kind`` is preserved and the
    trace is nested under :data:`MERGE_KEY`, matching the FX-003/FX-004 merge
    convention.
    """
    if not isinstance(ctx, dict) or not isinstance(observation, dict):
        return
    try:
        existing = ctx.get("_api_observation")
        if isinstance(existing, dict) and existing.get("kind") != OBSERVATION_KIND:
            existing[MERGE_KEY] = observation
        else:
            ctx["_api_observation"] = observation
        _log_observation(observation)
    except Exception:
        logger.debug("api name resolution diagnostic: observation attachment failed", exc_info=True)


def observe_char_width(
    handler: Any,
    ctx: dict[str, Any] | None,
    function_name: str,
    *,
    char_width: int | None = None,
    failure: str | None = None,
) -> dict[str, Any] | None:
    """Build and attach one character-width resolution observation.

    Args:
        handler: The ``ApiHandler`` instance whose ``get_char_width`` is running.
        ctx: The handler context (``{"func_name": "<dll>.<name>"}``).  No
            observation is attached when this is not a dict.
        function_name: The requested API spelling from ``ctx["func_name"]``.
        char_width: The width the engine selected (1 for ``A``, 2 for ``W``);
            ``None`` when selection failed.
        failure: Explicit failure reason; ``"undecorated_api_name"`` when
            ``get_char_width`` is about to raise its existing ``ApiEmuError``.

    Returns:
        The attached observation dict, or ``None`` when nothing was attached.

    Side effects:
        Writes one read-only observation to ``ctx["_api_observation"]`` and logs
        one structured INFO line.  Never raises and never touches guest state.
    """
    try:
        if not isinstance(ctx, dict) or not isinstance(function_name, str):
            return None
        module_name, name = _split_api_name(function_name)
        resolution = handler_resolution(handler, name)
        membership = module_export_membership(handler, module_name, name)
        signatures = signature_resolution(handler, module_name, name)
        observation: dict[str, Any] = {
            "kind": OBSERVATION_KIND,
            "schema_version": SCHEMA_VERSION,
            "api": _bounded_text(function_name),
            "module": _bounded_text(module_name),
            "function": _bounded_text(name),
            "char_width_selection": char_width_selection(name, char_width, failure),
            "failure": failure,
            "exception_type": "ApiEmuError" if failure else None,
            "handler_resolution": resolution,
            "module_export_membership": membership,
            "signature_resolution": signatures,
            "dispatch_provenance": dispatch_provenance(handler),
            "windows_semantics": windows_semantics(name, resolution, membership, signatures),
        }
        attach(ctx, observation)
        return observation
    except Exception:
        logger.debug("api name resolution diagnostic: observation failed", exc_info=True)
        return None


__all__ = [
    "MAX_TEXT_CHARS",
    "MERGE_KEY",
    "OBSERVATION_KIND",
    "SCHEMA_VERSION",
    "attach",
    "char_width_selection",
    "dispatch_provenance",
    "handler_resolution",
    "module_export_membership",
    "observe_char_width",
    "signature_resolution",
    "windows_semantics",
]
