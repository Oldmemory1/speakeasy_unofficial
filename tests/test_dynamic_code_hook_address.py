"""Regression test for dynamic-code hook trigger addresses."""

from types import SimpleNamespace

from speakeasy import common
from speakeasy.windows.winemu import WindowsEmulator


def test_dynamic_code_hook_exposes_exact_execution_address():
    observed = []
    mapping = SimpleNamespace(
        base=0x700000,
        size=0x4000,
        tag="api.VirtualAlloc.0x700000",
        prot=0x20,
    )
    emulator = SimpleNamespace(
        hooks={
            common.HOOK_DYN_CODE: [
                SimpleNamespace(cb=lambda event_mapping: observed.append((
                    event_mapping.execution_address,
                    event_mapping.base,
                    event_mapping.execution_caller_address,
                ))),
            ],
        },
        get_profiler=lambda: None,
        get_address_map=lambda _address: mapping,
        _dyn_code_caller_pc=0x401234,
    )

    WindowsEmulator._fire_dyn_code_hooks(emulator, 0x701234)

    assert observed == [(0x701234, 0x700000, 0x401234)]
    assert not hasattr(mapping, "execution_address")
    assert not hasattr(mapping, "execution_caller_address")
