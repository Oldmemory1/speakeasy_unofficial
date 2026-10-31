from types import SimpleNamespace

from speakeasy.config import UiConfig, get_windows_ui_profile
from speakeasy.profiler import Profiler, Run
from speakeasy.profiler_events import TracePosition
from speakeasy.winenv.api.usermode.user32 import (
    SM_CLEANBOOT,
    SM_CMONITORS,
    SM_CXSCREEN,
    SM_CYSCREEN,
    SM_REMOTESESSION,
    User32,
    resolve_system_metric,
)


def _ui(profile: str = "normal") -> UiConfig:
    return UiConfig.model_validate(get_windows_ui_profile(profile))


def _call_metric(ui: UiConfig, selector: int) -> tuple[int, dict]:
    emu = SimpleNamespace(config=SimpleNamespace(ui=ui))
    ctx = {}
    value = User32.GetSystemMetrics(None, emu, [selector], ctx)
    return value, ctx["_api_observation"]


def test_normal_profile_reports_normal_boot_and_desktop_geometry():
    ui = _ui()

    value, observation = _call_metric(ui, SM_CLEANBOOT)
    assert value == 0
    assert observation == {
        "kind": "system_metric",
        "selector": SM_CLEANBOOT,
        "metric": "SM_CLEANBOOT",
        "value": 0,
        "known": True,
        "profile": "normal",
        "interpretation": "normal_boot",
    }
    assert resolve_system_metric(SM_CXSCREEN, ui)[0] == 1024
    assert resolve_system_metric(SM_CYSCREEN, ui)[0] == 768
    assert resolve_system_metric(SM_CMONITORS, ui)[0] == 1
    assert resolve_system_metric(SM_REMOTESESSION, ui)[0] == 0


def test_safe_mode_and_remote_session_profiles_are_independent():
    safe_mode = _ui("safe_mode")
    remote_session = _ui("remote_session")

    assert _call_metric(safe_mode, SM_CLEANBOOT) == (
        1,
        {
            "kind": "system_metric",
            "selector": SM_CLEANBOOT,
            "metric": "SM_CLEANBOOT",
            "value": 1,
            "known": True,
            "profile": "safe_mode",
            "interpretation": "safe_mode",
        },
    )
    assert _call_metric(remote_session, SM_CLEANBOOT)[0] == 0
    assert _call_metric(remote_session, SM_REMOTESESSION)[0] == 1


def test_unknown_selector_uses_stable_zero_fallback_and_is_observable():
    value, observation = _call_metric(_ui(), 0x41414141)

    assert value == 0
    assert observation["known"] is False
    assert observation["metric"] is None
    assert observation["value"] == 0


def test_api_report_preserves_metric_observation():
    profiler = Profiler()
    run = Run()
    position = TracePosition(tick=12, tid=3, pid=2, pc=0x40D4A9)
    observation = {
        "kind": "system_metric",
        "selector": SM_CLEANBOOT,
        "metric": "SM_CLEANBOOT",
        "value": 0,
        "known": True,
        "profile": "normal",
    }

    profiler.record_api_event(
        run,
        position,
        "user32.GetSystemMetrics",
        0,
        [SM_CLEANBOOT],
        observation=observation,
    )

    event = run.events[0]
    assert event.pos.pc == 0x40D4A9
    assert event.args == ["0x43"]
    assert event.ret_val == "0x0"
    assert event.observation == observation


def test_ui_profiles_are_copies():
    first = get_windows_ui_profile("normal")
    first["clean_boot"] = 2

    assert get_windows_ui_profile("normal")["clean_boot"] == 0
