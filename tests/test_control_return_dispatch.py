from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from speakeasy.windows.common import API_CALLBACK_HANDLER_ADDR, SEH_RETURN_ADDR
from speakeasy.windows.winemu import WindowsEmulator


def _emulator_at(pc):
    return SimpleNamespace(
        run_complete=False,
        emu_complete=False,
        curr_run=SimpleNamespace(error=None),
        get_pc=Mock(return_value=pc),
        do_call_return=Mock(),
        continue_seh=Mock(),
        on_run_complete=Mock(),
        get_error_info=Mock(return_value="control-return-error"),
    )


def test_seh_control_return_is_dispatched_before_fetch():
    emu = _emulator_at(SEH_RETURN_ADDR)

    assert WindowsEmulator._dispatch_control_return(emu)
    emu.continue_seh.assert_called_once_with()
    emu.on_run_complete.assert_not_called()
    emu.do_call_return.assert_not_called()


def test_seh_control_return_completes_exhausted_run():
    emu = _emulator_at(SEH_RETURN_ADDR)
    emu.continue_seh.side_effect = lambda: setattr(emu, "run_complete", True)

    assert WindowsEmulator._dispatch_control_return(emu)
    emu.on_run_complete.assert_called_once_with()


def test_api_callback_control_return_uses_pending_callback():
    emu = _emulator_at(API_CALLBACK_HANDLER_ADDR)
    callback = (0x401000, "callback", (1, 2, 3))
    run = SimpleNamespace(api_callbacks=[callback])
    emu.get_current_run = Mock(return_value=run)

    assert WindowsEmulator._dispatch_control_return(emu)
    emu.do_call_return.assert_called_once_with(3, 0x401000)
    assert run.api_callbacks == []
    emu.on_run_complete.assert_not_called()


def test_api_callback_control_return_without_callback_fails_cleanly():
    emu = _emulator_at(API_CALLBACK_HANDLER_ADDR)
    emu.get_current_run = Mock(return_value=SimpleNamespace(api_callbacks=[]))

    assert WindowsEmulator._dispatch_control_return(emu)
    assert emu.curr_run.error == "control-return-error"
    emu.on_run_complete.assert_called_once_with()


@pytest.mark.skipif(
    not (Path(__file__).resolve().parents[2] / "samples" / "llm_handoff_samples").is_dir(),
    reason="integration samples are not available",
)
@pytest.mark.parametrize(
    "sample_id",
    [
        "270192196cb5dc6b0fc987e19c99701acce994ee826447e8ae011eb70681ff9f",
        "7379271c71866d3dd42ce6c25a1c97701330ae12f56e4674bd17f86010aa3592",
    ],
)
def test_control_return_samples_complete(config, run_test, sample_id):
    sample_dir = (
        Path(__file__).resolve().parents[2]
        / "samples"
        / "llm_handoff_samples"
        / "samples"
        / sample_id
    )
    data = (sample_dir / f"{sample_id}.exe").read_bytes()
    config.setdefault("modules", {})["functions_always_exist"] = True

    report = run_test(config, data)

    assert report.entry_points[0].error is None
