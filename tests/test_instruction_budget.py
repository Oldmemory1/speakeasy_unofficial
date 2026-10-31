"""Instruction-budget state regression test."""

from speakeasy import Speakeasy


def test_instruction_budget_state_is_exposed(config):
    config = dict(config)
    config["max_instructions"] = 1
    se = Speakeasy(config=config)
    try:
        shellcode = se.load_shellcode(data=b"\x90\x90\xc3", arch="amd64")
        se.run_shellcode(shellcode)
        assert se.emu.instruction_budget_exhausted is True
    finally:
        se.shutdown()


def test_normal_completion_does_not_set_instruction_budget(config):
    config = dict(config)
    config["max_instructions"] = 1_000
    se = Speakeasy(config=config)
    try:
        shellcode = se.load_shellcode(data=b"\x90\x90\xc3", arch="amd64")
        se.run_shellcode(shellcode)
        assert se.emu.instruction_budget_exhausted is False
        assert se.emu.run_complete is True
    finally:
        se.shutdown()
