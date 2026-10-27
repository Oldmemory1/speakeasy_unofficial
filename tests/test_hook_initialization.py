"""Regression tests for lazily registered hooks."""

from speakeasy import Speakeasy


def test_lazy_mem_map_hook_unpacks_callback_and_range(monkeypatch):
    registered = []
    fake = object.__new__(Speakeasy)

    # _init_hooks only drains these queues and dispatches through add_* methods.
    for name in (
        "api_hooks",
        "code_hooks",
        "dyn_code_hooks",
        "invalid_insn_hooks",
        "mem_read_hooks",
        "mem_write_hooks",
        "in_insn_hooks",
        "syscall_insn_hooks",
        "mem_invalid_hooks",
        "interrupt_hooks",
    ):
        setattr(fake, name, [])

    def callback(_emu, _base, _size, _tag, _protection, _flags):
        return None

    fake.mem_map_hooks = [(callback, 0x1000, 0x2000)]
    fake.add_mem_map_hook = lambda cb, begin=1, end=0: registered.append(
        (cb, begin, end)
    )

    Speakeasy._init_hooks(fake)

    assert registered == [(callback, 0x1000, 0x2000)]
    assert fake.mem_map_hooks == []
