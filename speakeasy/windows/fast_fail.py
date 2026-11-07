"""Explicit Windows ``__fastfail`` process-termination contract."""

FAST_FAIL_INTERRUPT_VECTOR = 0x29
STATUS_STACK_BUFFER_OVERRUN = 0xC0000409
TERMINATION_KIND = "process_terminated"
FAST_FAIL_GS_COOKIE_INIT = 6


def requires_kernel_bootstrap_recovery(
    fast_fail_code: int,
    *,
    kernel_mode: bool,
) -> bool:
    """Return whether the loader should satisfy a kernel GS-cookie bootstrap.

    A real Windows kernel loader initializes the GS cookie before driver code
    runs. Speakeasy does not model that loader step for every driver image, so
    an early ``FAST_FAIL_GS_COOKIE_INIT`` can represent missing bootstrap state
    rather than guest-requested process termination. This compatibility applies
    only to kernel mode; the same code in a user-mode guest remains a terminal
    fast fail.
    """
    return kernel_mode and fast_fail_code == FAST_FAIL_GS_COOKIE_INIT
