"""Process hardening: no core dump, no swap when possible."""
import ctypes
import resource

PR_SET_DUMPABLE = 4
MCL_CURRENT = 1
MCL_FUTURE = 2
_MIN_MEMLOCK = 1 << 30
_SWAP_WARNING = "memory not locked: it may be written to swap"


def harden_process() -> list[str]:
    warnings: list[str] = []
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        warnings.append("the process may still produce a core dump (prctl failed)")
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError):
        warnings.append("the core dump limit could not be set to zero")
    soft, _ = resource.getrlimit(resource.RLIMIT_MEMLOCK)
    if soft == resource.RLIM_INFINITY or soft >= _MIN_MEMLOCK:
        if libc.mlockall(MCL_CURRENT | MCL_FUTURE) != 0:
            warnings.append(_SWAP_WARNING)
    else:
        warnings.append(_SWAP_WARNING)
    return warnings
