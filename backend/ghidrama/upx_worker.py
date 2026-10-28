"""Apply process limits before exec'ing the configured UPX tool (never the sample)."""
from __future__ import annotations

import argparse
import os
import resource
import signal
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--upx", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--max-bytes", type=int, required=True)
    parser.add_argument("--timeout", type=int, required=True)
    args = parser.parse_args()
    if Path("/proc/self").exists():
        import ctypes
        expected_parent = int(os.environ["GHIDRAMA_PARENT_PID"])
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "Could not configure UPX parent-death signal")
        if os.getppid() != expected_parent:
            return
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (args.max_bytes, args.max_bytes))
    resource.setrlimit(resource.RLIMIT_AS, (1024 ** 3, 1024 ** 3))
    resource.setrlimit(resource.RLIMIT_CPU, (args.timeout, args.timeout + 1))
    os.execve(args.upx, [args.upx, "-d", "--no-color", "--no-progress", "-o", args.output, "--", args.input],
              {"PATH": os.defpath, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})


if __name__ == "__main__":
    main()
