#!/usr/bin/env python3
"""Run the brd correctness suites in order; exit non-zero if any suite fails."""

import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from drive import require_gate  # noqa: E402

require_gate()

HERE = os.path.dirname(os.path.abspath(__file__))
SUITES = [
    "e2e.py",
    "probe_sync.py",
    "probe_coldstart.py",
    "probe_reconnect.py",
    "probe_teardown.py",
    "probe_datagram.py",
    "probe_wide.py",
    "probe_predict.py",
    "probe_wedge.py",
    "probe_sessions.py",
    "probe_grep.py",
    "probe_query.py",
    "probe_forward.py",
    "probe_headless.py",
]

# Seconds one suite may take before it is called hung.
#
# Generous against the slowest of them - `probe_predict` spends its life on a
# 200 ms shim - and still far under a human's patience. Without it a wedged
# session takes the whole run with it and reports nothing, which is exactly
# the failure the suites exist to catch.
DEADLINE = 180

results = []
for suite in SUITES:
    print(f"===== {suite} =====", flush=True)
    started = time.monotonic()
    try:
        code = subprocess.run(
            [sys.executable, os.path.join(HERE, suite)],
            env=os.environ,
            timeout=DEADLINE,
        ).returncode
    except subprocess.TimeoutExpired:
        code = None
    elapsed = time.monotonic() - started
    results.append((suite, code, elapsed))
    print(flush=True)

print("===== summary =====", flush=True)
for suite, code, elapsed in results:
    verdict = "TIMEOUT" if code is None else "PASS" if code == 0 else "FAIL"
    named = "no exit" if code is None else f"exit {code}"
    print(f"{verdict}  {suite} ({named}, {elapsed:.0f}s)", flush=True)

sys.exit(0 if all(code == 0 for _, code, _ in results) else 1)
