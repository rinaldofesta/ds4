#!/bin/sh
# ds4_hooks test fixture: sleeps far longer than any test timeout_ms, so the
# per-hook timeout / process-group kill path is exercised deterministically.
sleep 5
