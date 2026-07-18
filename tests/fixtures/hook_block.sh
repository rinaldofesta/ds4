#!/bin/sh
# ds4_hooks test fixture: always blocks (exit 2), stderr carries a caller-supplied
# tag so tests can tell which invocation produced a given block_reason.
echo "nope: $HOOK_TEST_TAG" >&2
exit 2
