#!/bin/sh
# ds4_hooks test fixture: copies its stdin verbatim to $HOOK_STDIN_OUT so the
# test can byte-compare it against the payload ds4_hooks_run wrote.
cat > "$HOOK_STDIN_OUT"
exit 0
