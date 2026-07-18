#!/bin/sh
# ds4_hooks test fixture: exits with a non-0/non-2 status, simulating a broken
# hook (and indistinguishable from a real exec/spawn failure, which also
# surfaces as exit 127) -- both must fail open with a warning.
exit 127
