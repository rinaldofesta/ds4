#define DS4_HOOKS_TEST
#include "../ds4_hooks.c"
#include <stdio.h>
int main(void) {
    int failures = ds4_hooks_unit_tests_run();
    if (failures) { fprintf(stderr, "ds4_hooks tests: %d FAILED\n", failures); return 1; }
    printf("ds4_hooks tests: ok\n");
    return 0;
}
