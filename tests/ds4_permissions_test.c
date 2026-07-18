#define DS4_PERMISSIONS_TEST
#include "../ds4_permissions.c"
#include <stdio.h>
int main(void) {
    int failures = ds4_permissions_unit_tests_run();
    if (failures) { fprintf(stderr, "ds4_permissions tests: %d FAILED\n", failures); return 1; }
    printf("ds4_permissions tests: ok\n");
    return 0;
}
