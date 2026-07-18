#define DS4_CONFIG_TEST
#include "../ds4_config.c"
#include <stdio.h>
int main(void) {
    int failures = ds4_config_unit_tests_run();
    if (failures) { fprintf(stderr, "ds4_config tests: %d FAILED\n", failures); return 1; }
    printf("ds4_config tests: ok\n");
    return 0;
}
