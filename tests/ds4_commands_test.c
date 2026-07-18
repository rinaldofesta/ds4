#define DS4_COMMANDS_TEST
#include "../ds4_commands.c"
#include <stdio.h>
int main(void) {
    int failures = ds4_commands_unit_tests_run();
    if (failures) { fprintf(stderr, "ds4_commands tests: %d FAILED\n", failures); return 1; }
    printf("ds4_commands tests: ok\n");
    return 0;
}
