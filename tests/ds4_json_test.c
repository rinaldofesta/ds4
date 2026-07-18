#define DS4_JSON_TEST
#include "../ds4_json.c"
#include <stdio.h>
int main(void) {
    int failures = ds4_json_unit_tests_run();
    if (failures) { fprintf(stderr, "ds4_json tests: %d FAILED\n", failures); return 1; }
    printf("ds4_json tests: ok\n");
    return 0;
}
