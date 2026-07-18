#define DS4_SKILLS_TEST
#include "../ds4_skills.c"
#include <stdio.h>
int main(void) {
    int failures = ds4_skills_unit_tests_run();
    if (failures) { fprintf(stderr, "ds4_skills tests: %d FAILED\n", failures); return 1; }
    printf("ds4_skills tests: ok\n");
    return 0;
}
