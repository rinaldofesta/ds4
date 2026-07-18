#define DS4_MCP_TEST
#include "../ds4_mcp.c"
#include <stdio.h>
int main(void) {
    int failures = ds4_mcp_unit_tests_run();
    if (failures) { fprintf(stderr, "ds4_mcp tests: %d FAILED\n", failures); return 1; }
    printf("ds4_mcp tests: ok\n");
    return 0;
}
