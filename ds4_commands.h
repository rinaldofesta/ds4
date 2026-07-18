#ifndef DS4_COMMANDS_H
#define DS4_COMMANDS_H
#include <stddef.h>
#include "ds4_config.h"

typedef struct { char *name; char *path; } ds4_command_meta;
typedef struct { ds4_command_meta *v; int len; int cap; } ds4_command_list;

void ds4_commands_scan(const ds4_config *cfg, ds4_command_list *out, char *warn, size_t warn_len);
void ds4_commands_list_free(ds4_command_list *list);

/* slash_cmd is the first whitespace-delimited word including the leading '/',
 * e.g. "/review". Case-sensitive. */
bool ds4_commands_known(const ds4_command_list *list, const char *slash_cmd);

/* Reads the file body and replaces EVERY literal occurrence of "$ARGUMENTS"
 * with args ("" if args is NULL). Returns malloc'd text, NULL if command
 * unknown or file unreadable. No other substitution, no shell parsing. */
char *ds4_commands_expand(const ds4_command_list *list, const char *slash_cmd, const char *args);

#ifdef DS4_COMMANDS_TEST
int ds4_commands_unit_tests_run(void);
#endif
#endif
