#ifndef DS4_CONFIG_H
#define DS4_CONFIG_H
#include <stddef.h>
#include "ds4_json.h"

typedef struct ds4_config ds4_config;

/* Loads config relative to start_dir (NULL = cwd). Missing dirs/files are not
 * errors (empty config). A malformed settings.json is skipped fail-open; a
 * one-line warning is appended to warn (if warn_len > 0, always NUL-terminated,
 * possibly empty). Returns NULL only on allocation failure. */
ds4_config *ds4_config_load(const char *start_dir, char *warn, size_t warn_len);
void ds4_config_free(ds4_config *c);

const char *ds4_config_project_root(const ds4_config *c); /* NULL if none */
const char *ds4_config_project_ds4_dir(const ds4_config *c); /* "<root>/.ds4" or NULL (returned even if the dir doesn't exist yet -- callers stat it) */
const char *ds4_config_user_ds4_dir(const ds4_config *c);    /* "~/.ds4" expanded, NULL if no HOME */

/* Merged settings lookup: project settings.json first, then user. NULL if the
 * key is absent from both. Returned pointer is owned by the config object. */
const ds4_json_value *ds4_config_get(const ds4_config *c, const char *key);

/* Search roots for content (skills/, commands/, mcp.json), highest precedence
 * first: project .ds4 dir (if any), then user .ds4 dir (if any). Later tasks
 * extend this with plugin dirs; keep the accessor shape. */
int ds4_config_root_count(const ds4_config *c);
const char *ds4_config_root_at(const ds4_config *c, int i);

#ifdef DS4_CONFIG_TEST
int ds4_config_unit_tests_run(void);
#endif
#endif
