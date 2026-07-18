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

/* Search roots for content (skills/, commands/, mcp.json, hooks.json),
 * highest precedence first:
 *
 *   1. project .ds4 dir (if any)
 *   2. project .ds4/plugins/<name> dirs, sorted by strcmp(name)
 *   3. user .ds4 dir (if any)
 *   4. user .ds4/plugins/<name> dirs, sorted by strcmp(name)
 *
 * A plugin is a directory .ds4/plugins/<name>/ discovered at load time and
 * fed to callers as just another search root -- it adds no new mechanism, so
 * ds4_skills/ds4_commands/ds4_mcp need zero changes to pick plugin content
 * up (their existing precedence/shadowing semantics extend naturally: a
 * plugin can never outrank its own base root, but it does outrank every root
 * that follows it in this list). <name> must match
 * [A-Za-z0-9][A-Za-z0-9_-]{0,63} or the directory is skipped with a warning;
 * non-directory entries under plugins/ are silently ignored (same as a
 * stray file under skills/).
 *
 * IMPORTANT: settings.json is read ONLY from the two base roots (project
 * .ds4 and user .ds4), never from a plugin dir -- a plugin cannot alter
 * permissions or the settings-derived hook policy; see ds4_config_get and
 * ds4_hooks.h. ds4_hooks additionally reads a plugin-scoped hooks.json
 * directly (not through ds4_config_get), which is the one place plugins do
 * contribute lifecycle behavior -- by design, additively, never as a
 * settings override. */
int ds4_config_root_count(const ds4_config *c);
const char *ds4_config_root_at(const ds4_config *c, int i);

/* false / NULL for the two base roots (project .ds4, user .ds4); true / the
 * plugin's <name> for every other root. Out-of-range i behaves like
 * ds4_config_root_at (false / NULL). */
bool ds4_config_root_is_plugin(const ds4_config *c, int i);
const char *ds4_config_root_plugin_name(const ds4_config *c, int i);

#ifdef DS4_CONFIG_TEST
int ds4_config_unit_tests_run(void);
#endif
#endif
