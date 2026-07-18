#ifndef DS4_PERMISSIONS_H
#define DS4_PERMISSIONS_H
#include <stddef.h>
#include "ds4_config.h"

/* Opt-in confirm gate + allowlist for risky tools. Registered in
 * settings.json:
 *
 *   {"permissions": {
 *     "confirm": ["bash", "write", "edit"],
 *     "allow":   ["bash:make *", "bash:git status*", "write:*.md", "edit:*.c"]
 *   }}
 *
 * - confirm: tool names (exact, no globs) that require approval before they
 *   run. May name any tool -- native, "skill", or "mcp__*" wire names.
 * - allow: strings "<tool>:<pattern>"; pattern is fnmatch-matched against the
 *   tool call's SUBJECT (extracted by the caller -- see below). A matching
 *   allow rule silently permits the call without asking. Malformed entries
 *   (missing the ':') are skipped with a warning; siblings still load.
 * - Tools not listed in "confirm" are never gated, regardless of "allow".
 *
 * Merge semantics: "permissions" follows the same config merge as every
 * other key (see ds4_config_get) -- a project settings.json that has a
 * "permissions" key replaces the user one wholesale.
 *
 * SUBJECT extraction is the caller's job, not this module's (ds4_agent.c
 * glue): the value of the arg named "command" if present, else the arg named
 * "path", else the first arg's value, else "". This covers bash -> command,
 * write/edit/read -> path, skill -> name, and MCP tools -> first arg.
 */

typedef struct ds4_permissions ds4_permissions;
typedef enum { DS4_PERM_ALLOW, DS4_PERM_ASK } ds4_perm_decision;

/* NULL if no permissions key / no confirm entries. */
ds4_permissions *ds4_permissions_load(const ds4_config *cfg, char *warn, size_t warn_len);
void ds4_permissions_free(ds4_permissions *p);

/* Pure decision: ALLOW if p NULL, tool not in confirm, or an allow rule
 * matches (tool exact + fnmatch(pattern, subject)). ASK otherwise. */
ds4_perm_decision ds4_permissions_check(const ds4_permissions *p,
                                        const char *tool, const char *subject);

#ifdef DS4_PERMISSIONS_TEST
int ds4_permissions_unit_tests_run(void);
#endif
#endif
