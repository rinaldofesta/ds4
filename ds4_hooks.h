#ifndef DS4_HOOKS_H
#define DS4_HOOKS_H
#include <stddef.h>
#include <stdbool.h>
#include "ds4_config.h"

/* PreToolUse/PostToolUse shell hooks: user-configurable lifecycle commands
 * that wrap every tool execution (native, skill, and MCP alike). Registered
 * in settings.json:
 *
 *   {"hooks": {
 *     "PreToolUse":  [{"matcher": "bash",  "command": "./.ds4/hooks/guard.sh", "timeout_ms": 10000}],
 *     "PostToolUse": [{"matcher": "*",     "command": "./notify.sh"}]
 *   }}
 *
 * - matcher: fnmatch glob against the tool name the model invoked (native
 *   names, "skill", and "mcp__*" wire names all flow through). Missing/empty
 *   matcher defaults to "*".
 * - command: required. Run via `/bin/sh -c <command>`, cwd = project root
 *   (falls back to the caller's cwd if there is no project root). stdin is
 *   the payload JSON; stdout+stderr are each captured, capped at 64 KiB.
 * - timeout_ms: optional per-hook, default 10000. On timeout, the hook's
 *   whole process group is killed; the run is treated as fail-open (warn).
 * - exit 0 = allow, exit 2 = block (stderr becomes the model-visible
 *   reason). Anything else -- non-0/non-2 exit, timeout, spawn failure --
 *   fails open with a warning; it never blocks the tool call.
 *
 * Merge semantics: "hooks" follows the same config merge as every other key
 * (see ds4_config_get) -- a project settings.json that has a "hooks" key
 * replaces the user one wholesale (whole-key precedence, no deep merge
 * across PreToolUse/PostToolUse arrays from different files). Malformed
 * entries (missing command, a non-array event value, unknown event keys)
 * are skipped with a warning; never fatal.
 *
 * Plugin hooks (see ds4_config.h for what a plugin is): every plugin root
 * (ds4_config_root_is_plugin) may additionally carry its own
 * <plugin-root>/hooks.json, shaped exactly like settings.json's "hooks"
 * value: {"hooks": {"PreToolUse": [...], "PostToolUse": [...]}}. Unlike
 * settings.json's whole-key-replace merge, plugin hooks are purely additive:
 * they run AFTER the settings-derived hooks, in root order, and can never
 * replace or suppress them -- a plugin only ever adds lifecycle behavior, it
 * cannot alter permissions or override the settings-derived hook policy
 * (settings.json itself is never read from a plugin dir; see
 * ds4_config_root_count/root_at). A "command" that starts with "./" is
 * resolved against THAT PLUGIN's own directory (the leading "./" is dropped
 * and the plugin dir is prefixed instead), so a plugin bundle stays
 * relocatable regardless of ds4-agent's cwd or the project root; settings.json
 * hooks are unaffected (they already run with cwd = project root). A
 * malformed plugin hooks.json is fail-open: skip + warn, siblings (other
 * plugins, or the settings hooks) unaffected.
 *
 * Trust note: a project's .ds4/ (including its plugins/) is trusted the same
 * way project settings.json hooks already are -- running ds4-agent in a
 * cloned repo executes that repo's configured hooks, plugin hooks included.
 * Same model, no new exposure class.
 *
 * Payload shapes written to each hook's stdin (built by the caller):
 *   {"event":"PreToolUse","tool_name":"bash","tool_input":{"command":"make test"}}
 *   {"event":"PostToolUse","tool_name":"bash","tool_input":{...},"tool_output":"<first 8 KiB of result>"}
 */

typedef enum { DS4_HOOK_PRE_TOOL, DS4_HOOK_POST_TOOL } ds4_hook_event;
typedef struct ds4_hooks ds4_hooks;

/* NULL if no hooks key / zero valid entries -- callers gate all hook behavior
 * on the handle being non-NULL. */
ds4_hooks *ds4_hooks_load(const ds4_config *cfg, char *warn, size_t warn_len);
void ds4_hooks_free(ds4_hooks *h);
int  ds4_hooks_count(const ds4_hooks *h, ds4_hook_event event); /* 0 if h NULL */

typedef struct {
    bool blocked;          /* some hook exited 2 */
    char *block_reason;    /* captured stderr of the blocking hook (trimmed, capped), may be "" */
    char *warnings;        /* accumulated non-fatal hook failures this run, or NULL */
} ds4_hook_result;

/* Runs all hooks registered for (event, tool_name) in registration order
 * (project-file order); stops at the first block. payload_json is written to
 * each hook's stdin. h==NULL -> {false, NULL, NULL} immediately. */
ds4_hook_result ds4_hooks_run(ds4_hooks *h, ds4_hook_event event,
                              const char *tool_name, const char *payload_json);
void ds4_hook_result_free(ds4_hook_result *r);

#ifdef DS4_HOOKS_TEST
int ds4_hooks_unit_tests_run(void);
#endif
#endif
