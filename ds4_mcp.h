#ifndef DS4_MCP_H
#define DS4_MCP_H
#include <stddef.h>
#include "ds4_config.h"

/* MCP (Model Context Protocol) stdio client: spawns servers configured in
 * mcp.json across the ds4_config search roots, handshakes over newline
 * delimited JSON-RPC 2.0, lists their tools, and dispatches tools/call on
 * demand. See ds4_mcp.c for the protocol and sanitization details -- tool
 * names/descriptions/schemas enter the trusted system prompt, so intake is
 * sanitized the same way ds4_skills sanitizes SKILL.md frontmatter. */

typedef struct ds4_mcp_registry ds4_mcp_registry;

typedef struct {
    char *server_name;
    char *tool_name;          /* raw name from tools/list */
    char *wire_name;          /* "mcp__<server>__<tool>" */
    char *description;        /* sanitized */
    char *input_schema_json;  /* sanitized verbatim JSON text */
} ds4_mcp_tool;

typedef struct {
    int handshake_timeout_ms; /* <=0 -> 10000 */
    int call_timeout_ms;      /* <=0 -> 60000 */
} ds4_mcp_opts;

/* Reads mcp.json from all roots, spawns servers, handshakes, lists tools.
 * NEVER fatal: servers that fail to spawn/handshake/list are skipped with a
 * warning line in warn. Returns NULL only if no servers are configured at all
 * (so callers can gate all MCP behavior on registry != NULL). opts NULL = defaults. */
ds4_mcp_registry *ds4_mcp_registry_create(const ds4_config *cfg, const ds4_mcp_opts *opts,
                                          char *warn, size_t warn_len);
void ds4_mcp_registry_free(ds4_mcp_registry *reg); /* SIGTERM children, brief grace, SIGKILL; reap */

int ds4_mcp_registry_tool_count(const ds4_mcp_registry *reg);          /* 0 if reg NULL */
int ds4_mcp_registry_server_count(const ds4_mcp_registry *reg);        /* 0 if reg NULL */
const ds4_mcp_tool *ds4_mcp_registry_tool_at(const ds4_mcp_registry *reg, int i);
const ds4_mcp_tool *ds4_mcp_registry_find(const ds4_mcp_registry *reg, const char *wire_name); /* NULL-reg tolerant */

/* Synchronous tools/call. Always returns a malloc'd, model-facing plain-text
 * result -- success text, or "Tool error: ..." on any failure (timeout, dead
 * server, isError:true, JSON-RPC error). Never NULL, never crashes on dead pipe. */
char *ds4_mcp_registry_call_tool(ds4_mcp_registry *reg, const ds4_mcp_tool *tool,
                                 const char *arguments_json);

/* System-prompt block for all tools; NULL if reg NULL or zero tools. */
char *ds4_mcp_tools_prompt_text(const ds4_mcp_registry *reg);

/* DSML args -> JSON object text. args entries with is_string=true are emitted as
 * JSON-escaped strings; is_string=false values are emitted verbatim (the model
 * already wrote a JSON literal). Exposed for tests. Malloc'd, "{}" if argc==0. */
struct agent_tool_arg; /* forward-declared shape: see ds4_agent.c agent_tool_arg */
char *ds4_mcp_args_to_json(const char **names, const char **values, const int *is_string, int argc);

#ifdef DS4_MCP_TEST
#include <sys/types.h>
/* Test-only accessors into registry internals, so tests can assert on
 * process reaping without the public API needing to expose pid at all. */
int ds4_mcp_test_proc_count(const ds4_mcp_registry *reg);
pid_t ds4_mcp_test_proc_pid(const ds4_mcp_registry *reg, int i);
int ds4_mcp_unit_tests_run(void);
#endif
#endif
