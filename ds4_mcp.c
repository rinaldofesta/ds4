#include "ds4_mcp.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* stdio MCP client: mcp.json discovery/merge across ds4_config search roots,
 * newline-delimited JSON-RPC 2.0 over pipes to forked servers, and system
 * prompt catalog rendering. See ds4_mcp.h for the contract.
 *
 * Tool names/descriptions/inputSchema text enter the trusted system prompt
 * (ds4_mcp_tools_prompt_text), so intake is sanitized the same way
 * ds4_skills sanitizes SKILL.md frontmatter: names are regex-validated,
 * descriptions are capped and control-char/DSML-marker scrubbed, and
 * inputSchema JSON gets the same DSML-marker scrub (a hostile server must
 * not be able to smuggle a ｜DSML｜ marker into the trusted prompt via a
 * tool's declared name/description/schema). Tool CALL RESULTS are not
 * sanitized here -- they flow back as ordinary untrusted tool-role text,
 * same as bash/read output elsewhere in ds4_agent.c. */

#define DS4_MCP_MAX_CONFIG_SIZE (1u << 20) /* 1 MiB, mirrors ds4_config's settings cap */
#define DS4_MCP_MAX_DESC_BYTES 1024
#define DS4_MCP_MAX_SCHEMA_BYTES 8192
#define DS4_MCP_MAX_LINE_BYTES (4u * 1024 * 1024) /* 4 MiB */
#define DS4_MCP_MAX_PAGES 16
#define DS4_MCP_MALFORMED_LIMIT 8
#define DS4_MCP_DEFAULT_HANDSHAKE_MS 10000
#define DS4_MCP_DEFAULT_CALL_MS 60000
#define MCP_READ_CHUNK 8192

static char *mcp_strdup(const char *s) {
    size_t n = strlen(s);
    char *p = malloc(n + 1);
    if (p) memcpy(p, s, n + 1);
    return p;
}

/* Deliberately not depending on ds4_kvstore_path_join so this module stays
 * standalone-compilable for its test binary (same convention as ds4_skills). */
static char *mcp_join(const char *dir, const char *name) {
    size_t dlen = strlen(dir);
    int need_slash = dlen > 0 && dir[dlen - 1] != '/';
    size_t nlen = strlen(name);
    char *out = malloc(dlen + (need_slash ? 1 : 0) + nlen + 1);
    if (!out) return NULL;
    memcpy(out, dir, dlen);
    size_t pos = dlen;
    if (need_slash) out[pos++] = '/';
    memcpy(out + pos, name, nlen);
    pos += nlen;
    out[pos] = '\0';
    return out;
}

static void mcp_warn_append(char *warn, size_t warn_len, const char *ctx, const char *problem) {
    if (!warn || warn_len == 0) return;
    size_t cur = strlen(warn);
    if (cur + 1 >= warn_len) return;
    snprintf(warn + cur, warn_len - cur, "mcp: %s: %s\n", ctx, problem);
}

/* Server name: [A-Za-z0-9][A-Za-z0-9_-]{0,31} -- enters the trusted prompt
 * region via wire names, so it is validated before anything else. */
static bool mcp_valid_server_name(const char *s) {
    size_t n = strlen(s);
    if (n < 1 || n > 32) return false;
    if (!isalnum((unsigned char)s[0])) return false;
    for (size_t i = 1; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!(isalnum(c) || c == '_' || c == '-')) return false;
    }
    return true;
}

/* Tool name: [A-Za-z0-9][A-Za-z0-9_.-]{0,63} */
static bool mcp_valid_tool_name(const char *s) {
    size_t n = strlen(s);
    if (n < 1 || n > 64) return false;
    if (!isalnum((unsigned char)s[0])) return false;
    for (size_t i = 1; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!(isalnum(c) || c == '_' || c == '.' || c == '-')) return false;
    }
    return true;
}

/* Caps at 1024 bytes (never splitting a UTF-8 sequence) and replaces ASCII
 * control chars and the fullwidth vertical bar (UTF-8 EF BD 9C -- the DSML
 * marker char) with a space. Mirrors ds4_skills' sk_sanitize_description. */
static char *mcp_sanitize_desc(const char *desc) {
    size_t len = strlen(desc);
    size_t cap = DS4_MCP_MAX_DESC_BYTES;
    if (len > cap) {
        while (cap > 0 && ((unsigned char)desc[cap] & 0xC0) == 0x80) cap--;
        len = cap;
    }
    char *out = malloc(len + 1);
    if (!out) return NULL;
    size_t oi = 0;
    for (size_t i = 0; i < len; ) {
        if (i + 3 <= len &&
            (unsigned char)desc[i] == 0xEF &&
            (unsigned char)desc[i + 1] == 0xBD &&
            (unsigned char)desc[i + 2] == 0x9C)
        {
            out[oi++] = ' ';
            i += 3;
            continue;
        }
        unsigned char c = (unsigned char)desc[i];
        out[oi++] = (c < 0x20 || c == 0x7F) ? ' ' : (char)c;
        i++;
    }
    out[oi] = '\0';
    return out;
}

/* inputSchema is JSON, already properly escaped by the server; the only
 * intake risk is a raw ｜DSML｜ marker byte sequence smuggled inside a JSON
 * string value, so only that gets scrubbed (no control-char scrub, no
 * truncation here -- oversized schemas are dropped whole by the caller). */
static char *mcp_sanitize_bar_only(const char *s) {
    size_t len = strlen(s);
    char *out = malloc(len + 1);
    if (!out) return NULL;
    size_t oi = 0;
    for (size_t i = 0; i < len; ) {
        if (i + 3 <= len &&
            (unsigned char)s[i] == 0xEF &&
            (unsigned char)s[i + 1] == 0xBD &&
            (unsigned char)s[i + 2] == 0x9C)
        {
            out[oi++] = ' ';
            i += 3;
            continue;
        }
        out[oi++] = s[i];
        i++;
    }
    out[oi] = '\0';
    return out;
}

/* ---- mcp.json config discovery/merge ---- */

typedef struct {
    char *name;
    char **argv;      /* argv[0] = command, ..., NULL terminated */
    char **env_keys;
    char **env_vals;
    int envc;
} mcp_cfgentry;

typedef struct { mcp_cfgentry *v; int len, cap; } mcp_cfgentry_list;

static mcp_cfgentry *mcp_cfgentry_find(mcp_cfgentry_list *list, const char *name) {
    for (int i = 0; i < list->len; i++)
        if (!strcmp(list->v[i].name, name)) return &list->v[i];
    return NULL;
}

static void mcp_cfgentry_push(mcp_cfgentry_list *list, mcp_cfgentry entry) {
    if (list->len == list->cap) {
        list->cap = list->cap ? list->cap * 2 : 4;
        list->v = realloc(list->v, (size_t)list->cap * sizeof(list->v[0]));
    }
    list->v[list->len++] = entry;
}

static void mcp_cfgentry_free_one(mcp_cfgentry *e) {
    free(e->name);
    if (e->argv) {
        for (char **p = e->argv; *p; p++) free(*p);
        free(e->argv);
    }
    for (int i = 0; i < e->envc; i++) {
        free(e->env_keys[i]);
        free(e->env_vals[i]);
    }
    free(e->env_keys);
    free(e->env_vals);
}

static void mcp_cfgentry_list_free(mcp_cfgentry_list *list) {
    for (int i = 0; i < list->len; i++) mcp_cfgentry_free_one(&list->v[i]);
    free(list->v);
}

/* Validates and materializes one "name": {...} entry from mcpServers. Fully
 * fail-open: any shape violation warns and skips just this entry. */
static bool mcp_parse_server_entry(const char *name, const ds4_json_value *val, mcp_cfgentry *out,
                                   char *warn, size_t warn_len) {
    if (!mcp_valid_server_name(name)) {
        mcp_warn_append(warn, warn_len, name, "invalid server name, skipped");
        return false;
    }
    if (ds4_json_type_of(val) != DS4_JSON_OBJ) {
        mcp_warn_append(warn, warn_len, name, "server entry is not an object, skipped");
        return false;
    }
    const char *command = ds4_json_str(ds4_json_obj_get(val, "command"));
    if (!command || !command[0]) {
        mcp_warn_append(warn, warn_len, name, "missing/invalid command, skipped");
        return false;
    }
    const ds4_json_value *args_v = ds4_json_obj_get(val, "args");
    if (args_v && ds4_json_type_of(args_v) != DS4_JSON_ARR) {
        mcp_warn_append(warn, warn_len, name, "args is not an array, skipped");
        return false;
    }
    int nargs = args_v ? ds4_json_arr_len(args_v) : 0;
    for (int i = 0; i < nargs; i++) {
        if (!ds4_json_str(ds4_json_arr_get(args_v, i))) {
            mcp_warn_append(warn, warn_len, name, "args contains a non-string element, skipped");
            return false;
        }
    }
    const ds4_json_value *env_v = ds4_json_obj_get(val, "env");
    if (env_v && ds4_json_type_of(env_v) != DS4_JSON_OBJ) {
        mcp_warn_append(warn, warn_len, name, "env is not an object, skipped");
        return false;
    }
    int nenv = env_v ? ds4_json_obj_len(env_v) : 0;
    for (int i = 0; i < nenv; i++) {
        if (!ds4_json_str(ds4_json_obj_val_at(env_v, i))) {
            mcp_warn_append(warn, warn_len, name, "env contains a non-string value, skipped");
            return false;
        }
    }

    memset(out, 0, sizeof(*out));
    out->name = mcp_strdup(name);
    out->argv = malloc((size_t)(nargs + 2) * sizeof(char *));
    out->argv[0] = mcp_strdup(command);
    for (int i = 0; i < nargs; i++)
        out->argv[i + 1] = mcp_strdup(ds4_json_str(ds4_json_arr_get(args_v, i)));
    out->argv[nargs + 1] = NULL;

    out->envc = nenv;
    if (nenv > 0) {
        out->env_keys = malloc((size_t)nenv * sizeof(char *));
        out->env_vals = malloc((size_t)nenv * sizeof(char *));
        for (int i = 0; i < nenv; i++) {
            out->env_keys[i] = mcp_strdup(ds4_json_obj_key_at(env_v, i));
            out->env_vals[i] = mcp_strdup(ds4_json_str(ds4_json_obj_val_at(env_v, i)));
        }
    }
    return true;
}

/* Reads <root>/mcp.json (missing file is not an error) and merges its
 * mcpServers into list; an already-present name (higher-precedence root, or
 * an earlier same-file key) wins silently. */
static void mcp_load_root_file(const char *root, mcp_cfgentry_list *list, char *warn, size_t warn_len) {
    char *path = mcp_join(root, "mcp.json");
    if (!path) return;

    struct stat st;
    if (stat(path, &st) != 0) { free(path); return; }
    if (!S_ISREG(st.st_mode)) {
        mcp_warn_append(warn, warn_len, path, "not a regular file, skipped");
        free(path);
        return;
    }
    if (st.st_size < 0 || (size_t)st.st_size > DS4_MCP_MAX_CONFIG_SIZE) {
        mcp_warn_append(warn, warn_len, path, "exceeds 1 MiB, skipped");
        free(path);
        return;
    }
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        mcp_warn_append(warn, warn_len, path, "could not open, skipped");
        free(path);
        return;
    }
    size_t cap = (size_t)st.st_size + 1;
    char *buf = malloc(cap);
    if (!buf) {
        fclose(fp);
        mcp_warn_append(warn, warn_len, path, "out of memory, skipped");
        free(path);
        return;
    }
    size_t n = fread(buf, 1, (size_t)st.st_size, fp);
    fclose(fp);
    buf[n] = '\0';

    char jerr[128];
    ds4_json_value *root_v = ds4_json_parse(buf, jerr, sizeof(jerr));
    free(buf);
    if (!root_v) {
        mcp_warn_append(warn, warn_len, path, jerr[0] ? jerr : "malformed JSON, skipped");
        free(path);
        return;
    }
    if (ds4_json_type_of(root_v) != DS4_JSON_OBJ) {
        mcp_warn_append(warn, warn_len, path, "root is not an object, skipped");
        ds4_json_free(root_v);
        free(path);
        return;
    }
    const ds4_json_value *servers_v = ds4_json_obj_get(root_v, "mcpServers");
    if (!servers_v) { ds4_json_free(root_v); free(path); return; }
    if (ds4_json_type_of(servers_v) != DS4_JSON_OBJ) {
        mcp_warn_append(warn, warn_len, path, "mcpServers is not an object, skipped");
        ds4_json_free(root_v);
        free(path);
        return;
    }

    int n_servers = ds4_json_obj_len(servers_v);
    for (int i = 0; i < n_servers; i++) {
        const char *name = ds4_json_obj_key_at(servers_v, i);
        const ds4_json_value *val = ds4_json_obj_val_at(servers_v, i);
        if (mcp_cfgentry_find(list, name)) continue;
        mcp_cfgentry entry;
        if (mcp_parse_server_entry(name, val, &entry, warn, warn_len))
            mcp_cfgentry_push(list, entry);
    }

    ds4_json_free(root_v);
    free(path);
}

static void mcp_load_all(const ds4_config *cfg, mcp_cfgentry_list *list, char *warn, size_t warn_len) {
    int nroots = ds4_config_root_count(cfg);
    for (int i = 0; i < nroots; i++) {
        const char *root = ds4_config_root_at(cfg, i);
        if (!root) continue;
        mcp_load_root_file(root, list, warn, warn_len);
    }
}

/* ---- process + transport ---- */

typedef struct {
    char *name;
    pid_t pid;
    int fd_in;   /* write end: parent -> child stdin */
    int fd_out;  /* read end: child stdout -> parent */
    bool alive;
    int next_id;
    char *rbuf;
    size_t rbuf_len, rbuf_cap;
    int malformed_count;
} mcp_proc;

struct ds4_mcp_registry {
    mcp_proc *procs;
    int proc_count, proc_cap;
    ds4_mcp_tool *tools;
    int tool_count, tool_cap;
    ds4_mcp_opts opts;
};

static mcp_proc *mcp_proc_push(ds4_mcp_registry *reg, const char *name) {
    if (reg->proc_count == reg->proc_cap) {
        reg->proc_cap = reg->proc_cap ? reg->proc_cap * 2 : 4;
        reg->procs = realloc(reg->procs, (size_t)reg->proc_cap * sizeof(reg->procs[0]));
    }
    mcp_proc *p = &reg->procs[reg->proc_count++];
    memset(p, 0, sizeof(*p));
    p->name = mcp_strdup(name);
    p->pid = -1;
    p->fd_in = -1;
    p->fd_out = -1;
    return p;
}

static mcp_proc *mcp_find_proc(ds4_mcp_registry *reg, const char *name) {
    for (int i = 0; i < reg->proc_count; i++)
        if (!strcmp(reg->procs[i].name, name)) return &reg->procs[i];
    return NULL;
}

/* EOF/EPIPE/read error/oversized-line/malformed-flood all funnel here: the
 * process may still be technically running, but we stop trusting its
 * transport and start returning the "not running" error for its calls. */
static void mcp_mark_dead(mcp_proc *p) {
    if (!p->alive) return;
    p->alive = false;
    if (p->pid > 0) {
        int status;
        pid_t r = waitpid(p->pid, &status, WNOHANG);
        if (r == p->pid) p->pid = -1;
    }
}

static long mcp_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static bool mcp_rbuf_grow(mcp_proc *p, size_t need) {
    if (p->rbuf_cap - p->rbuf_len >= need) return true;
    size_t newcap = p->rbuf_cap ? p->rbuf_cap * 2 : 4096;
    while (newcap - p->rbuf_len < need) newcap *= 2;
    char *nb = realloc(p->rbuf, newcap);
    if (!nb) return false;
    p->rbuf = nb;
    p->rbuf_cap = newcap;
    return true;
}

/* Buffered line read with a per-call deadline: every wait for incoming bytes
 * goes through select(), so nothing here can block forever regardless of the
 * caller-supplied timeout_ms. Returns 1 with *line_out set (malloc'd, no
 * trailing '\n') on a complete line, 0 on timeout (server still considered
 * alive), -1 if the server died (EOF/error/oversized line -- proc is marked
 * dead before returning). */
static int mcp_read_line(mcp_proc *p, int timeout_ms, char **line_out) {
    *line_out = NULL;
    long deadline = mcp_now_ms() + (timeout_ms > 0 ? timeout_ms : 0);
    char chunk[MCP_READ_CHUNK];

    for (;;) {
        char *nl = p->rbuf ? memchr(p->rbuf, '\n', p->rbuf_len) : NULL;
        if (nl) {
            size_t linelen = (size_t)(nl - p->rbuf);
            char *line = malloc(linelen + 1);
            if (!line) { mcp_mark_dead(p); return -1; }
            memcpy(line, p->rbuf, linelen);
            line[linelen] = '\0';
            size_t consumed = linelen + 1;
            memmove(p->rbuf, p->rbuf + consumed, p->rbuf_len - consumed);
            p->rbuf_len -= consumed;
            *line_out = line;
            return 1;
        }
        if (p->rbuf_len > DS4_MCP_MAX_LINE_BYTES) {
            mcp_mark_dead(p);
            return -1;
        }

        long remaining = deadline - mcp_now_ms();
        if (remaining <= 0) return 0;

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(p->fd_out, &rfds);
        struct timeval tv;
        tv.tv_sec = remaining / 1000;
        tv.tv_usec = (remaining % 1000) * 1000;
        int sel = select(p->fd_out + 1, &rfds, NULL, NULL, &tv);
        if (sel < 0) {
            if (errno == EINTR) continue;
            mcp_mark_dead(p);
            return -1;
        }
        if (sel == 0) return 0;

        ssize_t rn = read(p->fd_out, chunk, sizeof(chunk));
        if (rn == 0) { mcp_mark_dead(p); return -1; }
        if (rn < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            mcp_mark_dead(p);
            return -1;
        }
        if (!mcp_rbuf_grow(p, (size_t)rn)) { mcp_mark_dead(p); return -1; }
        memcpy(p->rbuf + p->rbuf_len, chunk, (size_t)rn);
        p->rbuf_len += (size_t)rn;
    }
}

static bool mcp_send_line(mcp_proc *p, const char *text) {
    if (!p->alive) return false;
    size_t len = strlen(text);
    char *buf = malloc(len + 1);
    if (!buf) return false;
    memcpy(buf, text, len);
    buf[len] = '\n';
    size_t off = 0, total = len + 1;
    while (off < total) {
        ssize_t wn = write(p->fd_in, buf + off, total - off);
        if (wn < 0) {
            if (errno == EINTR) continue;
            free(buf);
            mcp_mark_dead(p);
            return false;
        }
        off += (size_t)wn;
    }
    free(buf);
    return true;
}

typedef enum { MCP_RESP_OK, MCP_RESP_TIMEOUT, MCP_RESP_DEAD } mcp_resp_status;

/* Echoes an unsolicited server->client request's id back verbatim (whatever
 * JSON type it was) inside a method-not-supported error reply, so it is
 * never mistaken for one of our own pending responses. */
static void mcp_send_error_reply(mcp_proc *p, const ds4_json_value *id_v) {
    char *idraw = ds4_json_raw(id_v);
    ds4_json_writer w = {0};
    ds4_json_w_raw(&w, "{\"jsonrpc\":\"2.0\",\"id\":");
    ds4_json_w_raw(&w, idraw ? idraw : "null");
    ds4_json_w_raw(&w, ",\"error\":{\"code\":-32601,\"message\":\"method not supported\"}}");
    free(idraw);
    char *line = ds4_json_w_take(&w);
    mcp_send_line(p, line);
    free(line);
}

/* Applies incoming-traffic discipline on every line until match_id's
 * response arrives: notifications (method, no id) are ignored; server->client
 * requests (method + id) get an immediate method-not-supported reply;
 * responses with a non-matching id are dropped; malformed JSON is counted
 * (>8 kills the server). On MCP_RESP_OK, *doc_out is the parsed response
 * object and the caller owns it (ds4_json_free). */
static mcp_resp_status mcp_await_response(mcp_proc *p, int match_id, int timeout_ms,
                                          ds4_json_value **doc_out) {
    *doc_out = NULL;
    if (!p->alive) return MCP_RESP_DEAD;
    long deadline = mcp_now_ms() + (timeout_ms > 0 ? timeout_ms : 0);

    for (;;) {
        long remaining = deadline - mcp_now_ms();
        if (remaining <= 0) return MCP_RESP_TIMEOUT;

        char *line = NULL;
        int rc = mcp_read_line(p, (int)remaining, &line);
        if (rc == 0) return MCP_RESP_TIMEOUT;
        if (rc < 0) return MCP_RESP_DEAD;

        char jerr[64];
        ds4_json_value *doc = ds4_json_parse(line, jerr, sizeof(jerr));
        free(line);
        if (!doc || ds4_json_type_of(doc) != DS4_JSON_OBJ) {
            ds4_json_free(doc);
            if (++p->malformed_count > DS4_MCP_MALFORMED_LIMIT) { mcp_mark_dead(p); return MCP_RESP_DEAD; }
            continue;
        }

        const ds4_json_value *method_v = ds4_json_obj_get(doc, "method");
        const ds4_json_value *id_v = ds4_json_obj_get(doc, "id");

        if (method_v && ds4_json_type_of(method_v) == DS4_JSON_STR) {
            if (id_v) mcp_send_error_reply(p, id_v);
            ds4_json_free(doc);
            continue;
        }
        if (id_v) {
            if (ds4_json_type_of(id_v) == DS4_JSON_NUM && (int)ds4_json_num(id_v, -1) == match_id) {
                *doc_out = doc;
                return MCP_RESP_OK;
            }
            ds4_json_free(doc);
            continue;
        }

        ds4_json_free(doc);
        if (++p->malformed_count > DS4_MCP_MALFORMED_LIMIT) { mcp_mark_dead(p); return MCP_RESP_DEAD; }
    }
}

static char *mcp_build_request(int id, const char *method, const char *params_json) {
    ds4_json_writer w = {0};
    char idbuf[24];
    snprintf(idbuf, sizeof(idbuf), "%d", id);
    ds4_json_w_raw(&w, "{\"jsonrpc\":\"2.0\",\"id\":");
    ds4_json_w_raw(&w, idbuf);
    ds4_json_w_raw(&w, ",\"method\":");
    ds4_json_w_string(&w, method);
    if (params_json) {
        ds4_json_w_raw(&w, ",\"params\":");
        ds4_json_w_raw(&w, params_json);
    }
    ds4_json_w_raw(&w, "}");
    return ds4_json_w_take(&w);
}

static char *mcp_build_notification(const char *method) {
    ds4_json_writer w = {0};
    ds4_json_w_raw(&w, "{\"jsonrpc\":\"2.0\",\"method\":");
    ds4_json_w_string(&w, method);
    ds4_json_w_raw(&w, "}");
    return ds4_json_w_take(&w);
}

/* fork(); child dup2's the pipes onto stdin/stdout, stderr -> /dev/null,
 * applies env via setenv, then execvp (no shell). Parent keeps the other
 * ends, CLOEXEC'd. Always leaves a proc entry behind (even on failure) so
 * ds4_mcp_registry_free has something consistent to iterate. */
static bool mcp_spawn(mcp_proc *proc, const mcp_cfgentry *cfg, char *warn, size_t warn_len) {
    int p_in[2], p_out[2];
    if (pipe(p_in) != 0) {
        mcp_warn_append(warn, warn_len, cfg->name, "failed to create stdin pipe, skipped");
        return false;
    }
    if (pipe(p_out) != 0) {
        mcp_warn_append(warn, warn_len, cfg->name, "failed to create stdout pipe, skipped");
        close(p_in[0]); close(p_in[1]);
        return false;
    }

    pid_t pid = fork();
    if (pid < 0) {
        mcp_warn_append(warn, warn_len, cfg->name, "fork failed, skipped");
        close(p_in[0]); close(p_in[1]); close(p_out[0]); close(p_out[1]);
        return false;
    }
    if (pid == 0) {
        dup2(p_in[0], STDIN_FILENO);
        dup2(p_out[1], STDOUT_FILENO);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        close(p_in[0]); close(p_in[1]);
        close(p_out[0]); close(p_out[1]);
        for (int i = 0; i < cfg->envc; i++)
            setenv(cfg->env_keys[i], cfg->env_vals[i], 1);
        execvp(cfg->argv[0], cfg->argv);
        _exit(127);
    }

    close(p_in[0]);
    close(p_out[1]);
    fcntl(p_in[1], F_SETFD, FD_CLOEXEC);
    fcntl(p_out[0], F_SETFD, FD_CLOEXEC);
    proc->pid = pid;
    proc->fd_in = p_in[1];
    proc->fd_out = p_out[0];
    proc->alive = true;
    proc->next_id = 1;
    return true;
}

/* ---- tool intake (validate + sanitize + push) ---- */

static char *mcp_build_wire_name(const char *server, const char *tool) {
    size_t sl = strlen(server), tl = strlen(tool);
    size_t total = 5 + sl + 2 + tl + 1; /* "mcp__" + server + "__" + tool + NUL */
    char *out = malloc(total);
    if (!out) return NULL;
    snprintf(out, total, "mcp__%s__%s", server, tool);
    return out;
}

static void mcp_process_tool_entry(ds4_mcp_registry *reg, const char *server_name,
                                   const ds4_json_value *tool_val, char *warn, size_t warn_len) {
    const char *raw_name = ds4_json_str(ds4_json_obj_get(tool_val, "name"));
    if (!raw_name || !mcp_valid_tool_name(raw_name)) {
        mcp_warn_append(warn, warn_len, server_name, "tool has missing/invalid name, skipped");
        return;
    }
    char *wire_name = mcp_build_wire_name(server_name, raw_name);
    if (ds4_mcp_registry_find(reg, wire_name)) {
        mcp_warn_append(warn, warn_len, server_name, "duplicate tool wire name, first one wins, skipped");
        free(wire_name);
        return;
    }

    const char *raw_desc = ds4_json_str(ds4_json_obj_get(tool_val, "description"));
    char *san_desc = mcp_sanitize_desc(raw_desc ? raw_desc : "");

    const ds4_json_value *schema_v = ds4_json_obj_get(tool_val, "inputSchema");
    char *schema_raw = schema_v ? ds4_json_raw(schema_v) : mcp_strdup("{}");
    char *schema_san = mcp_sanitize_bar_only(schema_raw);
    free(schema_raw);
    if (strlen(schema_san) > DS4_MCP_MAX_SCHEMA_BYTES) {
        mcp_warn_append(warn, warn_len, server_name, "tool inputSchema exceeds 8 KiB, tool skipped");
        free(schema_san);
        free(san_desc);
        free(wire_name);
        return;
    }

    if (reg->tool_count == reg->tool_cap) {
        reg->tool_cap = reg->tool_cap ? reg->tool_cap * 2 : 4;
        reg->tools = realloc(reg->tools, (size_t)reg->tool_cap * sizeof(reg->tools[0]));
    }
    ds4_mcp_tool *t = &reg->tools[reg->tool_count++];
    t->server_name = mcp_strdup(server_name);
    t->tool_name = mcp_strdup(raw_name);
    t->wire_name = wire_name;
    t->description = san_desc;
    t->input_schema_json = schema_san;
}

static const char MCP_INIT_PARAMS[] =
    "{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},"
    "\"clientInfo\":{\"name\":\"ds4-agent\",\"version\":\"0.1\"}}";

/* Handshake (initialize -> notifications/initialized) then tools/list
 * pagination (max 16 pages). Any failure at any step warns and returns,
 * leaving the proc in the registry (for teardown reaping) and whatever
 * tools had already been collected (possibly zero). */
static void mcp_discover_one(ds4_mcp_registry *reg, mcp_proc *p, const char *server_name,
                             char *warn, size_t warn_len) {
    int hs_ms = reg->opts.handshake_timeout_ms;

    int init_id = p->next_id++;
    char *req = mcp_build_request(init_id, "initialize", MCP_INIT_PARAMS);
    bool sent = mcp_send_line(p, req);
    free(req);
    if (!sent) {
        mcp_warn_append(warn, warn_len, server_name, "failed to send initialize, skipped");
        return;
    }

    ds4_json_value *doc = NULL;
    mcp_resp_status st = mcp_await_response(p, init_id, hs_ms, &doc);
    if (st == MCP_RESP_TIMEOUT) {
        mcp_warn_append(warn, warn_len, server_name, "initialize timed out, skipped");
        return;
    }
    if (st == MCP_RESP_DEAD) {
        mcp_warn_append(warn, warn_len, server_name, "died during handshake, skipped");
        return;
    }
    bool has_error = ds4_json_obj_get(doc, "error") != NULL;
    ds4_json_free(doc);
    if (has_error) {
        mcp_warn_append(warn, warn_len, server_name, "initialize returned an error, skipped");
        return;
    }

    char *note = mcp_build_notification("notifications/initialized");
    sent = mcp_send_line(p, note);
    free(note);
    if (!sent) {
        mcp_warn_append(warn, warn_len, server_name, "failed to send notifications/initialized, skipped");
        return;
    }

    char *cursor = NULL;
    for (int page = 0; page < DS4_MCP_MAX_PAGES; page++) {
        int list_id = p->next_id++;
        char *params;
        if (cursor) {
            ds4_json_writer pw = {0};
            ds4_json_w_raw(&pw, "{\"cursor\":");
            ds4_json_w_string(&pw, cursor);
            ds4_json_w_raw(&pw, "}");
            params = ds4_json_w_take(&pw);
        } else {
            params = mcp_strdup("{}");
        }
        char *lreq = mcp_build_request(list_id, "tools/list", params);
        free(params);
        sent = mcp_send_line(p, lreq);
        free(lreq);
        if (!sent) {
            mcp_warn_append(warn, warn_len, server_name, "failed to send tools/list, skipped remaining pages");
            break;
        }

        ds4_json_value *ldoc = NULL;
        mcp_resp_status lst = mcp_await_response(p, list_id, hs_ms, &ldoc);
        if (lst == MCP_RESP_TIMEOUT) {
            mcp_warn_append(warn, warn_len, server_name, "tools/list timed out, skipped remaining pages");
            break;
        }
        if (lst == MCP_RESP_DEAD) {
            mcp_warn_append(warn, warn_len, server_name, "died during tools/list, skipped remaining pages");
            break;
        }
        if (ds4_json_obj_get(ldoc, "error")) {
            mcp_warn_append(warn, warn_len, server_name, "tools/list returned an error, skipped remaining pages");
            ds4_json_free(ldoc);
            break;
        }
        const ds4_json_value *result_v = ds4_json_obj_get(ldoc, "result");
        const ds4_json_value *tools_v = ds4_json_obj_get(result_v, "tools");
        int n = ds4_json_arr_len(tools_v);
        for (int i = 0; i < n; i++)
            mcp_process_tool_entry(reg, server_name, ds4_json_arr_get(tools_v, i), warn, warn_len);

        const char *next_cursor = ds4_json_str(ds4_json_obj_get(result_v, "nextCursor"));
        free(cursor);
        cursor = (next_cursor && next_cursor[0]) ? mcp_strdup(next_cursor) : NULL;
        ds4_json_free(ldoc);
        if (!cursor) break;
    }
    free(cursor);
}

/* ---- public API ---- */

ds4_mcp_registry *ds4_mcp_registry_create(const ds4_config *cfg, const ds4_mcp_opts *opts,
                                          char *warn, size_t warn_len) {
    if (warn && warn_len) warn[0] = '\0';
    if (!cfg) return NULL;

    mcp_cfgentry_list configs = {0};
    mcp_load_all(cfg, &configs, warn, warn_len);
    if (configs.len == 0) {
        mcp_cfgentry_list_free(&configs);
        return NULL;
    }

    /* ds4-agent does not otherwise ignore SIGPIPE; only do so once we are
     * actually about to hold pipes to child processes, so the no-config path
     * (returned above) never touches process-wide signal state. */
    signal(SIGPIPE, SIG_IGN);

    ds4_mcp_registry *reg = calloc(1, sizeof(*reg));
    reg->opts.handshake_timeout_ms =
        (opts && opts->handshake_timeout_ms > 0) ? opts->handshake_timeout_ms : DS4_MCP_DEFAULT_HANDSHAKE_MS;
    reg->opts.call_timeout_ms =
        (opts && opts->call_timeout_ms > 0) ? opts->call_timeout_ms : DS4_MCP_DEFAULT_CALL_MS;

    for (int i = 0; i < configs.len; i++) {
        mcp_cfgentry *ce = &configs.v[i];
        mcp_proc *p = mcp_proc_push(reg, ce->name);
        if (!mcp_spawn(p, ce, warn, warn_len)) continue; /* proc stays (pid=-1); harmless in free */
        mcp_discover_one(reg, p, ce->name, warn, warn_len);
    }

    mcp_cfgentry_list_free(&configs);
    return reg;
}

void ds4_mcp_registry_free(ds4_mcp_registry *reg) {
    if (!reg) return;

    for (int i = 0; i < reg->proc_count; i++)
        if (reg->procs[i].pid > 0) kill(reg->procs[i].pid, SIGTERM);

    struct timespec step = { 0, 10 * 1000 * 1000 }; /* 10ms */
    for (int iter = 0; iter < 30; iter++) {
        bool all_reaped = true;
        for (int i = 0; i < reg->proc_count; i++) {
            mcp_proc *p = &reg->procs[i];
            if (p->pid <= 0) continue;
            int status;
            pid_t r = waitpid(p->pid, &status, WNOHANG);
            if (r == p->pid) p->pid = -1;
            else all_reaped = false;
        }
        if (all_reaped) break;
        nanosleep(&step, NULL);
    }
    for (int i = 0; i < reg->proc_count; i++) {
        mcp_proc *p = &reg->procs[i];
        if (p->pid > 0) {
            kill(p->pid, SIGKILL);
            waitpid(p->pid, NULL, 0);
            p->pid = -1;
        }
    }

    for (int i = 0; i < reg->proc_count; i++) {
        mcp_proc *p = &reg->procs[i];
        free(p->name);
        free(p->rbuf);
        if (p->fd_in >= 0) close(p->fd_in);
        if (p->fd_out >= 0) close(p->fd_out);
    }
    free(reg->procs);

    for (int i = 0; i < reg->tool_count; i++) {
        free(reg->tools[i].server_name);
        free(reg->tools[i].tool_name);
        free(reg->tools[i].wire_name);
        free(reg->tools[i].description);
        free(reg->tools[i].input_schema_json);
    }
    free(reg->tools);
    free(reg);
}

int ds4_mcp_registry_tool_count(const ds4_mcp_registry *reg) {
    return reg ? reg->tool_count : 0;
}

const ds4_mcp_tool *ds4_mcp_registry_tool_at(const ds4_mcp_registry *reg, int i) {
    if (!reg || i < 0 || i >= reg->tool_count) return NULL;
    return &reg->tools[i];
}

const ds4_mcp_tool *ds4_mcp_registry_find(const ds4_mcp_registry *reg, const char *wire_name) {
    if (!reg || !wire_name) return NULL;
    for (int i = 0; i < reg->tool_count; i++)
        if (!strcmp(reg->tools[i].wire_name, wire_name)) return &reg->tools[i];
    return NULL;
}

char *ds4_mcp_registry_call_tool(ds4_mcp_registry *reg, const ds4_mcp_tool *tool,
                                 const char *arguments_json) {
    if (!reg || !tool) return mcp_strdup("Tool error: invalid MCP tool\n");
    mcp_proc *p = mcp_find_proc(reg, tool->server_name);
    if (!p || !p->alive) {
        char buf[192];
        snprintf(buf, sizeof(buf), "Tool error: MCP server '%s' is not running\n", tool->server_name);
        return mcp_strdup(buf);
    }

    int id = p->next_id++;
    ds4_json_writer pw = {0};
    ds4_json_w_raw(&pw, "{\"name\":");
    ds4_json_w_string(&pw, tool->tool_name);
    ds4_json_w_raw(&pw, ",\"arguments\":");
    ds4_json_w_raw(&pw, (arguments_json && arguments_json[0]) ? arguments_json : "{}");
    ds4_json_w_raw(&pw, "}");
    char *params = ds4_json_w_take(&pw);
    char *req = mcp_build_request(id, "tools/call", params);
    free(params);
    bool sent = mcp_send_line(p, req);
    free(req);
    if (!sent) {
        char buf[192];
        snprintf(buf, sizeof(buf), "Tool error: MCP server '%s' is not running\n", tool->server_name);
        return mcp_strdup(buf);
    }

    ds4_json_value *doc = NULL;
    mcp_resp_status st = mcp_await_response(p, id, reg->opts.call_timeout_ms, &doc);
    if (st == MCP_RESP_TIMEOUT) {
        char buf[96];
        snprintf(buf, sizeof(buf), "Tool error: MCP call timed out after %dms\n", reg->opts.call_timeout_ms);
        return mcp_strdup(buf);
    }
    if (st == MCP_RESP_DEAD) {
        char buf[192];
        snprintf(buf, sizeof(buf), "Tool error: MCP server '%s' is not running\n", tool->server_name);
        return mcp_strdup(buf);
    }

    const ds4_json_value *err_v = ds4_json_obj_get(doc, "error");
    if (err_v) {
        const char *msg = ds4_json_str(ds4_json_obj_get(err_v, "message"));
        char *out;
        if (msg) {
            size_t need = strlen(msg) + 32;
            out = malloc(need);
            snprintf(out, need, "Tool error: %s\n", msg);
        } else {
            out = mcp_strdup("Tool error: MCP server returned an error\n");
        }
        ds4_json_free(doc);
        return out;
    }

    const ds4_json_value *result_v = ds4_json_obj_get(doc, "result");
    bool is_error = ds4_json_bool(ds4_json_obj_get(result_v, "isError"), false);
    const ds4_json_value *content_v = ds4_json_obj_get(result_v, "content");
    int n = ds4_json_arr_len(content_v);
    int text_count = 0, other_count = 0;
    ds4_json_writer body = {0};
    for (int i = 0; i < n; i++) {
        const ds4_json_value *item = ds4_json_arr_get(content_v, i);
        const char *type = ds4_json_str(ds4_json_obj_get(item, "type"));
        if (type && !strcmp(type, "text")) {
            const char *text = ds4_json_str(ds4_json_obj_get(item, "text"));
            if (text_count) ds4_json_w_raw(&body, "\n");
            ds4_json_w_raw(&body, text ? text : "");
            text_count++;
        } else {
            other_count++;
        }
    }
    char *bodytext;
    if (text_count == 0 && other_count > 0) {
        ds4_json_w_free(&body);
        char buf[64];
        snprintf(buf, sizeof(buf), "Tool result: %d non-text content item(s) omitted", other_count);
        bodytext = mcp_strdup(buf);
    } else {
        bodytext = ds4_json_w_take(&body);
    }
    ds4_json_free(doc);

    char *final_text;
    size_t bl = strlen(bodytext);
    if (is_error) {
        size_t need = bl + 16;
        final_text = malloc(need);
        snprintf(final_text, need, "Tool error: %s\n", bodytext);
    } else if (bl && bodytext[bl - 1] == '\n') {
        final_text = mcp_strdup(bodytext);
    } else {
        size_t need = bl + 2;
        final_text = malloc(need);
        snprintf(final_text, need, "%s\n", bodytext);
    }
    free(bodytext);
    return final_text;
}

/* Mirrors the structural shape (schema-block JSON, native tool syntax) that
 * agent_tools_prompt_after_edit / DS4_SKILLS_TOOL_DECL use to declare every
 * other tool, so the model sees MCP tools declared the same way. */
static char *mcp_tool_decl_block(const ds4_mcp_tool *tool) {
    ds4_json_writer w = {0};
    ds4_json_w_raw(&w, "{\n");
    ds4_json_w_raw(&w, "  \"type\": \"function\",\n");
    ds4_json_w_raw(&w, "  \"function\": {\n");
    ds4_json_w_raw(&w, "    \"name\": ");
    ds4_json_w_string(&w, tool->wire_name);
    ds4_json_w_raw(&w, ",\n");
    ds4_json_w_raw(&w, "    \"description\": ");
    ds4_json_w_string(&w, tool->description ? tool->description : "");
    ds4_json_w_raw(&w, ",\n");
    ds4_json_w_raw(&w, "    \"parameters\": ");
    ds4_json_w_raw(&w, (tool->input_schema_json && tool->input_schema_json[0]) ? tool->input_schema_json : "{}");
    ds4_json_w_raw(&w, "\n  }\n}\n");
    return ds4_json_w_take(&w);
}

char *ds4_mcp_tools_prompt_text(const ds4_mcp_registry *reg) {
    if (!reg || reg->tool_count == 0) return NULL;
    ds4_json_writer w = {0};
    ds4_json_w_raw(&w, "\n## External Tools (MCP)\n\n");
    for (int i = 0; i < reg->tool_count; i++) {
        char *block = mcp_tool_decl_block(&reg->tools[i]);
        ds4_json_w_raw(&w, block);
        free(block);
        if (i != reg->tool_count - 1) ds4_json_w_raw(&w, "\n");
    }
    return ds4_json_w_take(&w);
}

char *ds4_mcp_args_to_json(const char **names, const char **values, const int *is_string, int argc) {
    ds4_json_writer w = {0};
    ds4_json_w_raw(&w, "{");
    for (int i = 0; i < argc; i++) {
        if (i) ds4_json_w_raw(&w, ",");
        ds4_json_w_string(&w, names[i]);
        ds4_json_w_raw(&w, ":");
        if (is_string[i]) ds4_json_w_string(&w, values[i]);
        else ds4_json_w_raw(&w, values[i]);
    }
    ds4_json_w_raw(&w, "}");
    return ds4_json_w_take(&w);
}

#ifdef DS4_MCP_TEST

int ds4_mcp_test_proc_count(const ds4_mcp_registry *reg) { return reg ? reg->proc_count : 0; }

pid_t ds4_mcp_test_proc_pid(const ds4_mcp_registry *reg, int i) {
    if (!reg || i < 0 || i >= reg->proc_count) return -1;
    return reg->procs[i].pid;
}

#include <dirent.h>
#include <limits.h>

static int mcp_test_failures;

static void mcp_test_assert(int cond, const char *expr, const char *file, int line) {
    if (cond) return;
    fprintf(stderr, "%s:%d: assertion failed: %s\n", file, line, expr);
    mcp_test_failures++;
}
#define MCP_TEST_ASSERT(expr) mcp_test_assert((expr), #expr, __FILE__, __LINE__)

/* ---- self-contained fixture helpers (independent of module internals) ---- */

static char *mcp_test_join(const char *dir, const char *name) {
    size_t dlen = strlen(dir);
    int need_slash = dlen > 0 && dir[dlen - 1] != '/';
    size_t nlen = strlen(name);
    char *out = malloc(dlen + (need_slash ? 1 : 0) + nlen + 1);
    if (!out) return NULL;
    memcpy(out, dir, dlen);
    size_t pos = dlen;
    if (need_slash) out[pos++] = '/';
    memcpy(out + pos, name, nlen);
    pos += nlen;
    out[pos] = '\0';
    return out;
}

static char *mcp_test_strdup(const char *s) {
    size_t n = strlen(s);
    char *p = malloc(n + 1);
    if (p) memcpy(p, s, n + 1);
    return p;
}

static void mcp_test_mkdir_p(const char *path) {
    char *tmp = mcp_test_strdup(path);
    if (!tmp) return;
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        mkdir(tmp, 0700);
        *p = '/';
    }
    mkdir(tmp, 0700);
    free(tmp);
}

static void mcp_test_write_file(const char *path, const char *content) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return;
    fwrite(content, 1, strlen(content), fp);
    fclose(fp);
}

static void mcp_test_rmtree(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return;
    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        if (d) {
            struct dirent *de;
            while ((de = readdir(d)) != NULL) {
                if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
                char *child = mcp_test_join(path, de->d_name);
                if (child) { mcp_test_rmtree(child); free(child); }
            }
            closedir(d);
        }
        rmdir(path);
    } else {
        unlink(path);
    }
}

static void mcp_test_setenv_home(const char *value, char **saved_out) {
    const char *cur = getenv("HOME");
    *saved_out = cur ? mcp_test_strdup(cur) : NULL;
    if (value) setenv("HOME", value, 1);
    else unsetenv("HOME");
}

static void mcp_test_restore_home(char *saved) {
    if (saved) { setenv("HOME", saved, 1); free(saved); }
    else unsetenv("HOME");
}

/* Locates the built mock binary (test runs from repo root) and writes
 * <ds4dir>/mcp.json pointing "mock" at it with the given mode arg. */
static void mcp_test_write_mcpjson(const char *ds4dir, const char *mode) {
    char mockpath[PATH_MAX];
    if (!realpath("tests/mock_mcp_server", mockpath)) {
        fprintf(stderr, "mcp test fixture: could not resolve tests/mock_mcp_server\n");
        mockpath[0] = '\0';
    }
    char *path = mcp_test_join(ds4dir, "mcp.json");
    char content[PATH_MAX + 256];
    snprintf(content, sizeof(content),
             "{\"mcpServers\":{\"mock\":{\"command\":\"%s\",\"args\":[\"%s\"]}}}",
             mockpath, mode);
    mcp_test_write_file(path, content);
    free(path);
}

/* Sets up <tmp>/proj/.ds4/mcp.json (mode) plus an isolated empty HOME (no
 * ~/.ds4), and loads the config. Caller frees out_fx, out_home, and
 * out_saved_home (and the returned ds4_config, via ds4_config_free). */
static ds4_config *mcp_test_setup(const char *mode, char **out_fx, char **out_home, char **out_saved_home) {
    char tmpl[] = "/tmp/ds4_mcp_test.XXXXXX";
    char *fx = mkdtemp(tmpl);
    MCP_TEST_ASSERT(fx != NULL);
    if (!fx) return NULL;
    fx = mcp_test_strdup(fx);

    char *proj = mcp_test_join(fx, "proj");
    char *ds4dir = mcp_test_join(proj, ".ds4");
    mcp_test_mkdir_p(ds4dir);
    if (mode) mcp_test_write_mcpjson(ds4dir, mode);

    char *home = mcp_test_join(fx, "home");
    mcp_test_mkdir_p(home);
    char *saved_home;
    mcp_test_setenv_home(home, &saved_home);

    ds4_config *cfg = ds4_config_load(proj, NULL, 0);

    *out_fx = fx;
    *out_home = home;
    *out_saved_home = saved_home;
    free(proj);
    free(ds4dir);
    return cfg;
}

static void mcp_test_teardown(char *fx, char *home, char *saved_home) {
    mcp_test_restore_home(saved_home);
    free(home);
    mcp_test_rmtree(fx);
    free(fx);
}

/* ---- test groups ---- */

static void test_normal(void) {
    char *fx, *home, *saved_home;
    ds4_config *cfg = mcp_test_setup("normal", &fx, &home, &saved_home);
    MCP_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        char warn[512] = {0};
        ds4_mcp_registry *reg = ds4_mcp_registry_create(cfg, NULL, warn, sizeof(warn));
        MCP_TEST_ASSERT(reg != NULL);
        if (reg) {
            MCP_TEST_ASSERT(ds4_mcp_registry_tool_count(reg) == 2);
            const ds4_mcp_tool *echo = ds4_mcp_registry_find(reg, "mcp__mock__echo");
            const ds4_mcp_tool *add = ds4_mcp_registry_find(reg, "mcp__mock__add");
            MCP_TEST_ASSERT(echo != NULL);
            MCP_TEST_ASSERT(add != NULL);
            if (echo) {
                MCP_TEST_ASSERT(strcmp(echo->tool_name, "echo") == 0);
                MCP_TEST_ASSERT(echo->description != NULL && echo->description[0] != '\0');

                const char *names[1] = { "text" };
                const char *values[1] = { "hi \xef\xbd\x9c there" };
                int is_str[1] = { 1 };
                char *args_json = ds4_mcp_args_to_json(names, values, is_str, 1);
                char *result = ds4_mcp_registry_call_tool(reg, echo, args_json);
                MCP_TEST_ASSERT(result != NULL);
                if (result) {
                    MCP_TEST_ASSERT(strstr(result, "hi") != NULL);
                    MCP_TEST_ASSERT(strstr(result, "\xef\xbd\x9c") != NULL);
                    free(result);
                }
                free(args_json);
            }
            if (add) {
                const char *names[2] = { "a", "b" };
                const char *values[2] = { "-1", "2" };
                int is_str[2] = { 0, 0 };
                char *args_json = ds4_mcp_args_to_json(names, values, is_str, 2);
                char *result = ds4_mcp_registry_call_tool(reg, add, args_json);
                MCP_TEST_ASSERT(result != NULL);
                if (result) {
                    MCP_TEST_ASSERT(strncmp(result, "Tool error: ", 12) == 0);
                    free(result);
                }
                free(args_json);
            }
        }
        ds4_mcp_registry_free(reg);
    }
    ds4_config_free(cfg);
    mcp_test_teardown(fx, home, saved_home);
}

static void test_args_to_json(void) {
    {
        const char *names[1] = { "text" };
        const char *values[1] = { "hi\n\"there\"\xc3\xa9" };
        int is_str[1] = { 1 };
        char *got = ds4_mcp_args_to_json(names, values, is_str, 1);
        MCP_TEST_ASSERT(got != NULL);
        if (got) {
            MCP_TEST_ASSERT(strcmp(got, "{\"text\":\"hi\\n\\\"there\\\"\xc3\xa9\"}") == 0);
            free(got);
        }
    }
    {
        const char *names[3] = { "x", "y", "z" };
        const char *values[3] = { "3.14", "true", "{\"x\":1}" };
        int is_str[3] = { 0, 0, 0 };
        char *got = ds4_mcp_args_to_json(names, values, is_str, 3);
        MCP_TEST_ASSERT(got != NULL);
        if (got) {
            MCP_TEST_ASSERT(strcmp(got, "{\"x\":3.14,\"y\":true,\"z\":{\"x\":1}}") == 0);
            free(got);
        }
    }
    {
        char *got = ds4_mcp_args_to_json(NULL, NULL, NULL, 0);
        MCP_TEST_ASSERT(got != NULL);
        if (got) { MCP_TEST_ASSERT(strcmp(got, "{}") == 0); free(got); }
    }
}

static void test_exit_early(void) {
    char *fx, *home, *saved_home;
    ds4_config *cfg = mcp_test_setup("exit-early", &fx, &home, &saved_home);
    MCP_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        char warn[512] = {0};
        ds4_mcp_registry *reg = ds4_mcp_registry_create(cfg, NULL, warn, sizeof(warn));
        MCP_TEST_ASSERT(reg != NULL); /* a server WAS configured */
        MCP_TEST_ASSERT(ds4_mcp_registry_tool_count(reg) == 0);
        MCP_TEST_ASSERT(warn[0] != '\0');
        ds4_mcp_registry_free(reg);
    }
    ds4_config_free(cfg);
    mcp_test_teardown(fx, home, saved_home);
}

static void test_garbage(void) {
    char *fx, *home, *saved_home;
    ds4_config *cfg = mcp_test_setup("garbage", &fx, &home, &saved_home);
    MCP_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        char warn[512] = {0};
        ds4_mcp_registry *reg = ds4_mcp_registry_create(cfg, NULL, warn, sizeof(warn));
        MCP_TEST_ASSERT(reg != NULL);
        MCP_TEST_ASSERT(ds4_mcp_registry_tool_count(reg) == 0);
        MCP_TEST_ASSERT(warn[0] != '\0');
        ds4_mcp_registry_free(reg);
    }
    ds4_config_free(cfg);
    mcp_test_teardown(fx, home, saved_home);
}

static void test_slow_timeout(void) {
    char *fx, *home, *saved_home;
    ds4_config *cfg = mcp_test_setup("slow", &fx, &home, &saved_home);
    MCP_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        ds4_mcp_opts opts = { 0, 500 };
        char warn[512] = {0};
        ds4_mcp_registry *reg = ds4_mcp_registry_create(cfg, &opts, warn, sizeof(warn));
        MCP_TEST_ASSERT(reg != NULL);
        if (reg) {
            const ds4_mcp_tool *tool = ds4_mcp_registry_find(reg, "mcp__mock__slowtool");
            MCP_TEST_ASSERT(tool != NULL);
            if (tool) {
                long t0 = mcp_now_ms();
                char *result = ds4_mcp_registry_call_tool(reg, tool, "{}");
                long elapsed = mcp_now_ms() - t0;
                MCP_TEST_ASSERT(result != NULL);
                if (result) {
                    MCP_TEST_ASSERT(strstr(result, "timed out") != NULL);
                    free(result);
                }
                MCP_TEST_ASSERT(elapsed < 2000);
            }
        }
        ds4_mcp_registry_free(reg);
    }
    ds4_config_free(cfg);
    mcp_test_teardown(fx, home, saved_home);
}

static void test_evil(void) {
    char *fx, *home, *saved_home;
    ds4_config *cfg = mcp_test_setup("evil", &fx, &home, &saved_home);
    MCP_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        char warn[1024] = {0};
        ds4_mcp_registry *reg = ds4_mcp_registry_create(cfg, NULL, warn, sizeof(warn));
        MCP_TEST_ASSERT(reg != NULL);
        if (reg) {
            MCP_TEST_ASSERT(ds4_mcp_registry_tool_count(reg) == 2);
            const ds4_mcp_tool *bad = ds4_mcp_registry_find(reg, "mcp__mock__baddesc");
            MCP_TEST_ASSERT(bad != NULL);
            if (bad) {
                MCP_TEST_ASSERT(strstr(bad->description, "\xef\xbd\x9c") == NULL);
                MCP_TEST_ASSERT(strchr(bad->description, '\x1b') == NULL);
            }
            MCP_TEST_ASSERT(ds4_mcp_registry_find(reg, "mcp__mock__bigschema") == NULL);
            MCP_TEST_ASSERT(ds4_mcp_registry_find(reg, "mcp__mock__valid3") != NULL);

            char *prompt = ds4_mcp_tools_prompt_text(reg);
            MCP_TEST_ASSERT(prompt != NULL);
            if (prompt) {
                MCP_TEST_ASSERT(strstr(prompt, "\xef\xbd\x9c") == NULL);
                free(prompt);
            }
        }
        ds4_mcp_registry_free(reg);
    }
    ds4_config_free(cfg);
    mcp_test_teardown(fx, home, saved_home);
}

static void test_chatty(void) {
    char *fx, *home, *saved_home;
    ds4_config *cfg = mcp_test_setup("chatty", &fx, &home, &saved_home);
    MCP_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        char warn[512] = {0};
        ds4_mcp_registry *reg = ds4_mcp_registry_create(cfg, NULL, warn, sizeof(warn));
        MCP_TEST_ASSERT(reg != NULL);
        if (reg) {
            MCP_TEST_ASSERT(ds4_mcp_registry_tool_count(reg) == 2);
            const ds4_mcp_tool *echo = ds4_mcp_registry_find(reg, "mcp__mock__echo");
            MCP_TEST_ASSERT(echo != NULL);
            if (echo) {
                const char *names[1] = { "text" };
                const char *values[1] = { "hello" };
                int is_str[1] = { 1 };
                char *args_json = ds4_mcp_args_to_json(names, values, is_str, 1);
                char *result = ds4_mcp_registry_call_tool(reg, echo, args_json);
                MCP_TEST_ASSERT(result != NULL);
                if (result) { MCP_TEST_ASSERT(strstr(result, "hello") != NULL); free(result); }
                free(args_json);
            }
        }
        ds4_mcp_registry_free(reg);
    }
    ds4_config_free(cfg);
    mcp_test_teardown(fx, home, saved_home);
}

static void test_pages(void) {
    char *fx, *home, *saved_home;
    ds4_config *cfg = mcp_test_setup("pages", &fx, &home, &saved_home);
    MCP_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        char warn[512] = {0};
        ds4_mcp_registry *reg = ds4_mcp_registry_create(cfg, NULL, warn, sizeof(warn));
        MCP_TEST_ASSERT(reg != NULL);
        if (reg) {
            MCP_TEST_ASSERT(ds4_mcp_registry_tool_count(reg) == 2);
            MCP_TEST_ASSERT(ds4_mcp_registry_find(reg, "mcp__mock__page1tool") != NULL);
            MCP_TEST_ASSERT(ds4_mcp_registry_find(reg, "mcp__mock__page2tool") != NULL);
        }
        ds4_mcp_registry_free(reg);
    }
    ds4_config_free(cfg);
    mcp_test_teardown(fx, home, saved_home);
}

static void test_die_after_list(void) {
    char *fx, *home, *saved_home;
    ds4_config *cfg = mcp_test_setup("die-after-list", &fx, &home, &saved_home);
    MCP_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        char warn[512] = {0};
        ds4_mcp_registry *reg = ds4_mcp_registry_create(cfg, NULL, warn, sizeof(warn));
        MCP_TEST_ASSERT(reg != NULL);
        if (reg) {
            MCP_TEST_ASSERT(ds4_mcp_registry_tool_count(reg) == 1);
            const ds4_mcp_tool *tool = ds4_mcp_registry_find(reg, "mcp__mock__dietool");
            MCP_TEST_ASSERT(tool != NULL);
            if (tool) {
                long t0 = mcp_now_ms();
                char *result = ds4_mcp_registry_call_tool(reg, tool, "{}");
                long elapsed = mcp_now_ms() - t0;
                MCP_TEST_ASSERT(result != NULL);
                if (result) {
                    MCP_TEST_ASSERT(strstr(result, "not running") != NULL);
                    free(result);
                }
                MCP_TEST_ASSERT(elapsed < 2000);
            }
        }
        ds4_mcp_registry_free(reg); /* must not hang even though the child is long gone */
    }
    ds4_config_free(cfg);
    mcp_test_teardown(fx, home, saved_home);
}

static void test_no_config(void) {
    char *fx, *home, *saved_home;
    ds4_config *cfg = mcp_test_setup(NULL, &fx, &home, &saved_home); /* no mcp.json written */
    MCP_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        char warn[512] = {0};
        ds4_mcp_registry *reg = ds4_mcp_registry_create(cfg, NULL, warn, sizeof(warn));
        MCP_TEST_ASSERT(reg == NULL);
        MCP_TEST_ASSERT(ds4_mcp_registry_tool_count(reg) == 0);
        MCP_TEST_ASSERT(ds4_mcp_registry_tool_at(reg, 0) == NULL);
        MCP_TEST_ASSERT(ds4_mcp_registry_find(reg, "mcp__mock__echo") == NULL);
        MCP_TEST_ASSERT(ds4_mcp_tools_prompt_text(reg) == NULL);
        char *bad_call = ds4_mcp_registry_call_tool(reg, NULL, "{}");
        MCP_TEST_ASSERT(bad_call != NULL);
        free(bad_call);
        ds4_mcp_registry_free(reg); /* NULL: must not crash */
    }
    ds4_config_free(cfg);
    mcp_test_teardown(fx, home, saved_home);

    MCP_TEST_ASSERT(ds4_mcp_registry_create(NULL, NULL, NULL, 0) == NULL);
}

static void test_golden_prompt(void) {
    ds4_mcp_tool tools[2] = {
        { mcp_test_strdup("srv"), mcp_test_strdup("alpha"), mcp_test_strdup("mcp__srv__alpha"),
          mcp_test_strdup("Do a thing."),
          mcp_test_strdup("{\"type\":\"object\",\"properties\":{\"x\":{\"type\":\"string\"}},\"required\":[\"x\"]}") },
        { mcp_test_strdup("srv"), mcp_test_strdup("beta"), mcp_test_strdup("mcp__srv__beta"),
          mcp_test_strdup("Do another thing."),
          mcp_test_strdup("{\"type\":\"object\"}") },
    };
    ds4_mcp_registry reg = {0};
    reg.tools = tools;
    reg.tool_count = 2;

    char *got = ds4_mcp_tools_prompt_text(&reg);
    MCP_TEST_ASSERT(got != NULL);
    if (got) {
        const char *expected =
            "\n## External Tools (MCP)\n\n"
            "{\n"
            "  \"type\": \"function\",\n"
            "  \"function\": {\n"
            "    \"name\": \"mcp__srv__alpha\",\n"
            "    \"description\": \"Do a thing.\",\n"
            "    \"parameters\": {\"type\":\"object\",\"properties\":{\"x\":{\"type\":\"string\"}},\"required\":[\"x\"]}\n"
            "  }\n"
            "}\n"
            "\n"
            "{\n"
            "  \"type\": \"function\",\n"
            "  \"function\": {\n"
            "    \"name\": \"mcp__srv__beta\",\n"
            "    \"description\": \"Do another thing.\",\n"
            "    \"parameters\": {\"type\":\"object\"}\n"
            "  }\n"
            "}\n";
        MCP_TEST_ASSERT(strcmp(got, expected) == 0);
        free(got);
    }
    for (int i = 0; i < 2; i++) {
        free(tools[i].server_name); free(tools[i].tool_name); free(tools[i].wire_name);
        free(tools[i].description); free(tools[i].input_schema_json);
    }

    ds4_mcp_registry empty = {0};
    MCP_TEST_ASSERT(ds4_mcp_tools_prompt_text(&empty) == NULL);
    MCP_TEST_ASSERT(ds4_mcp_tools_prompt_text(NULL) == NULL);
}

static void test_registry_free_reaps(void) {
    char *fx, *home, *saved_home;
    ds4_config *cfg = mcp_test_setup("normal", &fx, &home, &saved_home);
    MCP_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        char warn[512] = {0};
        ds4_mcp_registry *reg = ds4_mcp_registry_create(cfg, NULL, warn, sizeof(warn));
        MCP_TEST_ASSERT(reg != NULL);
        if (reg) {
            MCP_TEST_ASSERT(ds4_mcp_test_proc_count(reg) == 1);
            pid_t pid = ds4_mcp_test_proc_pid(reg, 0);
            MCP_TEST_ASSERT(pid > 0);
            ds4_mcp_registry_free(reg);
            if (pid > 0) {
                int r = kill(pid, 0);
                MCP_TEST_ASSERT(r == -1 && errno == ESRCH);
            }
        } else {
            ds4_mcp_registry_free(reg);
        }
    }
    ds4_config_free(cfg);
    mcp_test_teardown(fx, home, saved_home);
}

/* mcp.json inside a plugin root is just another root's file to
 * mcp_load_all -- zero code changes needed here (mirrors the plugin tests in
 * ds4_skills.c/ds4_commands.c). One happy-path check: the mock spawns and
 * its tools are discovered exactly as when mcp.json lives in a base root. */
static void test_plugin_mcp_json_spawns_mock(void) {
    char tmpl[] = "/tmp/ds4_mcp_plugin_test.XXXXXX";
    char *fx = mkdtemp(tmpl);
    MCP_TEST_ASSERT(fx != NULL);
    if (!fx) return;
    fx = mcp_test_strdup(fx);

    char *proj = mcp_test_join(fx, "proj");
    char *proj_ds4 = mcp_test_join(proj, ".ds4");
    mcp_test_mkdir_p(proj_ds4);
    char *plugin_dir = mcp_test_join(proj_ds4, "plugins/myplugin");
    mcp_test_mkdir_p(plugin_dir);
    mcp_test_write_mcpjson(plugin_dir, "normal");

    char *home = mcp_test_join(fx, "home");
    mcp_test_mkdir_p(home);
    char *saved_home;
    mcp_test_setenv_home(home, &saved_home);

    ds4_config *cfg = ds4_config_load(proj, NULL, 0);
    MCP_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        char warn[512] = {0};
        ds4_mcp_registry *reg = ds4_mcp_registry_create(cfg, NULL, warn, sizeof(warn));
        MCP_TEST_ASSERT(reg != NULL);
        if (reg) {
            MCP_TEST_ASSERT(ds4_mcp_registry_tool_count(reg) == 2);
            const ds4_mcp_tool *echo = ds4_mcp_registry_find(reg, "mcp__mock__echo");
            MCP_TEST_ASSERT(echo != NULL);
        }
        ds4_mcp_registry_free(reg);
    }
    ds4_config_free(cfg);

    mcp_test_teardown(fx, home, saved_home);
    free(proj); free(proj_ds4); free(plugin_dir);
}

int ds4_mcp_unit_tests_run(void) {
    test_normal();
    test_args_to_json();
    test_exit_early();
    test_garbage();
    test_slow_timeout();
    test_evil();
    test_chatty();
    test_pages();
    test_die_after_list();
    test_no_config();
    test_golden_prompt();
    test_registry_free_reaps();
    test_plugin_mcp_json_spawns_mock();
    return mcp_test_failures;
}
#endif
