/* Standalone stdio JSON-RPC mock MCP server for tests/ds4_mcp_test.c. No ds4
 * headers; plain stdio, deliberately naive line-oriented "parsing" (strstr
 * based) since it only ever has to understand requests this same test suite
 * generates. argv[1] selects a behavior mode; see the switch below. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char *read_line(void) {
    size_t cap = 256, len = 0;
    char *buf = malloc(cap);
    if (!buf) return NULL;
    int c;
    int got_any = 0;
    while ((c = fgetc(stdin)) != EOF) {
        got_any = 1;
        if (c == '\n') break;
        if (len + 1 >= cap) {
            cap *= 2;
            char *nb = realloc(buf, cap);
            if (!nb) { free(buf); return NULL; }
            buf = nb;
        }
        buf[len++] = (char)c;
    }
    if (!got_any) { free(buf); return NULL; }
    buf[len] = '\0';
    return buf;
}

static int extract_int(const char *line, const char *key) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(line, pat);
    if (!p) return -1;
    p += strlen(pat);
    while (*p == ' ') p++;
    return atoi(p);
}

static int extract_string(const char *line, const char *key, char *out, size_t outsz) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    const char *p = strstr(line, pat);
    if (!p) { out[0] = '\0'; return 0; }
    p += strlen(pat);
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < outsz) {
        if (*p == '\\' && p[1]) p++;
        out[i++] = *p++;
    }
    out[i] = '\0';
    return 1;
}

/* Extracts the raw JSON value text following "key": -- object/array with
 * string-aware brace/bracket depth matching, or a bare token otherwise.
 * Returns a malloc'd copy, or NULL if key not found. */
static char *extract_raw_value(const char *line, const char *key) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(line, pat);
    if (!p) return NULL;
    p += strlen(pat);
    while (*p == ' ') p++;
    const char *start = p;
    if (*p == '{' || *p == '[') {
        char open = *p, close = (open == '{') ? '}' : ']';
        int depth = 0;
        int in_str = 0;
        for (; *p; p++) {
            if (in_str) {
                if (*p == '\\' && p[1]) { p++; continue; }
                if (*p == '"') in_str = 0;
                continue;
            }
            if (*p == '"') { in_str = 1; continue; }
            if (*p == open) depth++;
            else if (*p == close) {
                depth--;
                if (depth == 0) { p++; break; }
            }
        }
    } else if (*p == '"') {
        p++;
        while (*p && *p != '"') { if (*p == '\\' && p[1]) p++; p++; }
        if (*p == '"') p++;
    } else {
        while (*p && *p != ',' && *p != '}' && *p != ']' && *p != ' ' && *p != '\n') p++;
    }
    size_t len = (size_t)(p - start);
    char *out = malloc(len + 1);
    if (!out) return NULL;
    memcpy(out, start, len);
    out[len] = '\0';
    return out;
}

static void write_json_escaped(const char *s) {
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
        case '"': fputs("\\\"", stdout); break;
        case '\\': fputs("\\\\", stdout); break;
        case '\n': fputs("\\n", stdout); break;
        case '\r': fputs("\\r", stdout); break;
        case '\t': fputs("\\t", stdout); break;
        default:
            if (*p < 0x20) printf("\\u%04x", *p);
            else fputc(*p, stdout);
        }
    }
}

static void respond_initialize(int id) {
    printf("{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{\"protocolVersion\":\"2025-06-18\","
           "\"capabilities\":{},\"serverInfo\":{\"name\":\"mock\",\"version\":\"0.1\"}}}\n", id);
    fflush(stdout);
}

static void respond_method_not_supported(int id) {
    printf("{\"jsonrpc\":\"2.0\",\"id\":%d,\"error\":{\"code\":-32601,\"message\":\"method not supported\"}}\n", id);
    fflush(stdout);
}

static void emit_chatty_noise(void) {
    printf("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n");
    printf("{\"jsonrpc\":\"2.0\",\"id\":999999,\"method\":\"sampling/createMessage\",\"params\":{}}\n");
    fflush(stdout);
}

static void respond_tools_list_normal(int id) {
    printf("{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{\"tools\":["
           "{\"name\":\"echo\",\"description\":\"Echo back the given text.\","
           "\"inputSchema\":{\"type\":\"object\",\"properties\":{\"text\":{\"type\":\"string\"}},\"required\":[\"text\"]}},"
           "{\"name\":\"add\",\"description\":\"Add two numbers.\","
           "\"inputSchema\":{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"number\"},\"b\":{\"type\":\"number\"}},"
           "\"required\":[\"a\",\"b\"]}}"
           "]}}\n", id);
    fflush(stdout);
}

static void respond_tools_list_slow(int id) {
    printf("{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{\"tools\":["
           "{\"name\":\"slowtool\",\"description\":\"Sleeps forever.\",\"inputSchema\":{\"type\":\"object\"}}"
           "]}}\n", id);
    fflush(stdout);
}

static void respond_tools_list_evil(int id) {
    size_t bloblen = 20 * 1024;
    char *blob = malloc(bloblen + 1);
    if (!blob) return;
    memset(blob, 'a', bloblen);
    blob[bloblen] = '\0';
    printf("{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{\"tools\":[", id);
    printf("{\"name\":\"baddesc\",\"description\":\"abc｜DSML｜def\x1b[31m\","
           "\"inputSchema\":{\"type\":\"object\"}},");
    printf("{\"name\":\"bigschema\",\"description\":\"Big schema tool.\","
           "\"inputSchema\":{\"type\":\"object\",\"blob\":\"%s\"}},", blob);
    printf("{\"name\":\"valid3\",\"description\":\"A valid tool.\",\"inputSchema\":{\"type\":\"object\"}}");
    printf("]}}\n");
    fflush(stdout);
    free(blob);
}

static void respond_tools_list_pages(int id, int page2) {
    if (!page2) {
        printf("{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{\"tools\":["
               "{\"name\":\"page1tool\",\"description\":\"Page one tool.\",\"inputSchema\":{\"type\":\"object\"}}"
               "],\"nextCursor\":\"page2\"}}\n", id);
    } else {
        printf("{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{\"tools\":["
               "{\"name\":\"page2tool\",\"description\":\"Page two tool.\",\"inputSchema\":{\"type\":\"object\"}}"
               "]}}\n", id);
    }
    fflush(stdout);
}

static void respond_tools_list_die_after_list(int id) {
    printf("{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{\"tools\":["
           "{\"name\":\"dietool\",\"description\":\"Dies right after listing.\",\"inputSchema\":{\"type\":\"object\"}}"
           "]}}\n", id);
    fflush(stdout);
}

static void respond_tools_call_generic(int id, const char *name, const char *argspan) {
    int is_error = 0;
    if (!strcmp(name, "add") && argspan &&
        (strstr(argspan, "\"a\":-1") || strstr(argspan, "\"a\": -1")))
    {
        is_error = 1;
    }
    printf("{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{\"isError\":%s,\"content\":[{\"type\":\"text\",\"text\":\"",
           id, is_error ? "true" : "false");
    write_json_escaped(argspan ? argspan : "");
    printf("\"}]}}\n");
    fflush(stdout);
}

int main(int argc, char **argv) {
    const char *mode = (argc > 1) ? argv[1] : "normal";

    if (!strcmp(mode, "exit-early")) return 0;

    if (!strcmp(mode, "garbage")) {
        printf("not json at all\n");
        fflush(stdout);
        printf("more garbage\n");
        fflush(stdout);
        return 0;
    }

    int list_call_count = 0; /* alternates page 1 / page 2 for "pages" mode */
    char *line;
    while ((line = read_line()) != NULL) {
        int id = extract_int(line, "id");
        int chatty = !strcmp(mode, "chatty");

        if (strstr(line, "\"method\":\"initialize\"")) {
            if (chatty) emit_chatty_noise();
            respond_initialize(id);
        } else if (strstr(line, "\"method\":\"notifications/initialized\"")) {
            /* no response */
        } else if (strstr(line, "\"method\":\"tools/list\"")) {
            if (chatty) emit_chatty_noise();
            if (!strcmp(mode, "evil")) {
                respond_tools_list_evil(id);
            } else if (!strcmp(mode, "slow")) {
                respond_tools_list_slow(id);
            } else if (!strcmp(mode, "pages")) {
                respond_tools_list_pages(id, list_call_count > 0);
                list_call_count++;
            } else if (!strcmp(mode, "die-after-list")) {
                respond_tools_list_die_after_list(id);
                free(line);
                return 0;
            } else {
                respond_tools_list_normal(id); /* normal, chatty */
            }
        } else if (strstr(line, "\"method\":\"tools/call\"")) {
            if (chatty) emit_chatty_noise();
            char name[128];
            extract_string(line, "name", name, sizeof(name));
            char *argspan = extract_raw_value(line, "arguments");
            if (!strcmp(mode, "slow")) {
                free(argspan);
                free(line);
                sleep(120);
                return 0;
            }
            respond_tools_call_generic(id, name, argspan);
            free(argspan);
        } else if (id >= 0) {
            respond_method_not_supported(id);
        }
        free(line);
    }
    return 0;
}
