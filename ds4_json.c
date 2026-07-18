#include "ds4_json.h"
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Self-contained JSON DOM: parser + writer. No dependencies beyond libc.
 * Ported from the scanning logic in ds4_server.c (json_ws/json_string/
 * json_number/depth-limited skip), adapted to build a tree instead of
 * streaming, and made stricter about malformed \u escapes (server tolerates
 * lone surrogates by substituting U+FFFD; a DOM has no wire format to keep
 * flowing for, so it rejects them instead). */

/* Nesting guard: an ignored/attacker-controlled field like [[[[...]]]] must
 * not be allowed to recurse the whole C stack away before being rejected. */
#define DS4_JSON_MAX_DEPTH 128

static void json_die(const char *msg) {
    fprintf(stderr, "ds4_json: %s\n", msg);
    exit(1);
}

static void *json_xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) json_die("out of memory");
    return p;
}

static void *json_xcalloc(size_t n, size_t size) {
    void *p = calloc(n ? n : 1, size ? size : 1);
    if (!p) json_die("out of memory");
    return p;
}

static void *json_xrealloc(void *p, size_t n) {
    p = realloc(p, n ? n : 1);
    if (!p) json_die("out of memory");
    return p;
}

static char *json_xstrdup(const char *s) {
    size_t n = strlen(s);
    char *p = json_xmalloc(n + 1);
    memcpy(p, s, n + 1);
    return p;
}

static char *json_xstrndup(const char *s, size_t n) {
    char *p = json_xmalloc(n + 1);
    memcpy(p, s, n);
    p[n] = '\0';
    return p;
}

/* ---- growable byte buffer, shared by the writer API and the internal
 * string-escape decoder ---- */

static void jw_reserve(ds4_json_writer *w, size_t add) {
    if (add > SIZE_MAX - w->len - 1) json_die("buffer overflow");
    size_t need = w->len + add + 1;
    if (need <= w->cap) return;
    size_t cap = w->cap ? w->cap * 2 : 256;
    while (cap < need) {
        if (cap > SIZE_MAX / 2) {
            cap = need;
            break;
        }
        cap *= 2;
    }
    w->ptr = json_xrealloc(w->ptr, cap);
    w->cap = cap;
}

static void jw_append(ds4_json_writer *w, const char *p, size_t n) {
    jw_reserve(w, n);
    memcpy(w->ptr + w->len, p, n);
    w->len += n;
    w->ptr[w->len] = '\0';
}

static void jw_putc(ds4_json_writer *w, char c) {
    jw_append(w, &c, 1);
}

/* ---- DOM ---- */

struct ds4_json_value {
    ds4_json_type type;
    size_t start, end;   /* byte offsets of this value's span in src */
    const char *src;     /* shared source text; only the root frees it */
    bool is_root;
    union {
        bool b;
        double num;
        char *str;
        struct {
            ds4_json_value **items;
            int len, cap;
        } arr;
        struct {
            char **keys;
            ds4_json_value **vals;
            int len, cap;
        } obj;
    } u;
};

static ds4_json_value *json_value_new(ds4_json_type type, const char *src) {
    ds4_json_value *v = json_xcalloc(1, sizeof(*v));
    v->type = type;
    v->src = src;
    return v;
}

static void json_arr_push(ds4_json_value *v, ds4_json_value *item) {
    if (v->u.arr.len == v->u.arr.cap) {
        v->u.arr.cap = v->u.arr.cap ? v->u.arr.cap * 2 : 4;
        v->u.arr.items = json_xrealloc(v->u.arr.items,
                                       (size_t)v->u.arr.cap * sizeof(*v->u.arr.items));
    }
    v->u.arr.items[v->u.arr.len++] = item;
}

static void json_obj_push(ds4_json_value *v, char *key, ds4_json_value *val) {
    if (v->u.obj.len == v->u.obj.cap) {
        v->u.obj.cap = v->u.obj.cap ? v->u.obj.cap * 2 : 4;
        v->u.obj.keys = json_xrealloc(v->u.obj.keys,
                                      (size_t)v->u.obj.cap * sizeof(*v->u.obj.keys));
        v->u.obj.vals = json_xrealloc(v->u.obj.vals,
                                      (size_t)v->u.obj.cap * sizeof(*v->u.obj.vals));
    }
    v->u.obj.keys[v->u.obj.len] = key;
    v->u.obj.vals[v->u.obj.len] = val;
    v->u.obj.len++;
}

void ds4_json_free(ds4_json_value *v) {
    if (!v) return;
    switch (v->type) {
    case DS4_JSON_STR:
        free(v->u.str);
        break;
    case DS4_JSON_ARR:
        for (int i = 0; i < v->u.arr.len; i++) ds4_json_free(v->u.arr.items[i]);
        free(v->u.arr.items);
        break;
    case DS4_JSON_OBJ:
        for (int i = 0; i < v->u.obj.len; i++) {
            free(v->u.obj.keys[i]);
            ds4_json_free(v->u.obj.vals[i]);
        }
        free(v->u.obj.keys);
        free(v->u.obj.vals);
        break;
    default:
        break;
    }
    if (v->is_root) free((char *)v->src);
    free(v);
}

/* ---- parser ---- */

typedef struct {
    const char *begin;
    const char *p;
    char *err;
    size_t err_len;
    bool err_set;
} json_parser;

static void json_err(json_parser *ps, const char *msg) {
    if (ps->err_set) return;
    ps->err_set = true;
    if (ps->err && ps->err_len) {
        snprintf(ps->err, ps->err_len, "%s (at byte %zu)", msg,
                 (size_t)(ps->p - ps->begin));
    }
}

static void json_ws(const char **p) {
    while (**p && isspace((unsigned char)**p)) (*p)++;
}

static bool json_lit(const char **p, const char *lit) {
    size_t n = strlen(lit);
    if (strncmp(*p, lit, n) != 0) return false;
    *p += n;
    return true;
}

static bool json_number(const char **p, double *out) {
    char *end = NULL;
    double v = strtod(*p, &end);
    if (end == *p) return false;
    *p = end;
    *out = v;
    return true;
}

static int json_hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return -1;
}

/* Reads exactly 4 hex digits starting at *p (no leading "\u"). */
static bool json_hex4(const char **p, uint32_t *out) {
    uint32_t cp = 0;
    for (int i = 0; i < 4; i++) {
        int h = json_hex_digit((*p)[i]);
        if (h < 0) return false;
        cp = (cp << 4) | (uint32_t)h;
    }
    *p += 4;
    *out = cp;
    return true;
}

static void json_utf8_encode(ds4_json_writer *w, uint32_t cp) {
    if (cp > 0x10ffff) cp = 0xfffd;
    if (cp <= 0x7f) {
        jw_putc(w, (char)cp);
    } else if (cp <= 0x7ff) {
        jw_putc(w, (char)(0xc0 | (cp >> 6)));
        jw_putc(w, (char)(0x80 | (cp & 0x3f)));
    } else if (cp <= 0xffff) {
        jw_putc(w, (char)(0xe0 | (cp >> 12)));
        jw_putc(w, (char)(0x80 | ((cp >> 6) & 0x3f)));
        jw_putc(w, (char)(0x80 | (cp & 0x3f)));
    } else {
        jw_putc(w, (char)(0xf0 | (cp >> 18)));
        jw_putc(w, (char)(0x80 | ((cp >> 12) & 0x3f)));
        jw_putc(w, (char)(0x80 | ((cp >> 6) & 0x3f)));
        jw_putc(w, (char)(0x80 | (cp & 0x3f)));
    }
}

/* ps->p must point at the opening quote. Decodes into a freshly malloc'd
 * C string on success. Rejects unterminated strings, invalid/lone \u
 * surrogates, and \u0000 (a C string cannot represent an embedded NUL byte). */
static bool json_parse_string(json_parser *ps, char **out) {
    ps->p++; /* consume opening '"' */
    ds4_json_writer w = {0};
    for (;;) {
        unsigned char c = (unsigned char)*ps->p;
        if (c == '\0') {
            json_err(ps, "unterminated string");
            ds4_json_w_free(&w);
            return false;
        }
        if (c == '"') {
            ps->p++;
            break;
        }
        if (c != '\\') {
            jw_putc(&w, (char)c);
            ps->p++;
            continue;
        }
        ps->p++; /* consume backslash */
        c = (unsigned char)*ps->p;
        switch (c) {
        case '"': jw_putc(&w, '"'); ps->p++; break;
        case '\\': jw_putc(&w, '\\'); ps->p++; break;
        case '/': jw_putc(&w, '/'); ps->p++; break;
        case 'b': jw_putc(&w, '\b'); ps->p++; break;
        case 'f': jw_putc(&w, '\f'); ps->p++; break;
        case 'n': jw_putc(&w, '\n'); ps->p++; break;
        case 'r': jw_putc(&w, '\r'); ps->p++; break;
        case 't': jw_putc(&w, '\t'); ps->p++; break;
        case 'u': {
            ps->p++; /* now at first hex digit */
            uint32_t cp;
            if (!json_hex4(&ps->p, &cp)) {
                json_err(ps, "invalid \\u escape");
                ds4_json_w_free(&w);
                return false;
            }
            if (cp >= 0xdc00 && cp <= 0xdfff) {
                json_err(ps, "lone low surrogate in \\u escape");
                ds4_json_w_free(&w);
                return false;
            }
            if (cp >= 0xd800 && cp <= 0xdbff) {
                if (ps->p[0] != '\\' || ps->p[1] != 'u') {
                    json_err(ps, "lone high surrogate in \\u escape");
                    ds4_json_w_free(&w);
                    return false;
                }
                const char *lo_pos = ps->p + 2;
                uint32_t lo;
                if (!json_hex4(&lo_pos, &lo) || lo < 0xdc00 || lo > 0xdfff) {
                    json_err(ps, "invalid low surrogate in \\u escape");
                    ds4_json_w_free(&w);
                    return false;
                }
                ps->p = lo_pos;
                cp = 0x10000u + ((cp - 0xd800u) << 10) + (lo - 0xdc00u);
            }
            if (cp == 0) {
                json_err(ps, "NUL character in string is not supported");
                ds4_json_w_free(&w);
                return false;
            }
            json_utf8_encode(&w, cp);
            break;
        }
        default:
            json_err(ps, "invalid escape sequence");
            ds4_json_w_free(&w);
            return false;
        }
    }
    *out = ds4_json_w_take(&w);
    return true;
}

static bool json_parse_value(json_parser *ps, int depth, ds4_json_value **out);

static bool json_parse_array(json_parser *ps, int depth, ds4_json_value **out) {
    if (depth > DS4_JSON_MAX_DEPTH) {
        json_err(ps, "maximum nesting depth exceeded");
        return false;
    }
    size_t start = (size_t)(ps->p - ps->begin);
    ps->p++; /* consume '[' */
    ds4_json_value *v = json_value_new(DS4_JSON_ARR, ps->begin);
    json_ws(&ps->p);
    if (*ps->p == ']') {
        ps->p++;
    } else {
        for (;;) {
            ds4_json_value *item = NULL;
            if (!json_parse_value(ps, depth, &item)) {
                ds4_json_free(v);
                return false;
            }
            json_arr_push(v, item);
            json_ws(&ps->p);
            if (*ps->p == ']') {
                ps->p++;
                break;
            }
            if (*ps->p != ',') {
                json_err(ps, "expected ',' or ']' in array");
                ds4_json_free(v);
                return false;
            }
            ps->p++;
            json_ws(&ps->p);
            if (*ps->p == ']') {
                json_err(ps, "trailing comma in array");
                ds4_json_free(v);
                return false;
            }
        }
    }
    v->start = start;
    v->end = (size_t)(ps->p - ps->begin);
    *out = v;
    return true;
}

static bool json_parse_object(json_parser *ps, int depth, ds4_json_value **out) {
    if (depth > DS4_JSON_MAX_DEPTH) {
        json_err(ps, "maximum nesting depth exceeded");
        return false;
    }
    size_t start = (size_t)(ps->p - ps->begin);
    ps->p++; /* consume '{' */
    ds4_json_value *v = json_value_new(DS4_JSON_OBJ, ps->begin);
    json_ws(&ps->p);
    if (*ps->p == '}') {
        ps->p++;
    } else {
        for (;;) {
            json_ws(&ps->p);
            if (*ps->p != '"') {
                json_err(ps, "expected string key");
                ds4_json_free(v);
                return false;
            }
            char *key = NULL;
            if (!json_parse_string(ps, &key)) {
                ds4_json_free(v);
                return false;
            }
            json_ws(&ps->p);
            if (*ps->p != ':') {
                json_err(ps, "expected ':' after object key");
                free(key);
                ds4_json_free(v);
                return false;
            }
            ps->p++;
            ds4_json_value *val = NULL;
            if (!json_parse_value(ps, depth, &val)) {
                free(key);
                ds4_json_free(v);
                return false;
            }
            json_obj_push(v, key, val);
            json_ws(&ps->p);
            if (*ps->p == '}') {
                ps->p++;
                break;
            }
            if (*ps->p != ',') {
                json_err(ps, "expected ',' or '}' in object");
                ds4_json_free(v);
                return false;
            }
            ps->p++;
            json_ws(&ps->p);
            if (*ps->p == '}') {
                json_err(ps, "trailing comma in object");
                ds4_json_free(v);
                return false;
            }
        }
    }
    v->start = start;
    v->end = (size_t)(ps->p - ps->begin);
    *out = v;
    return true;
}

static bool json_parse_value(json_parser *ps, int depth, ds4_json_value **out) {
    json_ws(&ps->p);
    size_t start = (size_t)(ps->p - ps->begin);
    unsigned char c = (unsigned char)*ps->p;

    if (c == '{') return json_parse_object(ps, depth + 1, out);
    if (c == '[') return json_parse_array(ps, depth + 1, out);

    ds4_json_value *v = NULL;
    if (c == '"') {
        char *s = NULL;
        if (!json_parse_string(ps, &s)) return false;
        v = json_value_new(DS4_JSON_STR, ps->begin);
        v->u.str = s;
    } else if (json_lit(&ps->p, "true")) {
        v = json_value_new(DS4_JSON_BOOL, ps->begin);
        v->u.b = true;
    } else if (json_lit(&ps->p, "false")) {
        v = json_value_new(DS4_JSON_BOOL, ps->begin);
        v->u.b = false;
    } else if (json_lit(&ps->p, "null")) {
        v = json_value_new(DS4_JSON_NULL, ps->begin);
    } else if (c == '-' || (c >= '0' && c <= '9')) {
        double num;
        if (!json_number(&ps->p, &num)) {
            json_err(ps, "invalid number");
            return false;
        }
        v = json_value_new(DS4_JSON_NUM, ps->begin);
        v->u.num = num;
    } else {
        json_err(ps, c ? "unexpected character in value" : "unexpected end of input");
        return false;
    }
    v->start = start;
    v->end = (size_t)(ps->p - ps->begin);
    *out = v;
    return true;
}

ds4_json_value *ds4_json_parse(const char *text, char *err, size_t err_len) {
    if (err && err_len) err[0] = '\0';
    if (!text) text = "";
    char *src_copy = json_xstrdup(text);
    json_parser ps = { .begin = src_copy, .p = src_copy,
                        .err = err, .err_len = err_len, .err_set = false };

    ds4_json_value *root = NULL;
    if (!json_parse_value(&ps, 0, &root)) {
        free(src_copy);
        return NULL;
    }
    json_ws(&ps.p);
    if (*ps.p != '\0') {
        json_err(&ps, "trailing data after JSON value");
        ds4_json_free(root); /* is_root not set yet: frees children only */
        free(src_copy);
        return NULL;
    }
    root->is_root = true;
    return root;
}

/* ---- accessors ---- */

ds4_json_type ds4_json_type_of(const ds4_json_value *v) {
    return v ? v->type : DS4_JSON_NULL;
}

const char *ds4_json_str(const ds4_json_value *v) {
    return (v && v->type == DS4_JSON_STR) ? v->u.str : NULL;
}

double ds4_json_num(const ds4_json_value *v, double def) {
    return (v && v->type == DS4_JSON_NUM) ? v->u.num : def;
}

bool ds4_json_bool(const ds4_json_value *v, bool def) {
    return (v && v->type == DS4_JSON_BOOL) ? v->u.b : def;
}

int ds4_json_arr_len(const ds4_json_value *v) {
    return (v && v->type == DS4_JSON_ARR) ? v->u.arr.len : 0;
}

const ds4_json_value *ds4_json_arr_get(const ds4_json_value *v, int i) {
    if (!v || v->type != DS4_JSON_ARR || i < 0 || i >= v->u.arr.len) return NULL;
    return v->u.arr.items[i];
}

const ds4_json_value *ds4_json_obj_get(const ds4_json_value *v, const char *key) {
    if (!v || v->type != DS4_JSON_OBJ || !key) return NULL;
    for (int i = 0; i < v->u.obj.len; i++)
        if (strcmp(v->u.obj.keys[i], key) == 0) return v->u.obj.vals[i];
    return NULL;
}

int ds4_json_obj_len(const ds4_json_value *v) {
    return (v && v->type == DS4_JSON_OBJ) ? v->u.obj.len : 0;
}

const char *ds4_json_obj_key_at(const ds4_json_value *v, int i) {
    if (!v || v->type != DS4_JSON_OBJ || i < 0 || i >= v->u.obj.len) return NULL;
    return v->u.obj.keys[i];
}

const ds4_json_value *ds4_json_obj_val_at(const ds4_json_value *v, int i) {
    if (!v || v->type != DS4_JSON_OBJ || i < 0 || i >= v->u.obj.len) return NULL;
    return v->u.obj.vals[i];
}

char *ds4_json_raw(const ds4_json_value *v) {
    if (!v) return NULL;
    return json_xstrndup(v->src + v->start, v->end - v->start);
}

/* ---- writer ---- */

void ds4_json_w_free(ds4_json_writer *w) {
    free(w->ptr);
    memset(w, 0, sizeof(*w));
}

char *ds4_json_w_take(ds4_json_writer *w) {
    if (!w->ptr) return json_xstrdup("");
    char *p = w->ptr;
    memset(w, 0, sizeof(*w));
    return p;
}

void ds4_json_w_raw(ds4_json_writer *w, const char *s) {
    jw_append(w, s, strlen(s));
}

void ds4_json_w_string(ds4_json_writer *w, const char *s) {
    jw_putc(w, '"');
    if (s) {
        for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
            switch (*p) {
            case '"': jw_append(w, "\\\"", 2); break;
            case '\\': jw_append(w, "\\\\", 2); break;
            case '\n': jw_append(w, "\\n", 2); break;
            case '\r': jw_append(w, "\\r", 2); break;
            case '\t': jw_append(w, "\\t", 2); break;
            case '\b': jw_append(w, "\\b", 2); break;
            case '\f': jw_append(w, "\\f", 2); break;
            default:
                if (*p < 0x20) {
                    char esc[8];
                    snprintf(esc, sizeof(esc), "\\u%04x", *p);
                    jw_append(w, esc, 6);
                } else {
                    jw_putc(w, (char)*p);
                }
            }
        }
    }
    jw_putc(w, '"');
}

#ifdef DS4_JSON_TEST
#include <math.h>

static int json_test_failures;

static void json_test_assert(bool cond, const char *expr, const char *file, int line) {
    if (cond) return;
    fprintf(stderr, "%s:%d: assertion failed: %s\n", file, line, expr);
    json_test_failures++;
}
#define JSON_TEST_ASSERT(expr) json_test_assert((expr), #expr, __FILE__, __LINE__)

static char *json_test_build_nested_array(int n) {
    char *s = malloc((size_t)n * 2 + 2);
    int pos = 0;
    for (int i = 0; i < n; i++) s[pos++] = '[';
    s[pos++] = '0';
    for (int i = 0; i < n; i++) s[pos++] = ']';
    s[pos] = '\0';
    return s;
}

static void test_roundtrip_nested(void) {
    const char *src =
        "{\"name\":\"root\",\"count\":3,\"active\":true,\"missing\":null,"
        "\"tags\":[\"a\",\"b\",\"c\"],\"nested\":{\"x\":1,\"y\":2.5,\"flag\":false}}";
    char err[128] = {0};
    ds4_json_value *root = ds4_json_parse(src, err, sizeof(err));
    JSON_TEST_ASSERT(root != NULL);
    if (!root) return;
    JSON_TEST_ASSERT(ds4_json_type_of(root) == DS4_JSON_OBJ);
    JSON_TEST_ASSERT(strcmp(ds4_json_str(ds4_json_obj_get(root, "name")), "root") == 0);
    JSON_TEST_ASSERT(ds4_json_num(ds4_json_obj_get(root, "count"), -1) == 3.0);
    JSON_TEST_ASSERT(ds4_json_bool(ds4_json_obj_get(root, "active"), false) == true);
    JSON_TEST_ASSERT(ds4_json_type_of(ds4_json_obj_get(root, "missing")) == DS4_JSON_NULL);

    const ds4_json_value *tags = ds4_json_obj_get(root, "tags");
    JSON_TEST_ASSERT(ds4_json_arr_len(tags) == 3);
    JSON_TEST_ASSERT(strcmp(ds4_json_str(ds4_json_arr_get(tags, 0)), "a") == 0);
    JSON_TEST_ASSERT(strcmp(ds4_json_str(ds4_json_arr_get(tags, 1)), "b") == 0);
    JSON_TEST_ASSERT(strcmp(ds4_json_str(ds4_json_arr_get(tags, 2)), "c") == 0);

    const ds4_json_value *nested = ds4_json_obj_get(root, "nested");
    JSON_TEST_ASSERT(ds4_json_num(ds4_json_obj_get(nested, "x"), -1) == 1.0);
    JSON_TEST_ASSERT(ds4_json_num(ds4_json_obj_get(nested, "y"), -1) == 2.5);
    JSON_TEST_ASSERT(ds4_json_bool(ds4_json_obj_get(nested, "flag"), true) == false);
    JSON_TEST_ASSERT(ds4_json_obj_len(nested) == 3);
    JSON_TEST_ASSERT(strcmp(ds4_json_obj_key_at(nested, 0), "x") == 0);
    JSON_TEST_ASSERT(strcmp(ds4_json_obj_key_at(nested, 1), "y") == 0);
    JSON_TEST_ASSERT(strcmp(ds4_json_obj_key_at(nested, 2), "flag") == 0);

    char *raw = ds4_json_raw(nested);
    JSON_TEST_ASSERT(raw != NULL);
    if (raw) JSON_TEST_ASSERT(strcmp(raw, "{\"x\":1,\"y\":2.5,\"flag\":false}") == 0);
    free(raw);

    ds4_json_free(root);
}

static void test_mcp_json_fixture(void) {
    const char *src =
        "{\"mcpServers\":{\"fs\":{\"command\":\"npx\","
        "\"args\":[\"-y\",\"@modelcontextprotocol/server-filesystem\",\"/tmp\"],"
        "\"env\":{\"K\":\"V\"}}}}";
    char err[128] = {0};
    ds4_json_value *root = ds4_json_parse(src, err, sizeof(err));
    JSON_TEST_ASSERT(root != NULL);
    if (!root) return;

    const ds4_json_value *servers = ds4_json_obj_get(root, "mcpServers");
    JSON_TEST_ASSERT(ds4_json_obj_len(servers) == 1);
    JSON_TEST_ASSERT(strcmp(ds4_json_obj_key_at(servers, 0), "fs") == 0);

    const ds4_json_value *fs = ds4_json_obj_val_at(servers, 0);
    JSON_TEST_ASSERT(strcmp(ds4_json_str(ds4_json_obj_get(fs, "command")), "npx") == 0);

    const ds4_json_value *args = ds4_json_obj_get(fs, "args");
    JSON_TEST_ASSERT(ds4_json_arr_len(args) == 3);
    JSON_TEST_ASSERT(strcmp(ds4_json_str(ds4_json_arr_get(args, 0)), "-y") == 0);
    JSON_TEST_ASSERT(strcmp(ds4_json_str(ds4_json_arr_get(args, 1)),
                             "@modelcontextprotocol/server-filesystem") == 0);
    JSON_TEST_ASSERT(strcmp(ds4_json_str(ds4_json_arr_get(args, 2)), "/tmp") == 0);

    const ds4_json_value *envv = ds4_json_obj_get(fs, "env");
    JSON_TEST_ASSERT(strcmp(ds4_json_str(ds4_json_obj_get(envv, "K")), "V") == 0);

    ds4_json_free(root);
}

static void test_escapes(void) {
    char err[128] = {0};

    ds4_json_value *v = ds4_json_parse(
        "\"a\\\"b\\\\c\\/d\\n\\t\xc3\xa9\"", err, sizeof(err));
    JSON_TEST_ASSERT(v != NULL);
    if (v) {
        const char *s = ds4_json_str(v);
        JSON_TEST_ASSERT(s != NULL);
        if (s) JSON_TEST_ASSERT(strcmp(s, "a\"b\\c/d\n\t\xc3\xa9") == 0);
    }
    ds4_json_free(v);

    v = ds4_json_parse("\"\\ud83d\\ude00\"", err, sizeof(err));
    JSON_TEST_ASSERT(v != NULL);
    if (v) {
        const char *s = ds4_json_str(v);
        JSON_TEST_ASSERT(s != NULL);
        if (s) JSON_TEST_ASSERT(strcmp(s, "\xf0\x9f\x98\x80") == 0);
    }
    ds4_json_free(v);

    err[0] = '\0';
    v = ds4_json_parse("\"\\ud800\"", err, sizeof(err));
    JSON_TEST_ASSERT(v == NULL);
    JSON_TEST_ASSERT(err[0] != '\0');
}

static void test_numbers(void) {
    char err[128] = {0};
    struct { const char *src; double expect; } cases[] = {
        {"0", 0.0},
        {"-1", -1.0},
        {"3.14", 3.14},
        {"1e6", 1e6},
        {"-2.5e-3", -2.5e-3},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        ds4_json_value *v = ds4_json_parse(cases[i].src, err, sizeof(err));
        JSON_TEST_ASSERT(v != NULL);
        if (!v) continue;
        JSON_TEST_ASSERT(ds4_json_type_of(v) == DS4_JSON_NUM);
        JSON_TEST_ASSERT(ds4_json_num(v, -999.0) == cases[i].expect);
        ds4_json_free(v);
    }

    ds4_json_value *v = ds4_json_parse("1e400", err, sizeof(err));
    JSON_TEST_ASSERT(v != NULL);
    if (v) JSON_TEST_ASSERT(isinf(ds4_json_num(v, 0.0)));
    ds4_json_free(v);
}

static void test_malformed(void) {
    const char *bad[] = {
        "{\"a\":1,}",
        "{a:1}",
        "\"unterminated",
        "{\"a\":}",
        "[1,2",
        "{} extra",
        "",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char err[128] = {0};
        ds4_json_value *v = ds4_json_parse(bad[i], err, sizeof(err));
        JSON_TEST_ASSERT(v == NULL);
        JSON_TEST_ASSERT(err[0] != '\0');
        ds4_json_free(v);
    }

    /* err == NULL / err_len == 0 must not crash */
    ds4_json_value *v = ds4_json_parse("{bad", NULL, 0);
    JSON_TEST_ASSERT(v == NULL);
}

static void test_depth_bomb(void) {
    char err[256] = {0};

    char *deep_bad = json_test_build_nested_array(200);
    ds4_json_value *v = ds4_json_parse(deep_bad, err, sizeof(err));
    JSON_TEST_ASSERT(v == NULL);
    JSON_TEST_ASSERT(err[0] != '\0');
    ds4_json_free(v);
    free(deep_bad);

    char *deep_ok = json_test_build_nested_array(100);
    v = ds4_json_parse(deep_ok, err, sizeof(err));
    JSON_TEST_ASSERT(v != NULL);
    ds4_json_free(v);
    free(deep_ok);
}

static void test_writer(void) {
    ds4_json_writer w = {0};
    ds4_json_w_string(&w, "he said \"hi\"\n\t\\ and caf\xc3\xa9");
    char *s = ds4_json_w_take(&w);
    JSON_TEST_ASSERT(s != NULL);
    if (s) JSON_TEST_ASSERT(strcmp(s, "\"he said \\\"hi\\\"\\n\\t\\\\ and caf\xc3\xa9\"") == 0);
    free(s);

    ds4_json_writer w2 = {0};
    ds4_json_w_raw(&w2, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":");
    ds4_json_w_string(&w2, "hello");
    ds4_json_w_raw(&w2, "}");
    char *rpc = ds4_json_w_take(&w2);
    JSON_TEST_ASSERT(rpc != NULL);
    if (rpc) JSON_TEST_ASSERT(strcmp(rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":\"hello\"}") == 0);
    free(rpc);

    ds4_json_writer w3 = {0};
    char *empty = ds4_json_w_take(&w3);
    JSON_TEST_ASSERT(empty != NULL);
    if (empty) JSON_TEST_ASSERT(strcmp(empty, "") == 0);
    free(empty);

    ds4_json_writer w4 = {0};
    ds4_json_w_raw(&w4, "abc");
    ds4_json_w_free(&w4);
    JSON_TEST_ASSERT(w4.ptr == NULL && w4.len == 0 && w4.cap == 0);
}

static void test_null_tolerance(void) {
    JSON_TEST_ASSERT(ds4_json_type_of(NULL) == DS4_JSON_NULL);
    JSON_TEST_ASSERT(ds4_json_str(NULL) == NULL);
    JSON_TEST_ASSERT(ds4_json_num(NULL, 3.5) == 3.5);
    JSON_TEST_ASSERT(ds4_json_bool(NULL, true) == true);
    JSON_TEST_ASSERT(ds4_json_arr_len(NULL) == 0);
    JSON_TEST_ASSERT(ds4_json_arr_get(NULL, 0) == NULL);
    JSON_TEST_ASSERT(ds4_json_obj_get(NULL, "x") == NULL);
    JSON_TEST_ASSERT(ds4_json_obj_len(NULL) == 0);
    JSON_TEST_ASSERT(ds4_json_obj_key_at(NULL, 0) == NULL);
    JSON_TEST_ASSERT(ds4_json_obj_val_at(NULL, 0) == NULL);
    JSON_TEST_ASSERT(ds4_json_raw(NULL) == NULL);
    ds4_json_free(NULL);

    char err[64] = {0};
    ds4_json_value *num = ds4_json_parse("42", err, sizeof(err));
    JSON_TEST_ASSERT(num != NULL);
    if (num) {
        JSON_TEST_ASSERT(ds4_json_str(num) == NULL);
        JSON_TEST_ASSERT(ds4_json_arr_len(num) == 0);
        JSON_TEST_ASSERT(ds4_json_arr_get(num, 0) == NULL);
        JSON_TEST_ASSERT(ds4_json_obj_get(num, "x") == NULL);
        JSON_TEST_ASSERT(ds4_json_obj_len(num) == 0);
        JSON_TEST_ASSERT(ds4_json_num(num, 0) == 42.0);
    }
    ds4_json_free(num);
}

int ds4_json_unit_tests_run(void) {
    test_roundtrip_nested();
    test_mcp_json_fixture();
    test_escapes();
    test_numbers();
    test_malformed();
    test_depth_bomb();
    test_writer();
    test_null_tolerance();
    return json_test_failures;
}
#endif
