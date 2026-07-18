#include "ds4_commands.h"
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* User-defined slash commands: <root>/commands/<name>.md discovery and
 * $ARGUMENTS expansion. No dependencies beyond libc and ds4_config (for the
 * search roots). See ds4_commands.h for the contract.
 *
 * Directory convention: for each ds4_config search root (highest precedence
 * first: project .ds4, then user .ds4), scan <root>/commands/ for files
 * ending in ".md" directly (unlike skills, there is no per-command
 * subdirectory). The filename minus
 * the ".md" suffix is the command name; it must match
 * [A-Za-z0-9][A-Za-z0-9_-]{0,63} or the file is skipped with a warning. The
 * name is the only lookup and shadowing key: first occurrence (highest-
 * precedence root) wins, silently, exactly like ds4_skills. */

static char *dc_strndup(const char *s, size_t n) {
    char *p = malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n);
    p[n] = '\0';
    return p;
}

/* Deliberately not depending on ds4_kvstore_path_join so this module stays
 * standalone-compilable for its test binary. */
static char *dc_join(const char *dir, const char *name) {
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

static void dc_warn_append(char *warn, size_t warn_len, const char *path, const char *problem) {
    if (!warn || warn_len == 0) return;
    size_t cur = strlen(warn);
    if (cur + 1 >= warn_len) return; /* no room left */
    snprintf(warn + cur, warn_len - cur, "commands: %s: %s\n", path, problem);
}

/* name must match [A-Za-z0-9][A-Za-z0-9_-]{0,63}. */
static bool dc_valid_name(const char *s) {
    size_t n = strlen(s);
    if (n < 1 || n > 64) return false;
    if (!isalnum((unsigned char)s[0])) return false;
    for (size_t i = 1; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!(isalnum(c) || c == '_' || c == '-')) return false;
    }
    return true;
}

static void dc_list_push(ds4_command_list *out, char *name, char *path) {
    if (out->len == out->cap) {
        out->cap = out->cap ? out->cap * 2 : 4;
        out->v = realloc(out->v, (size_t)out->cap * sizeof(out->v[0]));
    }
    out->v[out->len].name = name;
    out->v[out->len].path = path;
    out->len++;
}

static const ds4_command_meta *dc_find(const ds4_command_list *list, const char *name) {
    if (!list || !name) return NULL;
    for (int i = 0; i < list->len; i++) {
        if (list->v[i].name && !strcmp(list->v[i].name, name))
            return &list->v[i];
    }
    return NULL;
}

/* Reads the whole file at path into a malloc'd NUL-terminated buffer, or NULL
 * if it cannot be opened/stat'd as a regular file (covers the "unreadable at
 * expand time" case, including a file removed since scan). */
static char *dc_read_file(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) return NULL;
    if (st.st_size < 0) return NULL;
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    size_t cap = (size_t)st.st_size + 1;
    char *buf = malloc(cap);
    if (!buf) { fclose(fp); return NULL; }
    size_t n = fread(buf, 1, (size_t)st.st_size, fp);
    fclose(fp);
    buf[n] = '\0';
    return buf;
}

/* Replaces every literal occurrence of needle in body with replacement,
 * scanning body left to right exactly once (never re-scanning text that was
 * just inserted). Malloc'd result, never NULL unless allocation fails. */
static char *dc_replace_all(const char *body, const char *needle, const char *replacement) {
    size_t needle_len = strlen(needle);
    size_t repl_len = strlen(replacement);
    size_t body_len = strlen(body);

    size_t count = 0;
    for (const char *p = body; (p = strstr(p, needle)) != NULL; p += needle_len) count++;

    size_t out_len = body_len - count * needle_len + count * repl_len;
    char *out = malloc(out_len + 1);
    if (!out) return NULL;

    size_t oi = 0;
    const char *p = body;
    const char *next;
    while ((next = strstr(p, needle)) != NULL) {
        size_t chunk = (size_t)(next - p);
        memcpy(out + oi, p, chunk);
        oi += chunk;
        memcpy(out + oi, replacement, repl_len);
        oi += repl_len;
        p = next + needle_len;
    }
    size_t rem = strlen(p);
    memcpy(out + oi, p, rem);
    oi += rem;
    out[oi] = '\0';
    return out;
}

/* entry_dir is a config root's "commands" directory; scans it non-
 * recursively for *.md files. Anything wrong with an individual file is
 * fail-open (warn + skip), never fatal. Files not ending in ".md" are not
 * command files at all and are ignored silently. */
static void dc_scan_root(const char *dir, ds4_command_list *out, char *warn, size_t warn_len) {
    DIR *d = opendir(dir);
    if (!d) {
        if (errno != ENOENT)
            dc_warn_append(warn, warn_len, dir, "could not open, skipped");
        return;
    }

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;

        size_t nlen = strlen(de->d_name);
        static const char suffix[] = ".md";
        size_t suflen = sizeof(suffix) - 1;
        if (nlen < suflen || strcmp(de->d_name + nlen - suflen, suffix) != 0)
            continue; /* not a command file */

        char *path = dc_join(dir, de->d_name);
        if (!path) continue;

        struct stat st;
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
            dc_warn_append(warn, warn_len, path, "not a regular file, skipped");
            free(path);
            continue;
        }

        char *name = dc_strndup(de->d_name, nlen - suflen);
        if (!name) { free(path); continue; }

        if (!dc_valid_name(name)) {
            dc_warn_append(warn, warn_len, path, "invalid command name, skipped");
            free(name);
            free(path);
            continue;
        }

        if (dc_find(out, name)) {
            /* Already discovered from a higher-precedence root (or an
             * earlier entry in this same root): first occurrence wins,
             * silently. */
            free(name);
            free(path);
            continue;
        }

        dc_list_push(out, name, path);
    }
    closedir(d);
}

void ds4_commands_scan(const ds4_config *cfg, ds4_command_list *out, char *warn, size_t warn_len) {
    memset(out, 0, sizeof(*out));
    if (warn && warn_len) warn[0] = '\0';
    if (!cfg) return;

    int nroots = ds4_config_root_count(cfg);
    for (int i = 0; i < nroots; i++) {
        const char *root = ds4_config_root_at(cfg, i);
        if (!root) continue;
        char *commands_dir = dc_join(root, "commands");
        if (!commands_dir) continue;
        dc_scan_root(commands_dir, out, warn, warn_len);
        free(commands_dir);
    }
}

void ds4_commands_list_free(ds4_command_list *list) {
    if (!list) return;
    for (int i = 0; i < list->len; i++) {
        free(list->v[i].name);
        free(list->v[i].path);
    }
    free(list->v);
    memset(list, 0, sizeof(*list));
}

bool ds4_commands_known(const ds4_command_list *list, const char *slash_cmd) {
    if (!list || !slash_cmd || slash_cmd[0] != '/') return false;
    return dc_find(list, slash_cmd + 1) != NULL;
}

char *ds4_commands_expand(const ds4_command_list *list, const char *slash_cmd, const char *args) {
    if (!list || !slash_cmd || slash_cmd[0] != '/') return NULL;
    const ds4_command_meta *m = dc_find(list, slash_cmd + 1);
    if (!m) return NULL;
    char *body = dc_read_file(m->path);
    if (!body) return NULL;
    char *out = dc_replace_all(body, "$ARGUMENTS", args ? args : "");
    free(body);
    return out;
}

#ifdef DS4_COMMANDS_TEST

static int dc_test_failures;

static void dc_test_assert(int cond, const char *expr, const char *file, int line) {
    if (cond) return;
    fprintf(stderr, "%s:%d: assertion failed: %s\n", file, line, expr);
    dc_test_failures++;
}
#define DC_TEST_ASSERT(expr) dc_test_assert((expr), #expr, __FILE__, __LINE__)

/* ---- self-contained fixture helpers (independent of module internals) ---- */

static char *dc_test_join(const char *dir, const char *name) {
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

static char *dc_test_strdup(const char *s) {
    size_t n = strlen(s);
    char *p = malloc(n + 1);
    if (p) memcpy(p, s, n + 1);
    return p;
}

static void dc_test_mkdir_p(const char *path) {
    char *tmp = dc_test_strdup(path);
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

static void dc_test_write_file(const char *path, const char *content) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return;
    fwrite(content, 1, strlen(content), fp);
    fclose(fp);
}

static void dc_test_rmtree(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return;
    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        if (d) {
            struct dirent *de;
            while ((de = readdir(d)) != NULL) {
                if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
                char *child = dc_test_join(path, de->d_name);
                if (child) {
                    dc_test_rmtree(child);
                    free(child);
                }
            }
            closedir(d);
        }
        rmdir(path);
    } else {
        unlink(path);
    }
}

static void dc_test_setenv_home(const char *value, char **saved_out) {
    const char *cur = getenv("HOME");
    *saved_out = cur ? dc_test_strdup(cur) : NULL;
    if (value) setenv("HOME", value, 1);
    else unsetenv("HOME");
}

static void dc_test_restore_home(char *saved) {
    if (saved) {
        setenv("HOME", saved, 1);
        free(saved);
    } else {
        unsetenv("HOME");
    }
}

/* ---- test groups ---- */

static void test_scan_project_user_collision(void) {
    char tmpl[] = "/tmp/ds4_commands_scan_test.XXXXXX";
    char *fx = mkdtemp(tmpl);
    DC_TEST_ASSERT(fx != NULL);
    if (!fx) return;

    char *proj = dc_test_join(fx, "proj");
    char *proj_ds4 = dc_test_join(proj, ".ds4");
    char *proj_cmds = dc_test_join(proj_ds4, "commands");
    dc_test_mkdir_p(proj_cmds);
    char *proj_a = dc_test_join(proj_cmds, "a.md");
    dc_test_write_file(proj_a, "Project A body.\n");
    char *proj_b = dc_test_join(proj_cmds, "b.md");
    dc_test_write_file(proj_b, "Project B body.\n");

    char *home = dc_test_join(fx, "home");
    char *home_ds4 = dc_test_join(home, ".ds4");
    char *home_cmds = dc_test_join(home_ds4, "commands");
    dc_test_mkdir_p(home_cmds);
    char *home_b = dc_test_join(home_cmds, "b.md");
    dc_test_write_file(home_b, "User B body.\n");
    char *home_c = dc_test_join(home_cmds, "c.md");
    dc_test_write_file(home_c, "User C body.\n");

    char *saved_home;
    dc_test_setenv_home(home, &saved_home);

    ds4_config *cfg = ds4_config_load(proj, NULL, 0);
    DC_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        DC_TEST_ASSERT(ds4_config_root_count(cfg) == 2);
        char warn[512] = {0};
        ds4_command_list list = {0};
        ds4_commands_scan(cfg, &list, warn, sizeof(warn));
        DC_TEST_ASSERT(list.len == 3);

        DC_TEST_ASSERT(ds4_commands_known(&list, "/a"));
        DC_TEST_ASSERT(ds4_commands_known(&list, "/b"));
        DC_TEST_ASSERT(ds4_commands_known(&list, "/c"));

        char *expanded_b = ds4_commands_expand(&list, "/b", NULL);
        DC_TEST_ASSERT(expanded_b != NULL);
        if (expanded_b) {
            DC_TEST_ASSERT(strcmp(expanded_b, "Project B body.\n") == 0);
            free(expanded_b);
        }
        ds4_commands_list_free(&list);
    }
    ds4_config_free(cfg);

    dc_test_restore_home(saved_home);
    free(proj); free(proj_ds4); free(proj_cmds); free(proj_a); free(proj_b);
    free(home); free(home_ds4); free(home_cmds); free(home_b); free(home_c);
    dc_test_rmtree(fx);
}

static void test_scan_invalid_names(void) {
    char tmpl[] = "/tmp/ds4_commands_invalid_test.XXXXXX";
    char *fx = mkdtemp(tmpl);
    DC_TEST_ASSERT(fx != NULL);
    if (!fx) return;

    char *proj = dc_test_join(fx, "proj");
    char *proj_ds4 = dc_test_join(proj, ".ds4");
    char *cmds = dc_test_join(proj_ds4, "commands");
    dc_test_mkdir_p(cmds);

    char *bad_space = dc_test_join(cmds, "bad name.md");
    dc_test_write_file(bad_space, "x\n");
    char *empty_name = dc_test_join(cmds, ".md");
    dc_test_write_file(empty_name, "x\n");

    char longname[80];
    memset(longname, 'a', 70);
    longname[70] = '\0';
    char longfile[90];
    snprintf(longfile, sizeof(longfile), "%s.md", longname);
    char *bad_long = dc_test_join(cmds, longfile);
    dc_test_write_file(bad_long, "x\n");

    char *good = dc_test_join(cmds, "good.md");
    dc_test_write_file(good, "Valid sibling.\n");

    char *home = dc_test_join(fx, "home");
    dc_test_mkdir_p(home);
    char *saved_home;
    dc_test_setenv_home(home, &saved_home);

    ds4_config *cfg = ds4_config_load(proj, NULL, 0);
    DC_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        char warn[2048] = {0};
        ds4_command_list list = {0};
        ds4_commands_scan(cfg, &list, warn, sizeof(warn));
        DC_TEST_ASSERT(list.len == 1);
        DC_TEST_ASSERT(ds4_commands_known(&list, "/good"));
        DC_TEST_ASSERT(warn[0] != '\0');
        ds4_commands_list_free(&list);
    }
    ds4_config_free(cfg);

    dc_test_restore_home(saved_home);
    free(proj); free(proj_ds4); free(cmds);
    free(bad_space); free(empty_name); free(bad_long); free(good); free(home);
    dc_test_rmtree(fx);
}

static void test_known_matching(void) {
    ds4_command_list list = {0};
    dc_list_push(&list, dc_test_strdup("x"), dc_test_strdup("/nonexistent/x.md"));

    DC_TEST_ASSERT(ds4_commands_known(&list, "/x"));
    DC_TEST_ASSERT(!ds4_commands_known(&list, "/y"));
    DC_TEST_ASSERT(!ds4_commands_known(&list, "x")); /* no leading slash */

    ds4_commands_list_free(&list);
}

static void test_expand_arguments(void) {
    char tmpl[] = "/tmp/ds4_commands_expand_test.XXXXXX";
    char *fx = mkdtemp(tmpl);
    DC_TEST_ASSERT(fx != NULL);
    if (!fx) return;

    char *zero_path = dc_test_join(fx, "zero.md");
    dc_test_write_file(zero_path, "No placeholder here.\n");
    char *one_path = dc_test_join(fx, "one.md");
    dc_test_write_file(one_path, "Do this: $ARGUMENTS\n");
    char *three_path = dc_test_join(fx, "three.md");
    dc_test_write_file(three_path, "$ARGUMENTS-$ARGUMENTS-$ARGUMENTS\n");

    ds4_command_list list = {0};
    dc_list_push(&list, dc_test_strdup("zero"), dc_test_strdup(zero_path));
    dc_list_push(&list, dc_test_strdup("one"), dc_test_strdup(one_path));
    dc_list_push(&list, dc_test_strdup("three"), dc_test_strdup(three_path));

    char *r0 = ds4_commands_expand(&list, "/zero", "ignored");
    DC_TEST_ASSERT(r0 != NULL);
    if (r0) { DC_TEST_ASSERT(strcmp(r0, "No placeholder here.\n") == 0); free(r0); }

    char *r1_null = ds4_commands_expand(&list, "/one", NULL);
    DC_TEST_ASSERT(r1_null != NULL);
    if (r1_null) { DC_TEST_ASSERT(strcmp(r1_null, "Do this: \n") == 0); free(r1_null); }

    const char *special = "\"$-with-a\nnewline";
    char *r1_special = ds4_commands_expand(&list, "/one", special);
    DC_TEST_ASSERT(r1_special != NULL);
    if (r1_special) {
        char expected[128];
        snprintf(expected, sizeof(expected), "Do this: %s\n", special);
        DC_TEST_ASSERT(strcmp(r1_special, expected) == 0);
        free(r1_special);
    }

    /* byte-exact golden */
    char *r3 = ds4_commands_expand(&list, "/three", "Z");
    DC_TEST_ASSERT(r3 != NULL);
    if (r3) { DC_TEST_ASSERT(strcmp(r3, "Z-Z-Z\n") == 0); free(r3); }

    ds4_commands_list_free(&list);
    free(zero_path); free(one_path); free(three_path);
    dc_test_rmtree(fx);
}

static void test_expand_unknown_and_deleted(void) {
    ds4_command_list list = {0};
    DC_TEST_ASSERT(ds4_commands_expand(&list, "/nope", NULL) == NULL);

    char tmpl[] = "/tmp/ds4_commands_deleted_test.XXXXXX";
    char *fx = mkdtemp(tmpl);
    DC_TEST_ASSERT(fx != NULL);
    if (fx) {
        char *path = dc_test_join(fx, "gone.md");
        dc_test_write_file(path, "temporary\n");
        dc_list_push(&list, dc_test_strdup("gone"), dc_test_strdup(path));
        DC_TEST_ASSERT(ds4_commands_known(&list, "/gone"));
        unlink(path);
        char *r = ds4_commands_expand(&list, "/gone", NULL);
        DC_TEST_ASSERT(r == NULL);
        free(path);
        dc_test_rmtree(fx);
    }
    ds4_commands_list_free(&list);
}

int ds4_commands_unit_tests_run(void) {
    test_scan_project_user_collision();
    test_scan_invalid_names();
    test_known_matching();
    test_expand_arguments();
    test_expand_unknown_and_deleted();
    return dc_test_failures;
}
#endif
