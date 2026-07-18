#include "ds4_permissions.h"
#include "ds4_json.h"
#include <fnmatch.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Opt-in confirm gate + allowlist. See ds4_permissions.h for the
 * settings.json schema and subject-extraction rules. This module is a pure,
 * standalone decision engine: no prompting, no I/O beyond settings.json
 * parsing -- all relay/prompting logic lives in ds4_agent.c glue. */

static char *pm_strdup(const char *s) {
    size_t n = strlen(s);
    char *p = malloc(n + 1);
    if (p) memcpy(p, s, n + 1);
    return p;
}

static void pm_warn_append(char *warn, size_t warn_len, const char *ctx, const char *problem) {
    if (!warn || warn_len == 0) return;
    size_t cur = strlen(warn);
    if (cur + 1 >= warn_len) return;
    snprintf(warn + cur, warn_len - cur, "permissions: %s: %s\n", ctx, problem);
}

typedef struct { char *tool; char *pattern; } allow_rule;

struct ds4_permissions {
    char **confirm;
    int confirm_len;
    allow_rule *allow;
    int allow_len;
};

ds4_permissions *ds4_permissions_load(const ds4_config *cfg, char *warn, size_t warn_len) {
    if (warn && warn_len) warn[0] = '\0';
    if (!cfg) return NULL;

    /* Task-2 config merge (ds4_config_get): a "permissions" key present in
     * the project settings.json is used in full, in place of the user one --
     * no deep merge across files, and no merge of the "confirm"/"allow"
     * arrays of two different files. Fetching the key once here is therefore
     * the entire merge story for this module (same precedent as ds4_hooks). */
    const ds4_json_value *perms_v = ds4_config_get(cfg, "permissions");
    if (!perms_v) return NULL;
    if (ds4_json_type_of(perms_v) != DS4_JSON_OBJ) {
        pm_warn_append(warn, warn_len, "permissions", "not an object, skipped");
        return NULL;
    }

    char **confirm = NULL;
    int confirm_len = 0, confirm_cap = 0;
    const ds4_json_value *confirm_v = ds4_json_obj_get(perms_v, "confirm");
    if (confirm_v) {
        if (ds4_json_type_of(confirm_v) != DS4_JSON_ARR) {
            pm_warn_append(warn, warn_len, "confirm", "not an array, skipped");
        } else {
            int n = ds4_json_arr_len(confirm_v);
            for (int i = 0; i < n; i++) {
                const char *s = ds4_json_str(ds4_json_arr_get(confirm_v, i));
                if (!s || !s[0]) {
                    pm_warn_append(warn, warn_len, "confirm", "entry is not a non-empty string, skipped");
                    continue;
                }
                if (confirm_len == confirm_cap) {
                    confirm_cap = confirm_cap ? confirm_cap * 2 : 4;
                    confirm = realloc(confirm, (size_t)confirm_cap * sizeof(*confirm));
                }
                confirm[confirm_len++] = pm_strdup(s);
            }
        }
    }

    /* No gated tools -- an "allow" list with nothing to gate is a no-op, so
     * bail out here without even validating it (mirrors ds4_hooks_load
     * bailing when both PreToolUse/PostToolUse end up empty). This is also
     * the "no permissions key" byte-identical regression lock's other half:
     * a permissions key that names zero confirm entries is just as inert. */
    if (confirm_len == 0) {
        for (int i = 0; i < confirm_len; i++) free(confirm[i]);
        free(confirm);
        return NULL;
    }

    allow_rule *allow = NULL;
    int allow_len = 0, allow_cap = 0;
    const ds4_json_value *allow_v = ds4_json_obj_get(perms_v, "allow");
    if (allow_v) {
        if (ds4_json_type_of(allow_v) != DS4_JSON_ARR) {
            pm_warn_append(warn, warn_len, "allow", "not an array, skipped");
        } else {
            int n = ds4_json_arr_len(allow_v);
            for (int i = 0; i < n; i++) {
                const char *s = ds4_json_str(ds4_json_arr_get(allow_v, i));
                if (!s) {
                    pm_warn_append(warn, warn_len, "allow", "entry is not a string, skipped");
                    continue;
                }
                const char *colon = strchr(s, ':');
                if (!colon) {
                    pm_warn_append(warn, warn_len, "allow", "malformed entry (missing ':'), skipped");
                    continue;
                }
                size_t tool_len = (size_t)(colon - s);
                char *tool = malloc(tool_len + 1);
                if (tool) {
                    memcpy(tool, s, tool_len);
                    tool[tool_len] = '\0';
                }
                char *pattern = pm_strdup(colon + 1);
                if (allow_len == allow_cap) {
                    allow_cap = allow_cap ? allow_cap * 2 : 4;
                    allow = realloc(allow, (size_t)allow_cap * sizeof(*allow));
                }
                allow[allow_len].tool = tool;
                allow[allow_len].pattern = pattern;
                allow_len++;
            }
        }
    }

    ds4_permissions *p = calloc(1, sizeof(*p));
    p->confirm = confirm;
    p->confirm_len = confirm_len;
    p->allow = allow;
    p->allow_len = allow_len;
    return p;
}

void ds4_permissions_free(ds4_permissions *p) {
    if (!p) return;
    for (int i = 0; i < p->confirm_len; i++) free(p->confirm[i]);
    free(p->confirm);
    for (int i = 0; i < p->allow_len; i++) {
        free(p->allow[i].tool);
        free(p->allow[i].pattern);
    }
    free(p->allow);
    free(p);
}

ds4_perm_decision ds4_permissions_check(const ds4_permissions *p,
                                        const char *tool, const char *subject) {
    if (!p) return DS4_PERM_ALLOW;
    const char *tname = tool ? tool : "";

    bool gated = false;
    for (int i = 0; i < p->confirm_len; i++) {
        if (!strcmp(p->confirm[i], tname)) { gated = true; break; }
    }
    if (!gated) return DS4_PERM_ALLOW;

    const char *subj = subject ? subject : "";
    for (int i = 0; i < p->allow_len; i++) {
        if (!p->allow[i].tool || strcmp(p->allow[i].tool, tname) != 0) continue;
        if (fnmatch(p->allow[i].pattern, subj, 0) == 0) return DS4_PERM_ALLOW;
    }
    return DS4_PERM_ASK;
}

#ifdef DS4_PERMISSIONS_TEST

#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>

static int perms_test_failures;

static void perms_test_assert(int cond, const char *expr, const char *file, int line) {
    if (cond) return;
    fprintf(stderr, "%s:%d: assertion failed: %s\n", file, line, expr);
    perms_test_failures++;
}
#define PERMS_TEST_ASSERT(expr) perms_test_assert((expr), #expr, __FILE__, __LINE__)

/* ---- self-contained fixture helpers (independent of module internals, mirrors ds4_hooks_test) ---- */

static char *pmt_join(const char *dir, const char *name) {
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

static void pmt_mkdir_p(const char *path) {
    char *tmp = pm_strdup(path);
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

static void pmt_write_file(const char *path, const char *content) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return;
    fwrite(content, 1, strlen(content), fp);
    fclose(fp);
}

static void pmt_rmtree(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return;
    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        if (d) {
            struct dirent *de;
            while ((de = readdir(d)) != NULL) {
                if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
                char *child = pmt_join(path, de->d_name);
                if (child) { pmt_rmtree(child); free(child); }
            }
            closedir(d);
        }
        rmdir(path);
    } else {
        unlink(path);
    }
}

static void pmt_setenv_home(const char *value, char **saved_out) {
    const char *cur = getenv("HOME");
    *saved_out = cur ? pm_strdup(cur) : NULL;
    if (value) setenv("HOME", value, 1);
    else unsetenv("HOME");
}

static void pmt_restore_home(char *saved) {
    if (saved) { setenv("HOME", saved, 1); free(saved); }
    else unsetenv("HOME");
}

/* Sets up <tmp>/proj/.ds4/settings.json (if proj_json non-NULL) and
 * <tmp>/home/.ds4/settings.json (if user_json non-NULL) under an isolated
 * HOME, and loads the config. Caller frees out_fx/out_home/out_saved_home
 * and the returned ds4_config (via ds4_config_free). */
static ds4_config *pmt_setup(const char *proj_json, const char *user_json,
                             char **out_fx, char **out_home, char **out_saved_home) {
    char tmpl[] = "/tmp/ds4_permissions_test.XXXXXX";
    char *fx = mkdtemp(tmpl);
    PERMS_TEST_ASSERT(fx != NULL);
    if (!fx) return NULL;
    fx = pm_strdup(fx);

    char *proj = pmt_join(fx, "proj");
    char *proj_ds4 = pmt_join(proj, ".ds4");
    pmt_mkdir_p(proj_ds4);
    if (proj_json) {
        char *proj_settings = pmt_join(proj_ds4, "settings.json");
        pmt_write_file(proj_settings, proj_json);
        free(proj_settings);
    }

    char *home = pmt_join(fx, "home");
    char *home_ds4 = pmt_join(home, ".ds4");
    pmt_mkdir_p(home_ds4);
    if (user_json) {
        char *home_settings = pmt_join(home_ds4, "settings.json");
        pmt_write_file(home_settings, user_json);
        free(home_settings);
    }

    char *saved_home;
    pmt_setenv_home(home, &saved_home);

    ds4_config *cfg = ds4_config_load(proj, NULL, 0);

    *out_fx = fx;
    *out_home = home;
    *out_saved_home = saved_home;
    free(proj); free(proj_ds4); free(home_ds4);
    return cfg;
}

static void pmt_teardown(char *fx, char *home, char *saved_home) {
    pmt_restore_home(saved_home);
    free(home);
    pmt_rmtree(fx);
    free(fx);
}

/* ---- test groups (A1-A5) ---- */

static void test_no_permissions_key(void) {
    char *fx, *home, *saved_home;
    ds4_config *cfg = pmt_setup(NULL, NULL, &fx, &home, &saved_home);
    PERMS_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        char warn[256] = {0};
        ds4_permissions *p = ds4_permissions_load(cfg, warn, sizeof(warn));
        PERMS_TEST_ASSERT(p == NULL);
        PERMS_TEST_ASSERT(ds4_permissions_check(p, "bash", "anything") == DS4_PERM_ALLOW);
    }
    PERMS_TEST_ASSERT(ds4_permissions_check(NULL, "bash", "anything") == DS4_PERM_ALLOW);
    ds4_config_free(cfg);
    pmt_teardown(fx, home, saved_home);
}

static void test_confirm_gating(void) {
    char *fx, *home, *saved_home;
    ds4_config *cfg = pmt_setup(
        "{\"permissions\":{\"confirm\":[\"bash\",\"write\"]}}",
        NULL, &fx, &home, &saved_home);
    PERMS_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        char warn[256] = {0};
        ds4_permissions *p = ds4_permissions_load(cfg, warn, sizeof(warn));
        PERMS_TEST_ASSERT(p != NULL);
        if (p) {
            /* Gated, no allow rule at all -> ASK. */
            PERMS_TEST_ASSERT(ds4_permissions_check(p, "bash", "make test") == DS4_PERM_ASK);
            /* Not in confirm -> ALLOW regardless of subject. */
            PERMS_TEST_ASSERT(ds4_permissions_check(p, "edit", "anything") == DS4_PERM_ALLOW);
            ds4_permissions_free(p);
        }
    }
    ds4_config_free(cfg);
    pmt_teardown(fx, home, saved_home);
}

static void test_allow_patterns(void) {
    /* "bash:make *" allows "make test", not "rm -rf /"; "write:*.md" gates paths. */
    {
        char *fx, *home, *saved_home;
        ds4_config *cfg = pmt_setup(
            "{\"permissions\":{\"confirm\":[\"bash\",\"write\"],"
            "\"allow\":[\"bash:make *\",\"write:*.md\"]}}",
            NULL, &fx, &home, &saved_home);
        PERMS_TEST_ASSERT(cfg != NULL);
        if (cfg) {
            char warn[256] = {0};
            ds4_permissions *p = ds4_permissions_load(cfg, warn, sizeof(warn));
            PERMS_TEST_ASSERT(p != NULL);
            if (p) {
                PERMS_TEST_ASSERT(ds4_permissions_check(p, "bash", "make test") == DS4_PERM_ALLOW);
                PERMS_TEST_ASSERT(ds4_permissions_check(p, "bash", "rm -rf /") == DS4_PERM_ASK);
                PERMS_TEST_ASSERT(ds4_permissions_check(p, "write", "README.md") == DS4_PERM_ALLOW);
                PERMS_TEST_ASSERT(ds4_permissions_check(p, "write", "notes.txt") == DS4_PERM_ASK);
                ds4_permissions_free(p);
            }
        }
        ds4_config_free(cfg);
        pmt_teardown(fx, home, saved_home);
    }
    /* "*"-pattern allows anything for that tool. */
    {
        char *fx, *home, *saved_home;
        ds4_config *cfg = pmt_setup(
            "{\"permissions\":{\"confirm\":[\"bash\"],\"allow\":[\"bash:*\"]}}",
            NULL, &fx, &home, &saved_home);
        PERMS_TEST_ASSERT(cfg != NULL);
        if (cfg) {
            char warn[256] = {0};
            ds4_permissions *p = ds4_permissions_load(cfg, warn, sizeof(warn));
            PERMS_TEST_ASSERT(p != NULL);
            if (p) {
                PERMS_TEST_ASSERT(ds4_permissions_check(p, "bash", "anything at all") == DS4_PERM_ALLOW);
                ds4_permissions_free(p);
            }
        }
        ds4_config_free(cfg);
        pmt_teardown(fx, home, saved_home);
    }
    /* Multiple rules for the same tool: any match wins. */
    {
        char *fx, *home, *saved_home;
        ds4_config *cfg = pmt_setup(
            "{\"permissions\":{\"confirm\":[\"bash\"],"
            "\"allow\":[\"bash:foo\",\"bash:make *\"]}}",
            NULL, &fx, &home, &saved_home);
        PERMS_TEST_ASSERT(cfg != NULL);
        if (cfg) {
            char warn[256] = {0};
            ds4_permissions *p = ds4_permissions_load(cfg, warn, sizeof(warn));
            PERMS_TEST_ASSERT(p != NULL);
            if (p) {
                PERMS_TEST_ASSERT(ds4_permissions_check(p, "bash", "make test") == DS4_PERM_ALLOW);
                ds4_permissions_free(p);
            }
        }
        ds4_config_free(cfg);
        pmt_teardown(fx, home, saved_home);
    }
    /* Malformed entry (no colon) is skipped with a warning; siblings still work. */
    {
        char *fx, *home, *saved_home;
        ds4_config *cfg = pmt_setup(
            "{\"permissions\":{\"confirm\":[\"bash\",\"write\"],"
            "\"allow\":[\"bash:make *\",\"no-colon-here\",\"write:*.md\"]}}",
            NULL, &fx, &home, &saved_home);
        PERMS_TEST_ASSERT(cfg != NULL);
        if (cfg) {
            char warn[512] = {0};
            ds4_permissions *p = ds4_permissions_load(cfg, warn, sizeof(warn));
            PERMS_TEST_ASSERT(p != NULL);
            PERMS_TEST_ASSERT(warn[0] != '\0');
            if (p) {
                PERMS_TEST_ASSERT(ds4_permissions_check(p, "bash", "make test") == DS4_PERM_ALLOW);
                PERMS_TEST_ASSERT(ds4_permissions_check(p, "write", "x.md") == DS4_PERM_ALLOW);
                ds4_permissions_free(p);
            }
        }
        ds4_config_free(cfg);
        pmt_teardown(fx, home, saved_home);
    }
}

static void test_empty_subject(void) {
    /* "*" matches "" -> ALLOW; "make *" does not match "" -> ASK. */
    char *fx, *home, *saved_home;
    ds4_config *cfg = pmt_setup(
        "{\"permissions\":{\"confirm\":[\"bash\",\"skill\"],"
        "\"allow\":[\"bash:*\",\"skill:make *\"]}}",
        NULL, &fx, &home, &saved_home);
    PERMS_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        char warn[256] = {0};
        ds4_permissions *p = ds4_permissions_load(cfg, warn, sizeof(warn));
        PERMS_TEST_ASSERT(p != NULL);
        if (p) {
            PERMS_TEST_ASSERT(ds4_permissions_check(p, "bash", "") == DS4_PERM_ALLOW);
            PERMS_TEST_ASSERT(ds4_permissions_check(p, "skill", "") == DS4_PERM_ASK);
            PERMS_TEST_ASSERT(ds4_permissions_check(p, "skill", NULL) == DS4_PERM_ASK);
            ds4_permissions_free(p);
        }
    }
    ds4_config_free(cfg);
    pmt_teardown(fx, home, saved_home);
}

static void test_wholesale_override(void) {
    /* Project gates "bash" only; user gates "write" only (no allow at all).
     * If the merge were deep (combining confirm arrays), "write" would also
     * end up gated here and ASK; wholesale project-over-user means "write"
     * never entered the merged confirm list at all, so it must stay ALLOW. */
    char *fx, *home, *saved_home;
    ds4_config *cfg = pmt_setup(
        "{\"permissions\":{\"confirm\":[\"bash\"]}}",
        "{\"permissions\":{\"confirm\":[\"write\"]}}",
        &fx, &home, &saved_home);
    PERMS_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        char warn[256] = {0};
        ds4_permissions *p = ds4_permissions_load(cfg, warn, sizeof(warn));
        PERMS_TEST_ASSERT(p != NULL);
        if (p) {
            PERMS_TEST_ASSERT(ds4_permissions_check(p, "bash", "anything") == DS4_PERM_ASK);
            PERMS_TEST_ASSERT(ds4_permissions_check(p, "write", "anything") == DS4_PERM_ALLOW);
            ds4_permissions_free(p);
        }
    }
    ds4_config_free(cfg);
    pmt_teardown(fx, home, saved_home);
}

int ds4_permissions_unit_tests_run(void) {
    test_no_permissions_key();
    test_confirm_gating();
    test_allow_patterns();
    test_empty_subject();
    test_wholesale_override();
    return perms_test_failures;
}

#endif
