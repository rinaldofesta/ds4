#include "ds4_config.h"
#include <ctype.h>
#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* .ds4 discovery + settings load/merge. No dependencies beyond libc and
 * ds4_json. See ds4_config.h for the contract.
 *
 * Directory conventions:
 *  - project root: nearest ancestor of the start dir containing a .ds4
 *    directory or a .git entry (directory or file -- worktrees use a .git
 *    file). Search walks up to the filesystem root; first hit wins.
 *  - user dir: ~/.ds4 via $HOME; NULL if HOME is unset/empty.
 *  - settings: <project-root>/.ds4/settings.json and ~/.ds4/settings.json,
 *    both optional. Merged view: project wins per top-level key (no deep
 *    merge in V1). */

#define DS4_CONFIG_MAX_SETTINGS_SIZE (1u << 20) /* 1 MiB */
#define DS4_CONFIG_MAX_WALK_LEVELS 64

/* One search root. Base roots (project_ds4_dir, user_ds4_dir) are aliased in
 * here -- dir points at the same allocation as the corresponding ds4_config
 * field, not a copy, so ds4_config_root_at(c, i) stays pointer-identical to
 * ds4_config_project_ds4_dir(c)/ds4_config_user_ds4_dir(c) for those indices
 * (existing callers/tests rely on that identity). Plugin roots own their dir
 * and plugin_name allocations. */
typedef struct {
    char *dir;
    char *plugin_name; /* NULL for a base root */
    bool dir_owned;
} ds4_config_root_entry;

struct ds4_config {
    char *project_root;    /* NULL if none */
    char *project_ds4_dir; /* "<root>/.ds4", NULL if no root */
    char *user_ds4_dir;    /* "<home>/.ds4", NULL if no HOME */
    char *memory_path;     /* discovered AGENTS.md/DS4.md, NULL if neither */
    ds4_json_value *project_settings; /* NULL if absent/malformed/no root */
    ds4_json_value *user_settings;    /* NULL if absent/malformed/no HOME */
    ds4_config_root_entry *roots;
    int root_count, root_cap;
};

static char *cfg_strdup(const char *s) {
    size_t n = strlen(s);
    char *p = malloc(n + 1);
    if (p) memcpy(p, s, n + 1);
    return p;
}

/* Simple static join, deliberately not depending on ds4_kvstore_path_join so
 * this module stays standalone-compilable for its test binary. */
static char *cfg_join(const char *dir, const char *name) {
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

static void cfg_warn_append(char *warn, size_t warn_len, const char *path, const char *problem) {
    if (!warn || warn_len == 0) return;
    size_t cur = strlen(warn);
    if (cur + 1 >= warn_len) return; /* no room left */
    snprintf(warn + cur, warn_len - cur, "config: %s: %s\n", path, problem);
}

static int cfg_is_dir(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static int cfg_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

/* Resolves symlinks (e.g. /tmp -> /private/tmp on macOS, or a symlinked
 * worktree) once up front so the subsequent walk is plain string surgery. */
static char *cfg_realpath_or_copy(const char *path) {
    char buf[PATH_MAX];
    if (realpath(path, buf)) return cfg_strdup(buf);
    return cfg_strdup(path);
}

/* path is an absolute, realpath-normalized dir with no trailing slash
 * (except "/" itself). Returns the parent, or NULL once at "/". */
static char *cfg_parent(const char *path) {
    if (strcmp(path, "/") == 0) return NULL;
    const char *slash = strrchr(path, '/');
    if (!slash) return NULL;
    size_t len = (slash == path) ? 1 : (size_t)(slash - path);
    char *out = malloc(len + 1);
    if (!out) return NULL;
    memcpy(out, path, len);
    out[len] = '\0';
    return out;
}

/* Walks from start_dir upward; first directory containing a .ds4 dir or a
 * .git entry (dir or file) wins. Returns a malloc'd absolute path, or NULL
 * if no marker was found within the walk guard. */
static char *cfg_find_project_root(const char *start_dir) {
    char *cur = cfg_realpath_or_copy(start_dir);
    if (!cur) return NULL;

    for (int level = 0; level < DS4_CONFIG_MAX_WALK_LEVELS; level++) {
        char *ds4_dir = cfg_join(cur, ".ds4");
        char *git_entry = cfg_join(cur, ".git");
        int hit = (ds4_dir && cfg_is_dir(ds4_dir)) || (git_entry && cfg_exists(git_entry));
        free(ds4_dir);
        free(git_entry);
        if (hit) return cur;

        char *parent = cfg_parent(cur);
        if (!parent || strcmp(parent, cur) == 0) {
            free(parent);
            break;
        }
        free(cur);
        cur = parent;
    }
    free(cur);
    return NULL;
}

/* Walks from start_dir upward exactly like cfg_find_project_root, but looks
 * for a project memory file instead of a .ds4/.git marker, and is otherwise
 * unrelated to it -- a memory file is discovered whether or not a project
 * root exists. At each level, AGENTS.md is checked first, then DS4.md; the
 * first hit (at the nearest level) wins, so a nearer DS4.md beats a farther
 * AGENTS.md, but AGENTS.md beats DS4.md within the same level. Same 64-level
 * guard. Returns a malloc'd absolute path, or NULL if neither name was found
 * within the walk guard. */
static char *cfg_find_memory_path(const char *start_dir) {
    char *cur = cfg_realpath_or_copy(start_dir);
    if (!cur) return NULL;

    for (int level = 0; level < DS4_CONFIG_MAX_WALK_LEVELS; level++) {
        char *agents_path = cfg_join(cur, "AGENTS.md");
        if (agents_path && cfg_exists(agents_path)) {
            free(cur);
            return agents_path;
        }
        free(agents_path);

        char *ds4_md_path = cfg_join(cur, "DS4.md");
        if (ds4_md_path && cfg_exists(ds4_md_path)) {
            free(cur);
            return ds4_md_path;
        }
        free(ds4_md_path);

        char *parent = cfg_parent(cur);
        if (!parent || strcmp(parent, cur) == 0) {
            free(parent);
            break;
        }
        free(cur);
        cur = parent;
    }
    free(cur);
    return NULL;
}

/* Reads <path> as a capped (1 MiB) blob: malloc'd, NUL-terminated. Missing
 * file is not an error (returns NULL silently). Anything else wrong (not a
 * regular file, too big, unreadable, OOM) is fail-open: skip and append a
 * warning. No parsing -- generic byte read shared by cfg_load_settings
 * (which parses the result as JSON) and, via ds4_config_read_capped_file,
 * by callers outside this module (today: the agent's project memory load). */
static char *cfg_read_capped_file(const char *path, char *warn, size_t warn_len) {
    struct stat st;
    if (stat(path, &st) != 0) return NULL; /* missing is not an error */

    if (!S_ISREG(st.st_mode)) {
        cfg_warn_append(warn, warn_len, path, "not a regular file, skipped");
        return NULL;
    }
    if (st.st_size < 0 || (size_t)st.st_size > DS4_CONFIG_MAX_SETTINGS_SIZE) {
        cfg_warn_append(warn, warn_len, path, "exceeds 1 MiB, skipped");
        return NULL;
    }

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        cfg_warn_append(warn, warn_len, path, "could not open, skipped");
        return NULL;
    }

    size_t cap = (size_t)st.st_size + 1;
    char *buf = malloc(cap);
    if (!buf) {
        fclose(fp);
        cfg_warn_append(warn, warn_len, path, "out of memory, skipped");
        return NULL;
    }
    size_t n = fread(buf, 1, (size_t)st.st_size, fp);
    fclose(fp);
    buf[n] = '\0';
    return buf;
}

/* Reads and parses <path> as a settings.json object. Missing file is not an
 * error (returns NULL silently). Anything else wrong (too big, unreadable,
 * malformed, non-object root) is fail-open: skip and append a warning. */
static ds4_json_value *cfg_load_settings(const char *path, char *warn, size_t warn_len) {
    char *buf = cfg_read_capped_file(path, warn, warn_len);
    if (!buf) return NULL;

    char err[128];
    ds4_json_value *v = ds4_json_parse(buf, err, sizeof(err));
    free(buf);

    if (!v) {
        cfg_warn_append(warn, warn_len, path, err[0] ? err : "malformed JSON, skipped");
        return NULL;
    }
    if (ds4_json_type_of(v) != DS4_JSON_OBJ) {
        cfg_warn_append(warn, warn_len, path, "root is not an object, skipped");
        ds4_json_free(v);
        return NULL;
    }
    return v;
}

/* Appends one search root entry. dir_owned marks whether ds4_config_free
 * must free(dir) itself (plugin roots) or leave it alone (base roots, which
 * alias project_ds4_dir/user_ds4_dir). plugin_name is always owned when
 * non-NULL. Returns false (and leaves *c untouched otherwise) only on
 * allocation failure. */
static bool cfg_root_push(ds4_config *c, char *dir, bool dir_owned, char *plugin_name) {
    if (c->root_count == c->root_cap) {
        int newcap = c->root_cap ? c->root_cap * 2 : 4;
        ds4_config_root_entry *nv = realloc(c->roots, (size_t)newcap * sizeof(*nv));
        if (!nv) return false;
        c->roots = nv;
        c->root_cap = newcap;
    }
    c->roots[c->root_count].dir = dir;
    c->roots[c->root_count].dir_owned = dir_owned;
    c->roots[c->root_count].plugin_name = plugin_name;
    c->root_count++;
    return true;
}

/* name must match [A-Za-z0-9][A-Za-z0-9_-]{0,63} -- same rule as skill and
 * command names (ds4_skills.c/ds4_commands.c), since a plugin name is really
 * just one more directory-name-derived identifier. */
static bool cfg_valid_plugin_name(const char *s) {
    size_t n = strlen(s);
    if (n < 1 || n > 64) return false;
    if (!isalnum((unsigned char)s[0])) return false;
    for (size_t i = 1; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!(isalnum(c) || c == '_' || c == '-')) return false;
    }
    return true;
}

typedef struct { char *name; char *dir; } cfg_plugin_entry;

static int cfg_plugin_cmp_name(const void *a, const void *b) {
    const cfg_plugin_entry *pa = (const cfg_plugin_entry *)a;
    const cfg_plugin_entry *pb = (const cfg_plugin_entry *)b;
    return strcmp(pa->name, pb->name);
}

/* Enumerates the directory entries of <base_ds4_dir>/plugins/ (directories
 * only, symlinks to a directory count), sorted by strcmp(name) for
 * determinism -- readdir()
 * order is not stable across filesystems/runs (same rationale as the
 * ds4_skills per-root sort). A missing plugins/ dir is not an error (silent,
 * out/out_len left at NULL/0). An entry that is not a directory is
 * silently skipped (mirrors how skills/commands treat a stray file); an
 * entry that IS a directory but fails the name pattern is skipped with a
 * warning. On return, *out is a malloc'd array (caller frees the array and,
 * for every entry, .name and .dir -- ownership of both is handed to the
 * caller, typically straight into the config's root list). */
static void cfg_discover_plugins(const char *base_ds4_dir, cfg_plugin_entry **out, int *out_len,
                                 char *warn, size_t warn_len) {
    *out = NULL;
    *out_len = 0;

    char *plugins_dir = cfg_join(base_ds4_dir, "plugins");
    if (!plugins_dir) return;

    DIR *d = opendir(plugins_dir);
    if (!d) {
        free(plugins_dir);
        return; /* no plugins/ dir at all: not an error */
    }

    cfg_plugin_entry *v = NULL;
    int len = 0, cap = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;

        char *entry_path = cfg_join(plugins_dir, de->d_name);
        if (!entry_path) continue;
        if (!cfg_is_dir(entry_path)) {
            free(entry_path);
            continue;
        }
        if (!cfg_valid_plugin_name(de->d_name)) {
            cfg_warn_append(warn, warn_len, entry_path, "invalid plugin name, skipped");
            free(entry_path);
            continue;
        }

        if (len == cap) {
            cap = cap ? cap * 2 : 4;
            v = realloc(v, (size_t)cap * sizeof(v[0]));
        }
        v[len].name = cfg_strdup(de->d_name);
        v[len].dir = entry_path;
        len++;
    }
    closedir(d);
    free(plugins_dir);

    if (len > 1) qsort(v, (size_t)len, sizeof(v[0]), cfg_plugin_cmp_name);

    *out = v;
    *out_len = len;
}

/* Pushes a base root (if present) followed by its sorted plugin roots.
 * base_dir/dir_owned=false is the ds4_config_root_at pointer-identity
 * contract described on ds4_config_root_entry; plugin roots are owned. */
static void cfg_push_base_and_plugins(ds4_config *c, char *base_dir, char *warn, size_t warn_len) {
    if (!base_dir) return;
    cfg_root_push(c, base_dir, false, NULL);

    cfg_plugin_entry *plugins = NULL;
    int nplugins = 0;
    cfg_discover_plugins(base_dir, &plugins, &nplugins, warn, warn_len);
    for (int i = 0; i < nplugins; i++)
        cfg_root_push(c, plugins[i].dir, true, plugins[i].name);
    free(plugins); /* ownership of .dir/.name moved into c->roots above */
}

ds4_config *ds4_config_load(const char *start_dir, char *warn, size_t warn_len) {
    if (warn && warn_len) warn[0] = '\0';

    ds4_config *c = calloc(1, sizeof(*c));
    if (!c) return NULL;

    char cwd_buf[PATH_MAX];
    const char *effective_start = start_dir;
    if (!effective_start) effective_start = getcwd(cwd_buf, sizeof(cwd_buf)) ? cwd_buf : ".";

    /* Independent of project-root discovery: a memory file is found whether
     * or not a .ds4 dir or .git entry exists anywhere in the walk. */
    c->memory_path = cfg_find_memory_path(effective_start);

    c->project_root = cfg_find_project_root(effective_start);
    if (c->project_root) {
        c->project_ds4_dir = cfg_join(c->project_root, ".ds4");
        if (!c->project_ds4_dir) {
            ds4_config_free(c);
            return NULL;
        }
    }

    const char *home = getenv("HOME");
    if (home && home[0]) {
        c->user_ds4_dir = cfg_join(home, ".ds4");
        if (!c->user_ds4_dir) {
            ds4_config_free(c);
            return NULL;
        }
    }

    if (c->project_ds4_dir) {
        char *settings_path = cfg_join(c->project_ds4_dir, "settings.json");
        if (!settings_path) {
            ds4_config_free(c);
            return NULL;
        }
        c->project_settings = cfg_load_settings(settings_path, warn, warn_len);
        free(settings_path);
    }
    if (c->user_ds4_dir) {
        char *settings_path = cfg_join(c->user_ds4_dir, "settings.json");
        if (!settings_path) {
            ds4_config_free(c);
            return NULL;
        }
        c->user_settings = cfg_load_settings(settings_path, warn, warn_len);
        free(settings_path);
    }

    /* Final root order: project base, project plugins (sorted), user base,
     * user plugins (sorted) -- see ds4_config.h. With no plugins/ dir
     * anywhere this produces exactly the pre-plugin two-root list, and
     * ds4_config_root_at keeps returning the base dirs by the same pointer
     * (cfg_push_base_and_plugins passes dir_owned=false for them). */
    cfg_push_base_and_plugins(c, c->project_ds4_dir, warn, warn_len);
    cfg_push_base_and_plugins(c, c->user_ds4_dir, warn, warn_len);

    return c;
}

void ds4_config_free(ds4_config *c) {
    if (!c) return;
    free(c->project_root);
    free(c->project_ds4_dir);
    free(c->user_ds4_dir);
    free(c->memory_path);
    ds4_json_free(c->project_settings);
    ds4_json_free(c->user_settings);
    for (int i = 0; i < c->root_count; i++) {
        if (c->roots[i].dir_owned) free(c->roots[i].dir);
        free(c->roots[i].plugin_name);
    }
    free(c->roots);
    free(c);
}

const char *ds4_config_project_root(const ds4_config *c) {
    return c ? c->project_root : NULL;
}

const char *ds4_config_project_ds4_dir(const ds4_config *c) {
    return c ? c->project_ds4_dir : NULL;
}

const char *ds4_config_user_ds4_dir(const ds4_config *c) {
    return c ? c->user_ds4_dir : NULL;
}

const char *ds4_config_memory_path(const ds4_config *c) {
    return c ? c->memory_path : NULL;
}

char *ds4_config_read_capped_file(const char *path, char *warn, size_t warn_len) {
    if (!path) return NULL;
    return cfg_read_capped_file(path, warn, warn_len);
}

const ds4_json_value *ds4_config_get(const ds4_config *c, const char *key) {
    if (!c || !key) return NULL;
    const ds4_json_value *v = ds4_json_obj_get(c->project_settings, key);
    if (v) return v;
    return ds4_json_obj_get(c->user_settings, key);
}

int ds4_config_root_count(const ds4_config *c) {
    return c ? c->root_count : 0;
}

const char *ds4_config_root_at(const ds4_config *c, int i) {
    if (!c || i < 0 || i >= c->root_count) return NULL;
    return c->roots[i].dir;
}

bool ds4_config_root_is_plugin(const ds4_config *c, int i) {
    if (!c || i < 0 || i >= c->root_count) return false;
    return c->roots[i].plugin_name != NULL;
}

const char *ds4_config_root_plugin_name(const ds4_config *c, int i) {
    if (!c || i < 0 || i >= c->root_count) return NULL;
    return c->roots[i].plugin_name;
}

#ifdef DS4_CONFIG_TEST

static int cfg_test_failures;

static void cfg_test_assert(int cond, const char *expr, const char *file, int line) {
    if (cond) return;
    fprintf(stderr, "%s:%d: assertion failed: %s\n", file, line, expr);
    cfg_test_failures++;
}
#define CFG_TEST_ASSERT(expr) cfg_test_assert((expr), #expr, __FILE__, __LINE__)

/* ---- self-contained fixture helpers (independent of module internals, so
 * the test file itself never has to change between RED and GREEN) ---- */

static char *cfg_test_join(const char *dir, const char *name) {
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

static char *cfg_test_strdup(const char *s) {
    size_t n = strlen(s);
    char *p = malloc(n + 1);
    if (p) memcpy(p, s, n + 1);
    return p;
}

static void cfg_test_mkdir_p(const char *path) {
    char *tmp = cfg_test_strdup(path);
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

static void cfg_test_write_file(const char *path, const char *content) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return;
    fwrite(content, 1, strlen(content), fp);
    fclose(fp);
}

static void cfg_test_rmtree(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return;
    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        if (d) {
            struct dirent *de;
            while ((de = readdir(d)) != NULL) {
                if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
                char *child = cfg_test_join(path, de->d_name);
                if (child) {
                    cfg_test_rmtree(child);
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

static void cfg_test_setenv_home(const char *value, char **saved_out) {
    const char *cur = getenv("HOME");
    *saved_out = cur ? cfg_test_strdup(cur) : NULL;
    if (value) setenv("HOME", value, 1);
    else unsetenv("HOME");
}

static void cfg_test_restore_home(char *saved) {
    if (saved) {
        setenv("HOME", saved, 1);
        free(saved);
    } else {
        unsetenv("HOME");
    }
}

/* ---- test groups ---- */

static void test_root_discovery(void) {
    char tmpl[] = "/tmp/ds4_cfg_root_test.XXXXXX";
    char *fx = mkdtemp(tmpl);
    CFG_TEST_ASSERT(fx != NULL);
    if (!fx) return;

    /* .ds4 directory marker, start 3 levels below */
    char *proj_a = cfg_test_join(fx, "projA");
    char *proj_a_ds4 = cfg_test_join(proj_a, ".ds4");
    char *start_a = cfg_test_join(proj_a, "x/y/z");
    cfg_test_mkdir_p(proj_a_ds4);
    cfg_test_mkdir_p(start_a);
    char resolved_a[PATH_MAX];
    CFG_TEST_ASSERT(realpath(proj_a, resolved_a) != NULL);

    ds4_config *c = ds4_config_load(start_a, NULL, 0);
    CFG_TEST_ASSERT(c != NULL);
    if (c) {
        const char *root = ds4_config_project_root(c);
        CFG_TEST_ASSERT(root != NULL);
        if (root) CFG_TEST_ASSERT(strcmp(root, resolved_a) == 0);
    }
    ds4_config_free(c);

    /* .git directory marker */
    char *proj_b = cfg_test_join(fx, "projB");
    char *proj_b_git = cfg_test_join(proj_b, ".git");
    char *start_b = cfg_test_join(proj_b, "x/y/z");
    cfg_test_mkdir_p(proj_b_git);
    cfg_test_mkdir_p(start_b);
    char resolved_b[PATH_MAX];
    CFG_TEST_ASSERT(realpath(proj_b, resolved_b) != NULL);

    c = ds4_config_load(start_b, NULL, 0);
    CFG_TEST_ASSERT(c != NULL);
    if (c) {
        const char *root = ds4_config_project_root(c);
        CFG_TEST_ASSERT(root != NULL);
        if (root) CFG_TEST_ASSERT(strcmp(root, resolved_b) == 0);
    }
    ds4_config_free(c);

    /* .git as a plain FILE (worktree case) */
    char *proj_c = cfg_test_join(fx, "projC");
    char *start_c = cfg_test_join(proj_c, "x/y/z");
    cfg_test_mkdir_p(start_c);
    char *proj_c_git = cfg_test_join(proj_c, ".git");
    cfg_test_write_file(proj_c_git, "gitdir: ../somewhere\n");
    char resolved_c[PATH_MAX];
    CFG_TEST_ASSERT(realpath(proj_c, resolved_c) != NULL);

    c = ds4_config_load(start_c, NULL, 0);
    CFG_TEST_ASSERT(c != NULL);
    if (c) {
        const char *root = ds4_config_project_root(c);
        CFG_TEST_ASSERT(root != NULL);
        if (root) CFG_TEST_ASSERT(strcmp(root, resolved_c) == 0);
    }
    ds4_config_free(c);

    /* nested project: inner .ds4 shadows outer, from inner start */
    char *outer = cfg_test_join(fx, "outer");
    char *outer_ds4 = cfg_test_join(outer, ".ds4");
    char *inner = cfg_test_join(outer, "inner");
    char *inner_ds4 = cfg_test_join(inner, ".ds4");
    char *start_inner = cfg_test_join(inner, "p/q");
    cfg_test_mkdir_p(outer_ds4);
    cfg_test_mkdir_p(inner_ds4);
    cfg_test_mkdir_p(start_inner);
    char resolved_inner[PATH_MAX];
    CFG_TEST_ASSERT(realpath(inner, resolved_inner) != NULL);

    c = ds4_config_load(start_inner, NULL, 0);
    CFG_TEST_ASSERT(c != NULL);
    if (c) {
        const char *root = ds4_config_project_root(c);
        CFG_TEST_ASSERT(root != NULL);
        if (root) CFG_TEST_ASSERT(strcmp(root, resolved_inner) == 0);
    }
    ds4_config_free(c);

    free(proj_a); free(proj_a_ds4); free(start_a);
    free(proj_b); free(proj_b_git); free(start_b);
    free(proj_c); free(start_c); free(proj_c_git);
    free(outer); free(outer_ds4); free(inner); free(inner_ds4); free(start_inner);
    cfg_test_rmtree(fx);
}

static void test_no_marker_project_root(void) {
    char tmpl[] = "/tmp/ds4_cfg_nomark_test.XXXXXX";
    char *fx = mkdtemp(tmpl);
    CFG_TEST_ASSERT(fx != NULL);
    if (!fx) return;

    char *home = cfg_test_join(fx, "home");
    char *start = cfg_test_join(fx, "a/b/c");
    cfg_test_mkdir_p(home);
    cfg_test_mkdir_p(start);

    char *saved_home;
    cfg_test_setenv_home(home, &saved_home);

    ds4_config *c = ds4_config_load(start, NULL, 0);
    CFG_TEST_ASSERT(c != NULL);
    if (c) {
        /* Deterministic regardless of what's above the fixture: HOME is set,
         * so the user side must always resolve. Only the project-root walk
         * is realpath-normalized, so this must match $HOME verbatim. */
        const char *udir = ds4_config_user_ds4_dir(c);
        CFG_TEST_ASSERT(udir != NULL);
        if (udir) {
            char expected[PATH_MAX + 8];
            snprintf(expected, sizeof(expected), "%s/.ds4", home);
            CFG_TEST_ASSERT(strcmp(udir, expected) == 0);
        }
        /* Project side: no marker exists inside the fixture, but walking up
         * could in principle escape into the real filesystem, so only assert
         * the accessor invariant rather than a specific NULL/non-NULL value. */
        const char *root = ds4_config_project_root(c);
        const char *pdir = ds4_config_project_ds4_dir(c);
        CFG_TEST_ASSERT((root == NULL) == (pdir == NULL));
    }
    ds4_config_free(c);

    cfg_test_restore_home(saved_home);
    free(home); free(start);
    cfg_test_rmtree(fx);
}

static void test_settings_merge(void) {
    char tmpl[] = "/tmp/ds4_cfg_merge_test.XXXXXX";
    char *fx = mkdtemp(tmpl);
    CFG_TEST_ASSERT(fx != NULL);
    if (!fx) return;

    char *proj = cfg_test_join(fx, "proj");
    char *proj_ds4 = cfg_test_join(proj, ".ds4");
    char *proj_settings = cfg_test_join(proj_ds4, "settings.json");
    cfg_test_mkdir_p(proj_ds4);
    cfg_test_write_file(proj_settings, "{\"a\":1,\"perm\":{\"x\":true}}");

    char *home = cfg_test_join(fx, "home");
    char *home_ds4 = cfg_test_join(home, ".ds4");
    char *home_settings = cfg_test_join(home_ds4, "settings.json");
    cfg_test_mkdir_p(home_ds4);
    cfg_test_write_file(home_settings, "{\"a\":2,\"b\":3}");

    char *saved_home;
    cfg_test_setenv_home(home, &saved_home);

    char warn[256] = {0};
    ds4_config *c = ds4_config_load(proj, warn, sizeof(warn));
    CFG_TEST_ASSERT(c != NULL);
    if (c) {
        CFG_TEST_ASSERT(ds4_json_num(ds4_config_get(c, "a"), -1) == 1.0);
        CFG_TEST_ASSERT(ds4_json_num(ds4_config_get(c, "b"), -1) == 3.0);
        const ds4_json_value *perm = ds4_config_get(c, "perm");
        CFG_TEST_ASSERT(perm != NULL);
        CFG_TEST_ASSERT(ds4_json_bool(ds4_json_obj_get(perm, "x"), false) == true);
        CFG_TEST_ASSERT(ds4_config_get(c, "absent-key") == NULL);
    }
    ds4_config_free(c);

    cfg_test_restore_home(saved_home);
    free(proj); free(proj_ds4); free(proj_settings);
    free(home); free(home_ds4); free(home_settings);
    cfg_test_rmtree(fx);
}

static void test_missing_and_malformed_settings(void) {
    char tmpl[] = "/tmp/ds4_cfg_missing_test.XXXXXX";
    char *fx = mkdtemp(tmpl);
    CFG_TEST_ASSERT(fx != NULL);
    if (!fx) return;

    /* missing settings files entirely -> empty config, empty warn */
    char *proj1 = cfg_test_join(fx, "proj1");
    char *proj1_ds4 = cfg_test_join(proj1, ".ds4");
    cfg_test_mkdir_p(proj1_ds4);

    char *home1 = cfg_test_join(fx, "home1");
    cfg_test_mkdir_p(home1);

    char *saved_home;
    cfg_test_setenv_home(home1, &saved_home);

    char warn[256] = {0};
    ds4_config *c = ds4_config_load(proj1, warn, sizeof(warn));
    CFG_TEST_ASSERT(c != NULL);
    CFG_TEST_ASSERT(warn[0] == '\0');
    if (c) CFG_TEST_ASSERT(ds4_config_get(c, "anything") == NULL);
    ds4_config_free(c);

    /* malformed project settings.json -> skipped fail-open, warn non-empty,
     * user settings still loaded */
    char *proj2 = cfg_test_join(fx, "proj2");
    char *proj2_ds4 = cfg_test_join(proj2, ".ds4");
    char *proj2_settings = cfg_test_join(proj2_ds4, "settings.json");
    cfg_test_mkdir_p(proj2_ds4);
    cfg_test_write_file(proj2_settings, "{ not json");

    char *home2 = cfg_test_join(fx, "home2");
    char *home2_ds4 = cfg_test_join(home2, ".ds4");
    char *home2_settings = cfg_test_join(home2_ds4, "settings.json");
    cfg_test_mkdir_p(home2_ds4);
    cfg_test_write_file(home2_settings, "{\"b\":5}");
    setenv("HOME", home2, 1);

    warn[0] = '\0';
    c = ds4_config_load(proj2, warn, sizeof(warn));
    CFG_TEST_ASSERT(c != NULL);
    CFG_TEST_ASSERT(warn[0] != '\0');
    if (c) {
        CFG_TEST_ASSERT(ds4_config_get(c, "a") == NULL);
        CFG_TEST_ASSERT(ds4_json_num(ds4_config_get(c, "b"), -1) == 5.0);
    }
    ds4_config_free(c);

    cfg_test_restore_home(saved_home);
    free(proj1); free(proj1_ds4); free(home1);
    free(proj2); free(proj2_ds4); free(proj2_settings);
    free(home2); free(home2_ds4); free(home2_settings);
    cfg_test_rmtree(fx);
}

/* This test's fixture has no .ds4/plugins/ anywhere, so it doubles as the
 * "no plugins dir -> byte-identical to pre-plugins root list" lock: root
 * count, pointer identity of the two base roots, and the new is_plugin/
 * plugin_name accessors must all come back exactly as they did before this
 * task (false/NULL for every root). */
static void test_roots_listing(void) {
    char tmpl[] = "/tmp/ds4_cfg_roots_test.XXXXXX";
    char *fx = mkdtemp(tmpl);
    CFG_TEST_ASSERT(fx != NULL);
    if (!fx) return;

    char *proj = cfg_test_join(fx, "proj");
    char *proj_ds4 = cfg_test_join(proj, ".ds4");
    cfg_test_mkdir_p(proj_ds4);

    char *home = cfg_test_join(fx, "home");
    cfg_test_mkdir_p(home);

    char *saved_home;
    cfg_test_setenv_home(home, &saved_home);

    ds4_config *c = ds4_config_load(proj, NULL, 0);
    CFG_TEST_ASSERT(c != NULL);
    if (c) {
        CFG_TEST_ASSERT(ds4_config_root_count(c) == 2);
        const char *r0 = ds4_config_root_at(c, 0);
        const char *r1 = ds4_config_root_at(c, 1);
        CFG_TEST_ASSERT(r0 != NULL && r0 == ds4_config_project_ds4_dir(c));
        CFG_TEST_ASSERT(r1 != NULL && r1 == ds4_config_user_ds4_dir(c));
        CFG_TEST_ASSERT(ds4_config_root_at(c, 2) == NULL);

        CFG_TEST_ASSERT(!ds4_config_root_is_plugin(c, 0));
        CFG_TEST_ASSERT(ds4_config_root_plugin_name(c, 0) == NULL);
        CFG_TEST_ASSERT(!ds4_config_root_is_plugin(c, 1));
        CFG_TEST_ASSERT(ds4_config_root_plugin_name(c, 1) == NULL);
        CFG_TEST_ASSERT(!ds4_config_root_is_plugin(c, 2));
        CFG_TEST_ASSERT(ds4_config_root_plugin_name(c, 2) == NULL);
    }
    ds4_config_free(c);

    unsetenv("HOME");
    c = ds4_config_load(proj, NULL, 0);
    CFG_TEST_ASSERT(c != NULL);
    if (c) {
        CFG_TEST_ASSERT(ds4_config_root_count(c) == 1);
        CFG_TEST_ASSERT(ds4_config_root_at(c, 0) == ds4_config_project_ds4_dir(c));
        CFG_TEST_ASSERT(ds4_config_user_ds4_dir(c) == NULL);
        CFG_TEST_ASSERT(!ds4_config_root_is_plugin(c, 0));
    }
    ds4_config_free(c);

    cfg_test_restore_home(saved_home);
    free(proj); free(proj_ds4); free(home);
    cfg_test_rmtree(fx);
}

/* Root order fixture: project root + 2 project plugins (created out of
 * alpha order on disk) + user root + 1 user plugin -> count 5, exact
 * expected order, is_plugin/plugin_name correct. Also covers an
 * invalid-plugin-name directory (skipped + warned) and a stray non-directory
 * entry under plugins/ (silently ignored, not warned). */
static void test_plugin_root_ordering(void) {
    char tmpl[] = "/tmp/ds4_cfg_plugins_test.XXXXXX";
    char *fx = mkdtemp(tmpl);
    CFG_TEST_ASSERT(fx != NULL);
    if (!fx) return;

    char *proj = cfg_test_join(fx, "proj");
    char *proj_ds4 = cfg_test_join(proj, ".ds4");
    cfg_test_mkdir_p(proj_ds4);

    /* deliberately created zeta before alpha, so the test can't pass just
     * because readdir() happened to return entries in sorted order */
    char *proj_plug_zeta = cfg_test_join(proj_ds4, "plugins/zeta");
    char *proj_plug_alpha = cfg_test_join(proj_ds4, "plugins/alpha");
    cfg_test_mkdir_p(proj_plug_zeta);
    cfg_test_mkdir_p(proj_plug_alpha);

    /* invalid plugin name (space): a real directory, skipped + warned */
    char *proj_plug_bad = cfg_test_join(proj_ds4, "plugins/bad name");
    cfg_test_mkdir_p(proj_plug_bad);

    /* an otherwise validly-named but non-directory entry: silently ignored,
     * mirrors how ds4_skills treats a stray file under skills/ */
    char *proj_plug_file = cfg_test_join(proj_ds4, "plugins/notadir");
    cfg_test_write_file(proj_plug_file, "x");

    char *home = cfg_test_join(fx, "home");
    char *home_ds4 = cfg_test_join(home, ".ds4");
    cfg_test_mkdir_p(home_ds4);
    char *home_plug = cfg_test_join(home_ds4, "plugins/gamma");
    cfg_test_mkdir_p(home_plug);

    char *saved_home;
    cfg_test_setenv_home(home, &saved_home);

    char warn[1024] = {0};
    ds4_config *c = ds4_config_load(proj, warn, sizeof(warn));
    CFG_TEST_ASSERT(c != NULL);
    if (c) {
        CFG_TEST_ASSERT(ds4_config_root_count(c) == 5);
        CFG_TEST_ASSERT(strstr(warn, "invalid plugin name") != NULL);

        const char *r0 = ds4_config_root_at(c, 0);
        CFG_TEST_ASSERT(r0 == ds4_config_project_ds4_dir(c));
        CFG_TEST_ASSERT(!ds4_config_root_is_plugin(c, 0));
        CFG_TEST_ASSERT(ds4_config_root_plugin_name(c, 0) == NULL);

        const char *r1 = ds4_config_root_at(c, 1);
        CFG_TEST_ASSERT(ds4_config_root_is_plugin(c, 1));
        CFG_TEST_ASSERT(r1 != NULL);
        const char *n1 = ds4_config_root_plugin_name(c, 1);
        CFG_TEST_ASSERT(n1 != NULL && strcmp(n1, "alpha") == 0);
        if (r1) {
            char expected[PATH_MAX];
            snprintf(expected, sizeof(expected), "%s/plugins/alpha", ds4_config_project_ds4_dir(c));
            CFG_TEST_ASSERT(strcmp(r1, expected) == 0);
        }

        const char *r2 = ds4_config_root_at(c, 2);
        CFG_TEST_ASSERT(ds4_config_root_is_plugin(c, 2));
        const char *n2 = ds4_config_root_plugin_name(c, 2);
        CFG_TEST_ASSERT(n2 != NULL && strcmp(n2, "zeta") == 0);
        if (r2) {
            char expected[PATH_MAX];
            snprintf(expected, sizeof(expected), "%s/plugins/zeta", ds4_config_project_ds4_dir(c));
            CFG_TEST_ASSERT(strcmp(r2, expected) == 0);
        }

        const char *r3 = ds4_config_root_at(c, 3);
        CFG_TEST_ASSERT(r3 == ds4_config_user_ds4_dir(c));
        CFG_TEST_ASSERT(!ds4_config_root_is_plugin(c, 3));
        CFG_TEST_ASSERT(ds4_config_root_plugin_name(c, 3) == NULL);

        const char *r4 = ds4_config_root_at(c, 4);
        CFG_TEST_ASSERT(ds4_config_root_is_plugin(c, 4));
        const char *n4 = ds4_config_root_plugin_name(c, 4);
        CFG_TEST_ASSERT(n4 != NULL && strcmp(n4, "gamma") == 0);
        if (r4) {
            char expected[PATH_MAX];
            snprintf(expected, sizeof(expected), "%s/plugins/gamma", ds4_config_user_ds4_dir(c));
            CFG_TEST_ASSERT(strcmp(r4, expected) == 0);
        }

        CFG_TEST_ASSERT(ds4_config_root_at(c, 5) == NULL);
        CFG_TEST_ASSERT(!ds4_config_root_is_plugin(c, 5));
        CFG_TEST_ASSERT(ds4_config_root_plugin_name(c, 5) == NULL);
    }
    ds4_config_free(c);

    cfg_test_restore_home(saved_home);
    free(proj); free(proj_ds4); free(proj_plug_zeta); free(proj_plug_alpha);
    free(proj_plug_bad); free(proj_plug_file);
    free(home); free(home_ds4); free(home_plug);
    cfg_test_rmtree(fx);
}

static void test_neither_root_accessors(void) {
    char tmpl[] = "/tmp/ds4_cfg_neither_test.XXXXXX";
    char *fx = mkdtemp(tmpl);
    CFG_TEST_ASSERT(fx != NULL);
    if (!fx) return;

    char *start = cfg_test_join(fx, "solo");
    cfg_test_mkdir_p(start);

    char *saved_home;
    cfg_test_setenv_home(NULL, &saved_home);

    ds4_config *c = ds4_config_load(start, NULL, 0);
    CFG_TEST_ASSERT(c != NULL);
    if (c) {
        CFG_TEST_ASSERT(ds4_config_user_ds4_dir(c) == NULL);
        CFG_TEST_ASSERT(ds4_config_get(c, "totally-made-up-key-zzz") == NULL);
        int expect_count = (ds4_config_project_ds4_dir(c) != NULL) ? 1 : 0;
        CFG_TEST_ASSERT(ds4_config_root_count(c) == expect_count);
        if (expect_count == 0) {
            CFG_TEST_ASSERT(ds4_config_root_at(c, 0) == NULL);
            CFG_TEST_ASSERT(ds4_config_project_root(c) == NULL);
        } else {
            CFG_TEST_ASSERT(ds4_config_root_at(c, 0) == ds4_config_project_ds4_dir(c));
        }
    }
    ds4_config_free(c);

    cfg_test_restore_home(saved_home);
    free(start);
    cfg_test_rmtree(fx);
}

/* ---- project memory discovery (AGENTS.md/DS4.md) ---- */

/* Both files present at the same level: AGENTS.md wins. */
static void test_memory_agents_beats_ds4_same_level(void) {
    char tmpl[] = "/tmp/ds4_cfg_mem_same_test.XXXXXX";
    char *fx = mkdtemp(tmpl);
    CFG_TEST_ASSERT(fx != NULL);
    if (!fx) return;

    char *proj = cfg_test_join(fx, "proj");
    char *agents = cfg_test_join(proj, "AGENTS.md");
    char *ds4md = cfg_test_join(proj, "DS4.md");
    cfg_test_mkdir_p(proj);
    cfg_test_write_file(agents, "agents content\n");
    cfg_test_write_file(ds4md, "ds4 content\n");

    char resolved[PATH_MAX];
    CFG_TEST_ASSERT(realpath(proj, resolved) != NULL);
    char expected[PATH_MAX + 16];
    snprintf(expected, sizeof(expected), "%s/AGENTS.md", resolved);

    ds4_config *c = ds4_config_load(proj, NULL, 0);
    CFG_TEST_ASSERT(c != NULL);
    if (c) {
        const char *mem = ds4_config_memory_path(c);
        CFG_TEST_ASSERT(mem != NULL);
        if (mem) CFG_TEST_ASSERT(strcmp(mem, expected) == 0);
    }
    ds4_config_free(c);

    free(proj); free(agents); free(ds4md);
    cfg_test_rmtree(fx);
}

/* DS4.md at the start level, AGENTS.md two levels up: the nearer DS4.md
 * wins even though AGENTS.md would otherwise take precedence at its own
 * level -- level precedence (nearest wins) outranks the AGENTS.md-over-DS4.md
 * tie-break, which only applies within a single level. */
static void test_memory_nearer_ds4_beats_farther_agents(void) {
    char tmpl[] = "/tmp/ds4_cfg_mem_nearer_test.XXXXXX";
    char *fx = mkdtemp(tmpl);
    CFG_TEST_ASSERT(fx != NULL);
    if (!fx) return;

    char *outer = cfg_test_join(fx, "outer");
    char *outer_agents = cfg_test_join(outer, "AGENTS.md");
    char *inner = cfg_test_join(outer, "inner");
    char *inner_ds4md = cfg_test_join(inner, "DS4.md");
    char *start = cfg_test_join(inner, "x/y");
    cfg_test_mkdir_p(inner);
    cfg_test_write_file(outer_agents, "outer agents\n");
    cfg_test_write_file(inner_ds4md, "inner ds4\n");
    cfg_test_mkdir_p(start);

    char resolved_inner[PATH_MAX];
    CFG_TEST_ASSERT(realpath(inner, resolved_inner) != NULL);
    char expected[PATH_MAX + 16];
    snprintf(expected, sizeof(expected), "%s/DS4.md", resolved_inner);

    ds4_config *c = ds4_config_load(start, NULL, 0);
    CFG_TEST_ASSERT(c != NULL);
    if (c) {
        const char *mem = ds4_config_memory_path(c);
        CFG_TEST_ASSERT(mem != NULL);
        if (mem) CFG_TEST_ASSERT(strcmp(mem, expected) == 0);
    }
    ds4_config_free(c);

    free(outer); free(outer_agents); free(inner); free(inner_ds4md); free(start);
    cfg_test_rmtree(fx);
}

/* Memory discovery is independent of project-root discovery: a fixture with
 * no .ds4 dir and no .git entry anywhere still yields a memory_path, while
 * project_root/project_ds4_dir stay NULL (soft invariant on that pair --
 * same caution as test_no_marker_project_root, since that half of the walk
 * could in principle escape into the real filesystem above the fixture; the
 * memory_path assertion itself is hard since AGENTS.md is placed inside the
 * fixture and is found before the walk ever needs to escape it). */
static void test_memory_independent_of_project_markers(void) {
    char tmpl[] = "/tmp/ds4_cfg_mem_indep_test.XXXXXX";
    char *fx = mkdtemp(tmpl);
    CFG_TEST_ASSERT(fx != NULL);
    if (!fx) return;

    char *proj = cfg_test_join(fx, "proj");
    char *agents = cfg_test_join(proj, "AGENTS.md");
    char *start = cfg_test_join(proj, "a/b");
    cfg_test_mkdir_p(start);
    cfg_test_write_file(agents, "memory without a project root\n");

    char resolved[PATH_MAX];
    CFG_TEST_ASSERT(realpath(proj, resolved) != NULL);
    char expected[PATH_MAX + 16];
    snprintf(expected, sizeof(expected), "%s/AGENTS.md", resolved);

    ds4_config *c = ds4_config_load(start, NULL, 0);
    CFG_TEST_ASSERT(c != NULL);
    if (c) {
        const char *root = ds4_config_project_root(c);
        const char *pdir = ds4_config_project_ds4_dir(c);
        CFG_TEST_ASSERT((root == NULL) == (pdir == NULL));

        const char *mem = ds4_config_memory_path(c);
        CFG_TEST_ASSERT(mem != NULL);
        if (mem) CFG_TEST_ASSERT(strcmp(mem, expected) == 0);
    }
    ds4_config_free(c);

    free(proj); free(agents); free(start);
    cfg_test_rmtree(fx);
}

/* Neither AGENTS.md nor DS4.md exists anywhere inside the fixture. In
 * principle the walk could escape above the fixture into the real
 * filesystem and find either name there (same caution as
 * test_no_marker_project_root); in practice a tmp dir's ancestors up to "/"
 * carry neither, so this locks the common-case guarantee that matters for
 * this task: no memory file anywhere -> memory_path NULL -> the agent's
 * dynamic-context/system-status paths add zero bytes. */
static void test_memory_absent_when_neither_present(void) {
    char tmpl[] = "/tmp/ds4_cfg_mem_absent_test.XXXXXX";
    char *fx = mkdtemp(tmpl);
    CFG_TEST_ASSERT(fx != NULL);
    if (!fx) return;

    char *start = cfg_test_join(fx, "proj/a/b");
    cfg_test_mkdir_p(start);

    ds4_config *c = ds4_config_load(start, NULL, 0);
    CFG_TEST_ASSERT(c != NULL);
    if (c) CFG_TEST_ASSERT(ds4_config_memory_path(c) == NULL);
    ds4_config_free(c);

    free(start);
    cfg_test_rmtree(fx);
}

/* Fixture-boundary caution (Task 2 style): the only marker anywhere in this
 * fixture sits at its top level (proj/DS4.md, with no AGENTS.md competing
 * anywhere), and the start dir is several levels below it. The walk must
 * still find it without ever needing to look outside the fixture, so this
 * assertion carries no escape risk regardless of what the real filesystem
 * above the fixture happens to contain. */
static void test_memory_walk_multiple_levels_bounded_by_fixture(void) {
    char tmpl[] = "/tmp/ds4_cfg_mem_bounded_test.XXXXXX";
    char *fx = mkdtemp(tmpl);
    CFG_TEST_ASSERT(fx != NULL);
    if (!fx) return;

    char *proj = cfg_test_join(fx, "proj");
    char *proj_ds4md = cfg_test_join(proj, "DS4.md");
    char *start = cfg_test_join(proj, "w/x/y/z");
    cfg_test_mkdir_p(start);
    cfg_test_write_file(proj_ds4md, "bounded fixture memory\n");

    char resolved[PATH_MAX];
    CFG_TEST_ASSERT(realpath(proj, resolved) != NULL);
    char expected[PATH_MAX + 16];
    snprintf(expected, sizeof(expected), "%s/DS4.md", resolved);

    ds4_config *c = ds4_config_load(start, NULL, 0);
    CFG_TEST_ASSERT(c != NULL);
    if (c) {
        const char *mem = ds4_config_memory_path(c);
        CFG_TEST_ASSERT(mem != NULL);
        if (mem) CFG_TEST_ASSERT(strcmp(mem, expected) == 0);
    }
    ds4_config_free(c);

    free(proj); free(proj_ds4md); free(start);
    cfg_test_rmtree(fx);
}

int ds4_config_unit_tests_run(void) {
    test_root_discovery();
    test_no_marker_project_root();
    test_settings_merge();
    test_missing_and_malformed_settings();
    test_roots_listing();
    test_neither_root_accessors();
    test_plugin_root_ordering();
    test_memory_agents_beats_ds4_same_level();
    test_memory_nearer_ds4_beats_farther_agents();
    test_memory_independent_of_project_markers();
    test_memory_absent_when_neither_present();
    test_memory_walk_multiple_levels_bounded_by_fixture();
    return cfg_test_failures;
}
#endif
