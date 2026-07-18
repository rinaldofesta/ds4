#include "ds4_skills.h"
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* SKILL.md discovery, frontmatter parsing, and system-prompt catalog
 * rendering. No dependencies beyond libc and ds4_config (for the search
 * roots) / ds4_json (for the catalog string builder). See ds4_skills.h for
 * the contract.
 *
 * Directory convention: for each ds4_config search root (highest precedence
 * first: project .ds4, then user .ds4), scan <root>/skills/<name>/SKILL.md. The
 * physical directory name under skills/ is never trusted for anything but
 * locating the file; the frontmatter `name` field is the only lookup and
 * shadowing key, and first occurrence (highest-precedence root) wins.
 *
 * Frontmatter parsing is a hand-rolled scanner, not a YAML parser -- see
 * ds4_skills_parse_frontmatter for the exact grammar it accepts. */

#define DS4_SKILLS_MAX_FILE_SIZE (1u << 20) /* 1 MiB */
#define DS4_SKILLS_MAX_DESC_BYTES 256

static char *sk_strdup(const char *s) {
    size_t n = strlen(s);
    char *p = malloc(n + 1);
    if (p) memcpy(p, s, n + 1);
    return p;
}

static char *sk_strndup(const char *s, size_t n) {
    char *p = malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n);
    p[n] = '\0';
    return p;
}

/* Deliberately not depending on ds4_kvstore_path_join so this module stays
 * standalone-compilable for its test binary. */
static char *sk_join(const char *dir, const char *name) {
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

static void sk_warn_append(char *warn, size_t warn_len, const char *path, const char *problem) {
    if (!warn || warn_len == 0) return;
    size_t cur = strlen(warn);
    if (cur + 1 >= warn_len) return; /* no room left */
    snprintf(warn + cur, warn_len - cur, "skills: %s: %s\n", path, problem);
}

/* name must match [A-Za-z0-9][A-Za-z0-9_-]{0,63}. */
static bool sk_valid_name(const char *s) {
    size_t n = strlen(s);
    if (n < 1 || n > 64) return false;
    if (!isalnum((unsigned char)s[0])) return false;
    for (size_t i = 1; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!(isalnum(c) || c == '_' || c == '-')) return false;
    }
    return true;
}

static const char *sk_line_end(const char *p) {
    const char *nl = strchr(p, '\n');
    return nl ? nl : p + strlen(p);
}

/* Trims one layer of matching surrounding single/double quotes, then dups. */
static char *sk_dup_value(const char *start, size_t len) {
    if (len >= 2) {
        char q = start[0];
        if ((q == '"' || q == '\'') && start[len - 1] == q) {
            start++;
            len -= 2;
        }
    }
    return sk_strndup(start, len);
}

/* Hand-rolled scanner (not a YAML parser): the file must open with a line
 * that is exactly "---"; frontmatter ends at the next line that is exactly
 * "---" (missing close -> invalid). Each line in between is "key: value"
 * split on the first ": "; unknown keys are ignored, lines without that
 * separator are ignored. Any line with leading whitespace or a "- " list
 * marker invalidates the whole file rather than risk mis-parsing nested
 * YAML. name and description are both required. */
bool ds4_skills_parse_frontmatter(const char *text, char **name, char **description,
                                  const char **body_start) {
    *name = NULL;
    *description = NULL;
    *body_start = NULL;
    if (!text) return false;

    const char *p = text;
    const char *le = sk_line_end(p);
    if (!(le - p == 3 && strncmp(p, "---", 3) == 0)) return false;
    p = (*le == '\n') ? le + 1 : le;

    char *nm = NULL, *desc = NULL;
    bool closed = false;
    while (*p) {
        le = sk_line_end(p);
        size_t linelen = (size_t)(le - p);
        bool has_nl = (*le == '\n');

        if (linelen == 3 && strncmp(p, "---", 3) == 0) {
            closed = true;
            p = has_nl ? le + 1 : le;
            break;
        }
        if (linelen > 0 && (p[0] == ' ' || p[0] == '\t')) {
            free(nm); free(desc);
            return false;
        }
        if (linelen >= 2 && p[0] == '-' && p[1] == ' ') {
            free(nm); free(desc);
            return false;
        }

        const char *sep = NULL;
        for (const char *q = p; q + 1 < le; q++) {
            if (q[0] == ':' && q[1] == ' ') { sep = q; break; }
        }
        if (sep) {
            size_t keylen = (size_t)(sep - p);
            const char *vstart = sep + 2;
            size_t vlen = (size_t)(le - vstart);
            char *value = sk_dup_value(vstart, vlen);
            if (keylen == 4 && strncmp(p, "name", 4) == 0) {
                free(nm);
                nm = value;
            } else if (keylen == 11 && strncmp(p, "description", 11) == 0) {
                free(desc);
                desc = value;
            } else {
                free(value); /* unknown keys ignored */
            }
        }
        p = has_nl ? le + 1 : le;
    }

    if (!closed || !nm || !nm[0] || !desc || !desc[0]) {
        free(nm);
        free(desc);
        return false;
    }
    *name = nm;
    *description = desc;
    *body_start = p;
    return true;
}

/* Caps at 256 bytes (never splitting a UTF-8 sequence) and replaces ASCII
 * control chars and the fullwidth vertical bar (UTF-8 EF BD 9C -- the DSML
 * marker char) with a space, so a hostile SKILL.md cannot inject DSML
 * control tokens into the trusted catalog text. Never mutates the stored
 * meta; applied only when rendering the catalog. */
static char *sk_sanitize_description(const char *desc) {
    size_t len = strlen(desc);
    size_t cap = DS4_SKILLS_MAX_DESC_BYTES;
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

static void sk_list_push(ds4_skill_list *out, char *name, char *description, char *dir) {
    if (out->len == out->cap) {
        out->cap = out->cap ? out->cap * 2 : 4;
        out->v = realloc(out->v, (size_t)out->cap * sizeof(out->v[0]));
    }
    out->v[out->len].name = name;
    out->v[out->len].description = description;
    out->v[out->len].dir = dir;
    out->len++;
}

static int sk_meta_cmp_name(const void *a, const void *b) {
    const ds4_skill_meta *ma = (const ds4_skill_meta *)a;
    const ds4_skill_meta *mb = (const ds4_skill_meta *)b;
    return strcmp(ma->name, mb->name);
}

/* entry_dir is "<root>/skills/<subdir>". Reads and validates its SKILL.md;
 * anything wrong is fail-open (warn + skip), never fatal. A directory under
 * skills/ with no SKILL.md at all is simply not a skill, silently.
 *
 * segment_start is the index in out->v where the current root's entries
 * began: a name collision against an index >= segment_start is a same-root
 * duplicate (warned); a collision against an earlier index is cross-root
 * shadowing by a higher-precedence root (silent, expected). */
static void sk_scan_one(const char *entry_dir, ds4_skill_list *out, int segment_start,
                        char *warn, size_t warn_len) {
    char *md_path = sk_join(entry_dir, "SKILL.md");
    if (!md_path) return;

    struct stat st;
    if (stat(md_path, &st) != 0) { free(md_path); return; }
    if (!S_ISREG(st.st_mode)) {
        sk_warn_append(warn, warn_len, md_path, "not a regular file, skipped");
        free(md_path);
        return;
    }
    if (st.st_size < 0 || (size_t)st.st_size > DS4_SKILLS_MAX_FILE_SIZE) {
        sk_warn_append(warn, warn_len, md_path, "exceeds 1 MiB, skipped");
        free(md_path);
        return;
    }
    FILE *fp = fopen(md_path, "rb");
    if (!fp) {
        sk_warn_append(warn, warn_len, md_path, "could not open, skipped");
        free(md_path);
        return;
    }
    size_t cap = (size_t)st.st_size + 1;
    char *buf = malloc(cap);
    if (!buf) {
        fclose(fp);
        sk_warn_append(warn, warn_len, md_path, "out of memory, skipped");
        free(md_path);
        return;
    }
    size_t n = fread(buf, 1, (size_t)st.st_size, fp);
    fclose(fp);
    buf[n] = '\0';

    char *name = NULL, *description = NULL;
    const char *body_start = NULL;
    bool ok = ds4_skills_parse_frontmatter(buf, &name, &description, &body_start);
    if (!ok) {
        sk_warn_append(warn, warn_len, md_path, "invalid SKILL.md frontmatter, skipped");
        free(buf);
        free(md_path);
        return;
    }
    if (!sk_valid_name(name)) {
        sk_warn_append(warn, warn_len, md_path, "invalid skill name, skipped");
        free(name);
        free(description);
        free(buf);
        free(md_path);
        return;
    }
    free(buf);

    const ds4_skill_meta *existing = ds4_skills_find(out, name);
    if (existing) {
        int idx = (int)(existing - out->v);
        if (idx >= segment_start) {
            /* Two different directories under the same root declared the
             * same frontmatter name; the first one scanned wins. */
            sk_warn_append(warn, warn_len, md_path,
                           "duplicate skill name within this root, first one scanned wins, skipped");
        }
        /* Else: already discovered from a higher-precedence root; shadowing,
         * not an error. */
        free(md_path);
        free(name);
        free(description);
        return;
    }
    free(md_path);
    sk_list_push(out, name, description, sk_strdup(entry_dir));
}

void ds4_skills_scan(const ds4_config *cfg, ds4_skill_list *out, char *warn, size_t warn_len) {
    memset(out, 0, sizeof(*out));
    if (warn && warn_len) warn[0] = '\0';
    if (!cfg) return;

    int nroots = ds4_config_root_count(cfg);
    for (int i = 0; i < nroots; i++) {
        const char *root = ds4_config_root_at(cfg, i);
        if (!root) continue;
        char *skills_dir = sk_join(root, "skills");
        if (!skills_dir) continue;

        int segment_start = out->len;

        DIR *d = opendir(skills_dir);
        if (!d) {
            if (errno != ENOENT)
                sk_warn_append(warn, warn_len, skills_dir, "could not open, skipped");
            free(skills_dir);
            continue;
        }
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
            char *entry_dir = sk_join(skills_dir, de->d_name);
            if (!entry_dir) continue;
            struct stat st;
            if (stat(entry_dir, &st) == 0 && S_ISDIR(st.st_mode))
                sk_scan_one(entry_dir, out, segment_start, warn, warn_len);
            free(entry_dir);
        }
        closedir(d);
        free(skills_dir);

        /* Directory enumeration order (readdir) is not deterministic across
         * filesystems/runs; sort this root's newly-added segment by name so
         * the catalog text -- and anything keyed on it, like a future
         * content-addressed sysprompt cache -- is stable across restarts.
         * Cross-root precedence (project before user) is untouched since
         * each root's segment is sorted only among itself, after its own
         * insertions are complete. */
        if (out->len - segment_start > 1) {
            qsort(out->v + segment_start, (size_t)(out->len - segment_start),
                  sizeof(out->v[0]), sk_meta_cmp_name);
        }
    }
}

void ds4_skills_list_free(ds4_skill_list *list) {
    if (!list) return;
    for (int i = 0; i < list->len; i++) {
        free(list->v[i].name);
        free(list->v[i].description);
        free(list->v[i].dir);
    }
    free(list->v);
    memset(list, 0, sizeof(*list));
}

const ds4_skill_meta *ds4_skills_find(const ds4_skill_list *list, const char *name) {
    if (!list || !name) return NULL;
    for (int i = 0; i < list->len; i++) {
        if (list->v[i].name && !strcmp(list->v[i].name, name))
            return &list->v[i];
    }
    return NULL;
}

char *ds4_skills_load_body(const ds4_skill_list *list, const char *name) {
    const ds4_skill_meta *meta = ds4_skills_find(list, name);
    if (!meta) return NULL;

    char *md_path = sk_join(meta->dir, "SKILL.md");
    if (!md_path) return NULL;
    struct stat st;
    if (stat(md_path, &st) != 0 || !S_ISREG(st.st_mode)) { free(md_path); return NULL; }
    if (st.st_size < 0 || (size_t)st.st_size > DS4_SKILLS_MAX_FILE_SIZE) {
        free(md_path);
        return NULL;
    }
    FILE *fp = fopen(md_path, "rb");
    if (!fp) { free(md_path); return NULL; }

    size_t cap = (size_t)st.st_size + 1;
    char *buf = malloc(cap);
    if (!buf) { fclose(fp); free(md_path); return NULL; }
    size_t n = fread(buf, 1, (size_t)st.st_size, fp);
    fclose(fp);
    free(md_path);
    buf[n] = '\0';

    char *nm = NULL, *desc = NULL;
    const char *body_start = NULL;
    bool ok = ds4_skills_parse_frontmatter(buf, &nm, &desc, &body_start);
    free(nm);
    free(desc);
    if (!ok) { free(buf); return NULL; }

    char *body = sk_strdup(body_start);
    free(buf);
    return body;
}

/* Mirrors the structural shape (schema-block JSON, native tool syntax) that
 * agent_tools_prompt_after_edit uses to declare google_search/visit_page/etc
 * in ds4_agent.c, so the model sees the skill tool declared the same way it
 * sees every other native tool. */
static const char DS4_SKILLS_TOOL_DECL[] =
    "{\n"
    "  \"type\": \"function\",\n"
    "  \"function\": {\n"
    "    \"name\": \"skill\",\n"
    "    \"description\": \"Load the full instructions for a named skill. Invoke it when one of the available skills below matches the task at hand.\",\n"
    "    \"parameters\": {\n"
    "      \"type\": \"object\",\n"
    "      \"properties\": {\n"
    "        \"name\": {\"type\": \"string\"}\n"
    "      },\n"
    "      \"required\": [\"name\"]\n"
    "    }\n"
    "  }\n"
    "}\n";

char *ds4_skills_catalog_prompt_text(const ds4_skill_list *list) {
    if (!list || list->len == 0) return NULL;

    ds4_json_writer w = {0};
    ds4_json_w_raw(&w, "\n## Skills\n\n");
    ds4_json_w_raw(&w, DS4_SKILLS_TOOL_DECL);
    ds4_json_w_raw(&w, "\nAvailable skills:\n");
    for (int i = 0; i < list->len; i++) {
        ds4_json_w_raw(&w, "- ");
        ds4_json_w_raw(&w, list->v[i].name);
        ds4_json_w_raw(&w, ": ");
        char *sdesc = sk_sanitize_description(list->v[i].description ? list->v[i].description : "");
        if (sdesc) {
            ds4_json_w_raw(&w, sdesc);
            free(sdesc);
        }
        ds4_json_w_raw(&w, "\n");
    }
    return ds4_json_w_take(&w);
}

#ifdef DS4_SKILLS_TEST

static int sk_test_failures;

static void sk_test_assert(int cond, const char *expr, const char *file, int line) {
    if (cond) return;
    fprintf(stderr, "%s:%d: assertion failed: %s\n", file, line, expr);
    sk_test_failures++;
}
#define SK_TEST_ASSERT(expr) sk_test_assert((expr), #expr, __FILE__, __LINE__)

/* ---- self-contained fixture helpers (independent of module internals) ---- */

static char *sk_test_join(const char *dir, const char *name) {
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

static char *sk_test_strdup(const char *s) {
    size_t n = strlen(s);
    char *p = malloc(n + 1);
    if (p) memcpy(p, s, n + 1);
    return p;
}

static void sk_test_mkdir_p(const char *path) {
    char *tmp = sk_test_strdup(path);
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

static void sk_test_write_file(const char *path, const char *content) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return;
    fwrite(content, 1, strlen(content), fp);
    fclose(fp);
}

static void sk_test_rmtree(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return;
    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        if (d) {
            struct dirent *de;
            while ((de = readdir(d)) != NULL) {
                if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
                char *child = sk_test_join(path, de->d_name);
                if (child) {
                    sk_test_rmtree(child);
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

static void sk_test_setenv_home(const char *value, char **saved_out) {
    const char *cur = getenv("HOME");
    *saved_out = cur ? sk_test_strdup(cur) : NULL;
    if (value) setenv("HOME", value, 1);
    else unsetenv("HOME");
}

static void sk_test_restore_home(char *saved) {
    if (saved) {
        setenv("HOME", saved, 1);
        free(saved);
    } else {
        unsetenv("HOME");
    }
}

/* ---- test groups ---- */

static void test_valid_skill_discovered(void) {
    char tmpl[] = "/tmp/ds4_skills_valid_test.XXXXXX";
    char *fx = mkdtemp(tmpl);
    SK_TEST_ASSERT(fx != NULL);
    if (!fx) return;

    char *proj = sk_test_join(fx, "proj");
    char *proj_ds4 = sk_test_join(proj, ".ds4");
    char *skill_dir = sk_test_join(proj_ds4, "skills/myskill");
    sk_test_mkdir_p(skill_dir);
    char *md_path = sk_test_join(skill_dir, "SKILL.md");
    sk_test_write_file(md_path,
        "---\n"
        "name: myskill\n"
        "description: Do the thing.\n"
        "---\n"
        "Full body text here.\n"
        "Second line.\n");

    char *home = sk_test_join(fx, "home");
    sk_test_mkdir_p(home);
    char *saved_home;
    sk_test_setenv_home(home, &saved_home);

    char cfgwarn[256] = {0};
    ds4_config *cfg = ds4_config_load(proj, cfgwarn, sizeof(cfgwarn));
    SK_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        char warn[512] = {0};
        ds4_skill_list list = {0};
        ds4_skills_scan(cfg, &list, warn, sizeof(warn));
        SK_TEST_ASSERT(list.len == 1);
        if (list.len == 1) {
            SK_TEST_ASSERT(strcmp(list.v[0].name, "myskill") == 0);
            SK_TEST_ASSERT(strcmp(list.v[0].description, "Do the thing.") == 0);
            const char *root0 = ds4_config_root_at(cfg, 0);
            SK_TEST_ASSERT(root0 != NULL);
            if (root0) {
                char expected_dir[PATH_MAX];
                snprintf(expected_dir, sizeof(expected_dir), "%s/skills/myskill", root0);
                SK_TEST_ASSERT(strcmp(list.v[0].dir, expected_dir) == 0);
            }
            char *body = ds4_skills_load_body(&list, "myskill");
            SK_TEST_ASSERT(body != NULL);
            if (body) {
                SK_TEST_ASSERT(strcmp(body, "Full body text here.\nSecond line.\n") == 0);
                free(body);
            }
        }
        ds4_skills_list_free(&list);
    }
    ds4_config_free(cfg);

    sk_test_restore_home(saved_home);
    free(proj); free(proj_ds4); free(skill_dir); free(md_path); free(home);
    sk_test_rmtree(fx);
}

static void test_shadowing(void) {
    char tmpl[] = "/tmp/ds4_skills_shadow_test.XXXXXX";
    char *fx = mkdtemp(tmpl);
    SK_TEST_ASSERT(fx != NULL);
    if (!fx) return;

    char *proj = sk_test_join(fx, "proj");
    char *proj_ds4 = sk_test_join(proj, ".ds4");
    char *proj_skill = sk_test_join(proj_ds4, "skills/proj-copy");
    sk_test_mkdir_p(proj_skill);
    char *proj_md = sk_test_join(proj_skill, "SKILL.md");
    sk_test_write_file(proj_md,
        "---\nname: shared\ndescription: Project version.\n---\nProject body.\n");

    char *home = sk_test_join(fx, "home");
    char *home_ds4 = sk_test_join(home, ".ds4");
    char *home_skill = sk_test_join(home_ds4, "skills/user-copy");
    sk_test_mkdir_p(home_skill);
    char *home_md = sk_test_join(home_skill, "SKILL.md");
    sk_test_write_file(home_md,
        "---\nname: shared\ndescription: User version.\n---\nUser body.\n");

    char *saved_home;
    sk_test_setenv_home(home, &saved_home);

    ds4_config *cfg = ds4_config_load(proj, NULL, 0);
    SK_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        SK_TEST_ASSERT(ds4_config_root_count(cfg) == 2);
        char warn[512] = {0};
        ds4_skill_list list = {0};
        ds4_skills_scan(cfg, &list, warn, sizeof(warn));
        int count = 0;
        for (int i = 0; i < list.len; i++)
            if (!strcmp(list.v[i].name, "shared")) count++;
        SK_TEST_ASSERT(count == 1);
        const ds4_skill_meta *m = ds4_skills_find(&list, "shared");
        SK_TEST_ASSERT(m != NULL);
        if (m) SK_TEST_ASSERT(strcmp(m->description, "Project version.") == 0);
        ds4_skills_list_free(&list);
    }
    ds4_config_free(cfg);

    sk_test_restore_home(saved_home);
    free(proj); free(proj_ds4); free(proj_skill); free(proj_md);
    free(home); free(home_ds4); free(home_skill); free(home_md);
    sk_test_rmtree(fx);
}

static void test_invalid_skipped(void) {
    char tmpl[] = "/tmp/ds4_skills_invalid_test.XXXXXX";
    char *fx = mkdtemp(tmpl);
    SK_TEST_ASSERT(fx != NULL);
    if (!fx) return;

    char *proj = sk_test_join(fx, "proj");
    char *proj_ds4 = sk_test_join(proj, ".ds4");
    char *skills = sk_test_join(proj_ds4, "skills");
    sk_test_mkdir_p(skills);

    struct { const char *dir; const char *content; } fixtures[] = {
        { "no-close", "---\nname: nc\ndescription: no close.\n" },
        { "no-desc", "---\nname: nd\n---\nbody\n" },
        { "nested-space", "---\nname: ns\n  foo: bar\ndescription: x.\n---\nbody\n" },
        { "nested-list", "---\nname: nl\n- item\ndescription: x.\n---\nbody\n" },
        { "bad-name-dotdot", "---\nname: ../evil\ndescription: x.\n---\nbody\n" },
        { "bad-name-space", "---\nname: has space\ndescription: x.\n---\nbody\n" },
        { "goodone", "---\nname: goodone\ndescription: Valid sibling.\n---\nbody\n" },
    };
    for (size_t i = 0; i < sizeof(fixtures) / sizeof(fixtures[0]); i++) {
        char *d = sk_test_join(skills, fixtures[i].dir);
        sk_test_mkdir_p(d);
        char *md = sk_test_join(d, "SKILL.md");
        sk_test_write_file(md, fixtures[i].content);
        free(md);
        free(d);
    }
    {
        char longname[80];
        memset(longname, 'a', 70);
        longname[70] = '\0';
        char *d = sk_test_join(skills, "bad-name-long");
        sk_test_mkdir_p(d);
        char *md = sk_test_join(d, "SKILL.md");
        char content[256];
        snprintf(content, sizeof(content), "---\nname: %s\ndescription: x.\n---\nbody\n", longname);
        sk_test_write_file(md, content);
        free(md);
        free(d);
    }

    char *home = sk_test_join(fx, "home");
    sk_test_mkdir_p(home);
    char *saved_home;
    sk_test_setenv_home(home, &saved_home);

    ds4_config *cfg = ds4_config_load(proj, NULL, 0);
    SK_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        char warn[2048] = {0};
        ds4_skill_list list = {0};
        ds4_skills_scan(cfg, &list, warn, sizeof(warn));
        SK_TEST_ASSERT(list.len == 1);
        SK_TEST_ASSERT(ds4_skills_find(&list, "goodone") != NULL);
        SK_TEST_ASSERT(warn[0] != '\0');
        ds4_skills_list_free(&list);
    }
    ds4_config_free(cfg);

    sk_test_restore_home(saved_home);
    free(proj); free(proj_ds4); free(skills); free(home);
    sk_test_rmtree(fx);
}

static void test_sanitization(void) {
    char tmpl[] = "/tmp/ds4_skills_sanitize_test.XXXXXX";
    char *fx = mkdtemp(tmpl);
    SK_TEST_ASSERT(fx != NULL);
    if (!fx) return;

    char *proj = sk_test_join(fx, "proj");
    char *proj_ds4 = sk_test_join(proj, ".ds4");

    /* description contains the DSML marker char (UTF-8 EF BD 9C) and an ESC
     * control byte; both must become plain spaces in catalog text. */
    char *skill_dir = sk_test_join(proj_ds4, "skills/nasty");
    sk_test_mkdir_p(skill_dir);
    char *md_path = sk_test_join(skill_dir, "SKILL.md");
    char content[512];
    snprintf(content, sizeof(content),
             "---\nname: nasty\ndescription: bad\xef\xbd\x9cmark\x1b" "end.\n---\nbody\n");
    sk_test_write_file(md_path, content);

    /* A second skill with a 300-byte description where a 2-byte UTF-8
     * character straddles the 256-byte truncation boundary. */
    char *skill_dir2 = sk_test_join(proj_ds4, "skills/longdesc");
    sk_test_mkdir_p(skill_dir2);
    char *md_path2 = sk_test_join(skill_dir2, "SKILL.md");
    char desc[301];
    memset(desc, 'x', sizeof(desc) - 1);
    desc[255] = (char)0xC3; /* lead byte of a 2-byte char straddling byte 256 */
    desc[256] = (char)0xA9;
    desc[300] = '\0';
    char content2[700];
    snprintf(content2, sizeof(content2), "---\nname: longdesc\ndescription: %s\n---\nbody\n", desc);
    sk_test_write_file(md_path2, content2);

    char *home = sk_test_join(fx, "home");
    sk_test_mkdir_p(home);
    char *saved_home;
    sk_test_setenv_home(home, &saved_home);

    ds4_config *cfg = ds4_config_load(proj, NULL, 0);
    SK_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        ds4_skill_list list = {0};
        ds4_skills_scan(cfg, &list, NULL, 0);
        char *catalog = ds4_skills_catalog_prompt_text(&list);
        SK_TEST_ASSERT(catalog != NULL);
        if (catalog) {
            SK_TEST_ASSERT(strstr(catalog, "\xef\xbd\x9c") == NULL);
            SK_TEST_ASSERT(strstr(catalog, "\x1b") == NULL);
            SK_TEST_ASSERT(strstr(catalog, "bad mark end.") != NULL);

            const char *line = strstr(catalog, "- longdesc: ");
            SK_TEST_ASSERT(line != NULL);
            if (line) {
                const char *nl = strchr(line, '\n');
                SK_TEST_ASSERT(nl != NULL);
                if (nl) {
                    size_t linelen = (size_t)(nl - line);
                    size_t desclen = linelen - strlen("- longdesc: ");
                    SK_TEST_ASSERT(desclen <= 256);
                    unsigned char last = (unsigned char)nl[-1];
                    SK_TEST_ASSERT((last & 0xC0) != 0x80); /* not a continuation byte */
                }
            }
            free(catalog);
        }
        ds4_skills_list_free(&list);
    }
    ds4_config_free(cfg);

    sk_test_restore_home(saved_home);
    free(proj); free(proj_ds4); free(skill_dir); free(md_path);
    free(skill_dir2); free(md_path2); free(home);
    sk_test_rmtree(fx);
}

static void test_golden_catalog_and_empty(void) {
    ds4_skill_list empty = {0};
    char *catalog = ds4_skills_catalog_prompt_text(&empty);
    SK_TEST_ASSERT(catalog == NULL);
    catalog = ds4_skills_catalog_prompt_text(NULL);
    SK_TEST_ASSERT(catalog == NULL);

    ds4_skill_list list = {0};
    sk_list_push(&list, sk_strdup("alpha"), sk_strdup("First skill."), sk_strdup("/tmp/alpha"));
    sk_list_push(&list, sk_strdup("beta"), sk_strdup("Second skill."), sk_strdup("/tmp/beta"));

    char *got = ds4_skills_catalog_prompt_text(&list);
    SK_TEST_ASSERT(got != NULL);
    if (got) {
        const char *expected =
            "\n## Skills\n\n"
            "{\n"
            "  \"type\": \"function\",\n"
            "  \"function\": {\n"
            "    \"name\": \"skill\",\n"
            "    \"description\": \"Load the full instructions for a named skill. Invoke it when one of the available skills below matches the task at hand.\",\n"
            "    \"parameters\": {\n"
            "      \"type\": \"object\",\n"
            "      \"properties\": {\n"
            "        \"name\": {\"type\": \"string\"}\n"
            "      },\n"
            "      \"required\": [\"name\"]\n"
            "    }\n"
            "  }\n"
            "}\n"
            "\nAvailable skills:\n"
            "- alpha: First skill.\n"
            "- beta: Second skill.\n";
        SK_TEST_ASSERT(strcmp(got, expected) == 0);
        free(got);
    }
    ds4_skills_list_free(&list);
}

static void test_sort_within_root_segment(void) {
    char tmpl[] = "/tmp/ds4_skills_sort_test.XXXXXX";
    char *fx = mkdtemp(tmpl);
    SK_TEST_ASSERT(fx != NULL);
    if (!fx) return;

    char *proj = sk_test_join(fx, "proj");
    char *proj_ds4 = sk_test_join(proj, ".ds4");
    char *skills = sk_test_join(proj_ds4, "skills");
    sk_test_mkdir_p(skills);

    /* Directory names are deliberately not alphabetical, and differ from the
     * frontmatter names, so the test cannot pass just because readdir()
     * happened to already return entries in sorted order. */
    struct { const char *dir; const char *name; const char *desc; } fixtures[] = {
        { "dir-zeta", "zeta", "Zeta skill." },
        { "dir-alpha", "alpha", "Alpha skill." },
        { "dir-mu", "mu", "Mu skill." },
    };
    for (size_t i = 0; i < sizeof(fixtures) / sizeof(fixtures[0]); i++) {
        char *d = sk_test_join(skills, fixtures[i].dir);
        sk_test_mkdir_p(d);
        char *md = sk_test_join(d, "SKILL.md");
        char content[256];
        snprintf(content, sizeof(content), "---\nname: %s\ndescription: %s\n---\nbody\n",
                 fixtures[i].name, fixtures[i].desc);
        sk_test_write_file(md, content);
        free(md);
        free(d);
    }

    char *home = sk_test_join(fx, "home");
    sk_test_mkdir_p(home);
    char *saved_home;
    sk_test_setenv_home(home, &saved_home);

    ds4_config *cfg = ds4_config_load(proj, NULL, 0);
    SK_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        ds4_skill_list list = {0};
        ds4_skills_scan(cfg, &list, NULL, 0);
        SK_TEST_ASSERT(list.len == 3);
        if (list.len == 3) {
            SK_TEST_ASSERT(strcmp(list.v[0].name, "alpha") == 0);
            SK_TEST_ASSERT(strcmp(list.v[1].name, "mu") == 0);
            SK_TEST_ASSERT(strcmp(list.v[2].name, "zeta") == 0);
        }
        char *catalog = ds4_skills_catalog_prompt_text(&list);
        SK_TEST_ASSERT(catalog != NULL);
        if (catalog) {
            const char *expected_tail =
                "Available skills:\n"
                "- alpha: Alpha skill.\n"
                "- mu: Mu skill.\n"
                "- zeta: Zeta skill.\n";
            SK_TEST_ASSERT(strstr(catalog, expected_tail) != NULL);
            free(catalog);
        }
        ds4_skills_list_free(&list);
    }
    ds4_config_free(cfg);

    sk_test_restore_home(saved_home);
    free(proj); free(proj_ds4); free(skills); free(home);
    sk_test_rmtree(fx);
}

static void test_same_root_duplicate_name_warns(void) {
    char tmpl[] = "/tmp/ds4_skills_dup_test.XXXXXX";
    char *fx = mkdtemp(tmpl);
    SK_TEST_ASSERT(fx != NULL);
    if (!fx) return;

    char *proj = sk_test_join(fx, "proj");
    char *proj_ds4 = sk_test_join(proj, ".ds4");
    char *skills = sk_test_join(proj_ds4, "skills");
    sk_test_mkdir_p(skills);

    /* Two different directories under the SAME root declaring the same
     * frontmatter name -- distinct from cross-root shadowing, which stays
     * silent. */
    char *dir_a = sk_test_join(skills, "dup-a");
    sk_test_mkdir_p(dir_a);
    char *md_a = sk_test_join(dir_a, "SKILL.md");
    sk_test_write_file(md_a, "---\nname: dupname\ndescription: From A.\n---\nbody a\n");

    char *dir_b = sk_test_join(skills, "dup-b");
    sk_test_mkdir_p(dir_b);
    char *md_b = sk_test_join(dir_b, "SKILL.md");
    sk_test_write_file(md_b, "---\nname: dupname\ndescription: From B.\n---\nbody b\n");

    char *home = sk_test_join(fx, "home");
    sk_test_mkdir_p(home);
    char *saved_home;
    sk_test_setenv_home(home, &saved_home);

    ds4_config *cfg = ds4_config_load(proj, NULL, 0);
    SK_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        char warn[512] = {0};
        ds4_skill_list list = {0};
        ds4_skills_scan(cfg, &list, warn, sizeof(warn));

        int count = 0;
        for (int i = 0; i < list.len; i++)
            if (!strcmp(list.v[i].name, "dupname")) count++;
        SK_TEST_ASSERT(count == 1);
        SK_TEST_ASSERT(strstr(warn, "duplicate skill name") != NULL);

        const ds4_skill_meta *m = ds4_skills_find(&list, "dupname");
        SK_TEST_ASSERT(m != NULL);
        if (m) {
            /* Which physical directory wins a same-root collision is
             * readdir()-order dependent (unspecified -- sorting happens
             * after all of a root's insertions complete, so it does not
             * make the dedup-at-insert race deterministic). Exactly one
             * winner is required, and it must be one of the two genuine
             * candidates, never corrupted or empty. */
            SK_TEST_ASSERT(strcmp(m->description, "From A.") == 0 ||
                           strcmp(m->description, "From B.") == 0);
        }
        ds4_skills_list_free(&list);
    }
    ds4_config_free(cfg);

    sk_test_restore_home(saved_home);
    free(proj); free(proj_ds4); free(skills);
    free(dir_a); free(md_a); free(dir_b); free(md_b); free(home);
    sk_test_rmtree(fx);
}

static void test_find_load_unknown(void) {
    ds4_skill_list list = {0};
    SK_TEST_ASSERT(ds4_skills_find(&list, "nope") == NULL);
    SK_TEST_ASSERT(ds4_skills_load_body(&list, "nope") == NULL);
    SK_TEST_ASSERT(ds4_skills_find(NULL, "nope") == NULL);
}

/* Plugin roots (ds4_config's .ds4/plugins/<name>) are just more search
 * roots to ds4_skills_scan -- zero code changes needed here, this only
 * proves the existing scan/shadowing logic already extends correctly once
 * ds4_config_root_count/root_at include plugin roots. */
static void test_plugin_skill_discovered_and_shadowed(void) {
    char tmpl[] = "/tmp/ds4_skills_plugin_test.XXXXXX";
    char *fx = mkdtemp(tmpl);
    SK_TEST_ASSERT(fx != NULL);
    if (!fx) return;

    char *proj = sk_test_join(fx, "proj");
    char *proj_ds4 = sk_test_join(proj, ".ds4");

    /* plugin-only skill: discovered purely via the plugin root */
    char *plugin_skill = sk_test_join(proj_ds4, "plugins/myplugin/skills/pluginskill");
    sk_test_mkdir_p(plugin_skill);
    char *plugin_md = sk_test_join(plugin_skill, "SKILL.md");
    sk_test_write_file(plugin_md,
        "---\nname: pluginskill\ndescription: From the plugin.\n---\nPlugin body.\n");

    /* same frontmatter name in the project base root and in a project
     * plugin: the base root must shadow the plugin (project .ds4 precedes
     * project .ds4/plugins/<name> in root order). */
    char *base_skill = sk_test_join(proj_ds4, "skills/shared-copy");
    sk_test_mkdir_p(base_skill);
    char *base_md = sk_test_join(base_skill, "SKILL.md");
    sk_test_write_file(base_md,
        "---\nname: shared\ndescription: Base project version.\n---\nBase body.\n");

    char *plugin_shared = sk_test_join(proj_ds4, "plugins/myplugin/skills/shared-copy");
    sk_test_mkdir_p(plugin_shared);
    char *plugin_shared_md = sk_test_join(plugin_shared, "SKILL.md");
    sk_test_write_file(plugin_shared_md,
        "---\nname: shared\ndescription: Plugin version.\n---\nPlugin shared body.\n");

    char *home = sk_test_join(fx, "home");
    sk_test_mkdir_p(home);
    char *saved_home;
    sk_test_setenv_home(home, &saved_home);

    ds4_config *cfg = ds4_config_load(proj, NULL, 0);
    SK_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        SK_TEST_ASSERT(ds4_config_root_count(cfg) == 3); /* project base + 1 project plugin + user base */
        char warn[512] = {0};
        ds4_skill_list list = {0};
        ds4_skills_scan(cfg, &list, warn, sizeof(warn));

        const ds4_skill_meta *plugin_only = ds4_skills_find(&list, "pluginskill");
        SK_TEST_ASSERT(plugin_only != NULL);
        if (plugin_only) SK_TEST_ASSERT(strcmp(plugin_only->description, "From the plugin.") == 0);

        const ds4_skill_meta *shared = ds4_skills_find(&list, "shared");
        SK_TEST_ASSERT(shared != NULL);
        if (shared) SK_TEST_ASSERT(strcmp(shared->description, "Base project version.") == 0);

        ds4_skills_list_free(&list);
    }
    ds4_config_free(cfg);

    sk_test_restore_home(saved_home);
    free(proj); free(proj_ds4); free(plugin_skill); free(plugin_md);
    free(base_skill); free(base_md); free(plugin_shared); free(plugin_shared_md);
    free(home);
    sk_test_rmtree(fx);
}

int ds4_skills_unit_tests_run(void) {
    test_valid_skill_discovered();
    test_shadowing();
    test_invalid_skipped();
    test_sanitization();
    test_golden_catalog_and_empty();
    test_find_load_unknown();
    test_sort_within_root_segment();
    test_same_root_duplicate_name_warns();
    test_plugin_skill_discovered_and_shadowed();
    return sk_test_failures;
}
#endif
