#include "ds4_hooks.h"
#include "ds4_json.h"
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* PreToolUse/PostToolUse shell hooks. See ds4_hooks.h for the settings.json
 * schema, payload shapes, and merge semantics. Subprocess mechanics: fork;
 * child setpgid(0,0) (so the whole process group -- including any
 * grandchildren a hook script spawns -- can be killed atomically on
 * timeout), dup2 three pipes (stdin/stdout/stderr), /bin/sh -c <command>;
 * parent drives everything through select() with a per-hook deadline, so a
 * hung or silent hook can never block the caller past its timeout_ms. */

#define DS4_HOOKS_DEFAULT_TIMEOUT_MS 10000
#define DS4_HOOKS_CAP_BYTES (64u * 1024) /* stdout/stderr capture cap */
#define DS4_HOOKS_READ_CHUNK 8192

static char *hk_strdup(const char *s) {
    size_t n = strlen(s);
    char *p = malloc(n + 1);
    if (p) memcpy(p, s, n + 1);
    return p;
}

static char *hk_vfmt(const char *fmt, va_list ap) {
    char stack[256];
    va_list ap2;
    va_copy(ap2, ap);
    int n = vsnprintf(stack, sizeof(stack), fmt, ap2);
    va_end(ap2);
    if (n < 0) return hk_strdup("hook error");
    if ((size_t)n < sizeof(stack)) return hk_strdup(stack);
    char *heap = malloc((size_t)n + 1);
    if (!heap) return hk_strdup(stack); /* truncated fallback on OOM */
    vsnprintf(heap, (size_t)n + 1, fmt, ap);
    return heap;
}

static char *hk_fmt(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char *s = hk_vfmt(fmt, ap);
    va_end(ap);
    return s;
}

static void hk_warn_append(char *warn, size_t warn_len, const char *ctx, const char *problem) {
    if (!warn || warn_len == 0) return;
    size_t cur = strlen(warn);
    if (cur + 1 >= warn_len) return;
    snprintf(warn + cur, warn_len - cur, "hooks: %s: %s\n", ctx, problem);
}

/* ---- settings.json parsing ---- */

typedef struct {
    char *matcher;   /* fnmatch glob, never NULL, defaults to "*" */
    char *command;   /* /bin/sh -c argument */
    int timeout_ms;  /* effective, always > 0 */
} hook_entry;

typedef struct { hook_entry *v; int len, cap; } hook_entry_list;

struct ds4_hooks {
    hook_entry_list events[2]; /* indexed by ds4_hook_event */
    char *cwd;                 /* project root snapshot at load time, NULL = inherit cwd */
};

static void hook_entry_push(hook_entry_list *list, hook_entry e) {
    if (list->len == list->cap) {
        list->cap = list->cap ? list->cap * 2 : 4;
        list->v = realloc(list->v, (size_t)list->cap * sizeof(list->v[0]));
    }
    list->v[list->len++] = e;
}

static void hook_entry_list_free(hook_entry_list *list) {
    for (int i = 0; i < list->len; i++) {
        free(list->v[i].matcher);
        free(list->v[i].command);
    }
    free(list->v);
    memset(list, 0, sizeof(*list));
}

static bool hk_event_from_key(const char *key, ds4_hook_event *out) {
    if (!strcmp(key, "PreToolUse")) { *out = DS4_HOOK_PRE_TOOL; return true; }
    if (!strcmp(key, "PostToolUse")) { *out = DS4_HOOK_POST_TOOL; return true; }
    return false;
}

ds4_hooks *ds4_hooks_load(const ds4_config *cfg, char *warn, size_t warn_len) {
    if (warn && warn_len) warn[0] = '\0';
    if (!cfg) return NULL;

    /* Task-2 config merge (ds4_config_get): a "hooks" key present in the
     * project settings.json is used in full, in place of the user one --
     * no deep merge across files, and no merge across the PreToolUse /
     * PostToolUse arrays of two different files. Fetching the key once here
     * is therefore the entire merge story for this module. */
    const ds4_json_value *hooks_v = ds4_config_get(cfg, "hooks");
    if (!hooks_v) return NULL;
    if (ds4_json_type_of(hooks_v) != DS4_JSON_OBJ) {
        hk_warn_append(warn, warn_len, "hooks", "not an object, skipped");
        return NULL;
    }

    ds4_hooks tmp = {0};
    int n = ds4_json_obj_len(hooks_v);
    for (int i = 0; i < n; i++) {
        const char *key = ds4_json_obj_key_at(hooks_v, i);
        const ds4_json_value *val = ds4_json_obj_val_at(hooks_v, i);
        ds4_hook_event ev;
        if (!hk_event_from_key(key, &ev)) {
            hk_warn_append(warn, warn_len, key, "unknown hook event, skipped");
            continue;
        }
        if (ds4_json_type_of(val) != DS4_JSON_ARR) {
            hk_warn_append(warn, warn_len, key, "hook event value is not an array, skipped");
            continue;
        }
        int m = ds4_json_arr_len(val);
        for (int j = 0; j < m; j++) {
            const ds4_json_value *entry = ds4_json_arr_get(val, j);
            if (ds4_json_type_of(entry) != DS4_JSON_OBJ) {
                hk_warn_append(warn, warn_len, key, "hook entry is not an object, skipped");
                continue;
            }
            const char *command = ds4_json_str(ds4_json_obj_get(entry, "command"));
            if (!command || !command[0]) {
                hk_warn_append(warn, warn_len, key, "hook entry missing command, skipped");
                continue;
            }
            const char *matcher = ds4_json_str(ds4_json_obj_get(entry, "matcher"));
            double timeout_num = ds4_json_num(ds4_json_obj_get(entry, "timeout_ms"), -1);

            hook_entry he;
            he.matcher = hk_strdup((matcher && matcher[0]) ? matcher : "*");
            he.command = hk_strdup(command);
            he.timeout_ms = (timeout_num > 0) ? (int)timeout_num : DS4_HOOKS_DEFAULT_TIMEOUT_MS;
            hook_entry_push(&tmp.events[ev], he);
        }
    }

    if (tmp.events[DS4_HOOK_PRE_TOOL].len == 0 && tmp.events[DS4_HOOK_POST_TOOL].len == 0) {
        hook_entry_list_free(&tmp.events[DS4_HOOK_PRE_TOOL]);
        hook_entry_list_free(&tmp.events[DS4_HOOK_POST_TOOL]);
        return NULL;
    }

    /* ds4-agent does not otherwise ignore SIGPIPE; only do so once we are
     * actually about to hold pipes to hook child processes (same
     * precedent/rationale as ds4_mcp_registry_create, ds4_server.c:11697,
     * and required here independently of whether MCP is also configured). */
    signal(SIGPIPE, SIG_IGN);

    ds4_hooks *h = calloc(1, sizeof(*h));
    h->events[DS4_HOOK_PRE_TOOL] = tmp.events[DS4_HOOK_PRE_TOOL];
    h->events[DS4_HOOK_POST_TOOL] = tmp.events[DS4_HOOK_POST_TOOL];
    const char *root = ds4_config_project_root(cfg);
    h->cwd = root ? hk_strdup(root) : NULL;
    return h;
}

void ds4_hooks_free(ds4_hooks *h) {
    if (!h) return;
    hook_entry_list_free(&h->events[DS4_HOOK_PRE_TOOL]);
    hook_entry_list_free(&h->events[DS4_HOOK_POST_TOOL]);
    free(h->cwd);
    free(h);
}

int ds4_hooks_count(const ds4_hooks *h, ds4_hook_event event) {
    if (!h) return 0;
    return h->events[event].len;
}

/* ---- subprocess mechanics ---- */

static long hk_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static char *hk_trim_dup(const char *s, size_t n) {
    size_t start = 0, end = n;
    while (start < end && (s[start] == ' ' || s[start] == '\t' ||
                            s[start] == '\r' || s[start] == '\n'))
        start++;
    while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\t' ||
                            s[end - 1] == '\r' || s[end - 1] == '\n'))
        end--;
    size_t len = end - start;
    char *out = malloc(len + 1);
    if (!out) return NULL;
    memcpy(out, s + start, len);
    out[len] = '\0';
    return out;
}

typedef enum { HOOK_RUN_OK, HOOK_RUN_BLOCKED, HOOK_RUN_WARN } hook_run_status;

typedef struct {
    hook_run_status status;
    char *block_reason; /* set iff status == HOOK_RUN_BLOCKED */
    char *warn_msg;      /* set iff status == HOOK_RUN_WARN */
} hook_run_outcome;

/* fork; child setpgid(0,0) then dup2's the three pipes onto stdin/stdout/
 * stderr and /bin/sh -c's the command (no shell inherited from the parent,
 * mirrors ds4_mcp's execvp-no-shell rationale except hooks need actual shell
 * parsing of the configured command string). Parent drives the whole
 * exchange -- writing payload_json to stdin, reading stdout+stderr each
 * capped at DS4_HOOKS_CAP_BYTES -- through a single select() loop bounded by
 * he->timeout_ms, so nothing here can block past the deadline regardless of
 * whether the hook reads its stdin, writes output, or exits at all. On
 * timeout the *whole process group* is SIGKILLed (covering any grandchild a
 * hook script spawned) and reaped before returning. */
static void hk_run_one(const ds4_hooks *h, const hook_entry *he,
                        const char *payload_json, hook_run_outcome *out) {
    memset(out, 0, sizeof(*out));

    int in_pipe[2], out_pipe[2], err_pipe[2];
    if (pipe(in_pipe) != 0) {
        out->status = HOOK_RUN_WARN;
        out->warn_msg = hk_fmt("failed to create stdin pipe: %s", strerror(errno));
        return;
    }
    if (pipe(out_pipe) != 0) {
        out->status = HOOK_RUN_WARN;
        out->warn_msg = hk_fmt("failed to create stdout pipe: %s", strerror(errno));
        close(in_pipe[0]); close(in_pipe[1]);
        return;
    }
    if (pipe(err_pipe) != 0) {
        out->status = HOOK_RUN_WARN;
        out->warn_msg = hk_fmt("failed to create stderr pipe: %s", strerror(errno));
        close(in_pipe[0]); close(in_pipe[1]);
        close(out_pipe[0]); close(out_pipe[1]);
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        out->status = HOOK_RUN_WARN;
        out->warn_msg = hk_fmt("fork failed: %s", strerror(errno));
        close(in_pipe[0]); close(in_pipe[1]);
        close(out_pipe[0]); close(out_pipe[1]);
        close(err_pipe[0]); close(err_pipe[1]);
        return;
    }
    if (pid == 0) {
        setpgid(0, 0);
        dup2(in_pipe[0], STDIN_FILENO);
        dup2(out_pipe[1], STDOUT_FILENO);
        dup2(err_pipe[1], STDERR_FILENO);
        close(in_pipe[0]); close(in_pipe[1]);
        close(out_pipe[0]); close(out_pipe[1]);
        close(err_pipe[0]); close(err_pipe[1]);
        if (h->cwd && chdir(h->cwd) != 0) _exit(127);
        execl("/bin/sh", "sh", "-c", he->command, (char *)NULL);
        _exit(127);
    }

    /* parent */
    /* Both sides call setpgid on the child: the child calls it on itself
     * above so the group exists even if it execs before the parent runs,
     * and the parent calls it here so the group exists even if the timeout
     * fires (and kill(-pid, SIGKILL) below runs) before the child gets
     * scheduled at all. Whichever call wins the race sets the same thing
     * (the child's pgid to its own pid), so this is idempotent, not a
     * conflict; the parent's call failing (ESRCH if the child has already
     * exited, EACCES if it already exec'd a set-id program) is fine to
     * ignore -- the child's own call already covers those cases. Without
     * this, a timeout that lands before the child's first scheduled
     * instruction would kill(-pid, ...) a process group that doesn't exist
     * yet (ESRCH, silently a no-op since the return value isn't checked),
     * and the subsequent blocking waitpid(pid, NULL, 0) would then hang
     * forever on a hook that was never actually signaled. */
    setpgid(pid, pid);
    close(in_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[1]);
    int fd_in = in_pipe[1], fd_out = out_pipe[0], fd_err = err_pipe[0];
    {
        int fl;
        fl = fcntl(fd_in, F_GETFL, 0); fcntl(fd_in, F_SETFL, fl | O_NONBLOCK);
        fl = fcntl(fd_out, F_GETFL, 0); fcntl(fd_out, F_SETFL, fl | O_NONBLOCK);
        fl = fcntl(fd_err, F_GETFL, 0); fcntl(fd_err, F_SETFL, fl | O_NONBLOCK);
        fcntl(fd_in, F_SETFD, FD_CLOEXEC);
        fcntl(fd_out, F_SETFD, FD_CLOEXEC);
        fcntl(fd_err, F_SETFD, FD_CLOEXEC);
    }

    size_t payload_len = payload_json ? strlen(payload_json) : 0;
    size_t payload_off = 0;
    bool stdin_open = true;
    if (payload_len == 0) {
        /* Nothing to write -- close immediately so the hook sees EOF on
         * stdin right away instead of waiting on a pipe that will never
         * receive data. */
        close(fd_in);
        fd_in = -1;
        stdin_open = false;
    }

    /* out_buf (the hook's stdout) is read and capped the same way err_buf
     * is, but purely to keep the pipe drained so a chatty hook can never
     * backpressure-block on a full stdout pipe -- its contents are never
     * surfaced anywhere (only stderr becomes block_reason on exit 2). */
    char *out_buf = malloc(DS4_HOOKS_CAP_BYTES);
    char *err_buf = malloc(DS4_HOOKS_CAP_BYTES);
    size_t out_len = 0, err_len = 0;
    bool out_eof = false, err_eof = false;
    bool timed_out = false;

    int timeout_ms = he->timeout_ms > 0 ? he->timeout_ms : DS4_HOOKS_DEFAULT_TIMEOUT_MS;
    long deadline = hk_now_ms() + timeout_ms;

    while (!out_eof || !err_eof) {
        long remaining = deadline - hk_now_ms();
        if (remaining <= 0) { timed_out = true; break; }

        fd_set rfds, wfds;
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        int maxfd = -1;
        if (!out_eof) { FD_SET(fd_out, &rfds); if (fd_out > maxfd) maxfd = fd_out; }
        if (!err_eof) { FD_SET(fd_err, &rfds); if (fd_err > maxfd) maxfd = fd_err; }
        if (stdin_open) { FD_SET(fd_in, &wfds); if (fd_in > maxfd) maxfd = fd_in; }

        struct timeval tv;
        tv.tv_sec = remaining / 1000;
        tv.tv_usec = (remaining % 1000) * 1000;
        int sel = select(maxfd + 1, &rfds, &wfds, NULL, &tv);
        if (sel < 0) {
            if (errno == EINTR) continue;
            break; /* fall through to reap + report whatever we captured */
        }
        if (sel == 0) { timed_out = true; break; }

        if (stdin_open && FD_ISSET(fd_in, &wfds)) {
            ssize_t wn = write(fd_in, payload_json + payload_off, payload_len - payload_off);
            if (wn < 0) {
                /* EPIPE (hook never reads stdin) and any other write error
                 * both just mean "stop trying to write" -- not a hook
                 * failure by themselves; the hook's exit code still decides
                 * the outcome. */
                if (errno != EAGAIN && errno != EINTR) {
                    close(fd_in);
                    fd_in = -1;
                    stdin_open = false;
                }
            } else {
                payload_off += (size_t)wn;
                if (payload_off >= payload_len) {
                    close(fd_in);
                    fd_in = -1;
                    stdin_open = false;
                }
            }
        }
        if (!out_eof && FD_ISSET(fd_out, &rfds)) {
            char chunk[DS4_HOOKS_READ_CHUNK];
            ssize_t rn = read(fd_out, chunk, sizeof(chunk));
            if (rn == 0) out_eof = true;
            else if (rn < 0) { if (errno != EAGAIN && errno != EINTR) out_eof = true; }
            else {
                size_t room = out_len < DS4_HOOKS_CAP_BYTES ? DS4_HOOKS_CAP_BYTES - out_len : 0;
                size_t take = (size_t)rn < room ? (size_t)rn : room;
                if (take) { memcpy(out_buf + out_len, chunk, take); out_len += take; }
            }
        }
        if (!err_eof && FD_ISSET(fd_err, &rfds)) {
            char chunk[DS4_HOOKS_READ_CHUNK];
            ssize_t rn = read(fd_err, chunk, sizeof(chunk));
            if (rn == 0) err_eof = true;
            else if (rn < 0) { if (errno != EAGAIN && errno != EINTR) err_eof = true; }
            else {
                size_t room = err_len < DS4_HOOKS_CAP_BYTES ? DS4_HOOKS_CAP_BYTES - err_len : 0;
                size_t take = (size_t)rn < room ? (size_t)rn : room;
                if (take) { memcpy(err_buf + err_len, chunk, take); err_len += take; }
            }
        }
    }

    int status = 0;
    bool reaped = false;
    if (!timed_out) {
        for (;;) {
            pid_t wr = waitpid(pid, &status, WNOHANG);
            if (wr == pid) { reaped = true; break; }
            if (hk_now_ms() >= deadline) { timed_out = true; break; }
            struct timespec nap = { 0, 5 * 1000 * 1000 }; /* 5ms poll */
            nanosleep(&nap, NULL);
        }
    }

    if (timed_out) {
        kill(-pid, SIGKILL);
        waitpid(pid, NULL, 0);
        out->status = HOOK_RUN_WARN;
        out->warn_msg = hk_fmt("timeout after %dms", timeout_ms);
    } else if (reaped && WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 0) {
            out->status = HOOK_RUN_OK;
        } else if (code == 2) {
            out->status = HOOK_RUN_BLOCKED;
            out->block_reason = hk_trim_dup(err_buf, err_len);
            if (!out->block_reason) out->block_reason = hk_strdup("");
        } else {
            out->status = HOOK_RUN_WARN;
            out->warn_msg = hk_fmt("hook exited with status %d", code);
        }
    } else {
        out->status = HOOK_RUN_WARN;
        out->warn_msg = hk_fmt("hook terminated abnormally");
    }

    if (fd_in >= 0) close(fd_in);
    close(fd_out);
    close(fd_err);
    free(out_buf);
    free(err_buf);
}

/* Appends a formatted "hooks: <tool_name>: <reason>\n" line to *acc
 * (realloc'd; NULL-safe; best-effort on OOM -- a dropped warning line is
 * never treated as fatal). */
static void hk_warnings_append(char **acc, const char *tool_name, const char *reason) {
    char *line = hk_fmt("hooks: %s: %s\n", tool_name, reason);
    size_t old_len = *acc ? strlen(*acc) : 0;
    size_t add_len = strlen(line);
    char *np = realloc(*acc, old_len + add_len + 1);
    if (np) {
        memcpy(np + old_len, line, add_len + 1);
        *acc = np;
    }
    free(line);
}

ds4_hook_result ds4_hooks_run(ds4_hooks *h, ds4_hook_event event,
                              const char *tool_name, const char *payload_json) {
    ds4_hook_result res = {0};
    if (!h) return res;
    const char *name = tool_name ? tool_name : "";
    hook_entry_list *list = &h->events[event];

    for (int i = 0; i < list->len; i++) {
        hook_entry *he = &list->v[i];
        if (fnmatch(he->matcher, name, 0) != 0) continue;

        hook_run_outcome out;
        hk_run_one(h, he, payload_json, &out);

        if (out.status == HOOK_RUN_BLOCKED) {
            res.blocked = true;
            res.block_reason = out.block_reason;
            break; /* stops at the first block; later hooks never run */
        }
        if (out.status == HOOK_RUN_WARN) {
            hk_warnings_append(&res.warnings, name, out.warn_msg ? out.warn_msg : "unknown failure");
            free(out.warn_msg);
        }
    }
    return res;
}

void ds4_hook_result_free(ds4_hook_result *r) {
    if (!r) return;
    free(r->block_reason);
    free(r->warnings);
    memset(r, 0, sizeof(*r));
}

#ifdef DS4_HOOKS_TEST

#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>

static int hooks_test_failures;

static void hooks_test_assert(int cond, const char *expr, const char *file, int line) {
    if (cond) return;
    fprintf(stderr, "%s:%d: assertion failed: %s\n", file, line, expr);
    hooks_test_failures++;
}
#define HOOKS_TEST_ASSERT(expr) hooks_test_assert((expr), #expr, __FILE__, __LINE__)

/* ---- self-contained fixture helpers (independent of module internals, mirrors ds4_mcp_test) ---- */

static char *hkt_join(const char *dir, const char *name) {
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

static void hkt_mkdir_p(const char *path) {
    char *tmp = hk_strdup(path);
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

static void hkt_write_file(const char *path, const char *content) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return;
    fwrite(content, 1, strlen(content), fp);
    fclose(fp);
}

static void hkt_rmtree(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return;
    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        if (d) {
            struct dirent *de;
            while ((de = readdir(d)) != NULL) {
                if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
                char *child = hkt_join(path, de->d_name);
                if (child) { hkt_rmtree(child); free(child); }
            }
            closedir(d);
        }
        rmdir(path);
    } else {
        unlink(path);
    }
}

static void hkt_setenv_home(const char *value, char **saved_out) {
    const char *cur = getenv("HOME");
    *saved_out = cur ? hk_strdup(cur) : NULL;
    if (value) setenv("HOME", value, 1);
    else unsetenv("HOME");
}

static void hkt_restore_home(char *saved) {
    if (saved) { setenv("HOME", saved, 1); free(saved); }
    else unsetenv("HOME");
}

static char *hkt_resolve_fixture(const char *rel) {
    char buf[PATH_MAX];
    if (!realpath(rel, buf)) {
        fprintf(stderr, "ds4_hooks test fixture: could not resolve %s\n", rel);
        return NULL;
    }
    chmod(buf, 0755); /* defensive: survive checkout quirks that drop +x */
    return hk_strdup(buf);
}

/* Sets up <tmp>/proj/.ds4/settings.json (if proj_json non-NULL) and
 * <tmp>/home/.ds4/settings.json (if user_json non-NULL) under an isolated
 * HOME, and loads the config. Caller frees out_fx/out_home/out_saved_home
 * and the returned ds4_config (via ds4_config_free). */
static ds4_config *hkt_setup(const char *proj_json, const char *user_json,
                             char **out_fx, char **out_home, char **out_saved_home) {
    char tmpl[] = "/tmp/ds4_hooks_test.XXXXXX";
    char *fx = mkdtemp(tmpl);
    HOOKS_TEST_ASSERT(fx != NULL);
    if (!fx) return NULL;
    fx = hk_strdup(fx);

    char *proj = hkt_join(fx, "proj");
    char *proj_ds4 = hkt_join(proj, ".ds4");
    hkt_mkdir_p(proj_ds4);
    if (proj_json) {
        char *proj_settings = hkt_join(proj_ds4, "settings.json");
        hkt_write_file(proj_settings, proj_json);
        free(proj_settings);
    }

    char *home = hkt_join(fx, "home");
    char *home_ds4 = hkt_join(home, ".ds4");
    hkt_mkdir_p(home_ds4);
    if (user_json) {
        char *home_settings = hkt_join(home_ds4, "settings.json");
        hkt_write_file(home_settings, user_json);
        free(home_settings);
    }

    char *saved_home;
    hkt_setenv_home(home, &saved_home);

    ds4_config *cfg = ds4_config_load(proj, NULL, 0);

    *out_fx = fx;
    *out_home = home;
    *out_saved_home = saved_home;
    free(proj); free(proj_ds4); free(home_ds4);
    return cfg;
}

static void hkt_teardown(char *fx, char *home, char *saved_home) {
    hkt_restore_home(saved_home);
    free(home);
    hkt_rmtree(fx);
    free(fx);
}

static long hkt_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ---- test groups (A1-A10) ---- */

static void test_allow(const char *allow_path) {
    char settings[1024];
    snprintf(settings, sizeof(settings),
             "{\"hooks\":{\"PreToolUse\":[{\"matcher\":\"bash\",\"command\":\"%s\"}]}}",
             allow_path);
    char *fx, *home, *saved_home;
    ds4_config *cfg = hkt_setup(settings, NULL, &fx, &home, &saved_home);
    HOOKS_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        char warn[256] = {0};
        ds4_hooks *h = ds4_hooks_load(cfg, warn, sizeof(warn));
        HOOKS_TEST_ASSERT(h != NULL);
        if (h) {
            ds4_hook_result r = ds4_hooks_run(h, DS4_HOOK_PRE_TOOL, "bash",
                                             "{\"event\":\"PreToolUse\"}");
            HOOKS_TEST_ASSERT(!r.blocked);
            HOOKS_TEST_ASSERT(r.warnings == NULL);
            ds4_hook_result_free(&r);
            ds4_hooks_free(h);
        }
    }
    ds4_config_free(cfg);
    hkt_teardown(fx, home, saved_home);
}

static void test_block(const char *block_path) {
    char settings[1024];
    snprintf(settings, sizeof(settings),
             "{\"hooks\":{\"PreToolUse\":[{\"matcher\":\"bash\",\"command\":\"HOOK_TEST_TAG=tag123 %s\"}]}}",
             block_path);
    char *fx, *home, *saved_home;
    ds4_config *cfg = hkt_setup(settings, NULL, &fx, &home, &saved_home);
    HOOKS_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        char warn[256] = {0};
        ds4_hooks *h = ds4_hooks_load(cfg, warn, sizeof(warn));
        HOOKS_TEST_ASSERT(h != NULL);
        if (h) {
            ds4_hook_result r = ds4_hooks_run(h, DS4_HOOK_PRE_TOOL, "bash", "{}");
            HOOKS_TEST_ASSERT(r.blocked);
            HOOKS_TEST_ASSERT(r.block_reason != NULL && strstr(r.block_reason, "tag123") != NULL);
            ds4_hook_result_free(&r);
            ds4_hooks_free(h);
        }
    }
    ds4_config_free(cfg);
    hkt_teardown(fx, home, saved_home);
}

static void test_fail_open(const char *broken_path) {
    char settings[1024];
    snprintf(settings, sizeof(settings),
             "{\"hooks\":{\"PreToolUse\":[{\"matcher\":\"bash\",\"command\":\"%s\"}]}}",
             broken_path);
    char *fx, *home, *saved_home;
    ds4_config *cfg = hkt_setup(settings, NULL, &fx, &home, &saved_home);
    HOOKS_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        char warn[256] = {0};
        ds4_hooks *h = ds4_hooks_load(cfg, warn, sizeof(warn));
        HOOKS_TEST_ASSERT(h != NULL);
        if (h) {
            ds4_hook_result r = ds4_hooks_run(h, DS4_HOOK_PRE_TOOL, "bash", "{}");
            HOOKS_TEST_ASSERT(!r.blocked);
            HOOKS_TEST_ASSERT(r.warnings != NULL);
            ds4_hook_result_free(&r);
            ds4_hooks_free(h);
        }
    }
    ds4_config_free(cfg);
    hkt_teardown(fx, home, saved_home);
}

static void test_timeout(const char *slow_path) {
    char settings[1024];
    snprintf(settings, sizeof(settings),
             "{\"hooks\":{\"PreToolUse\":[{\"matcher\":\"bash\",\"command\":\"%s\",\"timeout_ms\":300}]}}",
             slow_path);
    char *fx, *home, *saved_home;
    ds4_config *cfg = hkt_setup(settings, NULL, &fx, &home, &saved_home);
    HOOKS_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        char warn[256] = {0};
        ds4_hooks *h = ds4_hooks_load(cfg, warn, sizeof(warn));
        HOOKS_TEST_ASSERT(h != NULL);
        if (h) {
            long t0 = hkt_now_ms();
            ds4_hook_result r = ds4_hooks_run(h, DS4_HOOK_PRE_TOOL, "bash", "{}");
            long t1 = hkt_now_ms();
            HOOKS_TEST_ASSERT(!r.blocked);
            HOOKS_TEST_ASSERT(r.warnings != NULL && strstr(r.warnings, "timeout") != NULL);
            HOOKS_TEST_ASSERT((t1 - t0) < 2000);
            ds4_hook_result_free(&r);
            ds4_hooks_free(h);
        }
    }
    ds4_config_free(cfg);
    hkt_teardown(fx, home, saved_home);
}

static void test_matcher(const char *block_path) {
    /* Exact match vs. non-match: the block fixture doubles as a semaphore --
     * "did it run" is observable as "did it block". */
    {
        char settings[1024];
        snprintf(settings, sizeof(settings),
                 "{\"hooks\":{\"PreToolUse\":[{\"matcher\":\"bash\",\"command\":\"%s\"}]}}",
                 block_path);
        char *fx, *home, *saved_home;
        ds4_config *cfg = hkt_setup(settings, NULL, &fx, &home, &saved_home);
        if (cfg) {
            char warn[256] = {0};
            ds4_hooks *h = ds4_hooks_load(cfg, warn, sizeof(warn));
            if (h) {
                ds4_hook_result r1 = ds4_hooks_run(h, DS4_HOOK_PRE_TOOL, "bash", "{}");
                HOOKS_TEST_ASSERT(r1.blocked); /* matcher "bash" == tool "bash": ran */
                ds4_hook_result_free(&r1);

                ds4_hook_result r2 = ds4_hooks_run(h, DS4_HOOK_PRE_TOOL, "edit", "{}");
                HOOKS_TEST_ASSERT(!r2.blocked); /* matcher "bash" != tool "edit": did not run */
                ds4_hook_result_free(&r2);

                HOOKS_TEST_ASSERT(ds4_hooks_count(h, DS4_HOOK_POST_TOOL) == 0);
                ds4_hook_result r3 = ds4_hooks_run(h, DS4_HOOK_POST_TOOL, "bash", "{}");
                HOOKS_TEST_ASSERT(!r3.blocked); /* PreToolUse entry never fires for POST_TOOL */
                ds4_hook_result_free(&r3);

                ds4_hooks_free(h);
            }
        }
        ds4_config_free(cfg);
        hkt_teardown(fx, home, saved_home);
    }
    /* Glob "ba*" matches "bash"; "*" matches anything. */
    {
        char settings[1024];
        snprintf(settings, sizeof(settings),
                 "{\"hooks\":{\"PreToolUse\":["
                 "{\"matcher\":\"ba*\",\"command\":\"%s\"}"
                 "]}}",
                 block_path);
        char *fx, *home, *saved_home;
        ds4_config *cfg = hkt_setup(settings, NULL, &fx, &home, &saved_home);
        if (cfg) {
            char warn[256] = {0};
            ds4_hooks *h = ds4_hooks_load(cfg, warn, sizeof(warn));
            if (h) {
                ds4_hook_result r = ds4_hooks_run(h, DS4_HOOK_PRE_TOOL, "bash", "{}");
                HOOKS_TEST_ASSERT(r.blocked);
                ds4_hook_result_free(&r);
                ds4_hooks_free(h);
            }
        }
        ds4_config_free(cfg);
        hkt_teardown(fx, home, saved_home);
    }
    {
        char settings[1024];
        snprintf(settings, sizeof(settings),
                 "{\"hooks\":{\"PreToolUse\":[{\"matcher\":\"*\",\"command\":\"%s\"}]}}",
                 block_path);
        char *fx, *home, *saved_home;
        ds4_config *cfg = hkt_setup(settings, NULL, &fx, &home, &saved_home);
        if (cfg) {
            char warn[256] = {0};
            ds4_hooks *h = ds4_hooks_load(cfg, warn, sizeof(warn));
            if (h) {
                ds4_hook_result r = ds4_hooks_run(h, DS4_HOOK_PRE_TOOL, "anything_at_all", "{}");
                HOOKS_TEST_ASSERT(r.blocked);
                ds4_hook_result_free(&r);
                ds4_hooks_free(h);
            }
        }
        ds4_config_free(cfg);
        hkt_teardown(fx, home, saved_home);
    }
}

static void test_stdin_payload(const char *stdin_path) {
    char out_tmpl[] = "/tmp/ds4_hooks_stdin_out.XXXXXX";
    int outfd = mkstemp(out_tmpl);
    HOOKS_TEST_ASSERT(outfd >= 0);
    if (outfd >= 0) close(outfd);

    char settings[1024];
    snprintf(settings, sizeof(settings),
             "{\"hooks\":{\"PreToolUse\":[{\"matcher\":\"*\",\"command\":\"HOOK_STDIN_OUT=%s %s\"}]}}",
             out_tmpl, stdin_path);
    char *fx, *home, *saved_home;
    ds4_config *cfg = hkt_setup(settings, NULL, &fx, &home, &saved_home);
    HOOKS_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        char warn[256] = {0};
        ds4_hooks *h = ds4_hooks_load(cfg, warn, sizeof(warn));
        HOOKS_TEST_ASSERT(h != NULL);
        if (h) {
            const char *payload =
                "{\"event\":\"PreToolUse\",\"tool_name\":\"bash\",\"tool_input\":{\"command\":\"echo hi\"}}";
            ds4_hook_result r = ds4_hooks_run(h, DS4_HOOK_PRE_TOOL, "bash", payload);
            HOOKS_TEST_ASSERT(!r.blocked);
            ds4_hook_result_free(&r);

            FILE *fp = fopen(out_tmpl, "rb");
            HOOKS_TEST_ASSERT(fp != NULL);
            if (fp) {
                char buf[4096];
                size_t n = fread(buf, 1, sizeof(buf), fp);
                HOOKS_TEST_ASSERT(n == strlen(payload));
                HOOKS_TEST_ASSERT(n == strlen(payload) && memcmp(buf, payload, n) == 0);
                fclose(fp);
            }
            ds4_hooks_free(h);
        }
    }
    ds4_config_free(cfg);
    unlink(out_tmpl);
    hkt_teardown(fx, home, saved_home);
}

static void test_ordering_first_block_stops(const char *block_path) {
    char tmpl[] = "/tmp/ds4_hooks_ordering.XXXXXX";
    char *fx0 = mkdtemp(tmpl);
    HOOKS_TEST_ASSERT(fx0 != NULL);
    if (!fx0) return;
    char *sentinel = hkt_join(fx0, "sentinel");

    char settings[2048];
    snprintf(settings, sizeof(settings),
             "{\"hooks\":{\"PreToolUse\":["
             "{\"matcher\":\"*\",\"command\":\"HOOK_TEST_TAG=first %s\"},"
             "{\"matcher\":\"*\",\"command\":\"touch %s\"}"
             "]}}",
             block_path, sentinel);
    char *fx, *home, *saved_home;
    ds4_config *cfg = hkt_setup(settings, NULL, &fx, &home, &saved_home);
    HOOKS_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        char warn[256] = {0};
        ds4_hooks *h = ds4_hooks_load(cfg, warn, sizeof(warn));
        HOOKS_TEST_ASSERT(h != NULL);
        if (h) {
            HOOKS_TEST_ASSERT(ds4_hooks_count(h, DS4_HOOK_PRE_TOOL) == 2);
            ds4_hook_result r = ds4_hooks_run(h, DS4_HOOK_PRE_TOOL, "bash", "{}");
            HOOKS_TEST_ASSERT(r.blocked);
            struct stat st;
            HOOKS_TEST_ASSERT(stat(sentinel, &st) != 0); /* second hook must never have run */
            ds4_hook_result_free(&r);
            ds4_hooks_free(h);
        }
    }
    ds4_config_free(cfg);
    hkt_teardown(fx, home, saved_home);
    free(sentinel);
    hkt_rmtree(fx0);
}

static void test_no_hooks_key(void) {
    char *fx, *home, *saved_home;
    ds4_config *cfg = hkt_setup(NULL, NULL, &fx, &home, &saved_home);
    HOOKS_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        char warn[256] = {0};
        ds4_hooks *h = ds4_hooks_load(cfg, warn, sizeof(warn));
        HOOKS_TEST_ASSERT(h == NULL);
    }
    ds4_hook_result r = ds4_hooks_run(NULL, DS4_HOOK_PRE_TOOL, "bash", "{}");
    HOOKS_TEST_ASSERT(!r.blocked);
    HOOKS_TEST_ASSERT(r.block_reason == NULL);
    HOOKS_TEST_ASSERT(r.warnings == NULL);
    ds4_config_free(cfg);
    hkt_teardown(fx, home, saved_home);
}

static void test_wholesale_override(const char *allow_path, const char *block_path) {
    char proj_settings[1024];
    snprintf(proj_settings, sizeof(proj_settings),
             "{\"hooks\":{\"PreToolUse\":[{\"matcher\":\"bash\",\"command\":\"%s\"}]}}",
             allow_path);
    char user_settings[1024];
    snprintf(user_settings, sizeof(user_settings),
             "{\"hooks\":{\"PreToolUse\":[{\"matcher\":\"bash\",\"command\":\"%s\"}]}}",
             block_path);
    char *fx, *home, *saved_home;
    ds4_config *cfg = hkt_setup(proj_settings, user_settings, &fx, &home, &saved_home);
    HOOKS_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        char warn[256] = {0};
        ds4_hooks *h = ds4_hooks_load(cfg, warn, sizeof(warn));
        HOOKS_TEST_ASSERT(h != NULL);
        if (h) {
            HOOKS_TEST_ASSERT(ds4_hooks_count(h, DS4_HOOK_PRE_TOOL) == 1);
            ds4_hook_result r = ds4_hooks_run(h, DS4_HOOK_PRE_TOOL, "bash", "{}");
            /* If the user's block hook ran too, the merge was deep, not
             * wholesale -- it must not run at all. */
            HOOKS_TEST_ASSERT(!r.blocked);
            ds4_hook_result_free(&r);
            ds4_hooks_free(h);
        }
    }
    ds4_config_free(cfg);
    hkt_teardown(fx, home, saved_home);
}

static void test_malformed_entries_skipped(const char *allow_path) {
    char settings[2048];
    snprintf(settings, sizeof(settings),
             "{\"hooks\":{"
             "\"PreToolUse\":["
             "{\"matcher\":\"bash\"},"
             "\"not-an-object\","
             "{\"matcher\":\"bash\",\"command\":\"%s\"}"
             "],"
             "\"NotARealEvent\":[{\"command\":\"%s\"}],"
             "\"PostToolUse\":\"not-an-array\""
             "}}",
             allow_path, allow_path);
    char *fx, *home, *saved_home;
    ds4_config *cfg = hkt_setup(settings, NULL, &fx, &home, &saved_home);
    HOOKS_TEST_ASSERT(cfg != NULL);
    if (cfg) {
        char warn[1024] = {0};
        ds4_hooks *h = ds4_hooks_load(cfg, warn, sizeof(warn));
        HOOKS_TEST_ASSERT(h != NULL);
        HOOKS_TEST_ASSERT(warn[0] != '\0');
        if (h) {
            HOOKS_TEST_ASSERT(ds4_hooks_count(h, DS4_HOOK_PRE_TOOL) == 1);
            HOOKS_TEST_ASSERT(ds4_hooks_count(h, DS4_HOOK_POST_TOOL) == 0);
            ds4_hook_result r = ds4_hooks_run(h, DS4_HOOK_PRE_TOOL, "bash", "{}");
            HOOKS_TEST_ASSERT(!r.blocked);
            ds4_hook_result_free(&r);
            ds4_hooks_free(h);
        }
    }
    ds4_config_free(cfg);
    hkt_teardown(fx, home, saved_home);
}

int ds4_hooks_unit_tests_run(void) {
    char *allow = hkt_resolve_fixture("tests/fixtures/hook_allow.sh");
    char *block = hkt_resolve_fixture("tests/fixtures/hook_block.sh");
    char *broken = hkt_resolve_fixture("tests/fixtures/hook_broken.sh");
    char *stdin_fx = hkt_resolve_fixture("tests/fixtures/hook_stdin.sh");
    char *slow = hkt_resolve_fixture("tests/fixtures/hook_slow.sh");
    HOOKS_TEST_ASSERT(allow && block && broken && stdin_fx && slow);

    if (allow && block && broken && stdin_fx && slow) {
        test_allow(allow);
        test_block(block);
        test_fail_open(broken);
        test_timeout(slow);
        test_matcher(block);
        test_stdin_payload(stdin_fx);
        test_ordering_first_block_stops(block);
        test_no_hooks_key();
        test_wholesale_override(allow, block);
        test_malformed_entries_skipped(allow);
    }

    free(allow); free(block); free(broken); free(stdin_fx); free(slow);
    return hooks_test_failures;
}

#endif
