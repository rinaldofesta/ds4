#ifndef DS4_JSON_H
#define DS4_JSON_H
#include <stddef.h>
#include <stdbool.h>

typedef enum { DS4_JSON_NULL, DS4_JSON_BOOL, DS4_JSON_NUM,
               DS4_JSON_STR, DS4_JSON_ARR, DS4_JSON_OBJ } ds4_json_type;

typedef struct ds4_json_value ds4_json_value;

/* Parse a NUL-terminated JSON text. On success returns the root (caller frees
 * with ds4_json_free). On failure returns NULL and writes a short message
 * into err (if err_len > 0). Trailing non-whitespace after the value is an error. */
ds4_json_value *ds4_json_parse(const char *text, char *err, size_t err_len);
void ds4_json_free(ds4_json_value *v);

ds4_json_type ds4_json_type_of(const ds4_json_value *v);
/* Accessors are NULL-tolerant: passing NULL returns the default/NULL. */
const char *ds4_json_str(const ds4_json_value *v);            /* NULL if not DS4_JSON_STR */
double      ds4_json_num(const ds4_json_value *v, double def);
bool        ds4_json_bool(const ds4_json_value *v, bool def);
int         ds4_json_arr_len(const ds4_json_value *v);         /* 0 if not array */
const ds4_json_value *ds4_json_arr_get(const ds4_json_value *v, int i);
const ds4_json_value *ds4_json_obj_get(const ds4_json_value *v, const char *key);
/* Object iteration (needed by callers that enumerate mcpServers entries): */
int         ds4_json_obj_len(const ds4_json_value *v);         /* 0 if not object */
const char *ds4_json_obj_key_at(const ds4_json_value *v, int i);
const ds4_json_value *ds4_json_obj_val_at(const ds4_json_value *v, int i);
/* Verbatim source span of this value (malloc'd copy, caller frees) -- used to
 * pass tool inputSchema JSON through untouched. Whitespace inside the span is
 * preserved as-written; leading/trailing whitespace outside the value is not
 * included. NULL if v is NULL. */
char *ds4_json_raw(const ds4_json_value *v);

/* Minimal writer for composing requests. */
typedef struct { char *ptr; size_t len; size_t cap; } ds4_json_writer;
void  ds4_json_w_free(ds4_json_writer *w);
char *ds4_json_w_take(ds4_json_writer *w);   /* returns buffer (never NULL; "" if empty), resets w */
void  ds4_json_w_raw(ds4_json_writer *w, const char *s);      /* append as-is */
void  ds4_json_w_string(ds4_json_writer *w, const char *s);   /* append "..." with full JSON escaping */

#ifdef DS4_JSON_TEST
int ds4_json_unit_tests_run(void);  /* returns number of failures */
#endif
#endif
