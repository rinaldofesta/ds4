#ifndef DS4_SKILLS_H
#define DS4_SKILLS_H
#include <stddef.h>
#include "ds4_config.h"

/* Agent Skills discovery: SKILL.md files under the config search roots. See
 * ds4_skills.c for the frontmatter grammar and sanitization rules. */

typedef struct {
    char *name;
    char *description;
    char *dir;   /* directory containing SKILL.md */
} ds4_skill_meta;

typedef struct { ds4_skill_meta *v; int len; int cap; } ds4_skill_list;

/* Scans all config roots. Appends warning lines to warn (as in ds4_config_load). */
void ds4_skills_scan(const ds4_config *cfg, ds4_skill_list *out, char *warn, size_t warn_len);
void ds4_skills_list_free(ds4_skill_list *list);

const ds4_skill_meta *ds4_skills_find(const ds4_skill_list *list, const char *name);
/* Full markdown body (post-frontmatter) of the named skill, malloc'd; NULL if
 * unknown or unreadable. Re-reads from disk at call time. */
char *ds4_skills_load_body(const ds4_skill_list *list, const char *name);

/* System-prompt catalog block. NULL if list is empty (CRITICAL: no skills ==
 * no prompt change). Otherwise a malloc'd string in EXACTLY the format below. */
char *ds4_skills_catalog_prompt_text(const ds4_skill_list *list);

/* Exposed for tests: */
bool ds4_skills_parse_frontmatter(const char *text, char **name, char **description,
                                  const char **body_start);

#ifdef DS4_SKILLS_TEST
int ds4_skills_unit_tests_run(void);
#endif
#endif
