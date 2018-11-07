#include <string.h>
#include <link.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "dynamic-fasttp"
#define PR_DOMAIN  DBG_DYNAMIC

#include "libmcount/mcount.h"
#include "libmcount/internal.h"
#include "utils/utils.h"
#include "utils/list.h"
#include "utils/symbol.h"
#include "utils/filter.h"
#include "libfasttp/fasttp_wrapper.h"

struct tracepoint_handler {
	struct list_head list;
	tracepoint* tp;
};

static LIST_HEAD(tracepoint_list);

int mcount_setup_fasttp(struct symtabs *symtabs, char *patch_funcs, 
	enum uftrace_pattern_type ptype)
{
	int ret = 0;
	char *name = NULL;
	struct symtab *symtab = &symtabs->symtab;
	struct strv funcs = STRV_INIT;
	int j;

	if (patch_funcs == NULL)
		return 0;

	strv_split(&funcs, patch_funcs, ";");

	strv_for_each(&funcs, name, j) {
		unsigned i;
		struct sym *sym;
		struct uftrace_pattern patt;

		init_filter_pattern(ptype, &patt, name);

		for (i = 0; i < symtab->nr_sym; i++) {
			sym = &symtab->sym[i];

			if (!match_filter_pattern(&patt, sym->name))
				continue;

			struct tracepoint_handler* tracepoint_h;
			tracepoint_h = xmalloc(sizeof(*tracepoint_h));
			tracepoint_h->tp = new_tracepoint((void*) sym->addr);
			
			INIT_LIST_HEAD(&tracepoint_h->list);
			list_add(&tracepoint_h->list, &tracepoint_list);
		}

		free_filter_pattern(&patt);
	}

	strv_free(&funcs);
	return ret;
}

void mcount_cleanup_fasttp()
{
	struct tracepoint_handler *tracepoint_h;
	list_for_each_entry(tracepoint_h, &tracepoint_list, list) {
		delete_tracepoint(tracepoint_h->tp);
		free(tracepoint_h);
	}
}