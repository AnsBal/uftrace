#include <string.h>
#include <link.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "fasttp"
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
	char name[];
};

static struct mcount_dynamic_stats {
	int total;
	int failed;
	int skipped;
	int nomatch;
} stats;

static LIST_HEAD(tracepoint_list);

static float calc_percent(int n, int total)
{
	if (total == 0)
		return 0;

	return 100.0 * n / total;
}

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

	#define FASTTP_SKIP_SYMBOL(func)  { #func }
		struct {
			const char *name;
		} fasttp_skip_symbol[] = {
			/* mcount functions */
			FASTTP_SKIP_SYMBOL(_start),
			FASTTP_SKIP_SYMBOL(__gmon_start__),
			FASTTP_SKIP_SYMBOL(__static_initialization_and_destruction_0),
			FASTTP_SKIP_SYMBOL(_GLOBAL__sub_I_myex),
			FASTTP_SKIP_SYMBOL(__libc_csu_init),
			FASTTP_SKIP_SYMBOL(__libc_csu_fini),
			FASTTP_SKIP_SYMBOL(atexit),
		};
	#undef FASTTP_SKIP_SYMBOL
	size_t fasttp_skip_nr = ARRAY_SIZE(fasttp_skip_symbol);

	strv_split(&funcs, patch_funcs, ";");
	memset(&stats, 0, sizeof(stats));
	strv_for_each(&funcs, name, j) {
		unsigned i, j;
		struct sym *sym;
		struct uftrace_pattern patt;

		init_filter_pattern(ptype, &patt, name);

		for (i = 0; i < symtab->nr_sym; i++) {
			sym = &symtab->sym[i];
			bool skip = false;
			stats.total++;
			
			for (j = 0; j < fasttp_skip_nr; j++) {
				if (!strcmp(sym->name, fasttp_skip_symbol[j].name)) {
					skip = true;
					break;
				}
			}	

			if (!match_filter_pattern(&patt, sym->name) || skip) {
				stats.skipped++;
				continue;
			}
			if(sym->type != ST_LOCAL_FUNC && sym->type != ST_GLOBAL_FUNC && sym->type != ST_WEAK_FUNC) {
				stats.skipped++;
				continue;
			}

			tracepoint* tp = new_tracepoint((void*) sym->addr);

			if(!tp){
				pr_blue("failed to insert fasttp tracepoint in symbol: %s \n", sym->name);
				stats.failed++;
				continue;
			}
			
			struct tracepoint_handler* tracepoint_h;
			tracepoint_h = xmalloc(sizeof(*tracepoint_h) + strlen(sym->name) + 1);
			tracepoint_h->tp = tp;
			strcpy(tracepoint_h->name, sym->name);
			
			INIT_LIST_HEAD(&tracepoint_h->list);
			list_add(&tracepoint_h->list, &tracepoint_list);

			pr_blue("successfully inserted fasttp tracepoint in symbol: %s \n", tracepoint_h->name);
		}

		free_filter_pattern(&patt);
	}

	int success = stats.total - stats.failed - stats.skipped;
	pr_dbg("dynamic update stats:\n");
	pr_dbg("   total: %8d\n", stats.total);
	pr_dbg(" patched: %8d (%.2f%%)\n", success,
	       calc_percent(success, stats.total));
	pr_dbg("  failed: %8d (%.2f%%)\n", stats.failed,
	       calc_percent(stats.failed, stats.total));
	pr_dbg(" skipped: %8d (%.2f%%)\n", stats.skipped,
	       calc_percent(stats.skipped, stats.total));

	strv_free(&funcs);
	return ret;
}

static void free_tracepoint_handler(struct tracepoint_handler *tracepoint_h) 
{
	delete_tracepoint(tracepoint_h->tp);
	free(tracepoint_h);
}

/* FIXME Invalid return address, SHOULD NOT HAPPEN */
void mcount_cleanup_fasttp()
{
	struct tracepoint_handler *tracepoint_h, *tracepoint_h_tmp;
	list_for_each_entry_safe(tracepoint_h, tracepoint_h_tmp, &tracepoint_list, list) {
		pr_dbg2("removed fasttp tracepoint from symbol: %s \n", tracepoint_h->name);
		list_del(&tracepoint_h->list);
		free_tracepoint_handler(tracepoint_h);
	}
	INIT_LIST_HEAD(&tracepoint_list);
}