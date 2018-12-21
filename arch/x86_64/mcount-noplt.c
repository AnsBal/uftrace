#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <dlfcn.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "mcount"
#define PR_DOMAIN  DBG_MCOUNT

#include "uftrace.h"
#include "libmcount/mcount.h"
#include "libmcount/internal.h"
#include "utils/utils.h"
#include "utils/symbol.h"

#define TRAMP_ENT_SIZE    16  /* size of trampoilne for each entry */
#define TRAMP_PLT0_SIZE   32  /* module id + addres of plthook_addr() */
#define TRAMP_PCREL_JMP   10  /* PC_relative offset for JMP */
#define TRAMP_IDX_OFFSET  1
#define TRAMP_JMP_OFFSET  6

extern void __weak plt_hooker(void);
struct plthook_data * mcount_arch_hook_no_plt(struct uftrace_elf_data *elf,
					      const char *modname,
					      unsigned long offset)
{
	struct plthook_data *pd;
	void *trampoline;
	size_t tramp_len;
	uint32_t i;
	const uint8_t tramp_plt0[] = {  /* followed by module_id + plthook_addr */
		/* PUSH module_id */
		0xff, 0x35, 0xa, 0, 0, 0,
		/* JMP plthook_addr */
		0xff, 0x25, 0xc, 0, 0, 0,
		0xcc, 0xcc, 0xcc, 0xcc,
	};
	const uint8_t tramp_insns[] = {  /* make stack what plt_hooker expect */
		/* PUSH child_idx */
		0x68, 0, 0, 0, 0,
		/* JMP plt0 */
		0xe9, 0, 0, 0, 0,
		/* should never reach here */
		0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
	};
	const uint8_t tramp_plt1[] = {  
		/* JMP plthook_addr */
		0xff, 0x25, 0xa, 0, 0, 0,
		/* should never reach here */
		0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
		0xcc, 0xcc, 0xcc, 0xcc,
	};
	const uint8_t tramp_jmp_insns[] = {  
		/* JMP plt0 */
		0xe9, 0, 0, 0, 0,
		/* should never reach here */
		0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
		0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
	};

	void *plthook_addr = plt_hooker;
	void *tramp;

	pd = xzalloc(sizeof(*pd));
	pd->module_id = (unsigned long)pd;
	pd->base_addr = offset;

	if (load_elf_dynsymtab(&pd->dsymtab, elf, offset, 0) < 0 ||
	    pd->dsymtab.nr_sym == 0) {
		free(pd);
		return NULL;
	}

	tramp_len = TRAMP_PLT0_SIZE * 2 + pd->dsymtab.nr_sym * TRAMP_ENT_SIZE;
	trampoline = mmap(NULL, tramp_len, PROT_READ|PROT_WRITE,
			  MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (trampoline == MAP_FAILED) {
		pr_dbg("mmap failed: %m: ignore libcall hooking\n");
		free(pd);
		return NULL;
	}

	pd->pltgot_ptr = trampoline;
	pd->resolved_addr = xcalloc(pd->dsymtab.nr_sym, sizeof(long));

	/* add trampoline - save orig addr and replace GOT */
	pr_dbg2("module: %s (id: %lx), addr = %lx, TRAMPOLINE = %p\n",
		pd->mod_name, pd->module_id, pd->base_addr, pd->pltgot_ptr);

	/* setup PLT0 */
	memcpy(trampoline, tramp_plt0, sizeof(tramp_plt0));
	tramp = trampoline + sizeof(tramp_plt0);
	memcpy(tramp, &pd->module_id, sizeof(pd->module_id));
	tramp += sizeof(long);
	memcpy(tramp, &plthook_addr, sizeof(plthook_addr));
	tramp += sizeof(long);

	void* mcount_addr = dlsym(RTLD_NEXT, "mcount");

	/* setup PLT1 */
	memcpy(tramp, tramp_plt1, sizeof(tramp_plt1));
	tramp += sizeof(tramp_plt1);
	memcpy(tramp, &mcount_addr, sizeof(plthook_addr));
	tramp += sizeof(long);
	tramp += sizeof(long);

	#define SKIP_FUNC(func)  { #func }
		struct {
			const char *name;
			void *addr;
		} hook_list[] = {
			/*SKIP_FUNC(mcount),
			SKIP_FUNC(_mcount),
			SKIP_FUNC(__fentry__),
			SKIP_FUNC(__gnu_mcount_nc),
			SKIP_FUNC(__cyg_profile_func_enter),
			SKIP_FUNC(__cyg_profile_func_exit),*/
			SKIP_FUNC(mcount),
		};
	#undef SKIP_FUNC
	size_t plt_hook_nr = ARRAY_SIZE(hook_list);

	for (i = 0; i < pd->dsymtab.nr_sym; i++) {
		uint32_t pcrel;
		Elf64_Rela *rela;
		struct sym *sym;
		unsigned k;
		bool skip = false;
		bool is_mcount_sym = false;

		sym = &pd->dsymtab.sym[i];

		for (k = 0; k < plt_skip_nr; k++) {
			if (!strcmp(sym->name, plt_skip_syms[k].name)) {
				skip = true;
				break;
			}
		}
		if (skip)
			continue;
		printf("name %s\n", sym->name); fflush(stdout);

		for (k = 0; k < plt_hook_nr; k++) {
			if (!strcmp(sym->name, hook_list[k].name)) {
					is_mcount_sym = true;
					break;
			}
		}	

		if(is_mcount_sym) {
			/* copy trampoline instructions */
			memcpy(tramp, tramp_jmp_insns, TRAMP_ENT_SIZE);

			/* update jump offset */
			pcrel = trampoline + TRAMP_PLT0_SIZE - (tramp + 5);
			memcpy(tramp + 1, &pcrel, sizeof(pcrel));

			rela = (void*)sym->addr;
			/* save resolved address in GOT */
			memcpy(&pd->resolved_addr[i], (void *)rela->r_offset + offset,
				sizeof(long));
			/* update GOT to point the trampoline */
			memcpy((void *)rela->r_offset + offset, &tramp, sizeof(long));
		} else {
			/* copy trampoline instructions */
			memcpy(tramp, tramp_insns, TRAMP_ENT_SIZE);

			/* update offset (child id) */
			memcpy(tramp + TRAMP_IDX_OFFSET, &i, sizeof(i));

			/* update jump offset */
			pcrel = trampoline - (tramp + TRAMP_PCREL_JMP);
			memcpy(tramp + TRAMP_JMP_OFFSET, &pcrel, sizeof(pcrel));

			rela = (void*)sym->addr;
			/* save resolved address in GOT */
			memcpy(&pd->resolved_addr[i], (void *)rela->r_offset + offset,
				sizeof(long));
			/* update GOT to point the trampoline */
			memcpy((void *)rela->r_offset + offset, &tramp, sizeof(long));
		}

		tramp += TRAMP_ENT_SIZE;
	}

	mprotect(trampoline, tramp_len, PROT_READ|PROT_EXEC);

	pd->mod_name = xstrdup(modname);

	return pd;
}
