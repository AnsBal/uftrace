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
#define TRAMP_PLT1_SIZE   32  /* addres of mcount symbol */
#define TRAMP_PCREL_JMP   10  /* PC_relative offset for JMP */
#define TRAMP_MCOUNT_PCREL_JMP  5   /* PC_relative offset for JMP from tramp_plt1*/
#define TRAMP_IDX_OFFSET  1
#define TRAMP_MCOUNT_JMP_OFFSET 1
#define TRAMP_JMP_OFFSET  6

extern void __weak plt_hooker(void);
void mcount_arch_hook_no_plt(struct uftrace_elf_data *elf,
					      const char *modname,
					      unsigned long offset,
						  struct list_head* plthook_modules)
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
		goto out;
	}

	/* mcount must be hooked since libmcount is not preloaded */
	#define HOOK_FUNC(func)  { #func }
		struct {
			const char *name;
			void *addr;
		} mcount_hook_list[] = {
			/* mcount functions */
			HOOK_FUNC(mcount),
			HOOK_FUNC(_mcount),
			HOOK_FUNC(__fentry__),
			HOOK_FUNC(__gnu_mcount_nc),
			HOOK_FUNC(__cyg_profile_func_enter),
			HOOK_FUNC(__cyg_profile_func_exit),
			/* wrap functions */
			HOOK_FUNC(backtrace),
			HOOK_FUNC(__cxa_throw),
			HOOK_FUNC(__cxa_rethrow),
			HOOK_FUNC(dlop__cxa_begin_catchen),
			HOOK_FUNC(__cxa_end_catch),
			HOOK_FUNC(dlopen),
			HOOK_FUNC(pthread_exit),
			HOOK_FUNC(_Unwind_Resume),
			HOOK_FUNC(posix_spawn),
			HOOK_FUNC(posix_spawnp),
			HOOK_FUNC(execve),
			HOOK_FUNC(execvpe),
			HOOK_FUNC(fexecve),
		};
	#undef HOOK_FUNC
	size_t mcount_hook_nr = ARRAY_SIZE(mcount_hook_list);

	tramp_len = TRAMP_PLT0_SIZE + TRAMP_PLT0_SIZE * mcount_hook_nr + pd->dsymtab.nr_sym * TRAMP_ENT_SIZE;
	trampoline = mmap(NULL, tramp_len, PROT_READ|PROT_WRITE|PROT_EXEC,
			  MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (trampoline == MAP_FAILED) {
		pr_dbg("mmap failed: %m: ignore libcall hooking\n");
		goto out;
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

	Dl_info dl_info;
	dladdr(mcount_arch_hook_no_plt, &dl_info);
	void* libmcount_handle = dlopen(dl_info.dli_fname, RTLD_NOLOAD | RTLD_LAZY); 

	for (i = 0; i < mcount_hook_nr; i++) {
		mcount_hook_list[i].addr = dlsym(libmcount_handle, mcount_hook_list[i].name);
		
		memcpy(tramp, tramp_plt1, sizeof(tramp_plt1));
		tramp += sizeof(tramp_plt1);
		memcpy(tramp, &(mcount_hook_list[i].addr), sizeof(mcount_hook_list[i].addr));
		tramp += sizeof(long) * 2;
	}

	pd->mod_name = xstrdup(modname);

	// Needs to bee added to plthook_modules before updating GOT.
	list_add_tail(&pd->list, plthook_modules);

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
		
		for (k = 0; k < mcount_hook_nr; k++) {
			if (!strcmp(sym->name, mcount_hook_list[k].name)) {
				is_mcount_sym = true;
				break;
			}
		}	

		if(is_mcount_sym) {
			/* copy trampoline instructions */
			memcpy(tramp, tramp_jmp_insns, TRAMP_ENT_SIZE);

			/* update jump offset */
			pcrel = trampoline + TRAMP_PLT0_SIZE + TRAMP_PLT1_SIZE * k - (tramp + TRAMP_MCOUNT_PCREL_JMP);
			memcpy(tramp + TRAMP_MCOUNT_JMP_OFFSET, &pcrel, sizeof(pcrel));
		} else {
			/* copy trampoline instructions */
			memcpy(tramp, tramp_insns, TRAMP_ENT_SIZE);

			/* update offset (child id) */
			memcpy(tramp + TRAMP_IDX_OFFSET, &i, sizeof(i));

			/* update jump offset */
			pcrel = trampoline - (tramp + TRAMP_PCREL_JMP);
			memcpy(tramp + TRAMP_JMP_OFFSET, &pcrel, sizeof(pcrel));
		}

		rela = (void*)sym->addr;
		/* save resolved address in GOT */
		memcpy(&pd->resolved_addr[i], (void *)rela->r_offset + offset,
			sizeof(long));
		/* update GOT to point the trampoline */
		__atomic_store((long*)(rela->r_offset + offset), &tramp, __ATOMIC_SEQ_CST);

		tramp += TRAMP_ENT_SIZE;
	}

	mprotect(trampoline, tramp_len, PROT_READ|PROT_EXEC);
	return;
out:
	pr_dbg2("no PLTGOT found.. ignoring...\n");
	free(pd);
}