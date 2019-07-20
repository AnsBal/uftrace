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
						  struct list_head* plthook_modules,
						  unsigned long flags)
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

	if (load_elf_dynsymtab(&pd->dsymtab, elf, offset, flags) < 0 ||
	    pd->dsymtab.nr_sym == 0) {
		goto out;
	}

	tramp_len = TRAMP_PLT0_SIZE + TRAMP_PLT0_SIZE * mcount_hook_nr + pd->dsymtab.nr_sym * TRAMP_ENT_SIZE;
	trampoline = mmap(NULL, tramp_len, PROT_READ|PROT_WRITE|PROT_EXEC,
			  MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (trampoline == MAP_FAILED) {
		pr_dbg("mmap failed: %m: ignore libcall hooking\n");
		goto out;
	}

	pd->pltgot_ptr = trampoline;
	pd->pltgot_length = tramp_len;
	pd->plt_found = false;
	
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

void mcount_arch_unhook_no_plt(struct plthook_data *pd)
{
	uint32_t i, j;

	for (i = 0; i < pd->dsymtab.nr_sym; i++) {
		Elf64_Rela *rela;
		struct sym *sym;
		bool skip = false;
		unsigned long relro_start = 0;
		unsigned long relro_size = 0;
		unsigned long page_size;

		sym = &pd->dsymtab.sym[i];

		for (j = 0; j < plt_skip_nr; j++) {
			if (!strcmp(sym->name, plt_skip_syms[j].name)) {
				skip = true;
				break;
			}
		}
		if (skip)
			continue;

		rela = (void*)sym->addr;
		
		page_size = getpagesize();

		relro_start = rela->r_offset + pd->base_addr;
		relro_size  = sizeof(long);

		relro_start &= ~(page_size - 1);
		relro_size   = ALIGN(relro_size, page_size);

		mprotect((void *)relro_start, relro_size, PROT_READ | PROT_WRITE);
		__atomic_store((long*)(rela->r_offset + pd->base_addr), &pd->resolved_addr[i], __ATOMIC_SEQ_CST);
		mprotect((void *)relro_start, relro_size, PROT_READ);
	}
}