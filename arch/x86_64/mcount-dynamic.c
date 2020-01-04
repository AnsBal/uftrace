#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <pthread.h> 

/* This should be defined before #include "utils.h" */
#define PR_FMT     "dynamic"
#define PR_DOMAIN  DBG_DYNAMIC

#include "mcount-arch.h"
#include "libmcount/internal.h"
#include "utils/utils.h"
#include "utils/symbol.h"

#define PAGE_SIZE  4096
#define PAGE_ADDR(a)    ((void *)((a) & ~(PAGE_SIZE - 1)))
#define XRAY_SECT  "xray_instr_map"
#define MCOUNTLOC_SECT  "__mcount_loc"

#define CALL_INSN_SIZE  5
#define JMP_INSN_SIZE   6
const uint8_t trap_insn = 0xcc;
#define REG(name) REG_R##name

/* target instrumentation function it needs to call */
extern void __fentry__(void);
extern void __dentry__(void);
extern void __xray_entry(void);
extern void __xray_exit(void);

struct xray_instr_map {
	unsigned long addr;
	unsigned long entry;
	unsigned long type;
	unsigned long count;
};

enum mcount_x86_dynamic_type {
	DYNAMIC_NONE,
	DYNAMIC_PG,
	DYNAMIC_FENTRY,
	DYNAMIC_FENTRY_NOP,
	DYNAMIC_XRAY,
};

static const char *adi_type_names[] = {
	"none", "pg", "fentry", "fentry-nop", "xray",
};

struct arch_dynamic_info {
	enum mcount_x86_dynamic_type	type;
	struct xray_instr_map		*xrmap;
	unsigned long			*mcount_loc;
	unsigned			xrmap_count;
	unsigned			nr_mcount_loc;
};

static struct rb_root redirection_tree = RB_ROOT;


void install_trap_handler()
{
	struct sigaction act;

	sigaction(SIGTRAP, NULL, &act); /* get current trap handler */
	/*
	* reuse current trap handler and set mcount_dynamic_trap as the
	* master trap handler 
	*/
	sigaction(SIGTRAP, &act, NULL);
}

struct sigaction old_handler;
void mcount_sigusr_handler(int sig_number, siginfo_t* sig, void* _ctx);
void install_sigusr_handler(){
	struct sigaction sa;
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = &mcount_sigusr_handler;
	sigaction(SIGUSR1, &sa, &old_handler);
}

static mcount_redirection *lookup_redirection(struct rb_root *root,
					    unsigned long addr, bool create)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	mcount_redirection *iter;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, mcount_redirection, node);

		if (iter->addr == addr)
			return iter;

		if (iter->addr > addr)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	if (!create)
		return NULL;

	iter = xmalloc(sizeof(*iter));
	iter->addr = addr;

	rb_link_node(&iter->node, parent, p);
	rb_insert_color(&iter->node, root);
	return iter;
}

int mcount_setup_trampoline(struct mcount_dynamic_info *mdi)
{
	unsigned char trampoline[] = { 0xff, 0x25, 0x02, 0x00, 0x00, 0x00, 0xcc, 0xcc };
	unsigned long fentry_addr = (unsigned long)__fentry__;
	unsigned long xray_entry_addr = (unsigned long)__xray_entry;
	unsigned long xray_exit_addr = (unsigned long)__xray_exit;
	struct arch_dynamic_info *adi = mdi->arch;
	size_t trampoline_size = 16;
	void *trampoline_check;

	if (adi->type == DYNAMIC_XRAY)
		trampoline_size *= 2;

	/* find unused 16-byte at the end of the code segment */
	mdi->trampoline  = ALIGN(mdi->text_addr + mdi->text_size, PAGE_SIZE);
	mdi->trampoline -= trampoline_size;

	if (unlikely(mdi->trampoline < mdi->text_addr + mdi->text_size)) {
		mdi->trampoline += trampoline_size;
		mdi->text_size  += PAGE_SIZE;

		pr_dbg2("adding a page for fentry trampoline at %#lx\n",
			mdi->trampoline);

		trampoline_check = mmap((void *)mdi->trampoline, PAGE_SIZE,
					PROT_READ | PROT_WRITE | PROT_EXEC,
		     			MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
					-1, 0);

		if (trampoline_check == MAP_FAILED)
			pr_err("failed to mmap trampoline for setup");
	}

	if (mprotect(PAGE_ADDR(mdi->text_addr), mdi->text_size,
		     PROT_READ | PROT_WRITE | PROT_EXEC)) {
		pr_dbg("cannot setup trampoline due to protection: %m\n");
		return -1;
	}

	if (adi->type == DYNAMIC_XRAY) {
		/* jmpq  *0x2(%rip)     # <xray_entry_addr> */
		memcpy((void *)mdi->trampoline, trampoline, sizeof(trampoline));
		memcpy((void *)mdi->trampoline + sizeof(trampoline),
		       &xray_entry_addr, sizeof(xray_entry_addr));

		/* jmpq  *0x2(%rip)     # <xray_exit_addr> */
		memcpy((void *)mdi->trampoline + 16, trampoline, sizeof(trampoline));
		memcpy((void *)mdi->trampoline + 16 + sizeof(trampoline),
		       &xray_exit_addr, sizeof(xray_exit_addr));
	}
	else if (adi->type == DYNAMIC_FENTRY_NOP) {
		/* jmpq  *0x2(%rip)     # <fentry_addr> */
		memcpy((void *)mdi->trampoline, trampoline, sizeof(trampoline));
		memcpy((void *)mdi->trampoline + sizeof(trampoline),
		       &fentry_addr, sizeof(fentry_addr));
	}
	else if (adi->type == DYNAMIC_NONE) {
#ifdef HAVE_LIBCAPSTONE
		unsigned long dentry_addr = (unsigned long)__dentry__;

		/* jmpq  *0x2(%rip)     # <dentry_addr> */
		memcpy((void *)mdi->trampoline, trampoline, sizeof(trampoline));
		memcpy((void *)mdi->trampoline + sizeof(trampoline),
		       &dentry_addr, sizeof(dentry_addr));

		install_trap_handler();
		install_sigusr_handler();
#endif
	}
	return 0;
}

void mcount_cleanup_trampoline(struct mcount_dynamic_info *mdi)
{
	if (mprotect(PAGE_ADDR(mdi->text_addr), mdi->text_size, PROT_EXEC))
		pr_err("cannot restore trampoline due to protection");
}

static void read_xray_map(struct arch_dynamic_info *adi,
			  struct uftrace_elf_data *elf,
			  struct uftrace_elf_iter *iter,
			  unsigned long offset)
{
	typeof(iter->shdr) *shdr = &iter->shdr;

	adi->xrmap_count = shdr->sh_size / sizeof(*adi->xrmap);
	adi->xrmap = xmalloc(adi->xrmap_count * sizeof(*adi->xrmap));

	elf_get_secdata(elf, iter);
	elf_read_secdata(elf, iter, 0, adi->xrmap, shdr->sh_size);

	/* handle position independent code */
	if (elf->ehdr.e_type == ET_DYN) {
		struct xray_instr_map *xrmap;
		unsigned i;

		for (i = 0; i < adi->xrmap_count; i++) {
			xrmap = &adi->xrmap[i];

			xrmap->addr  += offset;
			xrmap->entry += offset;
		}
	}
}

static void read_mcount_loc(struct arch_dynamic_info *adi,
			    struct uftrace_elf_data *elf,
			    struct uftrace_elf_iter *iter,
			    unsigned long offset)
{
	typeof(iter->shdr) *shdr = &iter->shdr;

	adi->nr_mcount_loc = shdr->sh_size / sizeof(long);
	adi->mcount_loc = xmalloc(shdr->sh_size);

	elf_get_secdata(elf, iter);
	elf_read_secdata(elf, iter, 0, adi->mcount_loc, shdr->sh_size);

	/* symbol has relative address, fix it to match each other */
	if (elf->ehdr.e_type == ET_EXEC) {
		unsigned i;

		for (i = 0; i < adi->nr_mcount_loc; i++) {
			adi->mcount_loc[i] -= offset;
		}
	}
}

void mcount_arch_find_module(struct mcount_dynamic_info *mdi,
			     struct symtab *symtab)
{
	struct uftrace_elf_data elf;
	struct uftrace_elf_iter iter;
	struct arch_dynamic_info *adi;
	unsigned char fentry_nop_patt1[] = { 0x67, 0x0f, 0x1f, 0x04, 0x00 };
	unsigned char fentry_nop_patt2[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	unsigned i = 0;

	adi = xzalloc(sizeof(*adi));  /* DYNAMIC_NONE */

	if (elf_init(mdi->map->libname, &elf) < 0)
		goto out;

	elf_for_each_shdr(&elf, &iter) {
		char *shstr = elf_get_name(&elf, &iter, iter.shdr.sh_name);

		if (!strcmp(shstr, XRAY_SECT)) {
			adi->type = DYNAMIC_XRAY;
			read_xray_map(adi, &elf, &iter, mdi->base_addr);
			goto out;
		}

		if (!strcmp(shstr, MCOUNTLOC_SECT)) {
			read_mcount_loc(adi, &elf, &iter, mdi->base_addr);
			/* still needs to check pg or fentry */
		}
	}

	/* check first few functions have fentry signature */
	for (i = 0; i < symtab->nr_sym; i++) {
		struct sym *sym = &symtab->sym[i];
		void *code_addr = (void *)sym->addr + mdi->map->start;

		if (sym->type != ST_LOCAL_FUNC && sym->type != ST_GLOBAL_FUNC)
			continue;

		/* dont' check special functions */
		if (sym->name[0] == '_')
			continue;

		/* only support calls to __fentry__ at the beginning */
		if (!memcmp(code_addr, fentry_nop_patt1, CALL_INSN_SIZE) ||
		    !memcmp(code_addr, fentry_nop_patt2, CALL_INSN_SIZE)) {
			adi->type = DYNAMIC_FENTRY_NOP;
			goto out;
		}
	}

	switch (check_trace_functions(mdi->map->libname)) {
	case TRACE_MCOUNT:
		adi->type = DYNAMIC_PG;
		break;
	case TRACE_FENTRY:
		adi->type = DYNAMIC_FENTRY;
		break;
	default:
		break;
	}

out:
	pr_dbg("dynamic patch type: %s: %d (%s)\n", basename(mdi->map->libname),
	       adi->type, adi_type_names[adi->type]);

	mdi->arch = adi;
	elf_finish(&elf);
}

static unsigned long get_target_addr(struct mcount_dynamic_info *mdi, unsigned long addr)
{
	return mdi->trampoline - (addr + CALL_INSN_SIZE);
}

static int patch_fentry_func(struct mcount_dynamic_info *mdi, struct sym *sym)
{
	unsigned char nop1[] = { 0x67, 0x0f, 0x1f, 0x04, 0x00 };
	unsigned char nop2[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	unsigned char *insn = (void *)sym->addr + mdi->map->start;
	unsigned int target_addr;

	/* only support calls to __fentry__ at the beginning */
	if (memcmp(insn, nop1, sizeof(nop1)) &&  /* old pattern */
	    memcmp(insn, nop2, sizeof(nop2))) {  /* new pattern */
		pr_dbg("skip non-applicable functions: %s\n", sym->name);
		return INSTRUMENT_FAILED;
	}

	/* get the jump offset to the trampoline */
	target_addr = get_target_addr(mdi, (unsigned long)insn);
	if (target_addr == 0)
		return INSTRUMENT_SKIPPED;

	/* make a "call" insn with 4-byte offset */
	insn[0] = 0xe8;
	/* hopefully we're not patching 'memcpy' itself */
	memcpy(&insn[1], &target_addr, sizeof(target_addr));

	pr_dbg3("update function '%s' dynamically to call __fentry__\n",
		sym->name);

	return INSTRUMENT_SUCCESS;
}

static int update_xray_code(struct mcount_dynamic_info *mdi, struct sym *sym,
			    struct xray_instr_map *xrmap)
{
	unsigned char entry_insn[] = { 0xeb, 0x09 };
	unsigned char exit_insn[]  = { 0xc3, 0x2e };
	unsigned char pad[] = { 0x66, 0x0f, 0x1f, 0x84, 0x00,
				0x00, 0x02, 0x00, 0x00 };
	unsigned char nop6[] = { 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	unsigned char nop4[] = { 0x0f, 0x1f, 0x40, 0x00 };
	unsigned int target_addr;
	unsigned char *func = (void *)xrmap->addr;
	union {
		unsigned long word;
		char bytes[8];
	} patch;

	if (memcmp(func + 2, pad, sizeof(pad)))
		return INSTRUMENT_FAILED;

	if (xrmap->type == 0) {  /* ENTRY */
		if (memcmp(func, entry_insn, sizeof(entry_insn)))
			return INSTRUMENT_FAILED;

		target_addr = mdi->trampoline - (xrmap->addr + 5);

		memcpy(func + 5, nop6, sizeof(nop6));

		/* need to write patch_word atomically */
		patch.bytes[0] = 0xe8;  /* "call" insn */
		memcpy(&patch.bytes[1], &target_addr, sizeof(target_addr));
		memcpy(&patch.bytes[5], nop6, 3);

		memcpy(func, patch.bytes, sizeof(patch));
	}
	else {  /* EXIT */
		if (memcmp(func, exit_insn, sizeof(exit_insn)))
			return INSTRUMENT_FAILED;

		target_addr = mdi->trampoline + 16 - (xrmap->addr + 5);

		memcpy(func + 5, nop4, sizeof(nop4));

		/* need to write patch_word atomically */
		patch.bytes[0] = 0xe9;  /* "jmp" insn */
		memcpy(&patch.bytes[1], &target_addr, sizeof(target_addr));
		memcpy(&patch.bytes[5], nop4, 3);

		memcpy(func, patch.bytes, sizeof(patch));
	}

	pr_dbg3("update function '%s' dynamically to call xray functions\n",
		sym->name);
	return INSTRUMENT_SUCCESS;
}

static int patch_xray_func(struct mcount_dynamic_info *mdi, struct sym *sym)
{
	unsigned i;
	int ret = -2;
	struct arch_dynamic_info *adi = mdi->arch;
	struct xray_instr_map *xrmap;
	uint64_t sym_addr = sym->addr + mdi->map->start;

	/* xray provides a pair of entry and exit (or more) */
	for (i = 0; i < adi->xrmap_count; i++) {
		xrmap = &adi->xrmap[i];

		if (xrmap->addr < sym_addr || xrmap->addr >= sym_addr + sym->size)
			continue;

		while ((ret = update_xray_code(mdi, sym, xrmap)) == 0) {
			if (i == adi->xrmap_count - 1)
				break;
			i++;

			if (xrmap->entry != xrmap[1].entry)
				break;
			xrmap++;
		}

		break;
	}

	return ret;
}

void mcount_dynamic_trap(int sig, siginfo_t* info, void* _ctx)
{
	mcount_redirection *red;
	/* (%rip) - 1 is the addr of the trap instruction */
	unsigned long addr = ((ucontext_t*)_ctx)->uc_mcontext.gregs[REG(IP)] - 1;

	red = lookup_redirection(&redirection_tree, addr, false);
	if (red == NULL){
		/* raise sigaction and run normal handler */
		if(mcount_user_handler.sa_handler || mcount_user_handler.sa_sigaction)
		{
			if(mcount_user_handler.sa_flags & SA_SIGINFO)
				mcount_user_handler.sa_sigaction(sig, info, _ctx);
			else
				mcount_user_handler.sa_handler(sig);
		} else
		{
            exit(128 + sig);
        }
	} else {
		/* redirect thread to original instruction */
		((ucontext_t*)_ctx)->uc_mcontext.gregs[REG(IP)] = (unsigned long) red->insn;
	}

}

// Declaration of thread condition variable 
pthread_cond_t cond1 = PTHREAD_COND_INITIALIZER; 
// declaring mutex 
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER; 
	
struct sig_data {
	int th_counter;
	int nr_thread;
	struct mcount_orig_insn* orig;
};

void mcount_sigusr_handler(int sig_number, siginfo_t* sig, void* _ctx)
{
	struct sig_data* sd = sig->si_value.sival_ptr;
	struct mcount_orig_insn *orig;

	if(sd == NULL) {
		//TODO execute the appropriate handler based on whom raised the signal (us or the application)
		if(old_handler.sa_handler || old_handler.sa_sigaction)
		{
			if(old_handler.sa_flags & SA_SIGINFO)
				old_handler.sa_sigaction(sig_number, sig, _ctx);
			else
				old_handler.sa_handler(sig_number);
		}
	} else {
		orig = sd->orig;
	
		if(orig == NULL) {
			/* 
			* Manual Volume 3A: System Programming Guide section  
			* “Handling Self- and Cross-Modifying Code.” 
			* force the processor to execute a synchronizing instruction, prior 
			* to execution of the new code.
			*/
			asm volatile (
			"CPUID\n\t"/*serialize*/
			::: "%rax", "%rbx", "%rcx", "%rdx");
		} else {
			unsigned long rip = ((ucontext_t*)_ctx)->uc_mcontext.gregs[REG(IP)];
			/* orig->orig_addr point to the orig addr + 1 because 
			*  the border is not included when looking for sym by addr.
			*/
			if(rip >= orig->orig_addr && rip < orig->orig_addr + orig->orig_size - 1)
				/* redirect thread to original instruction */
				((ucontext_t*)_ctx)->uc_mcontext.gregs[REG(IP)] = (unsigned long) orig->insn + (rip - orig->orig_addr - 1);
		}

		pthread_mutex_lock(&lock);
		if(++sd->th_counter >= sd->nr_thread) {
			pthread_cond_signal(&cond1);
		}
		pthread_mutex_unlock(&lock);
	}
}

void signal_all_threads(struct mcount_orig_insn *orig){
	DIR *dir;
	struct dirent *entry;
	char str[128];
	char pid[10];
	int tid;

	strcpy(str, "/proc/");
	sprintf(pid, "%d", getpid());
	strcat(str, pid);
	strcat(str, "/task");

	struct sig_data sd = {0};
	sd.orig = orig;

	siginfo_t sig;
	sig.si_code = SI_QUEUE;
	sig.si_pid = getpid();
	sig.si_uid = getuid();

 	pthread_cond_init(&cond1, NULL);
    pthread_mutex_init(&lock, NULL);

	if ((dir = opendir(str)) == NULL)
		perror("opendir() error");
	else {
		while ((entry = readdir(dir)) != NULL) {
			if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
				sd.nr_thread++;
			}
		}
		sd.nr_thread--;
		rewinddir(dir);
		while ((entry = readdir(dir)) != NULL) {
			if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
				sscanf(entry->d_name, "%d", &tid); 
				if(tid != syscall(SYS_gettid)){
					//syscall(SYS_tgkill, getpid(), tid, SIGUSR1);
					sig.si_value.sival_ptr = &sd;
					syscall(SYS_rt_tgsigqueueinfo, getpid(), tid, SIGUSR1, &sig);
				}
			}
		}
		
		pthread_mutex_lock(&lock);
        struct timespec max_wait = {0, 0};
 		clock_gettime(CLOCK_REALTIME, &max_wait);
        max_wait.tv_sec += 1;
		while (sd.th_counter < sd.nr_thread) {
			pthread_cond_timedwait(&cond1, &lock, &max_wait);
		}
		pthread_mutex_unlock(&lock);
		
		//pthread_cond_wait(&cond1, &lock);
		closedir(dir);
	}
}

void issue_cpuid(){
	signal_all_threads(NULL);
}

/*
 *  we overwrite instructions over 5bytes from start of function
 *  to call '__dentry__' that seems similar like '__fentry__'.
 *
 *  while overwriting, After adding the generated instruction which
 *  returns to the address of the original instruction end,
 *  save it in the heap.
 *
 *  for example:
 *
 *   4005f0:       31 ed                   xor     %ebp,%ebp
 *   4005f2:       49 89 d1                mov     %rdx,%r9
 *   4005f5:       5e                      pop     %rsi
 *
 *  will changed like this :
 *
 *   4005f0	call qword ptr [rip + 0x200a0a] # 0x601000
 *
 *  and keeping original instruction :
 *
 *  Original Instructions---------------
 *    f1cff0:	xor ebp, ebp
 *    f1cff2:	mov r9, rdx
 *    f1cff5:	pop rsi
 *  Generated Instruction to return-----
 *    f1cff6:	jmp qword ptr [rip]
 *    f1cffc:	QW 0x00000000004005f6
 *
 *  In the original case, address 0x601000 has a dynamic symbol
 *  start address. It is also the first element in the GOT array.
 *  while initializing the mcount library, we will replace it with
 *  the address of the function '__dentry__'. so, the changed
 *  instruction will be calling '__dentry__'.
 *
 *  '__dentry__' has a similar function like '__fentry__'.
 *  the other thing is that it returns to original instructions
 *  we keeping. it makes it possible to execute the original
 *  instructions and return to the address at the end of the original
 *  instructions. Thus, the execution will goes on.
 *
 */

/*
 * Patch the instruction to the address as given for arguments.
 */
static void patch_code(struct mcount_dynamic_info *mdi,
		       uintptr_t addr, uint32_t origin_code_size,
			   struct mcount_orig_insn *orig)
{
	void *origin_code_addr;
	unsigned char call_insn[] = { 0xe8, 0x00, 0x00, 0x00, 0x00 };
	uint32_t target_addr = get_target_addr(mdi, addr);
	mcount_redirection *red;

	/* patch address */
	origin_code_addr = (void *)addr;

	/* Add a redirection */
	red = lookup_redirection(&redirection_tree, addr, true);
	red->insn = orig->insn;

	/* Detour the region */
	memcpy(origin_code_addr, &trap_insn, 1);

	signal_all_threads(orig);
	
	/* build the instrumentation instruction */
	memcpy(&call_insn[1], &target_addr, CALL_INSN_SIZE - 1);

	/*
	 * we need 5-bytes at least to instrumentation. however,
	 * if instructions is not fit 5-bytes, we will overwrite the
	 * 5-bytes and fill the remaining part of the last
	 * instruction with nop.
	 *
	 * [example]
	 * In this example, we overwrite 9-bytes to use 5-bytes.
	 *
	 * dynamic: 0x19e98b0[01]:push rbp
	 * dynamic: 0x19e98b1[03]:mov rbp, rsp
	 * dynamic: 0x19e98b4[05]:mov edi, 0x4005f4
	 *
	 * dynamic: 0x40054c[05]:call 0x400ff0
	 * dynamic: 0x400551[01]:nop
	 * dynamic: 0x400552[01]:nop
	 * dynamic: 0x400553[01]:nop
	 * dynamic: 0x400554[01]:nop
	 */
	
	/* Patch the offset */
	memcpy(origin_code_addr + 1, call_insn + 1, CALL_INSN_SIZE - 1);

	/* Issue CPUID on each processor */
	issue_cpuid();

	/* Patch the opcode */
	memcpy(origin_code_addr, call_insn, 1);

	memset(origin_code_addr + CALL_INSN_SIZE, 0x90,  /* NOP */
	       origin_code_size - CALL_INSN_SIZE);

	/* flush icache so that cpu can execute the new insn */
	__builtin___clear_cache(origin_code_addr,
				origin_code_addr + origin_code_size);
}

static void patch_code_nop(struct mcount_dynamic_info *mdi,
		       uintptr_t addr, uint32_t origin_code_size, struct mcount_nop_info *nopi,
			   struct mcount_orig_insn *orig)
{
	void *origin_code_addr;
	unsigned char call_insn[] = { 0xe8, 0x00, 0x00, 0x00, 0x00 };
	unsigned char jmp8_insn[] = { 0xeb, 0x00};
	uint32_t target_addr = get_target_addr(mdi, nopi->addr);
	mcount_redirection *red;

	/* NOP patch address */
	origin_code_addr = (void *)nopi->addr;

	/* build the instrumentation instruction */
	memcpy(&call_insn[1], &target_addr, CALL_INSN_SIZE - 1);


	memcpy(origin_code_addr, call_insn, CALL_INSN_SIZE);
	memset(origin_code_addr + CALL_INSN_SIZE, 0x90,  /* NOP */
	       nopi->size - CALL_INSN_SIZE);

	/* flush icache so that cpu can execute the new insn */
	__builtin___clear_cache(origin_code_addr,
				origin_code_addr + nopi->size);


	target_addr = nopi->addr - (addr + 2);
	/* Probe site patch address */
	origin_code_addr = (void *)addr;

	/* Add a redirection */
	red = lookup_redirection(&redirection_tree, addr, true);
	red->insn = orig->insn;

	/* Detour the region */
	memcpy(origin_code_addr, &trap_insn, 1);

	signal_all_threads(orig);

	/* build the instrumentation instruction */
	memcpy(&jmp8_insn[1], &target_addr, 1);

	/* Patch the offset */
	memcpy(origin_code_addr + 1, jmp8_insn + 1, 1);

	/* Issue CPUID on each processor */
	issue_cpuid();

	/* Patch the opcode */
	memcpy(origin_code_addr, jmp8_insn, 1);

	memset(origin_code_addr + 2, 0x90,  /* NOP */
	       origin_code_size - 2);

	/* flush icache so that cpu can execute the new insn */
	__builtin___clear_cache(origin_code_addr,
				origin_code_addr + origin_code_size);
}

static int patch_normal_func(struct mcount_dynamic_info *mdi, struct sym *sym, 
				 struct mcount_disasm_engine *disasm)
{
	uint8_t jmp_insn[14] = { 0xff, 0x25, };
	uint64_t jmp_target;
	struct mcount_orig_insn *orig;
	struct mcount_disasm_info info = {
		.sym  = sym,
		.addr = mdi->map->start + sym->addr,
	};
	int state;
	
	state = disasm_check_insns(disasm, mdi, &info);
	if (state != INSTRUMENT_SUCCESS)
		return state;	

	pr_dbg2("patch normal func: %s (patch size: %d)\n",
		sym->name, info.orig_size);

	/*
	 *  stored origin instruction block:
	 *  ----------------------
	 *  | [origin_code_size] |
	 *  ----------------------
	 *  | [jmpq    *0x0(rip) |
	 *  ----------------------
	 *  | [Return   address] |
	 *  ----------------------
	 */
	jmp_target = info.addr + info.orig_size;
	memcpy(jmp_insn + JMP_INSN_SIZE, &jmp_target, sizeof(jmp_target));

	if (info.has_jump)
		orig = mcount_save_code_addr(&info, jmp_insn, 0, info.addr + CALL_INSN_SIZE);		
	else
		orig = mcount_save_code_addr(&info, jmp_insn, sizeof(jmp_insn), info.addr + CALL_INSN_SIZE);			

	/* make sure orig->addr same as when called from __dentry__ */
	//orig->addr += CALL_INSN_SIZE;
	patch_code(mdi, info.addr, info.orig_size, orig);

	return INSTRUMENT_SUCCESS;
}

static int patch_jmp8_func(struct mcount_dynamic_info *mdi, struct sym *sym,
			    struct symtab *symtab, int index, struct mcount_disasm_engine *disasm)
{
	uint8_t jmp_insn[14] = { 0xff, 0x25, };
	uint64_t jmp_target;
	struct mcount_nop_info nopi;
	struct mcount_orig_insn *orig;
	struct mcount_disasm_info info = {
		.sym  = sym,
		.addr = mdi->map->start + sym->addr,
	};
	int state;

	state = disasm_jmp8_check_insns(disasm, mdi, &info);
	if (state != INSTRUMENT_SUCCESS)
		return state;

	nopi = disasm_find_nops(disasm, mdi, &info, symtab, index);
	if (nopi.addr == 0)
		return INSTRUMENT_FAILED;

	pr_dbg2("patch jmp8 func: %s (patch size: %d) \t nop start: %p end %lu  %p\n",
		sym->name, info.orig_size, nopi.addr, nopi.size, mdi->map->start);

	/*
	 *  stored origin instruction block:
	 *  ----------------------
	 *  | [origin_code_size] |
	 *  ----------------------
	 *  | [jmpq    *0x0(rip) |
	 *  ----------------------
	 *  | [Return   address] |
	 *  ----------------------
	 */
	jmp_target = info.addr + info.orig_size;
	memcpy(jmp_insn + JMP_INSN_SIZE, &jmp_target, sizeof(jmp_target));
	orig = mcount_save_code_addr(&info, jmp_insn, sizeof(jmp_insn), nopi.addr + CALL_INSN_SIZE);
	patch_code_nop(mdi, info.addr, info.orig_size, &nopi, orig);

	return INSTRUMENT_SUCCESS;
}

static int unpatch_func(uint8_t *insn, char *name)
{
	uint8_t nop5[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	uint8_t nop6[] = { 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	uint8_t *nop_insn;
	size_t nop_size;

	if (*insn == 0xe8) {
		nop_insn = nop5;
		nop_size = sizeof(nop5);
	}
	else if (insn[0] == 0xff && insn[1] == 0x15) {
		nop_insn = nop6;
		nop_size = sizeof(nop6);
	}
	else {
		return INSTRUMENT_SKIPPED;
	}

	pr_dbg3("unpatch fentry: %s\n", name);
	memcpy(insn, nop_insn, nop_size);
	__builtin___clear_cache(insn, insn + nop_size);

	return INSTRUMENT_SUCCESS;
}

static int unpatch_fentry_func(struct mcount_dynamic_info *mdi, struct sym *sym)
{
	uint64_t sym_addr = sym->addr + mdi->map->start;

	return unpatch_func((void *)sym_addr, sym->name);
}

static int cmp_loc(const void *a, const void *b)
{
	const struct sym *sym = a;
	uintptr_t loc = *(uintptr_t *)b;

	if (sym->addr <= loc && loc < sym->addr + sym->size)
		return 0;

	return sym->addr > loc ? 1 : -1;
}

static int unpatch_mcount_func(struct mcount_dynamic_info *mdi, struct sym *sym)
{
	struct arch_dynamic_info *adi = mdi->arch;

	uintptr_t *loc;

	if (adi->nr_mcount_loc != 0) {
		loc = bsearch(sym, adi->mcount_loc, adi->nr_mcount_loc,
			       sizeof(*adi->mcount_loc), cmp_loc);

		if (loc != NULL) {
			uint8_t *insn = (uint8_t*) *loc;
			return unpatch_func(insn + mdi->map->start, sym->name);
		}
	}

	return INSTRUMENT_SKIPPED;
}

int mcount_patch_func(struct mcount_dynamic_info *mdi, struct sym *sym,
		      struct symtab *symtab, int index, struct mcount_disasm_engine *disasm,
		      unsigned min_size)
{
	struct arch_dynamic_info *adi = mdi->arch;
	int result = INSTRUMENT_SKIPPED;

	switch (adi->type) {
	case DYNAMIC_XRAY:
		if (min_size < CALL_INSN_SIZE)
			min_size = CALL_INSN_SIZE;

		if (sym->size < min_size)
			return result;
		result = patch_xray_func(mdi, sym);
		break;

	case DYNAMIC_FENTRY_NOP:
		if (min_size < CALL_INSN_SIZE)
			min_size = CALL_INSN_SIZE;

		if (sym->size < min_size)
			return result;
		result = patch_fentry_func(mdi, sym);
		break;

	case DYNAMIC_NONE:
		if (min_size < 2)
			min_size = 2;

		if (sym->size < min_size)
			return result;
		result = patch_jmp8_func(mdi, sym, symtab, index, disasm);
		if (result != INSTRUMENT_SUCCESS) {
			if (min_size < CALL_INSN_SIZE)
				min_size = CALL_INSN_SIZE;

			if (sym->size < min_size)
				return result;
			result = patch_normal_func(mdi, sym, disasm);
		}
		break;

	default:
		break;
	}
	return result;
}

int mcount_unpatch_func(struct mcount_dynamic_info *mdi, struct sym *sym,
			struct mcount_disasm_engine *disasm)
{
	struct arch_dynamic_info *adi = mdi->arch;
	int result = INSTRUMENT_SKIPPED;

	switch (adi->type) {
	case DYNAMIC_FENTRY:
		result = unpatch_fentry_func(mdi, sym);
		break;

	case DYNAMIC_PG:
		result = unpatch_mcount_func(mdi, sym);
		break;

	default:
		break;
	}
	return result;
}

static void revert_normal_func(struct mcount_dynamic_info *mdi, struct sym *sym,
			       struct mcount_disasm_engine *disasm)
{
	void *addr = (void *)(uintptr_t)sym->addr + mdi->map->start;
	struct mcount_orig_insn *moi;

	moi = mcount_find_insn((uintptr_t)addr + CALL_INSN_SIZE);
	if (moi == NULL)
		return;

	memcpy(addr, moi->orig, moi->orig_size);
	__builtin___clear_cache(addr, addr + moi->orig_size);
}

void mcount_arch_dynamic_recover(struct mcount_dynamic_info *mdi,
				 struct mcount_disasm_engine *disasm)
{
	struct dynamic_bad_symbol *badsym, *tmp;

	list_for_each_entry_safe(badsym, tmp, &mdi->bad_syms, list) {
		if (!badsym->reverted)
			revert_normal_func(mdi, badsym->sym, disasm);

		list_del(&badsym->list);
		free(badsym);
	}
}

int mcount_arch_branch_table_size(struct mcount_disasm_info *info)
{
	return info->nr_branch * ARCH_BRANCH_ENTRY_SIZE;
}

void mcount_arch_patch_branch(struct mcount_disasm_info *info, struct mcount_orig_insn *orig)
{
	uint8_t trampoline[ARCH_TRAMPOLINE_SIZE] = { 0xff, 0x25, };
	uint64_t target = orig->insn_size;
	unsigned long jmp_target;
	unsigned long jcc_index;
	uint32_t disp;
	int i;

	/* patch conditional jumps instructions */
	for (i = 0; i < info->nr_branch; i++) {
		jmp_target = info->branch_info[i].branch_target;
		jcc_index = info->branch_info[i].insn_index;

		memcpy(trampoline + JMP_INSN_SIZE, &jmp_target, sizeof(jmp_target));
		memcpy(orig->insn + target, trampoline, sizeof(trampoline));

		disp = target - (jcc_index + 2);
		if (disp > SCHAR_MAX) { /* should not happen */
			pr_err("target is not in reach"); 
		}
		info->insns[jcc_index + 1] = disp;

		target += sizeof(trampoline);
	}
}
