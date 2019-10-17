#include "libmcount/internal.h"
#include "mcount-arch.h"

#define CALL_INSN_SIZE  5
#define JMP8_INSN_SIZE  2

#ifdef HAVE_LIBCAPSTONE
#include <capstone/capstone.h>
#include <capstone/platform.h>

struct disasm_check_data {
	uintptr_t		addr;
	uint32_t		func_size;
	uint32_t		patch_size;
	uint32_t		copy_size;
	uint32_t		size;
};

void mcount_disasm_init(struct mcount_disasm_engine *disasm)
{
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &disasm->engine) != CS_ERR_OK) {
		pr_dbg("failed to init Capstone disasm engine\n");
		return;
	}

	if (cs_option(disasm->engine, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
		pr_dbg("failed to set detail option\n");
}

void mcount_disasm_finish(struct mcount_disasm_engine *disasm)
{
	cs_close(&disasm->engine);
}

enum fail_reason {
	INSTRUMENT_FAIL_NODETAIL	= (1U << 0),
	INSTRUMENT_FAIL_NOOPRND		= (1U << 1),
	INSTRUMENT_FAIL_RELJMP		= (1U << 2),
	INSTRUMENT_FAIL_RELCALL		= (1U << 3),
	INSTRUMENT_FAIL_PICCODE		= (1U << 4),
};

enum branch_group {
	OP_GROUP_NOBRANCH = 0,
	OP_GROUP_JMP,
	OP_GROUP_CALL,
};

void print_instrument_fail_msg(int reason)
{
	if (reason & INSTRUMENT_FAIL_NOOPRND) {
		pr_dbg3("Not supported opcode without operand\n");
	}
	if (reason & INSTRUMENT_FAIL_RELJMP) {
		pr_dbg3("Not supported opcode that jump to relative address\n");
	}
	if (reason & INSTRUMENT_FAIL_RELCALL) {
		pr_dbg3("Not supported opcode that call to relative address\n");
	}
	if (reason & INSTRUMENT_FAIL_PICCODE) {
		pr_dbg3("Not supported Position Independent Code\n");
	}
}

static int opnd_reg(int capstone_reg)
{
	uint8_t x86_regs[] = {
		X86_REG_RAX, X86_REG_RBX, X86_REG_RCX, X86_REG_RDX,
		X86_REG_RDI, X86_REG_RSI, X86_REG_RBP, X86_REG_RSP,
		X86_REG_R8,  X86_REG_R9,  X86_REG_R10, X86_REG_R11,
		X86_REG_R12, X86_REG_R13, X86_REG_R14, X86_REG_R15,
	};
	size_t i;

	for (i = 0; i < sizeof(x86_regs); i++) {
		if (capstone_reg == x86_regs[i])
			return i;
	}
	return -1;
}

/*
 *  handle PIC code.
 *  for currently, this function targeted specific type of instruction.
 *
 *  this function manipulate the instruction like below,
 *    lea rcx, qword ptr [rip + 0x8f3f85]
 *  to this.
 *    mov rcx, [calculated PC + 0x8f3f85]
 */
static int handle_pic(cs_insn *insn, uint8_t insns[])
{
	cs_x86 *x86 = &insn->detail->x86;

#define REX   0
#define OPND  1
#define IMM   2

	/*
	 * array for mov instruction: REX + OPND + IMM(8-byte)
	 * ex) mov rbx, 0x555556d35690
	 */
	uint8_t mov_insns[10];

	const uint8_t mov_operands[] = {
	/*	rax,	rbx,	rcx,	rdx,	rdi,	rsi,	rbp,	rsp */
		0xb8,	0xbb,	0xb9,	0xba,	0xbf,	0xbe,	0xbd,	0xbc,
	/*	r8,	r9,	r10,	r11,	r12,	r13,	r14,	r15 */
		0xb8,	0xb9,	0xba,	0xbb,	0xbc,	0xbd,	0xbe,	0xbf,
	};

	/* for now, support LEA instruction only */
	if (strcmp(insn->mnemonic, "lea") != 0)
		goto out;

	/* according to intel manual, lea instruction takes 2 operand */
	cs_x86_op *opnd1 = &x86->operands[0];
	cs_x86_op *opnd2 = &x86->operands[1];

	/* check PC-relative addressing mode */
	if (opnd2->type != X86_OP_MEM || opnd2->mem.base != X86_REG_RIP)
		goto out;

	/* the SIB addressing is not supported yet */
	if (opnd2->mem.scale > 1 || opnd2->mem.disp == 0)
		goto out;

	if (X86_REG_RAX <= opnd1->reg && opnd1->reg <= X86_REG_RSP) {
		mov_insns[REX] = 0x48;
	}
	else if (X86_REG_R8 <= opnd1->reg && opnd1->reg <= X86_REG_R15) {
		mov_insns[REX] = 0x49;
	}
	else {
		goto out;
	}

	/* convert LEA to MOV instruction */
	mov_insns[OPND] = mov_operands[opnd_reg(opnd1->reg)];

	uint64_t PC_base = insn->address + insn->size + opnd2->mem.disp;
	*(uint64_t *)&mov_insns[IMM] = PC_base;

	memcpy(insns, (void *)mov_insns, sizeof(mov_insns));

	return sizeof(mov_insns);

out:
	return -1;
}

static int manipulate_insns(cs_insn *insn, uint8_t insns[], int* fail_reason)
{
	int res = -1;

	pr_dbg3("Try to instrument if instruction could be manipulate possibly.\n");

	switch (*fail_reason) {
		case INSTRUMENT_FAIL_PICCODE:
			res = handle_pic(insn, insns);
			if (res > 0) {
				*fail_reason ^= INSTRUMENT_FAIL_PICCODE;
			}
			break;
		default:
			break;
	}

	return res;
}

static int copy_insn_bytes(cs_insn *insn, uint8_t insns[])
{
	int res = insn->size;

	memcpy(insns, insn->bytes, res);
	return res;
}

/*
 * check whether the instruction can be executed regardless of its location.
 * returns false when instructions are not suitable for dynamic patch.
 *
 * TODO: this function is incomplete and need more classification.
 */
static int check_instrumentable(struct mcount_disasm_engine *disasm,
				 cs_insn *insn)
{
	int i;
	cs_x86 *x86;
	cs_detail *detail;
	int check_branch = OP_GROUP_NOBRANCH;
	int status = 0;

	/*
	 * 'detail' can be NULL on "data" instruction
	 * if SKIPDATA option is turned ON
	 */
	if (insn->detail == NULL) {
		status = INSTRUMENT_FAIL_NODETAIL;
		goto out;
	}

	detail = insn->detail;

	for (i = 0; i < detail->groups_count; i++) {
		if (detail->groups[i] == CS_GRP_CALL)
			check_branch = OP_GROUP_CALL;
		else if (detail->groups[i] == CS_GRP_JUMP)
			check_branch = OP_GROUP_JMP;
	}

	x86 = &insn->detail->x86;

	if (!x86->op_count)
		goto out;

	for (i = 0; i < x86->op_count; i++) {
		cs_x86_op *op = &x86->operands[i];

		switch((int)op->type) {
		case X86_OP_REG:
			continue;

		case X86_OP_IMM:
			if (check_branch == OP_GROUP_NOBRANCH)
				continue;

			if (check_branch == OP_GROUP_CALL)
				status |= INSTRUMENT_FAIL_RELCALL;
			else if (check_branch == OP_GROUP_JMP)
				status |= INSTRUMENT_FAIL_RELJMP;

			goto out;

		case X86_OP_MEM:
			if (op->mem.base == X86_REG_RIP ||
			    op->mem.index == X86_REG_RIP) {
				status |= INSTRUMENT_FAIL_PICCODE;
				goto out;
			}
			continue;

		default:
			continue;
		}
	}

out:
	if (status > 0)
		print_instrument_fail_msg(status);

	return status;
}

static bool check_unsupported(struct mcount_disasm_engine *disasm,
			      cs_insn *insn, struct mcount_dynamic_info *mdi,
			      struct mcount_disasm_info *info)
{
	int i;
	cs_x86 *x86;
	cs_detail *detail = insn->detail;
	unsigned long target;
	bool jump = false;

	if (detail == NULL)
		return false;

	detail = insn->detail;

	/* assume there's no call into the middle of function */
	for (i = 0; i < detail->groups_count; i++) {
		if (detail->groups[i] == CS_GRP_JUMP)
			jump = true;
	}

	if (!jump)
		return true;

	x86 = &insn->detail->x86;
	for (i = 0; i < x86->op_count; i++) {
		cs_x86_op *op = &x86->operands[i];

		switch((int)op->type) {
		case X86_OP_IMM:
			/* capstone seems already calculate target address */
			target = op->imm;

			/* disallow (back) jump to the prologue */
			if (info->addr < target &&
			    target < info->addr + info->copy_size)
				return false;

			/* disallow jump to middle of other function */
			if (info->addr > target ||
			    target >= info->addr + info->sym->size) {
				/* also mark the target function as invalid */
						pr_blue("bad sym found at %s : %s\t %s\n",
				info->sym->name, insn->mnemonic, insn->op_str);
				return !mcount_add_badsym(mdi, insn->address,
							  target);
			}
			break;
		case X86_OP_MEM:
		case X86_OP_REG:
			/* indirect jumps are not allowed */
			return false;
		default:
			break;
		}
	}

	return true;
}

static int disasm_size_check_insns(struct mcount_disasm_engine *disasm,
		       struct mcount_dynamic_info *mdi,
		       struct mcount_disasm_info *info,
			   uint8_t patch_insn_size)
{
	int status;
	cs_insn *insn = NULL;
	uint32_t count, i, size;
	uint8_t endbr64[] = { 0xf3, 0x0f, 0x1e, 0xfa };
	struct dynamic_bad_symbol *badsym;

	badsym = mcount_find_badsym(mdi, info->addr);
	if (badsym != NULL) {
		badsym->reverted = true;
		return INSTRUMENT_FAILED;
	}

	count = cs_disasm(disasm->engine, (void *)info->addr, info->sym->size,
			  info->addr, 0, &insn);
	if (count == 0 && !memcmp((void *)info->addr, endbr64, sizeof(endbr64))) {
		/* old version of capstone doesn't recognize ENDBR64 insn */
		unsigned long addr = info->addr + sizeof(endbr64);

		info->orig_size += sizeof(endbr64);
		info->copy_size += sizeof(endbr64);

		count = cs_disasm(disasm->engine, (void *)addr,
				  info->sym->size - sizeof(endbr64),
				  addr, 0, &insn);
	}

	for (i = 0; i < count; i++) {
		uint8_t insns_byte[32] = { 0, };

		status = check_instrumentable(disasm, &insn[i]);
		if (status > 0) {
			size = manipulate_insns(&insn[i], insns_byte, &status);
			if (status == 0)
				info->modified = true;
		}
		else
			size = copy_insn_bytes(&insn[i], insns_byte);

		if (status > 0) {
			status = INSTRUMENT_FAILED;
			//pr_dbg3("not supported instruction found at %s : %s\t %s\n",
			//	info->sym->name, insn[i].mnemonic, insn[i].op_str);
			pr_blue("not instrumentable instruction found at %s : %s\t %s\n",
				info->sym->name, insn[i].mnemonic, insn[i].op_str);
			goto out;
		}

		memcpy(info->insns + info->copy_size, insns_byte, size);
		info->copy_size += size;
		info->orig_size += insn[i].size;

		if (info->orig_size >= patch_insn_size)
			break;
	}

	while (++i < count) {
		if (!check_unsupported(disasm, &insn[i], mdi, info)) {
			status = INSTRUMENT_FAILED;
			pr_blue("not supported instruction found at %s : %s\t %s\n",
				info->sym->name, insn[i].mnemonic, insn[i].op_str);
			break;
		}
	}

out:
	if (count)
		cs_free(insn, count);

	return status;
}

static int prev_sym_index(struct symtab *symtab, int index) {
	struct sym *sym = &symtab->sym[index];
	struct sym *prev_sym = &symtab->sym[index];
	int i;
	#define JMP8_SIZE 2

	if(index == 0)
		return 0;
	
	for (i = index - 1; i > 0; i--) {
		prev_sym = &symtab->sym[i];
		if((sym->addr + JMP8_SIZE) - prev_sym->addr >= 128) {
			break;	
		}
		if (prev_sym->section != sym->section)
			break;
	}
	
	return i;
}

static bool is_unreachable_insn(cs_insn *insn_array, uint32_t index, 
				uint32_t count, 
				struct mcount_disasm_info *info) 
{	
	int i;
	int j;
	cs_x86 *x86;
	cs_detail *detail;
	bool jump = false;
	unsigned long target;
	cs_insn *insn = &insn_array[index];
	cs_insn *start_insn;

	if(index == 0) {
		return false;
	}
	i = index;

	while(i >= 0 && strcmp(insn->mnemonic, "nop") == 0) {
		i--;
		insn = &insn_array[i];
	}

	pr_blue("previous insn: %s %s \taddr %p \tsize %i\n",
			 insn->mnemonic, insn->op_str, insn->address, insn->size);
	
	if(strcmp(insn->mnemonic, "jmp") != 0 &&
		strcmp(insn->mnemonic, "ret") != 0) /*  &&
		strcmp(insn->mnemonic, "call") != 0 */
		return false;

	start_insn = &insn_array[i + 1];

	for (i = 0; i < count; i++) {
		insn = &insn_array[i];
		detail = insn->detail;
		if (detail == NULL)
			return false;

		for (j = 0; j < detail->groups_count; j++) {
			if (detail->groups[j] == CS_GRP_JUMP)
				jump = true;
		}

		if (!jump)
			continue;

		x86 = &insn->detail->x86;
		for (j = 0; j < x86->op_count; j++) {
			cs_x86_op *op = &x86->operands[j];

			switch((int)op->type) {
			case X86_OP_IMM:
				target = op->imm;

				if (start_insn->address <= target &&
					target <= insn_array[index].address) 
				{
					pr_blue("jump to unreachable_insn: %s %s \taddr %p \tsize %i\n",
							insn->mnemonic, insn->op_str, insn->address, insn->size);
					return false;
				}
				break;
			//case X86_OP_MEM:
			//case X86_OP_REG:
			//	return false;
			default:
				break;
			}
		}
	}

	return true;
}

static bool is_func_pad(struct mcount_nop_info *nopi,
 				struct mcount_dynamic_info *mdi, 
				struct symtab *symtab, 
				int psi,
				int csi) 
{	
	struct sym* prev_sym;
	struct sym* next_sym;
	unsigned long next_start;
	unsigned long prev_end;
	int i;

	for (i = psi; i < csi; i++){
		
		prev_sym = &symtab->sym[i];
		next_sym = &symtab->sym[i + 1];

		prev_end = mdi->map->start + prev_sym->addr + prev_sym->size;
		next_start = mdi->map->start + next_sym->addr;

		if(nopi->addr >= prev_end && next_start > nopi->addr) {
			
			pr_blue("FUNC PAD: %p in start %p  end %p \n", nopi->addr, prev_end, next_start);
			return true;
		}
	}

	return false;
}

static struct mcount_nops get_potential_nops(cs_insn *insn, uint32_t count, 
				struct mcount_disasm_info *info)
{
	struct mcount_nop_info *nopi;
	uint32_t i;
	uint32_t dbg_i;
	struct mcount_nops nops= {
		.count = 0,
	};

	//func_pad_index(insn, count, info);

	for (i = 0 ; i < count ; i++) {
		if (strcmp(insn[i].mnemonic, "nop") != 0)
			continue;

		if (insn[i].size >= 5 /*&& insn[i].size < 8*/) {
		 	/* we can use a relative call32 */

			/* skip insn if offset is out of range */
			int offset = insn[i].address - (info->addr + 2);
			if (offset < SCHAR_MIN || offset > SCHAR_MAX)
				continue;

			pr_blue("NOP found insn: %s %s \taddr %p \tsize %i\n",
				 insn[i].mnemonic, insn[i].op_str, insn[i].address, insn[i].size);
		
			nopi = &nops.infos[nops.count++];
			nopi->addr = insn[i].address;
			nopi->size = insn[i].size;
			nopi->index = i;
			
			if(nops.count == 1) {
				dbg_i = i;
			}

		} else if (insn[i].size >= 8) { // we dont get here for now
			/* we can use PUSH PUSH NOP call 00 00 00 00 */
			if (insn[i].size == 8) {
				nopi = &nops.infos[nops.count++];
				nopi->addr = insn[i].address + (insn[i].size - CALL_INSN_SIZE);
				nopi->size = CALL_INSN_SIZE;
				nopi->index = i;

			}
			else if (insn[i].size == 9) {

			}

		} else if (insn[i].size < 5) { 
			/*
			 * we first check the 2nd insn (it could be a nop) 
			 * else we can use it as trampoline to a 5 byte (or more) nop
			 */
			continue;
		}
	}

	if(nops.count == 0 )
		pr_blue("No potential NOP found\n");
	else 
		pr_blue("Potential NOP found insn: %s %s size: %i\n", insn[dbg_i].mnemonic,
					 insn[dbg_i].op_str, insn[dbg_i].size);

	return nops;
}

struct mcount_nop_info lookup_viable_nop(cs_insn *insn, uint32_t count, 
			struct mcount_nops* nops,
			struct mcount_dynamic_info *mdi,
			struct mcount_disasm_info *info,
			struct symtab *symtab, int index,
			int prev_index) 
{
	struct mcount_nop_info *nopi;
	struct mcount_nop_info ret;
	int i;

	/* ~3% loss 20-25 sym */
	for (i = 0; i < nops->count; i++) {
		nopi = &nops->infos[i];
		if(is_func_pad(nopi, mdi, symtab, prev_index, index)) {
			ret = *nopi;
			return ret;
		} else if (is_unreachable_insn(insn, nopi->index, count, info)) {
			ret = *nopi;
			return ret;
		} else {
			switch(nopi->size) {
			case 8: 
				ret.size = 5;
				ret.addr = nopi->addr + 3;
			return ret;

				break;
			case 9: 
				ret.size = 5;
				ret.addr = nopi->addr + 4;
			return ret;

				break;
			case 10: 
				ret.size = 5;
				ret.addr = nopi->addr + 5;
			return ret;

				break;
			}
			pr_blue("reachable size: %i\n", nopi->size);

			continue;
		}
	}
	
	if(nops->count != 0)
		pr_blue("not viable\n");

	return ret;
}

struct mcount_nop_info disasm_find_nops(struct mcount_disasm_engine *disasm,
		       struct mcount_dynamic_info *mdi,
		       struct mcount_disasm_info *info,
			   struct symtab *symtab, int index)
{
	cs_insn *insn = NULL;
	uint32_t count;
	uint8_t endbr64[] = { 0xf3, 0x0f, 0x1e, 0xfa };
	struct mcount_nops nops;
	struct mcount_nop_info ret;

	int prev_index = prev_sym_index(symtab, index);
	struct sym* prev_sym = &symtab->sym[prev_index];
	unsigned long prev_addr = mdi->map->start + prev_sym->addr;

	count = cs_disasm(disasm->engine, (void *)prev_addr, info->sym->addr - prev_sym->addr,
			  prev_addr, 0, &insn);
	if (count == 0 && !memcmp((void *)prev_addr, endbr64, sizeof(endbr64))) {
		/* old version of capstone doesn't recognize ENDBR64 insn */
		unsigned long addr = prev_addr + sizeof(endbr64);

		info->orig_size += sizeof(endbr64);
		info->copy_size += sizeof(endbr64);

		count = cs_disasm(disasm->engine, (void *)addr,
				   info->sym->addr - prev_sym->addr - sizeof(endbr64),
				   addr, 0, &insn);
	}

	pr_blue("\n------------sym: %s (%p - %p)  \tprev_sym: %s (%p - %p)--------------\n",	
			info->sym->name, info->sym->addr, info->sym->size, prev_sym->name, prev_sym->addr, prev_sym->size);

	nops = get_potential_nops(insn, count, info);
	ret = lookup_viable_nop(insn, count, &nops, mdi, info, symtab, index, prev_index);
	if (count)
		cs_free(insn, count);
	

	/* look 128 byte after the symbol */
	if(ret.addr == 0) { 
		count = cs_disasm(disasm->engine, (void *)info->addr, 128,
				info->addr, 0, &insn);
		if (count == 0 && !memcmp((void *)prev_addr, endbr64, sizeof(endbr64))) {
			/* old version of capstone doesn't recognize ENDBR64 insn */
			unsigned long addr = prev_addr + sizeof(endbr64);

			info->orig_size += sizeof(endbr64);
			info->copy_size += sizeof(endbr64);

			count = cs_disasm(disasm->engine, (void *)addr,
					info->sym->addr - prev_sym->addr - sizeof(endbr64),
					addr, 0, &insn);
		}

		nops = get_potential_nops(insn, count, info);
		ret = lookup_viable_nop(insn, count, &nops, mdi, info, symtab, index, prev_index);
		if (count)
			cs_free(insn, count);
	}

	return ret;
}


int disasm_check_insns(struct mcount_disasm_engine *disasm,
		       struct mcount_dynamic_info *mdi,
		       struct mcount_disasm_info *info)
{
	return disasm_size_check_insns(disasm, mdi, info, CALL_INSN_SIZE);
}

int disasm_jmp8_check_insns(struct mcount_disasm_engine *disasm,
		       struct mcount_dynamic_info *mdi,
		       struct mcount_disasm_info *info)
{
	return disasm_size_check_insns(disasm, mdi, info, JMP8_INSN_SIZE);
}

#else /* HAVE_LIBCAPSTONE */

int disasm_check_insns(struct mcount_disasm_engine *disasm,
		       struct mcount_dynamic_info *mdi,
		       struct mcount_disasm_info *info)
{
	return INSTRUMENT_FAILED;
}

#endif /* HAVE_LIBCAPSTONE */

