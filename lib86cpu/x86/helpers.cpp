/*
 * helpers for the instruction helpers
 *
 * ergo720                Copyright (c) 2022
 */

#include "helpers.h"


uint32_t
stack_pop_helper(cpu_t *cpu, uint32_t size_mode, uint32_t &addr, uint32_t eip)
{
	assert(size_mode != SIZE8);

	uint32_t ret;

	switch ((size_mode << 1) | ((cpu->cpu_ctx.hflags & HFLG_SS32) >> SS32_SHIFT))
	{
	case 0: { // sp, pop 32
		uint16_t sp = addr & 0xFFFF;
		ret = mem_read<uint32_t>(cpu, sp + cpu->cpu_ctx.regs.ss_hidden.base, eip, 0);
		addr = sp + 4;
	}
	break;

	case 1: { // esp, pop 32
		uint32_t esp = addr;
		ret = mem_read<uint32_t>(cpu, esp + cpu->cpu_ctx.regs.ss_hidden.base, eip, 0);
		addr = esp + 4;
	}
	break;

	case 2: { // sp, pop 16
		uint16_t sp = addr & 0xFFFF;
		ret = mem_read<uint16_t>(cpu, sp + cpu->cpu_ctx.regs.ss_hidden.base, eip, 0);
		addr = sp + 2;
	}
	break;

	case 3: { // esp, pop 16
		uint16_t esp = addr;
		ret = mem_read<uint16_t>(cpu, esp + cpu->cpu_ctx.regs.ss_hidden.base, eip, 0);
		addr = esp + 2;
	}
	break;

	default:
		LIB86CPU_ABORT();
	}

	return ret;
}

uint8_t
raise_exp_helper(cpu_t *cpu, uint16_t code, uint16_t idx, uint32_t eip)
{
	cpu->cpu_ctx.exp_info.exp_data.code = code;
	cpu->cpu_ctx.exp_info.exp_data.idx = idx;
	cpu->cpu_ctx.exp_info.exp_data.eip = eip;
	return 1;
}

uint8_t
read_seg_desc_helper(cpu_t *cpu, uint16_t sel, addr_t &desc_addr, uint64_t &desc, uint32_t eip)
{
	uint32_t base, limit;
	uint16_t idx = sel >> 3;
	if (((sel & 4) >> 2) == 0) {
		base = cpu->cpu_ctx.regs.gdtr_hidden.base;
		limit = cpu->cpu_ctx.regs.gdtr_hidden.limit;
	}
	else {
		base = cpu->cpu_ctx.regs.ldtr_hidden.base;
		limit = cpu->cpu_ctx.regs.ldtr_hidden.limit;
	}

	desc_addr = base + idx * 8;
	if (desc_addr + 7 > base + limit) { // sel idx outside of descriptor table
		return raise_exp_helper(cpu, sel & 0xFFFC, EXP_GP, eip);
	}

	desc = mem_read<uint64_t>(cpu, desc_addr, eip, 2);
	return 0;
}

void
set_access_flg_seg_desc_helper(cpu_t *cpu, uint64_t desc, addr_t desc_addr, uint32_t eip)
{
	if ((((desc & SEG_DESC_S) >> 44) | ((desc & SEG_DESC_A) >> 39)) == 1) {
		mem_write<uint64_t>(cpu, desc_addr, desc | SEG_DESC_A, eip, 2);
	}
}

uint32_t
read_seg_desc_base_helper(cpu_t *cpu, uint64_t desc)
{
	return (((desc & 0xFFFF0000) >> 16) | ((desc & 0xFF00000000) >> 16)) | ((desc & 0xFF00000000000000) >> 32);
}

uint32_t
read_seg_desc_flags_helper(cpu_t *cpu, uint64_t desc)
{
	return (desc & 0xFFFFFFFF00000000) >> 32;
}

uint32_t
read_seg_desc_limit_helper(cpu_t *cpu, uint64_t desc)
{
	uint32_t limit = (desc & 0xFFFF) | ((desc & 0xF000000000000) >> 32);
	if (desc & SEG_DESC_G) {
		limit = (limit << 12) | PAGE_MASK;
	}
	return limit;
}

uint8_t
check_ss_desc_priv_helper(cpu_t *cpu, uint16_t sel, uint16_t *cs, addr_t &desc_addr, uint64_t &desc, uint32_t eip)
{
	if ((sel >> 2) == 0) { // sel == NULL
		return raise_exp_helper(cpu, 0, EXP_GP, eip);
	}

	if (read_seg_desc_helper(cpu, sel, desc_addr, desc, eip)) {
		return 1;
	}

	uint16_t s = (desc & SEG_DESC_S) >> 44; // cannot be a system segment
	uint16_t d = (desc & SEG_DESC_DC) >> 42; // cannot be a code segment
	uint16_t w = (desc & SEG_DESC_W) >> 39; // cannot be a non-writable data segment
	uint16_t dpl = (desc & SEG_DESC_DPL) >> 42;
	uint16_t rpl = (sel & 3) << 5;
	uint16_t val;
	// check for segment privilege violations
	if (cs == nullptr) {
		uint16_t cpl = cpu->cpu_ctx.hflags & HFLG_CPL;
		val = ((((s | d) | w) | dpl) | rpl) ^ ((5 | (cpl << 3)) | (cpl << 5));
	}
	else {
		uint16_t rpl_cs = *cs & 3;
		val = ((((s | d) | w) | dpl) | rpl) ^ ((5 | (rpl_cs << 3)) | (rpl_cs << 5));
	}

	if (val) {
		return raise_exp_helper(cpu, sel & 0xFFFC, EXP_GP, eip);
	}

	uint64_t p = desc & SEG_DESC_P;
	if (p == 0) { // segment not present
		return raise_exp_helper(cpu, sel & 0xFFFC, EXP_SS, eip);
	}
	return 0;
}
