/*
 * instruction helpers
 *
 * ergo720                Copyright (c) 2022
 */

#include "instructions.h"


static uint32_t
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

static uint8_t
raise_exp_helper(cpu_t *cpu, uint16_t code, uint16_t idx, uint32_t eip)
{
	cpu->cpu_ctx.exp_info.exp_data.code = code;
	cpu->cpu_ctx.exp_info.exp_data.idx = idx;
	cpu->cpu_ctx.exp_info.exp_data.eip = eip;
	return 1;
}

static uint8_t
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

static void
set_access_flg_seg_desc_helper(cpu_t *cpu, uint64_t desc, addr_t desc_addr, uint32_t eip)
{
	if ((((desc & SEG_DESC_S) >> 44) | ((desc & SEG_DESC_A) >> 39)) == 1) {
		mem_write<uint64_t>(cpu, desc_addr, desc | SEG_DESC_A, eip, 2);
	}
}

static uint32_t
read_seg_desc_base_helper(cpu_t *cpu, uint64_t desc)
{
	return (((desc & 0xFFFF0000) >> 16) | ((desc & 0xFF00000000) >> 16)) | ((desc & 0xFF00000000000000) >> 32);
}

static uint32_t
read_seg_desc_flags_helper(cpu_t *cpu, uint64_t desc)
{
	return (desc & 0xFFFFFFFF00000000) >> 32;
}

static uint32_t
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

template<unsigned reg>
static void
write_seg_reg_helper(cpu_t *cpu, uint16_t sel, uint32_t base, uint32_t limit, uint32_t flags)
{
	switch (reg)
	{
	case CS_idx:
		cpu->cpu_ctx.regs.cs = sel;
		cpu->cpu_ctx.regs.cs_hidden.base = base;
		cpu->cpu_ctx.regs.cs_hidden.limit = limit;
		cpu->cpu_ctx.regs.cs_hidden.flags = flags;
		cpu->cpu_ctx.hflags = (((cpu->cpu_ctx.regs.cs_hidden.flags & SEG_HIDDEN_DB) >> 20) | sel) | (cpu->cpu_ctx.hflags & ~(HFLG_CS32 | HFLG_CPL));
		break;

	case SS_idx:
		cpu->cpu_ctx.regs.ss = sel;
		cpu->cpu_ctx.regs.ss_hidden.base = base;
		cpu->cpu_ctx.regs.ss_hidden.limit = limit;
		cpu->cpu_ctx.regs.ss_hidden.flags = flags;
		cpu->cpu_ctx.hflags = ((cpu->cpu_ctx.regs.ss_hidden.flags & SEG_HIDDEN_DB) >> 19) | (cpu->cpu_ctx.hflags & ~HFLG_SS32);
		break;

	case DS_idx:
		cpu->cpu_ctx.regs.ds = sel;
		cpu->cpu_ctx.regs.ds_hidden.base = base;
		cpu->cpu_ctx.regs.ds_hidden.limit = limit;
		cpu->cpu_ctx.regs.ds_hidden.flags = flags;
		break;

	case ES_idx:
		cpu->cpu_ctx.regs.es = sel;
		cpu->cpu_ctx.regs.es_hidden.base = base;
		cpu->cpu_ctx.regs.es_hidden.limit = limit;
		cpu->cpu_ctx.regs.es_hidden.flags = flags;
		break;

	case FS_idx:
		cpu->cpu_ctx.regs.fs = sel;
		cpu->cpu_ctx.regs.fs_hidden.base = base;
		cpu->cpu_ctx.regs.fs_hidden.limit = limit;
		cpu->cpu_ctx.regs.fs_hidden.flags = flags;
		break;

	case GS_idx:
		cpu->cpu_ctx.regs.gs = sel;
		cpu->cpu_ctx.regs.gs_hidden.base = base;
		cpu->cpu_ctx.regs.gs_hidden.limit = limit;
		cpu->cpu_ctx.regs.gs_hidden.flags = flags;
		break;

	default:
		LIB86CPU_ABORT();
	}
}

template<unsigned reg>
static void
validate_seg_helper(cpu_t *cpu)
{
	uint32_t flags;
	switch (reg)
	{
	case CS_idx:
		flags = cpu->cpu_ctx.regs.cs_hidden.flags;
		break;

	case SS_idx:
		flags = cpu->cpu_ctx.regs.ss_hidden.flags;
		break;

	case DS_idx:
		flags = cpu->cpu_ctx.regs.ds_hidden.flags;
		break;

	case ES_idx:
		flags = cpu->cpu_ctx.regs.es_hidden.flags;
		break;

	case FS_idx:
		flags = cpu->cpu_ctx.regs.fs_hidden.flags;
		break;

	case GS_idx:
		flags = cpu->cpu_ctx.regs.gs_hidden.flags;
		break;

	default:
		LIB86CPU_ABORT();
	}

	uint32_t c = flags & (1 << 10);
	uint32_t d = flags & (1 << 11);
	uint32_t s = flags & (1 << 12);
	uint32_t dpl = (flags & (3 << 13) >> 13);
	uint32_t cpl = cpu->cpu_ctx.hflags & HFLG_CPL;
	if ((cpl > dpl) && (s && ((d == 0) || (c == 0)))) {
		write_seg_reg_helper<reg>(cpu, 0, 0, 0, 0);
	}
}

uint8_t
lret_pe_helper(cpu_ctx_t *cpu_ctx, uint8_t size_mode, uint32_t eip)
{
	cpu_t *cpu = cpu_ctx->cpu;
	uint32_t esp = cpu->cpu_ctx.regs.esp;
	uint32_t ret_eip = stack_pop_helper(cpu, size_mode, esp, eip);
	uint16_t cs = stack_pop_helper(cpu, size_mode, esp, eip);
	
	if ((cs >> 2) == 0) { // sel == NULL
		return raise_exp_helper(cpu, 0, EXP_GP, eip);
	}
	
	addr_t desc_addr;
	uint64_t cs_desc;
	if (read_seg_desc_helper(cpu, cs, desc_addr, cs_desc, eip)) {
		return 1;
	}

	uint32_t s = (cs_desc & SEG_DESC_S) >> 44; // !(sys desc)
	uint32_t d = (cs_desc & SEG_DESC_DC) >> 42; // !(data desc)
	if ((s | d) != 3) {
		return raise_exp_helper(cpu, cs & 0xFFFC, EXP_GP, eip);
	}

	uint32_t rpl = cs & 3;
	if (rpl < (cpu->cpu_ctx.hflags & HFLG_CPL)) { // rpl < cpl
		return raise_exp_helper(cpu, cs & 0xFFFC, EXP_GP, eip);
	}

	uint64_t c = cs_desc & SEG_DESC_C;
	uint32_t dpl = (cs_desc & SEG_DESC_DPL) >> 45;
	if (c && (dpl > rpl)) { // conf && dpl > rpl
		return raise_exp_helper(cpu, cs & 0xFFFC, EXP_GP, eip);
	}

	uint64_t p = cs_desc & SEG_DESC_P;
	if (p == 0) { // segment not present
		return raise_exp_helper(cpu, cs & 0xFFFC, EXP_NP, eip);
	}

	if (rpl > (cpu->cpu_ctx.hflags & HFLG_CPL)) {
		// less privileged

		uint32_t ret_esp = stack_pop_helper(cpu, size_mode, esp, eip);
		uint16_t ss = stack_pop_helper(cpu, size_mode, esp, eip);
		addr_t ss_desc_addr;
		uint64_t ss_desc;
		if (check_ss_desc_priv_helper(cpu, ss, &cs, ss_desc_addr, ss_desc, eip)) {
			return 1;
		}

		set_access_flg_seg_desc_helper(cpu, ss_desc, ss_desc_addr, eip);
		set_access_flg_seg_desc_helper(cpu, cs_desc, desc_addr, eip);
		write_seg_reg_helper<SS_idx>(cpu, ss, read_seg_desc_base_helper(cpu, ss_desc), read_seg_desc_limit_helper(cpu, ss_desc), read_seg_desc_flags_helper(cpu, ss_desc));
		write_seg_reg_helper<CS_idx>(cpu, cs, read_seg_desc_base_helper(cpu, cs_desc), read_seg_desc_limit_helper(cpu, cs_desc), read_seg_desc_flags_helper(cpu, cs_desc));
		
		uint32_t stack_mask;
		if (cpu->cpu_ctx.regs.ss_hidden.flags & SEG_HIDDEN_DB) {
			stack_mask = 0xFFFFFFFF;
		}
		else {
			stack_mask = 0xFFFF;
		}
		cpu->cpu_ctx.regs.esp = (cpu->cpu_ctx.regs.esp & ~stack_mask) | (ret_esp & stack_mask);
		cpu->cpu_ctx.regs.eip = ret_eip;
		validate_seg_helper<DS_idx>(cpu);
		validate_seg_helper<ES_idx>(cpu);
		validate_seg_helper<FS_idx>(cpu);
		validate_seg_helper<GS_idx>(cpu);
	}
	else {
		// same privilege

		set_access_flg_seg_desc_helper(cpu, cs_desc, desc_addr, eip);
		cpu->cpu_ctx.regs.esp = esp;
		cpu->cpu_ctx.regs.eip = ret_eip;
		write_seg_reg_helper<CS_idx>(cpu, cs, read_seg_desc_base_helper(cpu, cs_desc), read_seg_desc_limit_helper(cpu, cs_desc), read_seg_desc_flags_helper(cpu, cs_desc));
	}

	return 0;
}
