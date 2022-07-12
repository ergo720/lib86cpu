/*
 * instruction helpers
 *
 * ergo720                Copyright (c) 2022
 */

#include "instructions.h"


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

template<bool is_iret>
uint8_t lret_pe_helper(cpu_ctx_t *cpu_ctx, uint8_t size_mode, uint32_t eip)
{
	cpu_t *cpu = cpu_ctx->cpu;
	uint32_t cpl = cpu->cpu_ctx.hflags & HFLG_CPL;
	uint32_t esp = cpu->cpu_ctx.regs.esp;
	uint32_t ret_eip, temp_eflags, eflags_mask;
	uint16_t cs;

	if constexpr (is_iret) {
		uint32_t eflags = cpu_ctx->regs.eflags;
		if (eflags & VM_MASK) {
			LIB86CPU_ABORT_msg("Virtual 8086 mode is not supported in iret instructions yet");
		}
		if (eflags & NT_MASK) {
			LIB86CPU_ABORT_msg("Task returns are not supported in iret instructions yet");
		}

		ret_eip = stack_pop_helper(cpu, size_mode, esp, eip);
		cs = stack_pop_helper(cpu, size_mode, esp, eip);
		temp_eflags = stack_pop_helper(cpu, size_mode, esp, eip);

		if (temp_eflags & VM_MASK) {
			LIB86CPU_ABORT_msg("Virtual 8086 mode returns are not supported in iret instructions yet");
		}

		if (size_mode == SIZE16) {
			eflags_mask = NT_MASK | DF_MASK | TF_MASK;
		}
		else {
			eflags_mask = ID_MASK | AC_MASK | RF_MASK | NT_MASK | DF_MASK | TF_MASK;
			if (cpl == 0) {
				eflags_mask |= (VIP_MASK | VIF_MASK | VM_MASK | IOPL_MASK);
			}
		}

		if (cpl <= ((cpu->cpu_ctx.regs.eflags & IOPL_MASK) >> 12)) {
			eflags_mask |= IF_MASK;
		}
	}
	else {
		ret_eip = stack_pop_helper(cpu, size_mode, esp, eip);
		cs = stack_pop_helper(cpu, size_mode, esp, eip);
	}
	
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
	if (rpl < cpl) { // rpl < cpl
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

	if (rpl > cpl) {
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

	if constexpr (is_iret) {
		write_eflags_helper(cpu, temp_eflags, eflags_mask);
	}

	return 0;
}

void
iret_real_helper(cpu_ctx_t *cpu_ctx, uint8_t size_mode, uint32_t eip)
{
	cpu_t *cpu = cpu_ctx->cpu;
	uint32_t esp = cpu->cpu_ctx.regs.esp;
	uint32_t eflags_mask;

	uint32_t ret_eip = stack_pop_helper(cpu, size_mode, esp, eip);
	uint16_t cs = stack_pop_helper(cpu, size_mode, esp, eip);
	uint32_t temp_eflags = stack_pop_helper(cpu, size_mode, esp, eip);

	if (size_mode == SIZE16) {
		eflags_mask = NT_MASK | IOPL_MASK | DF_MASK | IF_MASK | TF_MASK;
	}
	else {
		eflags_mask = ID_MASK | AC_MASK | RF_MASK | NT_MASK | IOPL_MASK | DF_MASK | IF_MASK | TF_MASK;
	}

	cpu->cpu_ctx.regs.esp = esp;
	cpu_ctx->regs.eip = ret_eip;
	cpu_ctx->regs.cs = cs;
	cpu_ctx->regs.cs_hidden.base = cs << 4;
	write_eflags_helper(cpu, temp_eflags, eflags_mask);
}

uint8_t
ljmp_pe_helper(cpu_ctx_t *cpu_ctx, uint16_t sel, uint8_t size_mode, uint32_t jmp_eip, uint32_t eip)
{
	cpu_t *cpu = cpu_ctx->cpu;
	uint16_t cpl = cpu->cpu_ctx.hflags & HFLG_CPL;

	if ((sel >> 2) == 0) { // sel == NULL
		return raise_exp_helper(cpu, 0, EXP_GP, eip);
	}

	addr_t desc_addr;
	uint64_t desc;
	if (read_seg_desc_helper(cpu, sel, desc_addr, desc, eip)) {
		return 1;
	}

	if (desc & SEG_DESC_S) {
		// non-system desc

		if ((desc & SEG_DESC_DC) == 0) { // !(data desc)
			return raise_exp_helper(cpu, sel & 0xFFFC, EXP_GP, eip);
		}

		uint16_t dpl = (desc & SEG_DESC_DPL) >> 45;

		if (desc & SEG_DESC_C) {
			// conforming

			if (dpl > cpl) { // dpl > cpl
				return raise_exp_helper(cpu, sel & 0xFFFC, EXP_GP, eip);
			}
		}
		else {
			// non-conforming

			uint16_t rpl = sel & 3;
			if ((rpl > cpl) || (dpl != cpl)) { // rpl > cpl || dpl != cpl
				return raise_exp_helper(cpu, sel & 0xFFFC, EXP_GP, eip);
			}
		}

		// commmon path for conf/non-conf

		if ((desc & SEG_DESC_P) == 0) { // segment not present
			return raise_exp_helper(cpu, sel & 0xFFFC, EXP_NP, eip);
		}

		set_access_flg_seg_desc_helper(cpu, desc, desc_addr, eip);
		write_seg_reg_helper<CS_idx>(cpu, (sel & 0xFFFC) | cpl, read_seg_desc_base_helper(cpu, desc), read_seg_desc_limit_helper(cpu, desc), read_seg_desc_flags_helper(cpu, desc));
		cpu_ctx->regs.eip = size_mode == SIZE16 ? jmp_eip & 0xFFFF : jmp_eip;
	}
	else {
		// system desc

		uint8_t sys_ty = (desc & SEG_DESC_TY) >> 40;
		switch (sys_ty)
		{
		case 1:
		case 5:
		case 9:
			LIB86CPU_ABORT_msg("Task and tss gates in jmp instructions are not supported yet");

		case 4: // call gate, 16 bit
		case 12: // call gate, 32 bit
			break;

		default:
			return raise_exp_helper(cpu, sel & 0xFFFC, EXP_GP, eip);
		}

		sys_ty >>= 3;
		uint16_t dpl = (desc & SEG_DESC_DPL) >> 45;
		uint16_t rpl = sel & 3;

		if ((dpl < cpl) || (rpl > dpl)) { // dpl < cpl || rpl > dpl
			return raise_exp_helper(cpu, sel & 0xFFFC, EXP_GP, eip);
		}

		if ((desc & SEG_DESC_P) == 0) { // segment not present
			return raise_exp_helper(cpu, sel & 0xFFFC, EXP_NP, eip);
		}

		uint16_t code_sel = (desc & 0xFFFF0000) >> 16;
		if ((code_sel >> 2) == 0) { // code_sel == NULL
			return raise_exp_helper(cpu, 0, EXP_GP, eip);
		}

		if (read_seg_desc_helper(cpu, code_sel, desc_addr, desc, eip)) { // read code desc pointed to by the call gate sel
			return 1;
		}

		dpl = (desc & SEG_DESC_DPL) >> 45;
		if (((((desc & SEG_DESC_S) >> 43) | ((desc & SEG_DESC_DC) >> 43)) != 3) || // !(code desc) || (conf && dpl > cpl) || (non-conf && dpl != cpl)
			((desc & SEG_DESC_C) && (dpl > cpl)) ||
			(((desc & SEG_DESC_C) == 0) && (dpl != cpl))) {
			return raise_exp_helper(cpu, code_sel & 0xFFFC, EXP_GP, eip);
		}

		if ((desc & SEG_DESC_P) == 0) { // segment not present
			return raise_exp_helper(cpu, code_sel & 0xFFFC, EXP_NP, eip);
		}

		set_access_flg_seg_desc_helper(cpu, desc, desc_addr, eip);
		write_seg_reg_helper<CS_idx>(cpu, (sel & 0xFFFC) | cpl, read_seg_desc_base_helper(cpu, desc), read_seg_desc_limit_helper(cpu, desc), read_seg_desc_flags_helper(cpu, desc));

		if (sys_ty == 0) {
			jmp_eip &= 0xFFFF;
		}
		cpu_ctx->regs.eip = jmp_eip;
	}

	return 0;
}

template uint8_t lret_pe_helper<true>(cpu_ctx_t *cpu_ctx, uint8_t size_mode, uint32_t eip);
template uint8_t lret_pe_helper<false>(cpu_ctx_t *cpu_ctx, uint8_t size_mode, uint32_t eip);
