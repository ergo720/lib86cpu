/*
 * instruction helpers
 *
 * ergo720                Copyright (c) 2022
 */

#include "instructions.h"
#include "debugger.h"
#include "clock.h"


template<unsigned reg>
concept is_valid_sel_idx = (reg == CS_idx) ||
(reg == SS_idx) ||
(reg == DS_idx) ||
(reg == ES_idx) ||
(reg == FS_idx) ||
(reg == GS_idx) ||
(reg == LDTR_idx) ||
(reg == TR_idx);

template<unsigned reg>
requires (is_valid_sel_idx<reg>)
static void
write_seg_reg_helper(cpu_t *cpu, uint16_t sel, uint32_t base, uint32_t limit, uint32_t flags)
{
	if constexpr (reg == LDTR_idx) {
		cpu->cpu_ctx.regs.ldtr = sel;
		cpu->cpu_ctx.regs.ldtr_hidden.base = base;
		cpu->cpu_ctx.regs.ldtr_hidden.limit = limit;
		cpu->cpu_ctx.regs.ldtr_hidden.flags = flags;
	}
	else if constexpr (reg == TR_idx) {
		cpu->cpu_ctx.regs.tr = sel;
		cpu->cpu_ctx.regs.tr_hidden.base = base;
		cpu->cpu_ctx.regs.tr_hidden.limit = limit;
		cpu->cpu_ctx.regs.tr_hidden.flags = flags;
	}
	else {
		constexpr uint32_t sel_mask = 1 << (reg + ZERO_SEL2HFLG);
		uint32_t sel_is_zero = base ? 0 : sel_mask;

		switch (reg)
		{
		case CS_idx:
			cpu->cpu_ctx.regs.cs = sel;
			cpu->cpu_ctx.regs.cs_hidden.base = base;
			cpu->cpu_ctx.regs.cs_hidden.limit = limit;
			cpu->cpu_ctx.regs.cs_hidden.flags = flags;
			cpu->cpu_ctx.hflags = (((cpu->cpu_ctx.regs.cs_hidden.flags & SEG_HIDDEN_DB) >> 20) | (sel & HFLG_CPL)) | sel_is_zero | (cpu->cpu_ctx.hflags & ~(HFLG_CS32 | HFLG_CPL | sel_mask));
			break;

		case SS_idx:
			cpu->cpu_ctx.regs.ss = sel;
			cpu->cpu_ctx.regs.ss_hidden.base = base;
			cpu->cpu_ctx.regs.ss_hidden.limit = limit;
			cpu->cpu_ctx.regs.ss_hidden.flags = flags;
			cpu->cpu_ctx.hflags = ((cpu->cpu_ctx.regs.ss_hidden.flags & SEG_HIDDEN_DB) >> 19) | sel_is_zero | (cpu->cpu_ctx.hflags & ~(HFLG_SS32 | sel_mask));
			break;

		case DS_idx:
			cpu->cpu_ctx.regs.ds = sel;
			cpu->cpu_ctx.regs.ds_hidden.base = base;
			cpu->cpu_ctx.regs.ds_hidden.limit = limit;
			cpu->cpu_ctx.regs.ds_hidden.flags = flags;
			cpu->cpu_ctx.hflags = sel_is_zero | (cpu->cpu_ctx.hflags & ~sel_mask);
			break;

		case ES_idx:
			cpu->cpu_ctx.regs.es = sel;
			cpu->cpu_ctx.regs.es_hidden.base = base;
			cpu->cpu_ctx.regs.es_hidden.limit = limit;
			cpu->cpu_ctx.regs.es_hidden.flags = flags;
			cpu->cpu_ctx.hflags = sel_is_zero | (cpu->cpu_ctx.hflags & ~sel_mask);
			break;

		case FS_idx:
			cpu->cpu_ctx.regs.fs = sel;
			cpu->cpu_ctx.regs.fs_hidden.base = base;
			cpu->cpu_ctx.regs.fs_hidden.limit = limit;
			cpu->cpu_ctx.regs.fs_hidden.flags = flags;
			cpu->cpu_ctx.hflags = sel_is_zero | (cpu->cpu_ctx.hflags & ~sel_mask);
			break;

		case GS_idx:
			cpu->cpu_ctx.regs.gs = sel;
			cpu->cpu_ctx.regs.gs_hidden.base = base;
			cpu->cpu_ctx.regs.gs_hidden.limit = limit;
			cpu->cpu_ctx.regs.gs_hidden.flags = flags;
			cpu->cpu_ctx.hflags = sel_is_zero | (cpu->cpu_ctx.hflags & ~sel_mask);
			break;

		default:
			LIB86CPU_ABORT();
		}
	}
}

template<unsigned reg>
static void
write_seg_reg_vm86_helper(cpu_t *cpu, uint16_t sel)
{
	constexpr uint64_t code_seg = (reg == CS_idx) ? SEG_DESC_DC : 0;
	write_seg_reg_helper<reg>(cpu, sel, sel << 4, 0xFFFF, (SEG_DESC_A | SEG_DESC_W | code_seg | SEG_DESC_S | SEG_DESC_DPL | SEG_DESC_P) >> 32);
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
uint32_t lret_pe_helper(cpu_ctx_t *cpu_ctx, uint8_t size_mode)
{
	cpu_t *cpu = cpu_ctx->cpu;
	uint32_t cpl = cpu->cpu_ctx.hflags & HFLG_CPL;
	uint32_t esp = cpu->cpu_ctx.regs.esp;
	uint32_t ret_eip, temp_eflags, eflags_mask;
	uint16_t cs;

	if constexpr (is_iret) {
		uint32_t eflags = cpu_ctx->regs.eflags;

		if (eflags & VM_MASK) {
			// return from vm86 mode
			if (((eflags & IOPL_MASK) >> 12) == 3) {
				iret_real_helper(cpu_ctx, size_mode);
				return 0;
			}

			return raise_exp_helper(cpu, 0, EXP_GP);
		}

		if (eflags & NT_MASK) {
			LIB86CPU_ABORT_msg("Task returns are not supported in iret instructions yet");
		}

		ret_eip = stack_pop_helper(cpu, size_mode, esp);
		cs = stack_pop_helper(cpu, size_mode, esp);
		temp_eflags = stack_pop_helper(cpu, size_mode, esp);

		if (temp_eflags & VM_MASK) {
			// return to vm86 mode
			uint32_t new_esp, ss, es, ds, fs, gs;

			new_esp = stack_pop_helper(cpu, SIZE32, esp);
			ss = stack_pop_helper(cpu, SIZE32, esp);
			es = stack_pop_helper(cpu, SIZE32, esp);
			ds = stack_pop_helper(cpu, SIZE32, esp);
			fs = stack_pop_helper(cpu, SIZE32, esp);
			gs = stack_pop_helper(cpu, SIZE32, esp);

			write_eflags_helper(cpu, temp_eflags, TF_MASK | AC_MASK | ID_MASK |
				IF_MASK | IOPL_MASK | VM_MASK | NT_MASK | VIF_MASK | VIP_MASK);

			write_seg_reg_vm86_helper<CS_idx>(cpu, cs);
			write_seg_reg_vm86_helper<SS_idx>(cpu, ss);
			write_seg_reg_vm86_helper<ES_idx>(cpu, es);
			write_seg_reg_vm86_helper<DS_idx>(cpu, ds);
			write_seg_reg_vm86_helper<FS_idx>(cpu, fs);
			write_seg_reg_vm86_helper<GS_idx>(cpu, gs);

			cpu->cpu_ctx.regs.esp = new_esp;
			cpu->cpu_ctx.regs.eip = ret_eip;
			cpu->cpu_ctx.hflags = ((cpu->cpu_ctx.hflags & ~HFLG_CPL) | 3);

			return 0;
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
		ret_eip = stack_pop_helper(cpu, size_mode, esp);
		cs = stack_pop_helper(cpu, size_mode, esp);
	}
	
	if ((cs >> 2) == 0) { // sel == NULL
		return raise_exp_helper(cpu, 0, EXP_GP);
	}
	
	addr_t desc_addr;
	uint64_t cs_desc;
	if (read_seg_desc_helper(cpu, cs, desc_addr, cs_desc)) {
		return 1;
	}

	uint32_t s = (cs_desc & SEG_DESC_S) >> 44; // !(sys desc)
	uint32_t d = (cs_desc & SEG_DESC_DC) >> 42; // !(data desc)
	if ((s | d) != 3) {
		return raise_exp_helper(cpu, cs & 0xFFFC, EXP_GP);
	}

	uint32_t rpl = cs & 3;
	if (rpl < cpl) { // rpl < cpl
		return raise_exp_helper(cpu, cs & 0xFFFC, EXP_GP);
	}

	uint64_t c = cs_desc & SEG_DESC_C;
	uint32_t dpl = (cs_desc & SEG_DESC_DPL) >> 45;
	if (c && (dpl > rpl)) { // conf && dpl > rpl
		return raise_exp_helper(cpu, cs & 0xFFFC, EXP_GP);
	}

	uint64_t p = cs_desc & SEG_DESC_P;
	if (p == 0) { // segment not present
		return raise_exp_helper(cpu, cs & 0xFFFC, EXP_NP);
	}

	if (rpl > cpl) {
		// less privileged

		uint32_t ret_esp = stack_pop_helper(cpu, size_mode, esp);
		uint16_t ss = stack_pop_helper(cpu, size_mode, esp);
		addr_t ss_desc_addr;
		uint64_t ss_desc;
		if (check_ss_desc_priv_helper(cpu, ss, &cs, ss_desc_addr, ss_desc)) {
			return 1;
		}

		set_access_flg_seg_desc_helper(cpu, ss_desc, ss_desc_addr);
		set_access_flg_seg_desc_helper(cpu, cs_desc, desc_addr);
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

		set_access_flg_seg_desc_helper(cpu, cs_desc, desc_addr);

		uint32_t stack_mask;
		if (cpu->cpu_ctx.hflags & HFLG_SS32) {
			stack_mask = 0xFFFFFFFF;
		}
		else {
			stack_mask = 0xFFFF;
		}
		cpu->cpu_ctx.regs.esp = (cpu->cpu_ctx.regs.esp & ~stack_mask) | (esp & stack_mask);
		cpu->cpu_ctx.regs.eip = ret_eip;
		write_seg_reg_helper<CS_idx>(cpu, cs, read_seg_desc_base_helper(cpu, cs_desc), read_seg_desc_limit_helper(cpu, cs_desc), read_seg_desc_flags_helper(cpu, cs_desc));
	}

	if constexpr (is_iret) {
		write_eflags_helper(cpu, temp_eflags, eflags_mask);
	}

	return 0;
}

void
iret_real_helper(cpu_ctx_t *cpu_ctx, uint8_t size_mode)
{
	cpu_t *cpu = cpu_ctx->cpu;
	uint32_t esp = cpu->cpu_ctx.regs.esp;
	uint32_t eflags_mask;

	uint32_t ret_eip = stack_pop_helper(cpu, size_mode, esp);
	uint16_t cs = stack_pop_helper(cpu, size_mode, esp);
	uint32_t temp_eflags = stack_pop_helper(cpu, size_mode, esp);

	if (cpu->cpu_ctx.regs.eflags & VM_MASK) {
		// vm86 mode masks iopl, real mode doesn't
		eflags_mask = TF_MASK | IF_MASK | DF_MASK | NT_MASK | RF_MASK | AC_MASK | ID_MASK;
	}
	else {
		eflags_mask = TF_MASK | IF_MASK | DF_MASK | IOPL_MASK | NT_MASK | RF_MASK | AC_MASK | ID_MASK;
	}

	if (size_mode == SIZE16) {
		// mask out flags in the upper word
		eflags_mask &= 0xFFFF;
	}

	cpu->cpu_ctx.regs.esp = (cpu->cpu_ctx.regs.esp & ~0xFFFF) | (esp & 0xFFFF);
	cpu_ctx->regs.eip = ret_eip;
	cpu_ctx->regs.cs = cs;
	cpu_ctx->regs.cs_hidden.base = cs << 4;
	write_eflags_helper(cpu, temp_eflags, eflags_mask);
}

uint32_t
ljmp_pe_helper(cpu_ctx_t *cpu_ctx, uint16_t sel, uint8_t size_mode, uint32_t jmp_eip)
{
	cpu_t *cpu = cpu_ctx->cpu;
	uint16_t cpl = cpu->cpu_ctx.hflags & HFLG_CPL;

	if ((sel >> 2) == 0) { // sel == NULL
		return raise_exp_helper(cpu, 0, EXP_GP);
	}

	addr_t desc_addr;
	uint64_t desc;
	if (read_seg_desc_helper(cpu, sel, desc_addr, desc)) {
		return 1;
	}

	if (desc & SEG_DESC_S) {
		// non-system desc

		if ((desc & SEG_DESC_DC) == 0) { // !(data desc)
			return raise_exp_helper(cpu, sel & 0xFFFC, EXP_GP);
		}

		uint16_t dpl = (desc & SEG_DESC_DPL) >> 45;

		if (desc & SEG_DESC_C) {
			// conforming

			if (dpl > cpl) { // dpl > cpl
				return raise_exp_helper(cpu, sel & 0xFFFC, EXP_GP);
			}
		}
		else {
			// non-conforming

			uint16_t rpl = sel & 3;
			if ((rpl > cpl) || (dpl != cpl)) { // rpl > cpl || dpl != cpl
				return raise_exp_helper(cpu, sel & 0xFFFC, EXP_GP);
			}
		}

		// common path for conf/non-conf

		if ((desc & SEG_DESC_P) == 0) { // segment not present
			return raise_exp_helper(cpu, sel & 0xFFFC, EXP_NP);
		}

		set_access_flg_seg_desc_helper(cpu, desc, desc_addr);
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
			return raise_exp_helper(cpu, sel & 0xFFFC, EXP_GP);
		}

		sys_ty >>= 3;
		uint16_t dpl = (desc & SEG_DESC_DPL) >> 45;
		uint16_t rpl = sel & 3;

		if ((dpl < cpl) || (rpl > dpl)) { // dpl < cpl || rpl > dpl
			return raise_exp_helper(cpu, sel & 0xFFFC, EXP_GP);
		}

		if ((desc & SEG_DESC_P) == 0) { // segment not present
			return raise_exp_helper(cpu, sel & 0xFFFC, EXP_NP);
		}

		uint16_t code_sel = (desc & 0xFFFF0000) >> 16;
		if ((code_sel >> 2) == 0) { // code_sel == NULL
			return raise_exp_helper(cpu, 0, EXP_GP);
		}

		if (read_seg_desc_helper(cpu, code_sel, desc_addr, desc)) { // read code desc pointed to by the call gate sel
			return 1;
		}

		dpl = (desc & SEG_DESC_DPL) >> 45;
		if (((((desc & SEG_DESC_S) >> 43) | ((desc & SEG_DESC_DC) >> 43)) != 3) || // !(code desc) || (conf && dpl > cpl) || (non-conf && dpl != cpl)
			((desc & SEG_DESC_C) && (dpl > cpl)) ||
			(((desc & SEG_DESC_C) == 0) && (dpl != cpl))) {
			return raise_exp_helper(cpu, code_sel & 0xFFFC, EXP_GP);
		}

		if ((desc & SEG_DESC_P) == 0) { // segment not present
			return raise_exp_helper(cpu, code_sel & 0xFFFC, EXP_NP);
		}

		set_access_flg_seg_desc_helper(cpu, desc, desc_addr);
		write_seg_reg_helper<CS_idx>(cpu, (sel & 0xFFFC) | cpl, read_seg_desc_base_helper(cpu, desc), read_seg_desc_limit_helper(cpu, desc), read_seg_desc_flags_helper(cpu, desc));

		if (sys_ty == 0) {
			jmp_eip &= 0xFFFF;
		}
		cpu_ctx->regs.eip = jmp_eip;
	}

	return 0;
}

uint32_t
lcall_pe_helper(cpu_ctx_t *cpu_ctx, uint16_t sel, uint32_t call_eip, uint8_t size_mode, uint32_t ret_eip)
{
	cpu_t *cpu = cpu_ctx->cpu;
	uint16_t cpl = cpu->cpu_ctx.hflags & HFLG_CPL;

	if ((sel >> 2) == 0) { // sel == NULL
		return raise_exp_helper(cpu, 0, EXP_GP);
	}

	addr_t cs_desc_addr;
	uint64_t cs_desc;
	if (read_seg_desc_helper(cpu, sel, cs_desc_addr, cs_desc)) {
		return 1;
	}

	if (cs_desc & SEG_DESC_S) {
		// non-system desc

		if ((cs_desc & SEG_DESC_DC) == 0) { // !(data desc)
			return raise_exp_helper(cpu, sel & 0xFFFC, EXP_GP);
		}

		uint16_t dpl = (cs_desc & SEG_DESC_DPL) >> 45;

		if (cs_desc & SEG_DESC_C) {
			// conforming

			if (dpl > cpl) { // dpl > cpl
				return raise_exp_helper(cpu, sel & 0xFFFC, EXP_GP);
			}
		}
		else {
			// non-conforming

			uint16_t rpl = sel & 3;
			if ((rpl > cpl) || (dpl != cpl)) { // rpl > cpl || dpl != cpl
				return raise_exp_helper(cpu, sel & 0xFFFC, EXP_GP);
			}
		}

		// common path for conf/non-conf

		if ((cs_desc & SEG_DESC_P) == 0) { // segment not present
			return raise_exp_helper(cpu, sel & 0xFFFC, EXP_NP);
		}

		uint32_t esp = cpu->cpu_ctx.regs.esp;
		stack_push_helper(cpu, cpu_ctx->regs.cs, size_mode, esp);
		stack_push_helper(cpu, ret_eip, size_mode, esp);
		set_access_flg_seg_desc_helper(cpu, cs_desc, cs_desc_addr);
		write_seg_reg_helper<CS_idx>(cpu, (sel & 0xFFFC) | cpl, read_seg_desc_base_helper(cpu, cs_desc), read_seg_desc_limit_helper(cpu, cs_desc), read_seg_desc_flags_helper(cpu, cs_desc));
		cpu->cpu_ctx.regs.esp = esp;
		cpu_ctx->regs.eip = call_eip; // call_eip is already appropriately masked by the caller
	}
	else {
		// system desc

		uint8_t sys_ty = (cs_desc & SEG_DESC_TY) >> 40;
		switch (sys_ty)
		{
		case 1:
		case 5:
		case 9:
			LIB86CPU_ABORT_msg("Task and tss gates in call instructions are not supported yet");

		case 4: // call gate, 16 bit
		case 12: // call gate, 32 bit
			break;

		default:
			return raise_exp_helper(cpu, sel & 0xFFFC, EXP_GP);
		}

		sys_ty >>= 3;
		uint16_t dpl = (cs_desc & SEG_DESC_DPL) >> 45;
		uint16_t rpl = sel & 3;

		if ((dpl < cpl) || (rpl > dpl)) { // dpl < cpl || rpl > dpl
			return raise_exp_helper(cpu, sel & 0xFFFC, EXP_GP);
		}

		if ((cs_desc & SEG_DESC_P) == 0) { // segment not present
			return raise_exp_helper(cpu, sel & 0xFFFC, EXP_NP);
		}

		uint32_t num_param = (cs_desc >> 32) & 0x1F;
		uint32_t new_eip = ((cs_desc & 0xFFFF000000000000) >> 32) | (cs_desc & 0xFFFF);
		uint16_t code_sel = (cs_desc & 0xFFFF0000) >> 16;
		if ((code_sel >> 2) == 0) { // code_sel == NULL
			return raise_exp_helper(cpu, 0, EXP_GP);
		}

		addr_t code_desc_addr;
		uint64_t code_desc;
		if (read_seg_desc_helper(cpu, code_sel, code_desc_addr, code_desc)) { // read code desc pointed to by the call gate sel
			return 1;
		}

		dpl = (code_desc & SEG_DESC_DPL) >> 45;
		if (((((code_desc & SEG_DESC_S) >> 43) | ((code_desc & SEG_DESC_DC) >> 43)) != 3) || // !(code desc) || dpl > cpl
			(dpl > cpl)) {
			return raise_exp_helper(cpu, code_sel & 0xFFFC, EXP_GP);
		}

		if ((code_desc & SEG_DESC_P) == 0) { // segment not present
			return raise_exp_helper(cpu, code_sel & 0xFFFC, EXP_NP);
		}

		uint32_t eip_mask, esp;
		if (((code_desc & SEG_DESC_C) == 0) && (dpl < cpl)) {
			// more privileged

			uint16_t ss;
			if (read_stack_ptr_from_tss_helper(cpu, dpl, esp, ss)) {
				return 1;
			}

			if ((ss >> 2) == 0) { // sel == NULL
				return raise_exp_helper(cpu, ss & 0xFFFC, EXP_TS);
			}

			addr_t ss_desc_addr;
			uint64_t ss_desc;
			if (read_seg_desc_helper(cpu, ss, ss_desc_addr, ss_desc)) { // read data (stack) desc pointed to by ss
				return 1;
			}

			uint16_t s = (ss_desc & SEG_DESC_S) >> 44; // !(sys desc)
			uint16_t d = (ss_desc & SEG_DESC_DC) >> 42; // data desc
			uint16_t w = (ss_desc & SEG_DESC_W) >> 39;	// writable
			uint16_t dpl_ss = (ss_desc & SEG_DESC_DPL) >> 42; // dpl(ss) == dpl(code)
			uint16_t rpl_ss = (ss & 3) << 5; // rpl(ss) == dpl(code)
			if (((((s | d) | w) | dpl_ss) | rpl_ss) ^ ((5 | (dpl << 3)) | (dpl << 5))) {
				return raise_exp_helper(cpu, ss & 0xFFFC, EXP_TS);
			}

			if ((ss_desc & SEG_DESC_P) == 0) { // segment not present
				return raise_exp_helper(cpu, ss & 0xFFFC, EXP_SS);
			}

			uint32_t stack_mask = ss_desc & SEG_DESC_DB ? 0xFFFFFFFF : 0xFFFF;
			uint32_t stack_base = read_seg_desc_base_helper(cpu, ss_desc);
			int32_t i = num_param - 1;
			if (sys_ty) { // 32 bit push
				eip_mask = 0xFFFFFFFF;
				esp -= 4;
				mem_write_helper<uint32_t>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.ss, 2); // push ss
				esp -= 4;
				mem_write_helper<uint32_t>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.esp, 2); // push esp
				while (i >= 0) {
					uint32_t param32 = mem_read_helper<uint32_t>(cpu_ctx, cpu_ctx->regs.ss_hidden.base + ((cpu_ctx->regs.esp + i * 4) & stack_mask), 2); // read param from src stack
					esp -= 4;
					mem_write_helper<uint32_t>(cpu_ctx, stack_base + (esp & stack_mask), param32, 2); // push param to dst stack
					--i;
				}
				esp -= 4;
				mem_write_helper<uint32_t>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.cs, 2); // push cs
				esp -= 4;
				mem_write_helper<uint32_t>(cpu_ctx, stack_base + (esp & stack_mask), ret_eip, 2); // push eip
			}
			else { // 16 bit push
				eip_mask = 0xFFFF;
				esp -= 2;
				mem_write_helper<uint16_t>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.ss, 2); // push ss
				esp -= 2;
				mem_write_helper<uint16_t>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.esp, 2); // push sp
				while (i >= 0) {
					uint16_t param16 = mem_read_helper<uint16_t>(cpu_ctx, cpu_ctx->regs.ss_hidden.base + ((cpu_ctx->regs.esp + i * 2) & stack_mask), 2); // read param from src stack
					esp -= 2;
					mem_write_helper<uint16_t>(cpu_ctx, stack_base + (esp & stack_mask), param16, 2); // push param to dst stack
					--i;
				}
				esp -= 2;
				mem_write_helper<uint16_t>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.cs, 2); // push cs
				esp -= 2;
				mem_write_helper<uint16_t>(cpu_ctx, stack_base + (esp & stack_mask), ret_eip, 2); // push ip
			}

			set_access_flg_seg_desc_helper(cpu, ss_desc, ss_desc_addr);
			write_seg_reg_helper<SS_idx>(cpu, (ss & 0xFFFC) | dpl, read_seg_desc_base_helper(cpu, ss_desc), read_seg_desc_limit_helper(cpu, ss_desc), read_seg_desc_flags_helper(cpu, ss_desc));
		}
		else {
			// same privilege

			esp = cpu_ctx->regs.esp;
			uint32_t stack_base = cpu_ctx->regs.ss_hidden.base;
			uint32_t stack_mask = cpu->cpu_ctx.hflags & HFLG_SS32 ? 0xFFFFFFFF : 0xFFFF;
			if (sys_ty) { // 32 bit push
				eip_mask = 0xFFFFFFFF;
				esp -= 4;
				mem_write_helper<uint32_t>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.cs, 0); // push cs
				esp -= 4;
				mem_write_helper<uint32_t>(cpu_ctx, stack_base + (esp & stack_mask), ret_eip, 0); // push eip
			}
			else { // 16 bit push
				eip_mask = 0xFFFF;
				esp -= 2;
				mem_write_helper<uint16_t>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.cs, 0); // push cs
				esp -= 2;
				mem_write_helper<uint16_t>(cpu_ctx, stack_base + (esp & stack_mask), ret_eip, 0); // push ip
			}
		}

		set_access_flg_seg_desc_helper(cpu, code_desc, code_desc_addr);
		write_seg_reg_helper<CS_idx>(cpu, (code_sel & 0xFFFC) | dpl, read_seg_desc_base_helper(cpu, code_desc), read_seg_desc_limit_helper(cpu, code_desc), read_seg_desc_flags_helper(cpu, code_desc));
		cpu->cpu_ctx.regs.esp = esp;
		cpu_ctx->regs.eip = (new_eip & ~eip_mask) | (new_eip & eip_mask);
	}

	return 0;
}

template<unsigned reg>
uint32_t mov_sel_real_helper(cpu_ctx_t *cpu_ctx, uint16_t sel)
{
	constexpr uint32_t sel_mask = 1 << (reg + ZERO_SEL2HFLG);
	uint32_t base = sel << 4;
	uint32_t sel_is_zero = base ? 0 : sel_mask;
	cpu_ctx->hflags = sel_is_zero | (cpu_ctx->hflags & ~sel_mask);

	switch (reg)
	{
	case CS_idx:
		cpu_ctx->regs.cs = sel;
		cpu_ctx->regs.cs_hidden.base = base;
		break;

	case SS_idx:
		cpu_ctx->regs.ss = sel;
		cpu_ctx->regs.ss_hidden.base = base;
		break;

	case DS_idx:
		cpu_ctx->regs.ds = sel;
		cpu_ctx->regs.ds_hidden.base = base;
		break;

	case ES_idx:
		cpu_ctx->regs.es = sel;
		cpu_ctx->regs.es_hidden.base = base;
		break;

	case FS_idx:
		cpu_ctx->regs.fs = sel;
		cpu_ctx->regs.fs_hidden.base = base;
		break;

	case GS_idx:
		cpu_ctx->regs.gs = sel;
		cpu_ctx->regs.gs_hidden.base = base;
		break;

	default:
		LIB86CPU_ABORT();
	}

	return 0;
}

template<unsigned reg>
uint32_t mov_sel_pe_helper(cpu_ctx_t *cpu_ctx, uint16_t sel)
{
	cpu_t *cpu = cpu_ctx->cpu;

	if constexpr (reg == SS_idx) {
		addr_t desc_addr;
		uint64_t desc;
		if (check_ss_desc_priv_helper(cpu, sel, nullptr, desc_addr, desc)) {
			return 1;
		}

		set_access_flg_seg_desc_helper(cpu, desc, desc_addr);
		write_seg_reg_helper<reg>(cpu, sel, read_seg_desc_base_helper(cpu, desc), read_seg_desc_limit_helper(cpu, desc), read_seg_desc_flags_helper(cpu, desc));
	}
	else {
		if ((sel >> 2) == 0) {
			write_seg_reg_helper<reg>(cpu, 0, 0, 0, 0);
			return 0;
		}

		addr_t desc_addr;
		uint64_t desc;
		if (check_seg_desc_priv_helper(cpu, sel, desc_addr, desc)) {
			return 1;
		}

		set_access_flg_seg_desc_helper(cpu, desc, desc_addr);
		write_seg_reg_helper<reg>(cpu, sel /* & rpl?? */, read_seg_desc_base_helper(cpu, desc), read_seg_desc_limit_helper(cpu, desc), read_seg_desc_flags_helper(cpu, desc));
	}

	return 0;
}

template<bool is_verr>
void verrw_helper(cpu_ctx_t *cpu_ctx, uint16_t sel)
{
	cpu_t *cpu = cpu_ctx->cpu;

	if ((sel >> 2) == 0) { // sel == NULL
		cpu_ctx->lazy_eflags.result |= 0x100;
		return;
	}

	addr_t desc_addr;
	uint64_t desc;
	if (read_seg_desc_helper(cpu, sel, desc_addr, desc)) { // gdt or ldt limit exceeded
		// NOTE: ignore possible gp exp raised by read_seg_desc_helper
		cpu_ctx->lazy_eflags.result |= 0x100;
		return;
	}

	uint16_t dpl = (desc & SEG_DESC_DPL) >> 45;
	if (((desc & SEG_DESC_S) == 0) || // system desc
		(((desc & SEG_DESC_TYC) != 0xC0000000000) && // code, conf desc
		(((cpu->cpu_ctx.hflags & HFLG_CPL) > dpl) || ((sel & 3) > dpl))) // cpl > dpl || rpl > dpl
		) {
		cpu_ctx->lazy_eflags.result |= 0x100;
		return;
	}

	if constexpr (is_verr) {
		if ((desc & SEG_DESC_DCRW) == 0x80000000000) { // code, exec only
			cpu_ctx->lazy_eflags.result |= 0x100;
			return;
		}
	}
	else {
		if ((desc & SEG_DESC_DCRW) != 0x20000000000) { // data, r/w
			cpu_ctx->lazy_eflags.result |= 0x100;
			return;
		}
	}

	uint32_t sfd = (cpu_ctx->lazy_eflags.result >> 31) ^ (cpu_ctx->lazy_eflags.auxbits & 1);
	uint32_t pdb = ((cpu_ctx->lazy_eflags.result << 8) ^ cpu_ctx->lazy_eflags.auxbits) & 0xFF00;
	cpu_ctx->lazy_eflags.result = 0;
	cpu_ctx->lazy_eflags.auxbits = (cpu_ctx->lazy_eflags.auxbits & 0xFFFF00FE) | (sfd | pdb);
}

uint32_t
ltr_helper(cpu_ctx_t *cpu_ctx, uint16_t sel)
{
	cpu_t *cpu = cpu_ctx->cpu;

	if ((sel >> 2) == 0) { // sel == NULL
		return raise_exp_helper(cpu, 0, EXP_GP);
	}

	addr_t desc_addr;
	uint64_t desc;
	if (read_seg_desc_helper<true>(cpu, sel, desc_addr, desc)) {
		return 1;
	}

	uint8_t s = (desc & SEG_DESC_S) >> 40;
	uint8_t ty = (desc & SEG_DESC_TY) >> 40;
	if (!(((s | ty) == SEG_DESC_TSS16AV) || ((s | ty) == SEG_DESC_TSS32AV))) { // must be an available tss
		return raise_exp_helper(cpu, sel & 0xFFFC, EXP_GP);
	}

	if ((desc & SEG_DESC_P) == 0) { // tss not present
		return raise_exp_helper(cpu, sel & 0xFFFC, EXP_NP);
	}

	mem_write_helper<uint64_t>(cpu_ctx, desc_addr, desc | SEG_DESC_BY, 2);
	write_seg_reg_helper<TR_idx>(cpu, sel, read_seg_desc_base_helper(cpu, desc), read_seg_desc_limit_helper(cpu, desc), read_seg_desc_flags_helper(cpu, desc));

	return 0;
}

uint32_t
lldt_helper(cpu_ctx_t *cpu_ctx, uint16_t sel)
{
	cpu_t *cpu = cpu_ctx->cpu;

	if ((sel >> 2) == 0) { // sel == NULL
		write_seg_reg_helper<LDTR_idx>(cpu, 0, 0, 0, 0);
		return 0;
	}

	addr_t desc_addr;
	uint64_t desc;
	if (read_seg_desc_helper(cpu, sel, desc_addr, desc)) {
		return 1;
	}

	uint8_t s = (desc & SEG_DESC_S) >> 40;
	uint8_t ty = (desc & SEG_DESC_TY) >> 40;
	if ((s | ty) != SEG_DESC_LDT) { // must be ldt type
		return raise_exp_helper(cpu, sel & 0xFFFC, EXP_GP);
	}

	if ((desc & SEG_DESC_P) == 0) { // ldt not present
		return raise_exp_helper(cpu, sel & 0xFFFC, EXP_NP);
	}

	write_seg_reg_helper<LDTR_idx>(cpu, sel, read_seg_desc_base_helper(cpu, desc), read_seg_desc_limit_helper(cpu, desc), read_seg_desc_flags_helper(cpu, desc));

	return 0;
}

template<unsigned idx1>
uint32_t update_crN_helper(cpu_ctx_t *cpu_ctx, uint32_t new_cr, uint8_t idx)
{
	// idx1 0 -> mov, 1 -> lmsw, 2 -> clts

	switch (idx)
	{
	case 0:
		if constexpr (idx1 == 0) {
			if (((new_cr & CR0_PE_MASK) == 0 && (new_cr & CR0_PG_MASK) >> 31 == 1) ||
				((new_cr & CR0_CD_MASK) == 0 && (new_cr & CR0_NW_MASK) >> 29 == 1)) {
				return 1;
			}

			// only flush the tlb if pg changed or wp changed and pg=1
			if (((cpu_ctx->regs.cr0 & CR0_PG_MASK) != (new_cr & CR0_PG_MASK)) ||
				(((cpu_ctx->regs.cr0 & CR0_WP_MASK) != (new_cr & CR0_WP_MASK)) && (new_cr & CR0_PG_MASK))) {
				tlb_flush_g_l(cpu_ctx->cpu);
			}
		}

		if constexpr (idx1 != 2) {
			cpu_ctx->hflags = (((new_cr & CR0_EM_MASK) << 3) | (cpu_ctx->hflags & ~HFLG_CR0_EM));
			cpu_ctx->hflags = (((new_cr & CR0_MP_MASK) << 14) | (cpu_ctx->hflags & ~HFLG_CR0_MP));
		}
		if constexpr (idx1 == 0) {
			cpu_ctx->hflags = (((new_cr & CR0_NE_MASK) << 2) | (cpu_ctx->hflags & ~HFLG_CR0_NE));
		}
		cpu_ctx->hflags = (((new_cr & CR0_TS_MASK) << 7) | (cpu_ctx->hflags & ~HFLG_CR0_TS));

		if constexpr (idx1 != 2) {
			if ((cpu_ctx->regs.cr0 & CR0_PE_MASK) != (new_cr & CR0_PE_MASK)) {
				if (new_cr & CR0_PE_MASK) {
					// real -> protected
					if (cpu_ctx->regs.cs_hidden.flags & SEG_HIDDEN_DB) {
						cpu_ctx->hflags |= HFLG_CS32;
					}
					if (cpu_ctx->regs.ss_hidden.flags & SEG_HIDDEN_DB) {
						cpu_ctx->hflags |= HFLG_SS32;
					}
					cpu_ctx->hflags |= (HFLG_PE_MODE | (cpu_ctx->regs.cs & HFLG_CPL));
				}
				else {
					// protected -> real
					cpu_ctx->hflags &= ~(HFLG_CPL | HFLG_CS32 | HFLG_SS32 | HFLG_PE_MODE);
				}

				// remove all breakpoints if the debugger is present
				if (cpu_ctx->cpu->cpu_flags & CPU_DBG_PRESENT) {
					hook_remove(cpu_ctx->cpu, cpu_ctx->cpu->bp_addr);
					hook_remove(cpu_ctx->cpu, cpu_ctx->cpu->db_addr);
					dbg_remove_sw_breakpoints(cpu_ctx->cpu);
					break_list.clear();
					LOG(log_level::info, "Removed all breakpoints because cpu mode changed");
				}
			}
		}

		if constexpr (idx1 == 0) {
			cpu_ctx->regs.cr0 = ((new_cr & CR0_FLG_MASK) | CR0_ET_MASK);
		}
		else if constexpr (idx1 == 1) {
			cpu_ctx->regs.cr0 = (((cpu_ctx->regs.cr0 & ~CR0_LMSW_MASK) | (new_cr & CR0_LMSW_MASK)) | CR0_ET_MASK);
		}
		else if constexpr (idx1 == 2) {
			cpu_ctx->regs.cr0 &= ~CR0_TS_MASK;
		}
		else {
			LIB86CPU_ABORT_msg("Unknown instruction specified with index %u", idx1);
		}
		break;

	case 3:
		if (cpu_ctx->regs.cr0 & CR0_PG_MASK) {
			if (cpu_ctx->regs.cr4 & CR4_PGE_MASK) {
				tlb_flush_l(cpu_ctx->cpu);
			}
			else {
				tlb_flush_g_l(cpu_ctx->cpu);
			}
		}

		cpu_ctx->regs.cr3 = (new_cr & CR3_FLG_MASK);
		break;

	case 4: {
		if (new_cr & CR4_RES_MASK) {
			return 1;
		}

		if (new_cr & CR4_PAE_MASK) {
			LIB86CPU_ABORT_msg("Attempted to set an unsupported bit in cr4, new_cr was 0x%08X", new_cr);
		}

		if ((cpu_ctx->regs.cr4 & (CR4_PSE_MASK | CR4_PGE_MASK)) != (new_cr & (CR4_PSE_MASK | CR4_PGE_MASK))) {
			tlb_flush_g_l(cpu_ctx->cpu);
		}

		cpu_ctx->hflags = ((new_cr & CR4_OSFXSR_MASK) | ((new_cr & (CR4_VME_MASK | CR4_PVI_MASK)) << 19) |
			(cpu_ctx->hflags & ~(HFLG_CR4_OSFXSR | HFLG_CR4_VME | HFLG_CR4_PVI)));
		cpu_ctx->regs.cr4 = new_cr;
	}
	break;

	case 2:
		// cr2 is handled by the jit
		assert(0);
		[[fallthrough]];

	default:
		LIB86CPU_ABORT();
	}

	return 0;
}

void
update_drN_helper(cpu_ctx_t *cpu_ctx, uint8_t dr_idx, uint32_t new_dr)
{
	switch (dr_idx)
	{
	case 0:
	case 1:
	case 2:
	case 3: {
		// if the watchpoint is disabled, then don't do anything, otherwise update it in the wp_data/wp_io struct
		cpu_ctx->regs.dr[dr_idx] = new_dr;
		if (cpu_get_watchpoint_type(cpu_ctx->cpu, dr_idx) == DR7_TYPE_IO_RW) {
			if (cpu_check_watchpoint_enabled(cpu_ctx->cpu, dr_idx) && (cpu_ctx->regs.cr4 & CR4_DE_MASK)) {
				for (auto &io : cpu_ctx->cpu->wp_io) {
					if (io.dr_idx == dr_idx) {
						size_t watch_len = cpu_get_watchpoint_length(cpu_ctx->cpu, dr_idx);
						io.watch_addr = cpu_ctx->regs.dr[dr_idx] & ~(watch_len - 1);
						io.watch_end = io.watch_addr + watch_len - 1;
						break;
					}
				}
			}
		}
		else {
			if (cpu_check_watchpoint_enabled(cpu_ctx->cpu, dr_idx)) {
				for (auto &data : cpu_ctx->cpu->wp_data) {
					if (data.dr_idx == dr_idx) {
						size_t watch_len = cpu_get_watchpoint_length(cpu_ctx->cpu, dr_idx);
						data.watch_addr = cpu_ctx->regs.dr[dr_idx] & ~(watch_len - 1);
						data.watch_end = data.watch_addr + watch_len - 1;
						break;
					}
				}
			}
		}
	}
	break;

	case 7: {
		// clear all watchpoints, and if it's disabled, then don't do anything, otherwise add it to the struct
		cpu_ctx->cpu->wp_io.clear();
		cpu_ctx->cpu->wp_data.clear();
		cpu_ctx->regs.dr[7] = new_dr;
		for (unsigned idx = 0; idx < 4; ++idx) {
			if (cpu_check_watchpoint_enabled(cpu_ctx->cpu, idx)) {
				size_t watch_len = cpu_get_watchpoint_length(cpu_ctx->cpu, idx);
				if (cpu_get_watchpoint_type(cpu_ctx->cpu, idx) == DR7_TYPE_IO_RW) {
					port_t watch_addr = cpu_ctx->regs.dr[idx] & ~(watch_len - 1);
					port_t watch_end = watch_addr + watch_len - 1;
					cpu_ctx->cpu->wp_io.emplace_back(idx, watch_addr, watch_end);
				}
				else {
					addr_t watch_addr = cpu_ctx->regs.dr[idx] & ~(watch_len - 1);
					addr_t watch_end = watch_addr + watch_len - 1;
					cpu_ctx->cpu->wp_data.emplace_back(idx, watch_addr, watch_end);
				}
			}
		}
	}
	break;

	case 4:
	case 5:
	case 6:
		// the other dr regs are handled by the jit
		assert(0);
		[[fallthrough]];

	default:
		LIB86CPU_ABORT();
	}
}

uint32_t
msr_read_helper(cpu_ctx_t *cpu_ctx)
{
	uint64_t val;

	switch (cpu_ctx->regs.ecx)
	{
	case IA32_APIC_BASE:
		val = MSR_IA32_APICBASE_BSP;
		break;

	case IA32_EBL_CR_POWERON:
		val = cpu_ctx->cpu->msr.ebl_cr_poweron;
		break;

	case IA32_BIOS_UPDT_TRIG:
		val = 0;
		break;

	case IA32_BIOS_SIGN_ID:
		val = cpu_ctx->cpu->msr.bios_sign_id;
		break;

	case IA32_MTRRCAP:
		val = (MSR_MTRRcap_VCNT | MSR_MTRRcap_FIX | MSR_MTRRcap_WC);
		break;

	case IA32_SYSENTER_CS:
		val = cpu_ctx->cpu->msr.sys_cs & 0xFFFFFFFF;
		break;

	case IA32_SYSENTER_ESP:
		val = cpu_ctx->cpu->msr.sys_esp;
		break;

	case IA32_SYSENTER_EIP:
		val = cpu_ctx->cpu->msr.sys_eip;
		break;

	case IA32_MCG_CAP:
		val = cpu_ctx->cpu->msr.mcg_cap;
		break;

	case IA32_MCG_STATUS:
		val = cpu_ctx->cpu->msr.mcg_status;
		break;

	case IA32_MCG_CTL:
		if (cpu_ctx->cpu->msr.mcg_cap & MCG_CTL_P) {
			val = cpu_ctx->cpu->msr.mcg_ctl;
		}
		else {
			val = 0;
		}
		break;

	case IA32_MTRR_PHYSBASE(0):
	case IA32_MTRR_PHYSBASE(1):
	case IA32_MTRR_PHYSBASE(2):
	case IA32_MTRR_PHYSBASE(3):
	case IA32_MTRR_PHYSBASE(4):
	case IA32_MTRR_PHYSBASE(5):
	case IA32_MTRR_PHYSBASE(6):
	case IA32_MTRR_PHYSBASE(7):
		val = cpu_ctx->cpu->msr.mtrr.phys_var[(cpu_ctx->regs.ecx - IA32_MTRR_PHYSBASE_base) / 2].base;
		break;

	case IA32_MTRR_PHYSMASK(0):
	case IA32_MTRR_PHYSMASK(1):
	case IA32_MTRR_PHYSMASK(2):
	case IA32_MTRR_PHYSMASK(3):
	case IA32_MTRR_PHYSMASK(4):
	case IA32_MTRR_PHYSMASK(5):
	case IA32_MTRR_PHYSMASK(6):
	case IA32_MTRR_PHYSMASK(7):
		val = cpu_ctx->cpu->msr.mtrr.phys_var[(cpu_ctx->regs.ecx - IA32_MTRR_PHYSMASK_base) / 2].mask;
		break;

	case IA32_MTRR_FIX64K_00000:
		val = cpu_ctx->cpu->msr.mtrr.phys_fixed[0];
		break;

	case IA32_MTRR_FIX16K_80000:
	case IA32_MTRR_FIX16K_A0000:
		val = cpu_ctx->cpu->msr.mtrr.phys_fixed[cpu_ctx->regs.ecx - IA32_MTRR_FIX16K_80000 + 1];
		break;

	case IA32_MTRR_FIX4K_C0000:
	case IA32_MTRR_FIX4K_C8000:
	case IA32_MTRR_FIX4K_D0000:
	case IA32_MTRR_FIX4K_D8000:
	case IA32_MTRR_FIX4K_E0000:
	case IA32_MTRR_FIX4K_E8000:
	case IA32_MTRR_FIX4K_F0000:
	case IA32_MTRR_FIX4K_F8000:
		val = cpu_ctx->cpu->msr.mtrr.phys_fixed[cpu_ctx->regs.ecx - IA32_MTRR_FIX4K_C0000 + 3];
		break;

	case IA32_PAT:
		val = cpu_ctx->cpu->msr.pat;
		break;

	case IA32_MTRR_DEF_TYPE:
		val = cpu_ctx->cpu->msr.mtrr.def_type;
		break;

	default:
		if ((cpu_ctx->regs.ecx >= IA32_MC0_CTL) && (cpu_ctx->regs.ecx < (IA32_MC0_CTL + MCG_NUM_BANKS * 4))) {
			uint32_t bank_offset = (cpu_ctx->regs.ecx - IA32_MC0_CTL) / 4;
			uint32_t reg_offset = (cpu_ctx->regs.ecx - IA32_MC0_CTL) & 3;
			val = cpu_ctx->cpu->msr.mca_banks[bank_offset][reg_offset];
			break;
		}

		LIB86CPU_ABORT_msg("Unhandled msr read to register at address 0x%X", cpu_ctx->regs.ecx);
	}

	cpu_ctx->regs.edx = (val >> 32);
	cpu_ctx->regs.eax = val;

	return 0;
}

uint32_t
msr_write_helper(cpu_ctx_t *cpu_ctx)
{
	uint64_t val = (static_cast<uint64_t>(cpu_ctx->regs.edx) << 32) | cpu_ctx->regs.eax;

	switch (cpu_ctx->regs.ecx)
	{
	case IA32_APIC_BASE:
		if (val & MSR_IA32_APIC_BASE_RES) {
			return 1;
		}
		break;

	case IA32_EBL_CR_POWERON:
		if (val & MSR_EBL_CR_POWERON_RES) {
			return 1;
		}
		cpu_ctx->cpu->msr.ebl_cr_poweron = (cpu_ctx->cpu->msr.ebl_cr_poweron & ~MSR_EBL_CR_POWERON_RW) | (val & MSR_EBL_CR_POWERON_RW);
		break;

	case IA32_BIOS_UPDT_TRIG:
		cpu_ctx->cpu->microcode_updated = 1;
		break;

	case IA32_BIOS_SIGN_ID:
		if (val & MSR_BIOS_SIGN_ID_RES) {
			return 1;
		}
		cpu_ctx->cpu->msr.bios_sign_id = val;
		break;

	case IA32_MTRRCAP:
		return 1;

	case IA32_SYSENTER_CS:
		cpu_ctx->cpu->msr.sys_cs = (val & 0xFFFFFFFF);
		break;

	case IA32_SYSENTER_ESP:
		cpu_ctx->cpu->msr.sys_esp = val;
		break;

	case IA32_SYSENTER_EIP:
		cpu_ctx->cpu->msr.sys_eip = val;
		break;

	case IA32_MCG_CAP:
		break;

	case IA32_MCG_STATUS:
		if (MCG_STATUS_RES) {
			return 1;
		}
		cpu_ctx->cpu->msr.mcg_status = val;
		break;

	case IA32_MCG_CTL:
		if ((cpu_ctx->cpu->msr.mcg_cap & MCG_CTL_P) && ((val == MCG_CTL_ENABLE) || (val == MCG_CTL_DISABLE))) {
			cpu_ctx->cpu->msr.mcg_ctl = val;
		}
		break;

	case IA32_MTRR_PHYSBASE(0):
	case IA32_MTRR_PHYSBASE(1):
	case IA32_MTRR_PHYSBASE(2):
	case IA32_MTRR_PHYSBASE(3):
	case IA32_MTRR_PHYSBASE(4):
	case IA32_MTRR_PHYSBASE(5):
	case IA32_MTRR_PHYSBASE(6):
	case IA32_MTRR_PHYSBASE(7):
		if (val & MSR_MTRR_PHYSBASE_RES) {
			return 1;
		}
		cpu_ctx->cpu->msr.mtrr.phys_var[(cpu_ctx->regs.ecx - IA32_MTRR_PHYSBASE_base) / 2].base = val;
		break;

	case IA32_MTRR_PHYSMASK(0):
	case IA32_MTRR_PHYSMASK(1):
	case IA32_MTRR_PHYSMASK(2):
	case IA32_MTRR_PHYSMASK(3):
	case IA32_MTRR_PHYSMASK(4):
	case IA32_MTRR_PHYSMASK(5):
	case IA32_MTRR_PHYSMASK(6):
	case IA32_MTRR_PHYSMASK(7):
		if (val & MSR_MTRR_PHYSMASK_RES) {
			return 1;
		}
		cpu_ctx->cpu->msr.mtrr.phys_var[(cpu_ctx->regs.ecx - IA32_MTRR_PHYSMASK_base) / 2].mask = val;
		break;

	case IA32_MTRR_FIX64K_00000:
		cpu_ctx->cpu->msr.mtrr.phys_fixed[0] = val;
		break;

	case IA32_MTRR_FIX16K_80000:
	case IA32_MTRR_FIX16K_A0000:
		cpu_ctx->cpu->msr.mtrr.phys_fixed[cpu_ctx->regs.ecx - IA32_MTRR_FIX16K_80000 + 1] = val;
		break;

	case IA32_MTRR_FIX4K_C0000:
	case IA32_MTRR_FIX4K_C8000:
	case IA32_MTRR_FIX4K_D0000:
	case IA32_MTRR_FIX4K_D8000:
	case IA32_MTRR_FIX4K_E0000:
	case IA32_MTRR_FIX4K_E8000:
	case IA32_MTRR_FIX4K_F0000:
	case IA32_MTRR_FIX4K_F8000:
		cpu_ctx->cpu->msr.mtrr.phys_fixed[cpu_ctx->regs.ecx - IA32_MTRR_FIX4K_C0000 + 3] = val;
		break;

	case IA32_PAT:
		if (val & MSR_PAT_RES) {
			return 1;
		}
		for (unsigned i = 0; i < 7; ++i) {
			uint64_t pat_type = (val >> (i * 8)) & 7;
			if ((pat_type == PAT_TYPE_RES2) || (pat_type == PAT_TYPE_RES3)) {
				return 1;
			}
		}
		cpu_ctx->cpu->msr.pat = val;
		break;

	case IA32_MTRR_DEF_TYPE:
		if (val & MSR_MTRR_DEF_TYPE_RES) {
			return 1;
		}
		cpu_ctx->cpu->msr.mtrr.def_type = val;
		break;

	default:
		if ((cpu_ctx->regs.ecx >= IA32_MC0_CTL) && (cpu_ctx->regs.ecx < (IA32_MC0_CTL + MCG_NUM_BANKS * 4))) {
			uint32_t bank_offset = (cpu_ctx->regs.ecx - IA32_MC0_CTL) / 4;
			uint32_t reg_offset = (cpu_ctx->regs.ecx - IA32_MC0_CTL) & 3;
			switch (reg_offset)
			{
			case MCi_CTL:
				if ((val != MCG_CTL_ENABLE) && (val != MCG_CTL_DISABLE)) {
					return 0;
				}
				break;

			case MCi_STATUS:
			case MCi_ADDR:
			case MCi_MISC:
				if (val) {
					return 1;
				}
			}
			cpu_ctx->cpu->msr.mca_banks[bank_offset][reg_offset] = val;
			break;
		}

		LIB86CPU_ABORT_msg("Unhandled msr write to register at address 0x%X", cpu_ctx->regs.ecx);
	}

	return 0;
}

uint32_t
divd_helper(cpu_ctx_t *cpu_ctx, uint32_t d)
{
	uint64_t D = (static_cast<uint64_t>(cpu_ctx->regs.eax)) | (static_cast<uint64_t>(cpu_ctx->regs.edx) << 32);
	if (d == 0) {
		return raise_exp_helper(cpu_ctx->cpu, 0, EXP_DE);
	}
	uint64_t q = (D / d);
	uint64_t r = (D % d);
	if (q > 0xFFFFFFFF) {
		return raise_exp_helper(cpu_ctx->cpu, 0, EXP_DE);
	}
	cpu_ctx->regs.eax = q;
	cpu_ctx->regs.edx = r;

	return 0;
}

uint32_t
divw_helper(cpu_ctx_t *cpu_ctx, uint16_t d)
{
	uint32_t D = (cpu_ctx->regs.eax & 0xFFFF) | ((cpu_ctx->regs.edx & 0xFFFF) << 16);
	if (d == 0) {
		return raise_exp_helper(cpu_ctx->cpu, 0, EXP_DE);
	}
	uint32_t q = (D / d);
	uint32_t r = (D % d);
	if (q > 0xFFFF) {
		return raise_exp_helper(cpu_ctx->cpu, 0, EXP_DE);
	}
	q &= 0xFFFF;
	r &= 0xFFFF;
	cpu_ctx->regs.eax = (cpu_ctx->regs.eax & ~0xFFFF) | q;
	cpu_ctx->regs.edx = (cpu_ctx->regs.edx & ~0xFFFF) | r;

	return 0;
}

uint32_t
divb_helper(cpu_ctx_t *cpu_ctx, uint8_t d)
{
	uint16_t D = cpu_ctx->regs.eax & 0xFFFF;
	if (d == 0) {
		return raise_exp_helper(cpu_ctx->cpu, 0, EXP_DE);
	}
	uint16_t q = (D / d);
	uint16_t r = (D % d);
	if (q > 0xFF) {
		return raise_exp_helper(cpu_ctx->cpu, 0, EXP_DE);
	}
	q &= 0xFF;
	r &= 0xFF;
	cpu_ctx->regs.eax = (cpu_ctx->regs.eax & ~0xFFFF) | (r << 8) | q;

	return 0;
}

uint32_t
idivd_helper(cpu_ctx_t *cpu_ctx, uint32_t d)
{
	int64_t D = static_cast<int64_t>((static_cast<uint64_t>(cpu_ctx->regs.eax)) | (static_cast<uint64_t>(cpu_ctx->regs.edx) << 32));
	int32_t d0 = static_cast<int32_t>(d);
	if (d0 == 0) {
		return raise_exp_helper(cpu_ctx->cpu, 0, EXP_DE);
	}
	int64_t q = (D / d0);
	int64_t r = (D % d0);
	if (q != static_cast<int32_t>(q)) {
		return raise_exp_helper(cpu_ctx->cpu, 0, EXP_DE);
	}
	cpu_ctx->regs.eax = q;
	cpu_ctx->regs.edx = r;

	return 0;
}

uint32_t
idivw_helper(cpu_ctx_t *cpu_ctx, uint16_t d)
{
	int32_t D = static_cast<int32_t>((cpu_ctx->regs.eax & 0xFFFF) | ((cpu_ctx->regs.edx & 0xFFFF) << 16));
	int16_t d0 = static_cast<int16_t>(d);
	if (d0 == 0) {
		return raise_exp_helper(cpu_ctx->cpu, 0, EXP_DE);
	}
	int32_t q = (D / d0);
	int32_t r = (D % d0);
	if (q != static_cast<int16_t>(q)) {
		return raise_exp_helper(cpu_ctx->cpu, 0, EXP_DE);
	}
	q &= 0xFFFF;
	r &= 0xFFFF;
	cpu_ctx->regs.eax = (cpu_ctx->regs.eax & ~0xFFFF) | q;
	cpu_ctx->regs.edx = (cpu_ctx->regs.edx & ~0xFFFF) | r;

	return 0;
}

uint32_t
idivb_helper(cpu_ctx_t *cpu_ctx, uint8_t d)
{
	int16_t D = static_cast<int16_t>(cpu_ctx->regs.eax & 0xFFFF);
	int8_t d0 = static_cast<int8_t>(d);
	if (d0 == 0) {
		return raise_exp_helper(cpu_ctx->cpu, 0, EXP_DE);
	}
	int16_t q = (D / d0);
	int16_t r = (D % d0);
	if (q != static_cast<int8_t>(q)) {
		return raise_exp_helper(cpu_ctx->cpu, 0, EXP_DE);
	}
	q &= 0xFF;
	r &= 0xFF;
	cpu_ctx->regs.eax = (cpu_ctx->regs.eax & ~0xFFFF) | (r << 8) | q;

	return 0;
}

void
cpuid_helper(cpu_ctx_t *cpu_ctx)
{
	// these are the same values that the xbox cpu reports with cpuid. They were tested against real hardware here https://github.com/mborgerson/xemu/issues/509

	switch (cpu_ctx->regs.eax)
	{
	default:
	case 2:
		cpu_ctx->regs.eax = 0x03020101;
		cpu_ctx->regs.ebx = 0;
		cpu_ctx->regs.edx = 0x0C040841;
		cpu_ctx->regs.ecx = 0;
		break;

	case 1:
		cpu_ctx->regs.eax = 0x0000068A;
		cpu_ctx->regs.ebx = 0;
		cpu_ctx->regs.edx = 0x0383F9FF; // fpu, vme, de, pse, tsc, msr, pae, mce, cx8, sep, mtrr, pge, mca, cmov, pat, pse-36, mmx, fxsr, sse
		cpu_ctx->regs.ecx = 0;
		if (cpu_ctx->cpu->microcode_updated) {
			cpu_ctx->cpu->msr.bios_sign_id = INTEL_MICROCODE_ID;
		}
		break;

	case 0:
		cpu_ctx->regs.eax = 2;
		cpu_ctx->regs.ebx = 0x756E6547; // "Genu"
		cpu_ctx->regs.edx = 0x49656E69; // "ineI"
		cpu_ctx->regs.ecx = 0x6C65746E; // "ntel"
		break;
	}
}

template<bool should_check_timeout>
void hlt_helper(cpu_ctx_t *cpu_ctx)
{
	while (true) {
		uint32_t int_ret = cpu_do_int(cpu_ctx, cpu_ctx->cpu->read_int_fn(cpu_ctx));
		uint32_t timeout_ret = should_check_timeout ? cpu_timer_helper(cpu_ctx) : 0;
		uint32_t ret = int_ret | timeout_ret;

		if ((ret & (CPU_HW_INT | CPU_TIMEOUT_INT)) == CPU_NO_INT) {
			// either nothing changed or it's not a hw int, keep looping in both cases
			continue;
		}

		if (ret & CPU_HW_INT) {
			// hw int, exit the loop and clear the halted state
			cpu_ctx->cpu->is_halted = 0;
			return;
		}

		// timeout, exit the loop and set the halted state
		cpu_ctx->cpu->is_halted = 1;
		return;
	}
}

void
invlpg_helper(cpu_ctx_t *cpu_ctx, addr_t addr)
{
	tlb_invalidate(cpu_ctx->cpu, addr);
}

template JIT_API uint32_t lret_pe_helper<true>(cpu_ctx_t *cpu_ctx, uint8_t size_mode);
template JIT_API uint32_t lret_pe_helper<false>(cpu_ctx_t *cpu_ctx, uint8_t size_mode);

template JIT_API void verrw_helper<true>(cpu_ctx_t *cpu_ctx, uint16_t sel);
template JIT_API void verrw_helper<false>(cpu_ctx_t *cpu_ctx, uint16_t sel);

template JIT_API void hlt_helper<true>(cpu_ctx_t *cpu_ctx);
template JIT_API void hlt_helper<false>(cpu_ctx_t *cpu_ctx);

template JIT_API uint32_t mov_sel_real_helper<DS_idx>(cpu_ctx_t *cpu_ctx, uint16_t sel);
template JIT_API uint32_t mov_sel_real_helper<ES_idx>(cpu_ctx_t *cpu_ctx, uint16_t sel);
template JIT_API uint32_t mov_sel_real_helper<SS_idx>(cpu_ctx_t *cpu_ctx, uint16_t sel);
template JIT_API uint32_t mov_sel_real_helper<FS_idx>(cpu_ctx_t *cpu_ctx, uint16_t sel);
template JIT_API uint32_t mov_sel_real_helper<GS_idx>(cpu_ctx_t *cpu_ctx, uint16_t sel);

template JIT_API uint32_t mov_sel_pe_helper<DS_idx>(cpu_ctx_t *cpu_ctx, uint16_t sel);
template JIT_API uint32_t mov_sel_pe_helper<ES_idx>(cpu_ctx_t *cpu_ctx, uint16_t sel);
template JIT_API uint32_t mov_sel_pe_helper<SS_idx>(cpu_ctx_t *cpu_ctx, uint16_t sel);
template JIT_API uint32_t mov_sel_pe_helper<FS_idx>(cpu_ctx_t *cpu_ctx, uint16_t sel);
template JIT_API uint32_t mov_sel_pe_helper<GS_idx>(cpu_ctx_t *cpu_ctx, uint16_t sel);

template JIT_API uint32_t update_crN_helper<0>(cpu_ctx_t* cpu_ctx, uint32_t new_cr, uint8_t idx);
template JIT_API uint32_t update_crN_helper<1>(cpu_ctx_t* cpu_ctx, uint32_t new_cr, uint8_t idx);
template JIT_API uint32_t update_crN_helper<2>(cpu_ctx_t* cpu_ctx, uint32_t new_cr, uint8_t idx);
