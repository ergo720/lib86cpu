/*
 * x86 exception support
 *
 * ergo720                Copyright (c) 2020
 */

#include "x86_internal.h"
#include "x86_memory.h"

#define PUSHW(val) esp -= 2; \
mem_write<uint16_t>(cpu_ctx->cpu, stack_base + (esp & stack_mask), val, 0);
#define PUSHL(val) esp -= 4; \
mem_write<uint32_t>(cpu_ctx->cpu, stack_base + (esp & stack_mask), val, 0);


static void
set_access_flg_seg_desc(cpu_ctx_t *cpu_ctx, uint64_t desc, addr_t desc_addr)
{
	if ((((desc & SEG_DESC_S) >> 44) | ((desc & SEG_DESC_A) >> 39)) == 1) {
		mem_write<uint64_t>(cpu_ctx->cpu, desc_addr, desc | SEG_DESC_A, 0);
	}
}

static uint32_t
read_seg_base(uint64_t desc)
{
	return ((desc & 0xFFFF0000) >> 16) | ((desc & 0xFF00000000) >> 16) | ((desc & 0xFF00000000000000) >> 32);
}

static uint32_t
read_seg_limit(uint64_t desc)
{
	uint32_t limit = (desc & 0xFFFF) | ((desc & 0xF000000000000) >> 32);
	if (desc & SEG_DESC_G) {
		limit = (limit << 12) | PAGE_MASK;
	}

	return limit;
}

static uint32_t
read_seg_flags(uint64_t desc)
{
	return (desc & 0xFFFFFFFF00000000) >> 32;
}

static uint64_t
read_seg_desc(cpu_ctx_t *cpu_ctx, uint16_t sel, addr_t *desc_addr, int expno)
{
	uint16_t sel_idx = sel & ~7;
	uint32_t base, limit;
	if (sel & 4) {
		base = cpu_ctx->regs.ldtr_hidden.base;
		limit = cpu_ctx->regs.ldtr_hidden.limit;
	}
	else {
		base = cpu_ctx->regs.gdtr_hidden.base;
		limit = cpu_ctx->regs.gdtr_hidden.limit;
	}

	if (sel_idx + 7 > limit) {
		throw 0U;
	}

	*desc_addr = base + sel_idx;

	return mem_read<uint64_t>(cpu_ctx->cpu, base + sel_idx, 0);
}

static void
read_stack_ptr_from_tss(cpu_t *cpu, uint32_t dest_cpl, uint32_t *esp, uint16_t *ss)
{
	uint32_t type = (cpu->cpu_ctx.regs.tr_hidden.flags & SEG_HIDDEN_TSS_TY) >> 11;
	uint32_t idx = (2 << type) + dest_cpl * (4 << type);
	if (idx + (4 << type) - 1 > cpu->cpu_ctx.regs.tr_hidden.limit) {
		throw 0U;
	}

	cpu->cpu_ctx.hflags |= HFLG_CPL_PRIV;
	if (type) {
		*esp = mem_read<uint32_t>(cpu, cpu->cpu_ctx.regs.tr_hidden.base + idx, 0);
		*ss = mem_read<uint16_t>(cpu, cpu->cpu_ctx.regs.tr_hidden.base + idx + 4, 0);
	}
	else {
		*esp = mem_read<uint16_t>(cpu, cpu->cpu_ctx.regs.tr_hidden.base + idx, 0);
		*ss = mem_read<uint16_t>(cpu, cpu->cpu_ctx.regs.tr_hidden.base + idx + 2, 0);
	}

	cpu->cpu_ctx.hflags &= ~HFLG_CPL_PRIV;
}

static uint8_t
exception_has_code(uint32_t expno)
{
	switch (expno)
	{
	case EXP_DF:
	case EXP_TS:
	case EXP_NP:
	case EXP_SS:
	case EXP_GP:
	case EXP_PF:
	case EXP_AC:
		return 1;

	default:
		return 0;
	}
}

void
cpu_throw_exception(cpu_ctx_t *cpu_ctx, uint64_t exp_data, uint32_t eip)
{
	cpu_ctx->cpu->exp_idx = exp_data & 0xFF;
	cpu_ctx->cpu->exp_code = (exp_data & 0xFFFF0000) >> 16;
	cpu_ctx->cpu->exp_fault_addr = exp_data >> 32;

	// throw an exception to forcefully transfer control to the exception handler
	throw eip;
}

void
cpu_raise_exception(cpu_ctx_t *cpu_ctx, uint32_t eip)
{
	// TODO: handle double and triple faults

	try {
		cpu_t *cpu = cpu_ctx->cpu;
		uint8_t expno = cpu->exp_idx;
		cpu_ctx->hflags &= ~HFLG_CPL_PRIV;

		uint32_t old_eflags = cpu_ctx->regs.eflags |
			((cpu_ctx->lazy_eflags.auxbits & 0x80000000) >> 31) |
			((cpu_ctx->lazy_eflags.parity[(cpu_ctx->lazy_eflags.result & 0xFF) ^ ((cpu_ctx->lazy_eflags.auxbits & 0xFF00) >> 8)] ^ 1) << 2) |
			((cpu_ctx->lazy_eflags.auxbits & 8) << 1) |
			((cpu_ctx->lazy_eflags.result == 0) << 6) |
			(((cpu_ctx->lazy_eflags.result & 0x80000000) >> 31) ^ (cpu_ctx->lazy_eflags.auxbits & 1) << 7) |
			(((cpu_ctx->lazy_eflags.auxbits & 0x80000000) ^ ((cpu_ctx->lazy_eflags.auxbits & 0x40000000) << 1)) >> 20);

		if (cpu_ctx->hflags & HFLG_PE_MODE) {
			if (expno * 8 + 7 > cpu_ctx->regs.idtr_hidden.limit) {
				throw 0U;
			}

			uint64_t desc = mem_read<uint64_t>(cpu, cpu_ctx->regs.idtr_hidden.base + expno * 8, eip);
			uint16_t type = (desc >> 40) & 0x1F;
			uint32_t new_eip, eflags;
			switch (type)
			{
			case 5:  // task gate
				// we don't support task gates yet, so just abort
				LIB86CPU_ABORT_msg("Protected mode exception task gates are not supported (for now)\n");
				break;

			case 6:  // interrupt gate, 16 bit
			case 14: // interrupt gate, 32 bit
				eflags = cpu_ctx->regs.eflags & ~IF_MASK;
				new_eip = ((desc & 0xFFFF000000000000) >> 32) | (desc & 0xFFFF);
				break;

			case 7:  // trap gate, 16 bit
			case 15: // trap gate, 32 bit
				eflags = cpu_ctx->regs.eflags;
				new_eip = ((desc & 0xFFFF000000000000) >> 32) | (desc & 0xFFFF);
				break;

			default:
				throw 0U;
			}

			if ((desc & SEG_DESC_P) == 0) {
				throw 0U;
			}

			uint16_t sel = (desc & 0xFFFF0000) >> 16;
			if ((sel & 0xFFFC) == 0) {
				throw 0U;
			}

			addr_t desc_addr;
			desc = read_seg_desc(cpu_ctx, sel, &desc_addr, EXP_GP);
			uint16_t dpl = (desc & SEG_DESC_DPL) >> 45;
			if (dpl > (cpu_ctx->hflags & HFLG_CPL)) {
				throw 0U;
			}

			if ((desc & SEG_DESC_P) == 0) {
				throw 0U;
			}

			if (desc & SEG_DESC_C) {
				dpl = cpu_ctx->hflags & HFLG_CPL;
			}

			set_access_flg_seg_desc(cpu_ctx, desc, desc_addr);
			uint32_t seg_base = read_seg_base(desc);
			uint32_t seg_limit = read_seg_limit(desc);
			uint32_t seg_flags = read_seg_flags(desc);
			uint32_t stack_switch, stack_mask, stack_base, esp;
			uint32_t new_esp;
			uint16_t new_ss;
			if (dpl < (cpu_ctx->hflags & HFLG_CPL)) { // more privileged
				read_stack_ptr_from_tss(cpu_ctx->cpu, dpl, &new_esp, &new_ss);

				if ((new_ss >> 2) == 0) {
					throw 0U;
				}

				desc = read_seg_desc(cpu_ctx, new_ss, &desc_addr, EXP_TS);
				uint16_t p = (desc & SEG_DESC_P) >> 40;
				uint16_t s = (desc & SEG_DESC_S) >> 44;
				uint16_t d = (desc & SEG_DESC_DC) >> 42;
				uint16_t w = (desc & SEG_DESC_W) >> 39;
				uint16_t ss_dpl = (desc & SEG_DESC_DPL) >> 42;
				uint16_t ss_rpl = (new_ss & 3) << 5;
				if ((s | d | w | ss_dpl | ss_rpl | p) ^ ((0x85 | (dpl << 3)) | (dpl << 5))) {
					throw 0U;
				}

				set_access_flg_seg_desc(cpu_ctx, desc, desc_addr);
				stack_switch = 1;
				stack_mask = desc & SEG_DESC_DB ? 0xFFFFFFFF : 0xFFFF;
				stack_base = read_seg_base(desc);
				esp = new_esp;
			}
			else { // same privilege
				cpu_ctx->hflags |= HFLG_CPL_PRIV;
				stack_switch = 0;
				stack_mask = cpu_ctx->regs.ss_hidden.flags & SEG_HIDDEN_DB ? 0xFFFFFFFF : 0xFFFF;
				stack_base = cpu_ctx->regs.ss_hidden.base;
				esp = cpu_ctx->regs.esp;
			}

			uint8_t has_code = exception_has_code(expno);
			type >>= 3;
			if (type) { // push 32
				if (stack_switch) {
					PUSHL(cpu_ctx->regs.ss);
					PUSHL(cpu_ctx->regs.esp);
				}
				PUSHL(old_eflags);
				PUSHL(cpu_ctx->regs.cs);
				PUSHL(eip);
				if (has_code) {
					PUSHL(cpu_ctx->cpu->exp_code);
				}
			}
			else { // push 16
				if (stack_switch) {
					PUSHW(cpu_ctx->regs.ss);
					PUSHW(cpu_ctx->regs.esp);
				}
				PUSHW(old_eflags);
				PUSHW(cpu_ctx->regs.cs);
				PUSHW(eip);
				if (has_code) {
					PUSHW(cpu_ctx->cpu->exp_code);
				}
			}

			if (stack_switch) {
				uint32_t flags = read_seg_flags(desc);
				cpu_ctx->regs.ss = (new_ss & ~3) | dpl;
				cpu_ctx->regs.ss_hidden.base = stack_base;
				cpu_ctx->regs.ss_hidden.limit = read_seg_limit(desc);
				cpu_ctx->regs.ss_hidden.flags = flags;
				cpu_ctx->hflags = ((flags & SEG_HIDDEN_DB) >> 19) | (cpu_ctx->hflags & ~HFLG_SS32);
			}

			cpu_ctx->regs.eflags = (eflags & ~(VM_MASK | RF_MASK | NT_MASK | TF_MASK));
			cpu_ctx->regs.esp = (cpu_ctx->regs.esp & ~stack_mask) | (esp & stack_mask);
			cpu_ctx->regs.cs = (sel & ~3) | dpl;
			cpu_ctx->regs.cs_hidden.base = seg_base;
			cpu_ctx->regs.cs_hidden.limit = seg_limit;
			cpu_ctx->regs.cs_hidden.flags = seg_flags;
			cpu_ctx->hflags = (((seg_flags & SEG_HIDDEN_DB) >> 20) | dpl) | (cpu_ctx->hflags & ~(HFLG_CS32 | HFLG_CPL));
			cpu_ctx->regs.eip = new_eip;
			if (expno == EXP_PF) {
				cpu_ctx->regs.cr2 = cpu_ctx->cpu->exp_fault_addr;
			}
		}
		else {
			if (expno * 4 + 3 > cpu_ctx->regs.idtr_hidden.limit) {
				throw 0U;
			}

			uint32_t vec_entry = mem_read<uint32_t>(cpu, cpu_ctx->regs.idtr_hidden.base + expno * 4, eip);
			uint32_t stack_mask = 0xFFFF;
			uint32_t stack_base = cpu_ctx->regs.ss_hidden.base;
			uint32_t esp = cpu_ctx->regs.esp;
			PUSHW(old_eflags);
			PUSHW(cpu_ctx->regs.cs);
			PUSHW(eip);

			cpu_ctx->regs.eflags &= ~(AC_MASK | RF_MASK | IF_MASK | TF_MASK);
			cpu_ctx->regs.esp = (cpu_ctx->regs.esp & ~stack_mask) | (esp & stack_mask);
			cpu_ctx->regs.cs = vec_entry >> 16;
			cpu_ctx->regs.cs_hidden.base = cpu_ctx->regs.cs << 4;
			cpu_ctx->regs.eip = vec_entry & 0xFFFF;
		}

		cpu_ctx->hflags |= HFLG_CPL_PRIV;
		return;
	}
	catch (uint32_t dummy) {
		LIB86CPU_ABORT_msg("An exception was raised while trying to deliver another exception\n");
	}
}
