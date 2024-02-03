/*
 * x86 translation code
 *
 * ergo720                Copyright (c) 2019
 */

#include "internal.h"
#include "memory_management.h"
#include "main_wnd.h"
#include "debugger.h"
#include "helpers.h"
#include "clock.h"

#ifdef LIB86CPU_X64_EMITTER
#include "x64/jit.h"
#endif

#define BAD LIB86CPU_ABORT_msg("Encountered unimplemented instruction %s", log_instr(disas_ctx->virt_pc - cpu->instr_bytes, &instr).c_str())

// Make sure we can safely use memset on the register structs
static_assert(std::is_trivially_copyable_v<regs_t>);
static_assert(std::is_trivially_copyable_v<msr_t>);


void
cpu_reset(cpu_t *cpu)
{
	std::memset(&cpu->cpu_ctx.regs, 0, sizeof(regs_t));
	std::memset(&cpu->msr, 0, sizeof(msr_t));
	cpu->cpu_ctx.regs.eip = 0x0000FFF0;
	cpu->cpu_ctx.regs.edx = 0x0000068A;
	cpu->cpu_ctx.regs.cs = 0xF000;
	cpu->cpu_ctx.regs.cs_hidden.base = 0xFFFF0000;
	cpu->cpu_ctx.regs.es_hidden.limit = cpu->cpu_ctx.regs.cs_hidden.limit = cpu->cpu_ctx.regs.ss_hidden.limit =
	cpu->cpu_ctx.regs.ds_hidden.limit = cpu->cpu_ctx.regs.fs_hidden.limit = cpu->cpu_ctx.regs.gs_hidden.limit = 0xFFFF;
	cpu->cpu_ctx.regs.cs_hidden.flags = ((1 << 15) | (1 << 12) | (1 << 11) | (1 << 9) | (1 << 8)); // present, code, readable, accessed
	cpu->cpu_ctx.regs.es_hidden.flags = cpu->cpu_ctx.regs.ss_hidden.flags = cpu->cpu_ctx.regs.ds_hidden.flags =
	cpu->cpu_ctx.regs.fs_hidden.flags = cpu->cpu_ctx.regs.gs_hidden.flags = ((1 << 15) | (1 << 12) | (1 << 9) | (1 << 8)); // present, data, writable, accessed
	cpu->cpu_ctx.regs.eflags = 0x2;
	cpu->cpu_ctx.regs.cr0 = 0x60000010;
	cpu->cpu_ctx.regs.dr[6] = DR6_RES_MASK;
	cpu->cpu_ctx.regs.dr[7] = DR7_RES_MASK;
	cpu->cpu_ctx.regs.idtr_hidden.limit = cpu->cpu_ctx.regs.gdtr_hidden.limit = cpu->cpu_ctx.regs.ldtr_hidden.limit =
	cpu->cpu_ctx.regs.tr_hidden.limit = 0xFFFF;
	cpu->cpu_ctx.regs.ldtr_hidden.flags = ((1 << 15) | (2 << 8)); // present, ldt
	cpu->cpu_ctx.regs.tr_hidden.flags = ((1 << 15) | (11 << 8)); // present, 32bit tss busy
	cpu->cpu_ctx.regs.mxcsr = 0x1F80;
	cpu->cpu_ctx.lazy_eflags.result = 0x100; // make zf=0
	cpu->a20_mask = 0xFFFFFFFF; // gate closed
	cpu->cpu_ctx.exp_info.old_exp = EXP_INVALID;
	cpu->msr.mcg_cap = (MCG_NUM_BANKS | MCG_CTL_P | MCG_SER_P);
	cpu->msr.mcg_ctl = MCG_CTL_ENABLE;
	for (unsigned i = 0; i < MCG_NUM_BANKS; ++i) {
		cpu->msr.mca_banks[i][MCi_CTL] = MCi_CTL_ENABLE;
	}
	tsc_init(cpu);
	fpu_init(cpu);
}

static void
check_dbl_exp(cpu_ctx_t *cpu_ctx)
{
	uint16_t idx = cpu_ctx->exp_info.exp_data.idx;
	bool old_contributory = cpu_ctx->exp_info.old_exp == 0 || (cpu_ctx->exp_info.old_exp >= 10 && cpu_ctx->exp_info.old_exp <= 13);
	bool curr_contributory = idx == 0 || (idx >= 10 && idx <= 13);

	LOG(log_level::info, "%s old: %u new %u", __func__, cpu_ctx->exp_info.old_exp, idx);

	if (cpu_ctx->exp_info.old_exp == EXP_DF) {
		throw lc86_exp_abort("The guest has triple faulted, cannot continue", lc86_status::success);
	}

	if ((old_contributory && curr_contributory) || (cpu_ctx->exp_info.old_exp == EXP_PF && (curr_contributory || (idx == EXP_PF)))) {
		cpu_ctx->exp_info.exp_data.code = 0;
		cpu_ctx->exp_info.exp_data.eip = 0;
		idx = EXP_DF;
	}

	if (curr_contributory || (idx == EXP_PF) || (idx == EXP_DF)) {
		cpu_ctx->exp_info.old_exp = idx;
	}

	cpu_ctx->exp_info.exp_data.idx = idx;
}

template<unsigned is_intn, bool is_hw_int>
translated_code_t *cpu_raise_exception(cpu_ctx_t *cpu_ctx)
{
	// is_intn -> not a int instruction(0), int3(1), intn(2), into(3), is_hw_int -> hardware interrupt

	if constexpr (!(is_intn) && !(is_hw_int)) {
		check_dbl_exp(cpu_ctx);
	}

	cpu_t *cpu = cpu_ctx->cpu;
	uint32_t fault_addr = cpu_ctx->exp_info.exp_data.fault_addr;
	uint16_t code = cpu_ctx->exp_info.exp_data.code;
	uint16_t idx = cpu_ctx->exp_info.exp_data.idx;
	uint32_t eip = cpu_ctx->exp_info.exp_data.eip;
	uint32_t old_eflags = read_eflags(cpu);

	if (cpu_ctx->hflags & HFLG_PE_MODE) {
		// protected mode

		constexpr uint16_t ext_flg = is_intn ? 0 : 1; // EXT flag clear for INT instructions, set otherwise

		uint32_t iopl = (cpu_ctx->regs.eflags & IOPL_MASK) >> 12;
		if ((is_intn == 2) && (((cpu_ctx->regs.eflags & VM_MASK) | (cpu_ctx->hflags & HFLG_CR4_VME)) == VM_MASK) &&
			(((cpu_ctx->regs.eflags & IOPL_MASK) >> 12) < 3)) {
			cpu_ctx->exp_info.exp_data.code = 0;
			cpu_ctx->exp_info.exp_data.idx = EXP_GP;
			return cpu_raise_exception(cpu_ctx);
		}

		if ((is_intn == 2) && (((cpu_ctx->regs.eflags & VM_MASK) | (cpu_ctx->hflags & HFLG_CR4_VME)) == (VM_MASK | HFLG_CR4_VME))) {
			uint16_t offset = mem_read_helper<uint16_t>(cpu_ctx, cpu_ctx->regs.tr_hidden.base + 102, eip, 0);
			uint8_t io_int_table_byte = mem_read_helper<uint8_t>(cpu_ctx, cpu_ctx->regs.tr_hidden.base + offset - 32 + idx / 8, eip, 0);
			if ((io_int_table_byte & (1 << (idx % 8))) == 0) {
				if (iopl < 3) {
					old_eflags = ((old_eflags & VIF_MASK) >> 10) | (old_eflags & ~(IF_MASK | IOPL_MASK)) | IOPL_MASK;
				}
				uint32_t esp = cpu_ctx->regs.esp;
				uint32_t stack_mask = cpu_ctx->hflags & HFLG_SS32 ? 0xFFFFFFFF : 0xFFFF;
				uint32_t stack_base = cpu_ctx->regs.ss_hidden.base;
				esp -= 2;
				mem_write_helper<uint16_t>(cpu_ctx, stack_base + (esp & stack_mask), old_eflags, eip, 0);
				esp -= 2;
				mem_write_helper<uint16_t>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.cs, eip, 0);
				esp -= 2;
				mem_write_helper<uint16_t>(cpu_ctx, stack_base + (esp & stack_mask), eip, eip, 0);
				uint32_t vec_entry = mem_read_helper<uint32_t>(cpu_ctx, idx * 4, eip, 0);
				uint32_t eflags_mask = TF_MASK;
				cpu_ctx->regs.esp = (cpu_ctx->regs.esp & ~stack_mask) | (esp & stack_mask);
				cpu_ctx->regs.cs = vec_entry >> 16;
				cpu_ctx->regs.cs_hidden.base = cpu_ctx->regs.cs << 4;
				cpu_ctx->regs.eip = vec_entry & 0xFFFF;
				if (iopl == 3) {
					eflags_mask |= (IF_MASK | VIF_MASK);
				}
				cpu_ctx->regs.eflags &= ~eflags_mask;
				cpu_ctx->hflags &= ~(HFLG_DBG_TRAP | HFLG_INHIBIT_INT);
				cpu_ctx->exp_info.old_exp = EXP_INVALID;
				if (idx == EXP_PF) {
					cpu_ctx->regs.cr2 = fault_addr;
				}
				if (idx == EXP_DB) {
					cpu_ctx->regs.dr[7] &= ~DR7_GD_MASK;
				}

				return nullptr;
			}
			else {
				if (iopl != 3) {
					cpu_ctx->exp_info.exp_data.code = 0;
					cpu_ctx->exp_info.exp_data.idx = EXP_GP;
					return cpu_raise_exception(cpu_ctx);
				}
			}
		}

		if (idx * 8 + 7 > cpu_ctx->regs.idtr_hidden.limit) {
			cpu_ctx->exp_info.exp_data.code = idx * 8 + 2 + ext_flg;
			cpu_ctx->exp_info.exp_data.idx = EXP_GP;
			return cpu_raise_exception(cpu_ctx);
		}

		uint64_t desc = mem_read_helper<uint64_t>(cpu_ctx, cpu_ctx->regs.idtr_hidden.base + idx * 8, eip, 2);
		uint16_t type = (desc >> 40) & 0x1F;
		uint32_t new_eip, eflags;
		switch (type)
		{
		case 5:  // task gate
			// we don't support task gates yet, so just abort
			LIB86CPU_ABORT_msg("Task gates are not supported yet while delivering an exception");

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
			cpu_ctx->exp_info.exp_data.code = idx * 8 + 2 + ext_flg;
			cpu_ctx->exp_info.exp_data.idx = EXP_GP;
			return cpu_raise_exception(cpu_ctx);
		}

		uint32_t dpl = (desc & SEG_DESC_DPL) >> 45;
		uint32_t cpl = cpu_ctx->hflags & HFLG_CPL;
		if (is_intn && (dpl < cpl)) { // only INT instructions check the dpl of the gate in the idt
			cpu_ctx->exp_info.exp_data.code = idx * 8 + 2;
			cpu_ctx->exp_info.exp_data.idx = EXP_GP;
			return cpu_raise_exception(cpu_ctx);
		}

		if ((desc & SEG_DESC_P) == 0) {
			cpu_ctx->exp_info.exp_data.code = idx * 8 + 2 + ext_flg;
			cpu_ctx->exp_info.exp_data.idx = EXP_NP;
			return cpu_raise_exception(cpu_ctx);
		}

		uint16_t sel = (desc & 0xFFFF0000) >> 16;
		if ((sel >> 2) == 0) {
			cpu_ctx->exp_info.exp_data.code = ext_flg;
			cpu_ctx->exp_info.exp_data.idx = EXP_GP;
			return cpu_raise_exception(cpu_ctx);
		}

		addr_t code_desc_addr;
		uint64_t code_desc;
		if (read_seg_desc_helper(cpu, sel, code_desc_addr, code_desc, eip)) {
			cpu_ctx->exp_info.exp_data.code += ext_flg;
			return cpu_raise_exception(cpu_ctx);
		}

		dpl = (code_desc & SEG_DESC_DPL) >> 45;
		if (dpl > cpl) {
			cpu_ctx->exp_info.exp_data.code = (sel & 0xFFFC) + ext_flg;
			cpu_ctx->exp_info.exp_data.idx = EXP_GP;
			return cpu_raise_exception(cpu_ctx);
		}

		if ((code_desc & SEG_DESC_P) == 0) {
			cpu_ctx->exp_info.exp_data.code = (sel & 0xFFFC) + ext_flg;
			cpu_ctx->exp_info.exp_data.idx = EXP_NP;
			return cpu_raise_exception(cpu_ctx);
		}

		if (code_desc & SEG_DESC_C) {
			dpl = cpl;
		}

		set_access_flg_seg_desc_helper(cpu, code_desc, code_desc_addr, eip);

		const auto &exp_has_code = [idx]() -> uint8_t
		{
			if constexpr (is_intn || is_hw_int) {
				// INT instructions and hw interrupts don't push error codes
				return 0;
			}
			else {
				switch (idx)
				{
				case EXP_DF:
				case EXP_TS:
				case EXP_NP:
				case EXP_SS:
				case EXP_GP:
				case EXP_PF:
				case EXP_AC:
					return 1;
				}

				return 0;
			}
		};

		uint32_t seg_base = read_seg_desc_base_helper(cpu, code_desc);
		uint32_t seg_limit = read_seg_desc_limit_helper(cpu, code_desc);
		uint32_t seg_flags = read_seg_desc_flags_helper(cpu, code_desc);
		uint32_t stack_switch, stack_mask, stack_base, esp;
		uint32_t new_esp;
		uint16_t new_ss;
		uint64_t ss_desc;

		if (dpl < cpl) {
			// more privileged

			const auto &check_ss_desc = [eip, cpu]<bool is_vm86>(cpu_ctx_t *cpu_ctx, uint32_t dpl, uint32_t &new_esp, uint16_t &new_ss, uint64_t &ss_desc)
			{
				addr_t ss_desc_addr;

				if (read_stack_ptr_from_tss_helper(cpu, dpl, new_esp, new_ss, eip, is_vm86 ? 2 : 0)) {
					cpu_ctx->exp_info.exp_data.code += ext_flg;
					return true;
				}

				if ((new_ss >> 2) == 0) {
					cpu_ctx->exp_info.exp_data.code = ext_flg;
					cpu_ctx->exp_info.exp_data.idx = EXP_TS;
					return true;
				}

				if (read_seg_desc_helper(cpu, new_ss, ss_desc_addr, ss_desc, eip)) {
					cpu_ctx->exp_info.exp_data.code += ext_flg;
					cpu_ctx->exp_info.exp_data.idx = EXP_TS;
					return true;
				}

				uint32_t p = (ss_desc & SEG_DESC_P) >> 40;
				uint32_t s = (ss_desc & SEG_DESC_S) >> 44;
				uint32_t d = (ss_desc & SEG_DESC_DC) >> 42;
				uint32_t w = (ss_desc & SEG_DESC_W) >> 39;
				uint32_t ss_dpl = (ss_desc & SEG_DESC_DPL) >> 42;
				uint32_t ss_rpl = (new_ss & 3) << 5;
				uint32_t dpl_compare = is_vm86 ? 0 : dpl;
				if ((s | d | w | ss_dpl | ss_rpl | p) ^ ((0x85 | (dpl_compare << 3)) | (dpl_compare << 5))) {
					cpu_ctx->exp_info.exp_data.code = (new_ss & 0xFFFC) + ext_flg;
					cpu_ctx->exp_info.exp_data.idx = EXP_TS;
					return true;
				}

				set_access_flg_seg_desc_helper(cpu, ss_desc, ss_desc_addr, eip);

				return false;
			};

			if (cpu_ctx->regs.eflags & VM_MASK) {
				if (dpl) {
					cpu_ctx->exp_info.exp_data.code = (sel & 0xFFFC) + ext_flg;
					cpu_ctx->exp_info.exp_data.idx = EXP_GP;
					return cpu_raise_exception(cpu_ctx);
				}

				if (check_ss_desc.template operator()<true>(cpu_ctx, dpl, new_esp, new_ss, ss_desc)) {
					return cpu_raise_exception(cpu_ctx);
				}

				uint32_t esp = new_esp;
				uint32_t stack_mask = ss_desc & SEG_DESC_DB ? 0xFFFFFFFF : 0xFFFF;
				uint32_t stack_base = read_seg_desc_base_helper(cpu, ss_desc);

				const auto &push_regs = [old_eflags, eip, exp_has_code, code]<bool is_idt32>(cpu_ctx_t *cpu_ctx, uint32_t &esp, uint32_t stack_mask, uint32_t stack_base)
				{
					using T = std::conditional_t<is_idt32, uint32_t, uint16_t>;
					constexpr uint32_t push_size = sizeof(T);

					esp -= push_size;
					mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.gs, eip, 2);
					esp -= push_size;
					mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.fs, eip, 2);
					esp -= push_size;
					mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.ds, eip, 2);
					esp -= push_size;
					mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.es, eip, 2);
					esp -= push_size;
					mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.ss, eip, 2);
					esp -= push_size;
					mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.esp, eip, 2);
					esp -= push_size;
					mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), old_eflags, eip, 2);
					esp -= push_size;
					mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.cs, eip, 2);
					esp -= push_size;
					mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), eip, eip, 2);
					if (exp_has_code()) {
						esp -= push_size;
						mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), code, eip, 2);
					}
				};

				if ((type == 14) || (type == 15)) {
					push_regs.template operator()<true>(cpu_ctx, esp, stack_mask, stack_base);
				}
				else {
					push_regs.template operator()<false>(cpu_ctx, esp, stack_mask, stack_base);
					new_eip &= 0xFFFF;
				}

				cpu_ctx->regs.gs = cpu_ctx->regs.fs = cpu_ctx->regs.ds = cpu_ctx->regs.es = 0;
				cpu_ctx->regs.gs_hidden.base = cpu_ctx->regs.fs_hidden.base = cpu_ctx->regs.ds_hidden.base = cpu_ctx->regs.es_hidden.base = 0;
				cpu_ctx->regs.gs_hidden.limit = cpu_ctx->regs.fs_hidden.limit = cpu_ctx->regs.ds_hidden.limit = cpu_ctx->regs.es_hidden.limit = 0;
				cpu_ctx->regs.gs_hidden.flags = cpu_ctx->regs.fs_hidden.flags = cpu_ctx->regs.ds_hidden.flags = cpu_ctx->regs.es_hidden.flags = 0;
				cpu_ctx->regs.cs = sel & 0xFFC;
				cpu_ctx->regs.cs_hidden.base = seg_base;
				cpu_ctx->regs.cs_hidden.limit = seg_limit;
				cpu_ctx->regs.cs_hidden.flags = seg_flags;
				cpu_ctx->hflags = ((cpu_ctx->regs.cs_hidden.flags & SEG_HIDDEN_DB) >> 20) | (cpu_ctx->hflags & ~(HFLG_CS32 | HFLG_CPL));
				cpu_ctx->regs.ss = new_ss;
				cpu_ctx->regs.ss_hidden.base = stack_base;
				cpu_ctx->regs.ss_hidden.limit = read_seg_desc_limit_helper(cpu, ss_desc);
				cpu_ctx->regs.ss_hidden.flags = read_seg_desc_flags_helper(cpu, ss_desc);
				cpu_ctx->hflags = ((cpu_ctx->regs.ss_hidden.flags & SEG_HIDDEN_DB) >> 19) | (cpu_ctx->hflags & ~HFLG_SS32);
				cpu_ctx->regs.eflags = (eflags & ~(VM_MASK | RF_MASK | NT_MASK | TF_MASK));
				cpu_ctx->regs.esp = (cpu_ctx->regs.esp & ~stack_mask) | (esp & stack_mask);
				cpu_ctx->regs.eip = new_eip;
				cpu_ctx->hflags &= ~(HFLG_DBG_TRAP | HFLG_INHIBIT_INT);
				cpu_ctx->exp_info.old_exp = EXP_INVALID;
				if (idx == EXP_PF) {
					cpu_ctx->regs.cr2 = fault_addr;
				}
				if (idx == EXP_DB) {
					cpu_ctx->regs.dr[7] &= ~DR7_GD_MASK;
				}

				return nullptr;
			}

			if (check_ss_desc.template operator()<false>(cpu_ctx, dpl, new_esp, new_ss, ss_desc)) {
				return cpu_raise_exception(cpu_ctx);
			}

			stack_switch = 1;
			stack_mask = ss_desc & SEG_DESC_DB ? 0xFFFFFFFF : 0xFFFF;
			stack_base = read_seg_desc_base_helper(cpu, ss_desc);
			esp = new_esp;
		}
		else {
			if (cpu_ctx->regs.eflags & VM_MASK) {
				cpu_ctx->exp_info.exp_data.code = (sel & 0xFFFC) + ext_flg;
				cpu_ctx->exp_info.exp_data.idx = EXP_GP;
				return cpu_raise_exception(cpu_ctx);
			}
			else if (dpl == cpl) {
				// same privilege

				stack_switch = 0;
				stack_mask = cpu_ctx->hflags & HFLG_SS32 ? 0xFFFFFFFF : 0xFFFF;
				stack_base = cpu_ctx->regs.ss_hidden.base;
				esp = cpu_ctx->regs.esp;
			}
			else {
				cpu_ctx->exp_info.exp_data.code = (sel & 0xFFFC) + ext_flg;
				cpu_ctx->exp_info.exp_data.idx = EXP_GP;
				return cpu_raise_exception(cpu_ctx);
			}
		}

		uint8_t has_code = exp_has_code();

		const auto &push_regs = [old_eflags, eip, has_code, code]<bool is_push32, bool stack_switch>(cpu_ctx_t *cpu_ctx, uint32_t &esp, uint32_t stack_mask,
			uint32_t stack_base, uint8_t is_priv)
		{
			using T = std::conditional_t<is_push32, uint32_t, uint16_t>;
			constexpr uint32_t push_size = sizeof(T);

			if constexpr (stack_switch) {
				esp -= push_size;
				mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.ss, eip, is_priv);
				esp -= push_size;
				mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.esp, eip, is_priv);
			}
			esp -= push_size;
			mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), old_eflags, eip, is_priv);
			esp -= push_size;
			mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.cs, eip, is_priv);
			esp -= push_size;
			mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), eip, eip, is_priv);
			if (has_code) {
				esp -= push_size;
				mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), code, eip, is_priv);
			}
		};

		type >>= 3;
		if (stack_switch) {
			if (type) { // push 32, priv
				push_regs.template operator()<true, true>(cpu_ctx, esp, stack_mask, stack_base, 2);
			}
			else { // push 16, priv
				push_regs.template operator()<false, true>(cpu_ctx, esp, stack_mask, stack_base, 2);
			}

			uint32_t ss_flags = read_seg_desc_flags_helper(cpu, ss_desc);
			cpu_ctx->regs.ss = (new_ss & ~3) | dpl;
			cpu_ctx->regs.ss_hidden.base = stack_base;
			cpu_ctx->regs.ss_hidden.limit = read_seg_desc_limit_helper(cpu, ss_desc);
			cpu_ctx->regs.ss_hidden.flags = ss_flags;
			cpu_ctx->hflags = ((ss_flags & SEG_HIDDEN_DB) >> 19) | (cpu_ctx->hflags & ~HFLG_SS32);
		}
		else {
			if (type) { // push 32, not priv
				push_regs.template operator()<true, false>(cpu_ctx, esp, stack_mask, stack_base, 0);
			}
			else { // push 16, not priv
				push_regs.template operator()<false, false>(cpu_ctx, esp, stack_mask, stack_base, 0);
			}
		}

		cpu_ctx->regs.eflags = (eflags & ~(VM_MASK | RF_MASK | NT_MASK | TF_MASK));
		cpu_ctx->regs.esp = (cpu_ctx->regs.esp & ~stack_mask) | (esp & stack_mask);
		cpu_ctx->regs.cs = (sel & ~3) | dpl;
		cpu_ctx->regs.cs_hidden.base = seg_base;
		cpu_ctx->regs.cs_hidden.limit = seg_limit;
		cpu_ctx->regs.cs_hidden.flags = seg_flags;
		cpu_ctx->hflags = (((seg_flags & SEG_HIDDEN_DB) >> 20) | dpl) | (cpu_ctx->hflags & ~(HFLG_CS32 | HFLG_CPL));
		cpu_ctx->regs.eip = new_eip;
		if (idx == EXP_PF) {
			cpu_ctx->regs.cr2 = fault_addr;
		}
	}
	else {
		// real mode

		if (idx * 4 + 3 > cpu_ctx->regs.idtr_hidden.limit) {
			cpu_ctx->exp_info.exp_data.code = idx * 8 + 2;
			cpu_ctx->exp_info.exp_data.idx = EXP_GP;
			return cpu_raise_exception(cpu_ctx);
		}

		uint32_t vec_entry = mem_read_helper<uint32_t>(cpu_ctx, cpu_ctx->regs.idtr_hidden.base + idx * 4, eip, 0);
		uint32_t stack_mask = 0xFFFF;
		uint32_t stack_base = cpu_ctx->regs.ss_hidden.base;
		uint32_t esp = cpu_ctx->regs.esp;
		esp -= 2;
		mem_write_helper<uint16_t>(cpu_ctx, stack_base + (esp & stack_mask), old_eflags, eip, 0);
		esp -= 2;
		mem_write_helper<uint16_t>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.cs, eip, 0);
		esp -= 2;
		mem_write_helper<uint16_t>(cpu_ctx, stack_base + (esp & stack_mask), eip, eip, 0);

		cpu_ctx->regs.eflags &= ~(AC_MASK | RF_MASK | IF_MASK | TF_MASK);
		cpu_ctx->regs.esp = (cpu_ctx->regs.esp & ~stack_mask) | (esp & stack_mask);
		cpu_ctx->regs.cs = vec_entry >> 16;
		cpu_ctx->regs.cs_hidden.base = cpu_ctx->regs.cs << 4;
		cpu_ctx->regs.eip = vec_entry & 0xFFFF;
	}

	cpu_ctx->hflags &= ~(HFLG_DBG_TRAP | HFLG_INHIBIT_INT);
	cpu_ctx->exp_info.old_exp = EXP_INVALID;
	if (idx == EXP_DB) {
		cpu_ctx->regs.dr[7] &= ~DR7_GD_MASK;
	}

	return nullptr;
}

addr_t
get_pc(cpu_ctx_t *cpu_ctx)
{
	return cpu_ctx->regs.cs_hidden.base + cpu_ctx->regs.eip;
}

// dummy tc only used for comparisons in the ibtc. Using the invalid hflag makes sure that comparisons with it always fail, and avoids the need to check
// if an entry in the ibtc exists (e.g. checking for nullptr)
static translated_code_t dummy_tc(HFLG_INVALID);

translated_code_t::translated_code_t() noexcept
{
	size = 0;
	flags = 0;
	ptr_code = nullptr;
	for (auto &entry : ibtc) {
		entry = &dummy_tc;
	}
}

static inline uint32_t
tc_hash(addr_t pc)
{
	return pc & (CODE_CACHE_MAX_SIZE - 1);
}

template<bool remove_hook>
void tc_invalidate(cpu_ctx_t *cpu_ctx, addr_t phys_addr, [[maybe_unused]] uint8_t size, [[maybe_unused]] uint32_t eip)
{
	bool halt_tc = false;

	if constexpr (!remove_hook) {
		if (cpu_ctx->cpu->cpu_flags & CPU_ALLOW_CODE_WRITE) {
			return;
		}
	}

	// find all tc's in the page phys_addr belongs to
	auto it_map = cpu_ctx->cpu->tc_page_map.find(phys_addr >> PAGE_SHIFT);
	if (it_map != cpu_ctx->cpu->tc_page_map.end()) {
		auto it_set = it_map->second.begin();
		uint32_t flags = (cpu_ctx->hflags & HFLG_CONST) | (cpu_ctx->regs.eflags & EFLAGS_CONST);
		std::vector<std::unordered_set<translated_code_t *>::iterator> tc_to_delete;
		// iterate over all tc's found in the page
		while (it_set != it_map->second.end()) {
			translated_code_t *tc_in_page = *it_set;
			// only invalidate the tc if phys_addr is included in the translated address range of the tc
			// hook tc's have a zero guest code size, so they are unaffected by guest writes and do not need to be considered by tc_invalidate
			bool remove_tc;
			if constexpr (remove_hook) {
				remove_tc = !tc_in_page->size && (tc_in_page->pc == phys_addr);
			}
			else {
				remove_tc = tc_in_page->size && !(std::min(phys_addr + size - 1, tc_in_page->pc + tc_in_page->size - 1) < std::max(phys_addr, tc_in_page->pc));
			}

			if (remove_tc) {
				auto it_list = tc_in_page->linked_tc.begin();
				// now unlink all other tc's that jump to this tc (aka the predecessors)
				while (it_list != tc_in_page->linked_tc.end()) {
					uint32_t tc_link_type = (*it_list)->flags & TC_FLG_LINK_MASK;
					if ((tc_link_type == TC_FLG_DIRECT) || (tc_link_type == TC_FLG_DST_COND) || (tc_link_type == TC_FLG_DST_ONLY)) {
						if ((*it_list)->jmp_offset[0] == tc_in_page->ptr_code) {
							(*it_list)->jmp_offset[0] = (*it_list)->jmp_offset[2];
						}
						if ((*it_list)->jmp_offset[1] == tc_in_page->ptr_code) {
							(*it_list)->jmp_offset[1] = (*it_list)->jmp_offset[2];
						}
					}
					else {
						assert((tc_link_type == TC_FLG_INDIRECT) || (tc_link_type == TC_FLG_RET));
						for (auto &entry : (*it_list)->ibtc) {
							if (entry == tc_in_page) {
								entry = &dummy_tc;
							}
						}
					}
					++it_list;
				}

				// now update the linked_tc list of the tc's that this tc is (in)directly jumping to (aka the successors)
				const auto update_linked_tc_lambda = [tc_in_page](translated_code_t *tc) {
					if (tc == tc_in_page) {
						return true;
					}
					return false;
				};
				if (tc_in_page->jmp_offset[0] != tc_in_page->jmp_offset[2]) {
					translated_code_t *dst_tc = *reinterpret_cast<translated_code_t **>(reinterpret_cast<uint8_t *>(tc_in_page->jmp_offset[0]) - 14);
					[[maybe_unused]] const auto erased = std::erase_if(dst_tc->linked_tc, update_linked_tc_lambda);
					assert(erased);
				}
				if (tc_in_page->jmp_offset[1] != tc_in_page->jmp_offset[2]) {
					translated_code_t *next_tc = *reinterpret_cast<translated_code_t **>(reinterpret_cast<uint8_t *>(tc_in_page->jmp_offset[1]) - 14);
					[[maybe_unused]] const auto erased = std::erase_if(next_tc->linked_tc, update_linked_tc_lambda);
					assert(erased);
				}
				for (auto &entry : tc_in_page->ibtc) {
					if (entry->guest_flags != HFLG_INVALID) {
						[[maybe_unused]] const auto erased = std::erase_if(entry->linked_tc, update_linked_tc_lambda);
						assert(erased);
					}
				}

				// delete the found tc from the code cache
				uint32_t idx = tc_hash(tc_in_page->pc);
				auto it = cpu_ctx->cpu->code_cache[idx].begin();
				while (it != cpu_ctx->cpu->code_cache[idx].end()) {
					if (it->get() == tc_in_page) {
						try {
							if (it->get()->cs_base == cpu_ctx->regs.cs_hidden.base &&
								it->get()->pc == get_code_addr(cpu_ctx->cpu, get_pc(cpu_ctx), cpu_ctx->regs.eip) &&
								it->get()->guest_flags == flags) {
								// worst case: the write overlaps with the tc we are currently executing
								halt_tc = true;
								if constexpr (!remove_hook) {
									cpu_ctx->cpu->cpu_flags |= (CPU_DISAS_ONE | CPU_ALLOW_CODE_WRITE);
								}
							}
						}
						catch (host_exp_t type) {
							// the current tc cannot fault
						}
						cpu_ctx->cpu->code_cache[idx].erase(it);
						break;
					}
					++it;
				}

				// we can't delete the tc in tc_page_map right now because it would invalidate its iterator, which is still needed below
				tc_to_delete.push_back(it_set);

				if constexpr (remove_hook) {
					break;
				}
			}
			++it_set;
		}

		// delete the found tc's from tc_page_map
		for (auto &it : tc_to_delete) {
			it_map->second.erase(it);
		}

		// if the tc_page_map for phys_addr is now empty, also clear the corresponding smc bit and its key in the map
		if (it_map->second.empty()) {
			cpu_ctx->cpu->smc.reset(phys_addr >> PAGE_SHIFT);
			cpu_ctx->cpu->tc_page_map.erase(it_map);
		}
	}

	if (halt_tc) {
		// in this case the tc we were executing must be interrupted and to do that, we must return to the translator with an exception
		if constexpr (!remove_hook) {
			cpu_ctx->regs.eip = eip;
		}
		throw host_exp_t::halt_tc;
	}
}

template void tc_invalidate<true>(cpu_ctx_t * cpu_ctx, addr_t phys_addr, [[maybe_unused]] uint8_t size, [[maybe_unused]] uint32_t eip);
template void tc_invalidate<false>(cpu_ctx_t * cpu_ctx, addr_t phys_addr, [[maybe_unused]] uint8_t size, [[maybe_unused]] uint32_t eip);

static translated_code_t *
tc_cache_search(cpu_t *cpu, addr_t pc)
{
	uint32_t flags = (cpu->cpu_ctx.hflags & HFLG_CONST) | (cpu->cpu_ctx.regs.eflags & EFLAGS_CONST);
	uint32_t idx = tc_hash(pc);
	auto it = cpu->code_cache[idx].begin();
	while (it != cpu->code_cache[idx].end()) {
		translated_code_t *tc = it->get();
		if (tc->cs_base == cpu->cpu_ctx.regs.cs_hidden.base &&
			tc->pc == pc &&
			tc->guest_flags == flags) {
			return tc;
		}
		it++;
	}

	return nullptr;
}

static void
tc_cache_insert(cpu_t *cpu, addr_t pc, std::unique_ptr<translated_code_t> &&tc)
{
	cpu->num_tc++;
	cpu->tc_page_map[pc >> PAGE_SHIFT].insert(tc.get());
	cpu->code_cache[tc_hash(pc)].push_front(std::move(tc));
}

template<bool should_flush_tlb>
void tc_should_clear_cache_and_tlb(cpu_t *cpu, addr_t start, addr_t end)
{
	for (uint32_t tlb_idx_s = start >> PAGE_SHIFT, tlb_idx_e = end >> PAGE_SHIFT; tlb_idx_s <= tlb_idx_e; ++tlb_idx_s) {
		if (cpu->smc[tlb_idx_s]) {
			tc_cache_clear(cpu);
			break;
		}
	}

	if constexpr (should_flush_tlb) {
		tlb_flush(cpu);
	}
}

void
tc_cache_clear(cpu_t *cpu)
{
	// Use this when you want to destroy all tc's but without affecting the actual code allocated. E.g: on x86-64, you'll want to keep the .pdata sections
	// when this is called from a function called from the JITed code, and the current function can potentially throw an exception
	cpu->tc_page_map.clear();
	cpu->smc.reset();
	for (auto &bucket : cpu->code_cache) {
		bucket.clear();
	}
}

void
tc_cache_purge(cpu_t *cpu)
{
	// This is like tc_cache_clear, but it also frees all code allocated. E.g: on x86-64, the jit also emits .pdata sections that hold the exception tables
	// necessary to unwind the stack of the JITed functions
	tc_cache_clear(cpu);
	cpu->jit->destroy_all_code();
	cpu->num_tc = 0;
}

static void
tc_link_direct(translated_code_t *prev_tc, translated_code_t *ptr_tc)
{
	uint32_t num_jmp = prev_tc->flags & TC_FLG_NUM_JMP;

	switch (num_jmp)
	{
	case 0:
		break;

	case 1:
	case 2:
		switch ((prev_tc->flags & TC_FLG_JMP_TAKEN) >> 4)
		{
		case TC_JMP_DST_PC:
			prev_tc->jmp_offset[0] = ptr_tc->ptr_code;
			ptr_tc->linked_tc.push_front(prev_tc);
			break;

		case TC_JMP_NEXT_PC:
			prev_tc->jmp_offset[1] = ptr_tc->ptr_code;
			ptr_tc->linked_tc.push_front(prev_tc);
			break;

		case TC_JMP_RET:
			if (num_jmp == 1) {
				break;
			}
			[[fallthrough]];

		default:
			LIB86CPU_ABORT();
		}
		break;

	default:
		LIB86CPU_ABORT();
	}
}

void
tc_link_dst_only(translated_code_t *prev_tc, translated_code_t *ptr_tc)
{
	switch (prev_tc->flags & TC_FLG_NUM_JMP)
	{
	case 0:
		break;

	case 1:
		prev_tc->jmp_offset[0] = ptr_tc->ptr_code;
		ptr_tc->linked_tc.push_front(prev_tc);
		break;

	default:
		LIB86CPU_ABORT();
	}
}

static void
tc_link_indirect(cpu_t *cpu, translated_code_t *prev_tc, translated_code_t *ptr_tc)
{
	// dst pc of ptr_tc must be in the same page of prev_tc to avoid possible page faults
	if ((ptr_tc->virt_pc & ~PAGE_MASK) == (prev_tc->virt_pc & ~PAGE_MASK)) {
		for (auto &entry : prev_tc->ibtc) {
			if (entry->guest_flags == HFLG_INVALID) {
				entry = ptr_tc;
				ptr_tc->linked_tc.push_front(prev_tc);
				return;
			}
		}

		// if we reach here, it means the ibtc is full. In this case we pick a random entry and replace it
		std::uniform_int_distribution<uint32_t> dis(0, 2);
		uint32_t idx = dis(cpu->rng_gen);
		[[maybe_unused]] const auto erased = std::erase_if(prev_tc->ibtc[idx]->linked_tc, [prev_tc](translated_code_t *tc) {
			if (tc == prev_tc) {
				return true;
			}
			return false;
			});
		assert(erased);
		prev_tc->ibtc[idx] = ptr_tc;
		ptr_tc->linked_tc.push_front(prev_tc);
	}
}

entry_t
link_indirect_handler(cpu_ctx_t *cpu_ctx, translated_code_t *tc)
{
	// NOTE: make sure to check guest_flags first, so that if we are comparing against the dummy_tc, we fail at the first comparison
	for (const auto entry : tc->ibtc) {
		if (entry->guest_flags == ((cpu_ctx->hflags & HFLG_CONST) | (cpu_ctx->regs.eflags & EFLAGS_CONST)) && // must have matching hidden flags
			(entry->cs_base == cpu_ctx->regs.cs_hidden.base) && // must have same cs_base to avoid jumping to wrong pc
			(entry->virt_pc == get_pc(cpu_ctx))) { // must match dst pc we are jumping to
			return entry->ptr_code;
		}
	}

	return tc->jmp_offset[2];
}

static void
tc_link_prev(cpu_t *cpu, translated_code_t *prev_tc, translated_code_t *ptr_tc)
{
	// see if we can link the previous tc with the current one
	if (prev_tc != nullptr) {
		switch (prev_tc->flags & TC_FLG_LINK_MASK)
		{
		case 0:
			break;

		case TC_FLG_DST_ONLY:
			tc_link_dst_only(prev_tc, ptr_tc);
			break;

		case TC_FLG_DIRECT:
		case TC_FLG_DST_COND:
			tc_link_direct(prev_tc, ptr_tc);
			break;

		case TC_FLG_RET:
		case TC_FLG_INDIRECT:
			tc_link_indirect(cpu, prev_tc, ptr_tc);
			break;

		default:
			LIB86CPU_ABORT();
		}
	}
}

static void
cpu_translate(cpu_t *cpu)
{
	disas_ctx_t *disas_ctx = &cpu->disas_ctx;
	cpu->translate_next = 1;
	cpu->virt_pc = disas_ctx->virt_pc;

	decoded_instr instr;
	ZydisDecoder decoder;
	ZyanStatus status;

	init_instr_decoder(disas_ctx, &decoder);

	do {
		cpu->instr_eip = cpu->virt_pc - cpu->cpu_ctx.regs.cs_hidden.base;

		try {
			status = decode_instr(cpu, disas_ctx, &decoder, &instr);
		}
		catch (host_exp_t type) {
			// this happens on instr breakpoints (not int3)
			assert(type == host_exp_t::db_exp);
			cpu->jit->gen_raise_exp_inline(0, 0, EXP_DB, cpu->instr_eip);
			disas_ctx->flags |= DISAS_FLG_DBG_FAULT;
			return;
		}

		if (ZYAN_SUCCESS(status)) {
			// successfully decoded

			// NOTE: the second OR for disas_ctx->flags is to handle the edge case where the last byte of the current instructions ends exactly at a page boundary. In this case,
			// the current block can be added to the code cache (so DISAS_FLG_PAGE_CROSS should not be set), but the translation of this block must terminate now (so
			// DISAS_FLG_PAGE_CROSS_NEXT should be set)
			cpu->instr_bytes = instr.i.length;
			disas_ctx->flags |= ((disas_ctx->virt_pc & ~PAGE_MASK) != ((disas_ctx->virt_pc + cpu->instr_bytes - 1) & ~PAGE_MASK)) << 2;
			disas_ctx->flags |= ((disas_ctx->virt_pc & ~PAGE_MASK) != ((disas_ctx->virt_pc + cpu->instr_bytes) & ~PAGE_MASK)) << 5;
			disas_ctx->pc += cpu->instr_bytes;
			disas_ctx->virt_pc += cpu->instr_bytes;

			// att syntax uses percentage symbols to designate the operands, which will cause an error/crash if we (or the client)
			// attempts to interpret them as conversion specifiers, so we pass the formatted instruction as an argument
			LOG(log_level::debug, "0x%08X  %s", disas_ctx->virt_pc - cpu->instr_bytes, instr_logfn(disas_ctx->virt_pc - cpu->instr_bytes, &instr).c_str());
		}
		else {
			// NOTE: if rf is set, then it means we are translating the instr that caused a breakpoint. However, the exp handler always clears rf on itw own,
			// which means we do not need to do it again here in the case the original instr raises another kind of exp
			switch (status)
			{
			case ZYDIS_STATUS_BAD_REGISTER:
			case ZYDIS_STATUS_ILLEGAL_LOCK:
			case ZYDIS_STATUS_DECODING_ERROR:
				// illegal and/or undefined instruction, or lock prefix used on an instruction which does not accept it or used as source operand,
				// or the instruction encodes a register that cannot be used (e.g. mov cs, edx)
				cpu->jit->gen_raise_exp_inline(0, 0, EXP_UD, cpu->instr_eip);
				return;

			case ZYDIS_STATUS_NO_MORE_DATA:
				// buffer < 15 bytes
				cpu->cpu_flags &= ~(CPU_DISAS_ONE | CPU_ALLOW_CODE_WRITE);
				if (disas_ctx->exp_data.idx == EXP_PF) {
					// buffer size reduced because of page fault on second page
					disas_ctx->flags |= DISAS_FLG_FETCH_FAULT;
					cpu->jit->gen_raise_exp_inline(disas_ctx->exp_data.fault_addr, disas_ctx->exp_data.code, disas_ctx->exp_data.idx, disas_ctx->exp_data.eip);
					return;
				}
				else {
					// buffer size reduced because ram/rom region ended
					LIB86CPU_ABORT_msg("Attempted to execute code outside of ram/rom!");
				}

			case ZYDIS_STATUS_INSTRUCTION_TOO_LONG: {
				// instruction length > 15 bytes
				cpu->cpu_flags &= ~(CPU_DISAS_ONE | CPU_ALLOW_CODE_WRITE);
				volatile addr_t addr = get_code_addr<true>(cpu, disas_ctx->virt_pc + X86_MAX_INSTR_LENGTH, disas_ctx->virt_pc - cpu->cpu_ctx.regs.cs_hidden.base, disas_ctx);
				if (disas_ctx->exp_data.idx == EXP_PF) {
					disas_ctx->flags |= DISAS_FLG_FETCH_FAULT;
					cpu->jit->gen_raise_exp_inline(disas_ctx->exp_data.fault_addr, disas_ctx->exp_data.code, disas_ctx->exp_data.idx, disas_ctx->exp_data.eip);
				}
				else {
					cpu->jit->gen_raise_exp_inline(0, 0, EXP_GP, disas_ctx->virt_pc - cpu->cpu_ctx.regs.cs_hidden.base);
				}
				return;
			}

			default:
				LIB86CPU_ABORT_msg("Unhandled zydis decode return status");
			}
		}


		if ((disas_ctx->flags & DISAS_FLG_CS32) ^ ((instr.i.attributes & ZYDIS_ATTRIB_HAS_OPERANDSIZE) >> 43)) {
			cpu->size_mode = SIZE32;
		}
		else {
			cpu->size_mode = SIZE16;
		}

		if ((disas_ctx->flags & DISAS_FLG_CS32) ^ ((instr.i.attributes & ZYDIS_ATTRIB_HAS_ADDRESSSIZE) >> 44)) {
			cpu->addr_mode = ADDR32;
		}
		else {
			cpu->addr_mode = ADDR16;
		}

		switch (instr.i.mnemonic)
		{
		case ZYDIS_MNEMONIC_AAA:
			cpu->jit->aaa(&instr);
			break;

		case ZYDIS_MNEMONIC_AAD:
			cpu->jit->aad(&instr);
			break;

		case ZYDIS_MNEMONIC_AAM:
			cpu->jit->aam(&instr);
			break;

		case ZYDIS_MNEMONIC_AAS:
			cpu->jit->aas(&instr);
			break;

		case ZYDIS_MNEMONIC_ADC:
			cpu->jit->adc(&instr);
			break;

		case ZYDIS_MNEMONIC_ADD:
			cpu->jit->add(&instr);
			break;

		case ZYDIS_MNEMONIC_AND:
			cpu->jit->and_(&instr);
			break;

		case ZYDIS_MNEMONIC_ARPL:
			cpu->jit->arpl(&instr);
			break;

		case ZYDIS_MNEMONIC_BOUND:
			cpu->jit->bound(&instr);
			break;

		case ZYDIS_MNEMONIC_BSF:
			cpu->jit->bsf(&instr);
			break;

		case ZYDIS_MNEMONIC_BSR:
			cpu->jit->bsr(&instr);
			break;

		case ZYDIS_MNEMONIC_BSWAP:
			cpu->jit->bswap(&instr);
			break;

		case ZYDIS_MNEMONIC_BT:
			cpu->jit->bt(&instr);
			break;

		case ZYDIS_MNEMONIC_BTC:
			cpu->jit->btc(&instr);
			break;

		case ZYDIS_MNEMONIC_BTR:
			cpu->jit->btr(&instr);
			break;

		case ZYDIS_MNEMONIC_BTS:
			cpu->jit->bts(&instr);
			break;

		case ZYDIS_MNEMONIC_CALL:
			cpu->jit->call(&instr);
			break;

		case ZYDIS_MNEMONIC_CBW:
			cpu->jit->cbw(&instr);
			break;

		case ZYDIS_MNEMONIC_CDQ:
			cpu->jit->cdq(&instr);
			break;

		case ZYDIS_MNEMONIC_CLC:
			cpu->jit->clc(&instr);
			break;

		case ZYDIS_MNEMONIC_CLD:
			cpu->jit->cld(&instr);
			break;

		case ZYDIS_MNEMONIC_CLI:
			cpu->jit->cli(&instr);
			break;

		case ZYDIS_MNEMONIC_CLTS:
			cpu->jit->clts(&instr);
			break;

		case ZYDIS_MNEMONIC_CMC:
			cpu->jit->cmc(&instr);
			break;

		case ZYDIS_MNEMONIC_CMOVB:
		case ZYDIS_MNEMONIC_CMOVBE:
		case ZYDIS_MNEMONIC_CMOVL:
		case ZYDIS_MNEMONIC_CMOVLE:
		case ZYDIS_MNEMONIC_CMOVNB:
		case ZYDIS_MNEMONIC_CMOVNBE:
		case ZYDIS_MNEMONIC_CMOVNL:
		case ZYDIS_MNEMONIC_CMOVNLE:
		case ZYDIS_MNEMONIC_CMOVNO:
		case ZYDIS_MNEMONIC_CMOVNP:
		case ZYDIS_MNEMONIC_CMOVNS:
		case ZYDIS_MNEMONIC_CMOVNZ:
		case ZYDIS_MNEMONIC_CMOVO:
		case ZYDIS_MNEMONIC_CMOVP:
		case ZYDIS_MNEMONIC_CMOVS:
		case ZYDIS_MNEMONIC_CMOVZ:
			cpu->jit->cmovcc(&instr);
			break;

		case ZYDIS_MNEMONIC_CMP:
			cpu->jit->cmp(&instr);
			break;

		case ZYDIS_MNEMONIC_CMPSB:
		case ZYDIS_MNEMONIC_CMPSW:
		case ZYDIS_MNEMONIC_CMPSD:
			cpu->jit->cmps(&instr);
			break;

		case ZYDIS_MNEMONIC_CMPXCHG:
			cpu->jit->cmpxchg(&instr);
			break;

		case ZYDIS_MNEMONIC_CMPXCHG8B:
			cpu->jit->cmpxchg8b(&instr);
			break;

		case ZYDIS_MNEMONIC_CPUID:
			cpu->jit->cpuid(&instr);
			break;

		case ZYDIS_MNEMONIC_CWD:
			cpu->jit->cwd(&instr);
			break;

		case ZYDIS_MNEMONIC_CWDE:
			cpu->jit->cwde(&instr);
			break;

		case ZYDIS_MNEMONIC_DAA:
			cpu->jit->daa(&instr);
			break;

		case ZYDIS_MNEMONIC_DAS:
			cpu->jit->das(&instr);
			break;

		case ZYDIS_MNEMONIC_DEC:
			cpu->jit->dec(&instr);
			break;

		case ZYDIS_MNEMONIC_DIV:
			cpu->jit->div(&instr);
			break;

		case ZYDIS_MNEMONIC_ENTER:
			cpu->jit->enter(&instr);
			break;

		case ZYDIS_MNEMONIC_FLD:
			cpu->jit->fld(&instr);
			break;

		case ZYDIS_MNEMONIC_FLDCW:
			cpu->jit->fldcw(&instr);
			break;

		case ZYDIS_MNEMONIC_FNCLEX:
			cpu->jit->fnclex(&instr);
			break;

		case ZYDIS_MNEMONIC_FNINIT:
			cpu->jit->fninit(&instr);
			break;

		case ZYDIS_MNEMONIC_FNSTCW:
			cpu->jit->fnstcw(&instr);
			break;

		case ZYDIS_MNEMONIC_FNSTSW:
			cpu->jit->fnstsw(&instr);
			break;

		case ZYDIS_MNEMONIC_FWAIT:
			cpu->jit->fwait(&instr);
			break;

		case ZYDIS_MNEMONIC_FXRSTOR:
			cpu->jit->fxrstor(&instr);
			break;

		case ZYDIS_MNEMONIC_FXSAVE:
			cpu->jit->fxsave(&instr);
			break;

		case ZYDIS_MNEMONIC_HLT:
			cpu->jit->hlt(&instr);
			break;

		case ZYDIS_MNEMONIC_IDIV:
			cpu->jit->idiv(&instr);
			break;

		case ZYDIS_MNEMONIC_IMUL:
			cpu->jit->imul(&instr);
			break;

		case ZYDIS_MNEMONIC_IN:
			cpu->jit->in(&instr);
			break;

		case ZYDIS_MNEMONIC_INC:
			cpu->jit->inc(&instr);
			break;

		case ZYDIS_MNEMONIC_INSB:
		case ZYDIS_MNEMONIC_INSD:
		case ZYDIS_MNEMONIC_INSW:
			cpu->jit->ins(&instr);
			break;

		case ZYDIS_MNEMONIC_INT3:
			cpu->jit->int3(&instr);
			break;

		case ZYDIS_MNEMONIC_INT:
			cpu->jit->intn(&instr);
			break;

		case ZYDIS_MNEMONIC_INTO:
			cpu->jit->into(&instr);
			break;

		case ZYDIS_MNEMONIC_INVD:        BAD;
		case ZYDIS_MNEMONIC_INVLPG:
			cpu->jit->invlpg(&instr);
			break;

		case ZYDIS_MNEMONIC_IRET:
		case ZYDIS_MNEMONIC_IRETD:
			cpu->jit->iret(&instr);
			break;

		case ZYDIS_MNEMONIC_JCXZ:
		case ZYDIS_MNEMONIC_JECXZ:
		case ZYDIS_MNEMONIC_JO:
		case ZYDIS_MNEMONIC_JNO:
		case ZYDIS_MNEMONIC_JB:
		case ZYDIS_MNEMONIC_JNB:
		case ZYDIS_MNEMONIC_JZ:
		case ZYDIS_MNEMONIC_JNZ:
		case ZYDIS_MNEMONIC_JBE:
		case ZYDIS_MNEMONIC_JNBE:
		case ZYDIS_MNEMONIC_JS:
		case ZYDIS_MNEMONIC_JNS:
		case ZYDIS_MNEMONIC_JP:
		case ZYDIS_MNEMONIC_JNP:
		case ZYDIS_MNEMONIC_JL:
		case ZYDIS_MNEMONIC_JNL:
		case ZYDIS_MNEMONIC_JLE:
		case ZYDIS_MNEMONIC_JNLE:
			cpu->jit->jcc(&instr);
			break;

		case ZYDIS_MNEMONIC_JMP:
			cpu->jit->jmp(&instr);
			break;

		case ZYDIS_MNEMONIC_LAHF:
			cpu->jit->lahf(&instr);
			break;

		case ZYDIS_MNEMONIC_LAR:         BAD;
		case ZYDIS_MNEMONIC_LDS:
			cpu->jit->lds(&instr);
			break;

		case ZYDIS_MNEMONIC_LEA:
			cpu->jit->lea(&instr);
			break;

		case ZYDIS_MNEMONIC_LEAVE:
			cpu->jit->leave(&instr);
			break;

		case ZYDIS_MNEMONIC_LES:
			cpu->jit->les(&instr);
			break;

		case ZYDIS_MNEMONIC_LFS:
			cpu->jit->lfs(&instr);
			break;

		case ZYDIS_MNEMONIC_LGDT:
			cpu->jit->lgdt(&instr);
			break;

		case ZYDIS_MNEMONIC_LGS:
			cpu->jit->lgs(&instr);
			break;

		case ZYDIS_MNEMONIC_LIDT:
			cpu->jit->lidt(&instr);
			break;

		case ZYDIS_MNEMONIC_LLDT:
			cpu->jit->lldt(&instr);
			break;

		case ZYDIS_MNEMONIC_LMSW:
			cpu->jit->lmsw(&instr);
			break;

		case ZYDIS_MNEMONIC_LODSB:
		case ZYDIS_MNEMONIC_LODSD:
		case ZYDIS_MNEMONIC_LODSW:
			cpu->jit->lods(&instr);
			break;

		case ZYDIS_MNEMONIC_LOOP:
		case ZYDIS_MNEMONIC_LOOPE:
		case ZYDIS_MNEMONIC_LOOPNE:
			cpu->jit->loop(&instr);
			break;

		case ZYDIS_MNEMONIC_LSL:         BAD;
		case ZYDIS_MNEMONIC_LSS:
			cpu->jit->lss(&instr);
			break;

		case ZYDIS_MNEMONIC_LTR:
			cpu->jit->ltr(&instr);
			break;

		case ZYDIS_MNEMONIC_MOV:
			cpu->jit->mov(&instr);
			break;

		case ZYDIS_MNEMONIC_MOVAPS:
			cpu->jit->movaps(&instr);
			break;

		case ZYDIS_MNEMONIC_MOVD:BAD;

		case ZYDIS_MNEMONIC_MOVNTPS:
			cpu->jit->movntps(&instr);
			break;

		case ZYDIS_MNEMONIC_MOVSB:
		case ZYDIS_MNEMONIC_MOVSD:
		case ZYDIS_MNEMONIC_MOVSW:
			cpu->jit->movs(&instr);
			break;

		case ZYDIS_MNEMONIC_MOVSX:
			cpu->jit->movsx(&instr);
			break;

		case ZYDIS_MNEMONIC_MOVZX:
			cpu->jit->movzx(&instr);
			break;

		case ZYDIS_MNEMONIC_MUL:
			cpu->jit->mul(&instr);
			break;

		case ZYDIS_MNEMONIC_NEG:
			cpu->jit->neg(&instr);
			break;

		case ZYDIS_MNEMONIC_NOP:
			// nothing to do
			break;

		case ZYDIS_MNEMONIC_NOT:
			cpu->jit->not_(&instr);
			break;

		case ZYDIS_MNEMONIC_OR:
			cpu->jit->or_(&instr);
			break;

		case ZYDIS_MNEMONIC_OUT:
			cpu->jit->out(&instr);
			break;

		case ZYDIS_MNEMONIC_OUTSB:
		case ZYDIS_MNEMONIC_OUTSD:
		case ZYDIS_MNEMONIC_OUTSW:
			cpu->jit->outs(&instr);
			break;

		case ZYDIS_MNEMONIC_PAUSE:
			// nothing to do
			break;

		case ZYDIS_MNEMONIC_POP:
			cpu->jit->pop(&instr);
			break;

		case ZYDIS_MNEMONIC_POPA:
		case ZYDIS_MNEMONIC_POPAD:
			cpu->jit->popa(&instr);
			break;

		case ZYDIS_MNEMONIC_POPF:
		case ZYDIS_MNEMONIC_POPFD:
			cpu->jit->popf(&instr);
			break;

		case ZYDIS_MNEMONIC_PUSH:
			cpu->jit->push(&instr);
			break;

		case ZYDIS_MNEMONIC_PUSHA:
		case ZYDIS_MNEMONIC_PUSHAD:
			cpu->jit->pusha(&instr);
			break;

		case ZYDIS_MNEMONIC_PUSHF:
		case ZYDIS_MNEMONIC_PUSHFD:
			cpu->jit->pushf(&instr);
			break;

		case ZYDIS_MNEMONIC_RCL:
			cpu->jit->rcl(&instr);
			break;

		case ZYDIS_MNEMONIC_RCR:
			cpu->jit->rcr(&instr);
			break;

		case ZYDIS_MNEMONIC_RDMSR:
			cpu->jit->rdmsr(&instr);
			break;

		case ZYDIS_MNEMONIC_RDPMC:       BAD;
		case ZYDIS_MNEMONIC_RDTSC:
			cpu->jit->rdtsc(&instr);
			break;

		case ZYDIS_MNEMONIC_RET:
			cpu->jit->ret(&instr);
			break;

		case ZYDIS_MNEMONIC_ROL:
			cpu->jit->rol(&instr);
			break;

		case ZYDIS_MNEMONIC_ROR:
			cpu->jit->ror(&instr);
			break;

		case ZYDIS_MNEMONIC_RSM:         BAD;
		case ZYDIS_MNEMONIC_SAHF:
			cpu->jit->sahf(&instr);
			break;

		case ZYDIS_MNEMONIC_SAR:
			cpu->jit->sar(&instr);
			break;

		case ZYDIS_MNEMONIC_SBB:
			cpu->jit->sbb(&instr);
			break;

		case ZYDIS_MNEMONIC_SCASB:
		case ZYDIS_MNEMONIC_SCASD:
		case ZYDIS_MNEMONIC_SCASW:
			cpu->jit->scas(&instr);
			break;

		case ZYDIS_MNEMONIC_SETB:
		case ZYDIS_MNEMONIC_SETBE:
		case ZYDIS_MNEMONIC_SETL:
		case ZYDIS_MNEMONIC_SETLE:
		case ZYDIS_MNEMONIC_SETNB:
		case ZYDIS_MNEMONIC_SETNBE:
		case ZYDIS_MNEMONIC_SETNL:
		case ZYDIS_MNEMONIC_SETNLE:
		case ZYDIS_MNEMONIC_SETNO:
		case ZYDIS_MNEMONIC_SETNP:
		case ZYDIS_MNEMONIC_SETNS:
		case ZYDIS_MNEMONIC_SETNZ:
		case ZYDIS_MNEMONIC_SETO:
		case ZYDIS_MNEMONIC_SETP:
		case ZYDIS_MNEMONIC_SETS:
		case ZYDIS_MNEMONIC_SETZ:
			cpu->jit->setcc(&instr);
			break;

		case ZYDIS_MNEMONIC_SFENCE:
			// ignored, because we don't reorder instructions
			break;

		case ZYDIS_MNEMONIC_SGDT:
			cpu->jit->sgdt(&instr);
			break;

		case ZYDIS_MNEMONIC_SHL:
			cpu->jit->shl(&instr);
			break;

		case ZYDIS_MNEMONIC_SHLD:
			cpu->jit->shld(&instr);
			break;

		case ZYDIS_MNEMONIC_SHR:
			cpu->jit->shr(&instr);
			break;

		case ZYDIS_MNEMONIC_SHRD:
			cpu->jit->shrd(&instr);
			break;

		case ZYDIS_MNEMONIC_SIDT:
			cpu->jit->sidt(&instr);
			break;

		case ZYDIS_MNEMONIC_SLDT:
			cpu->jit->sldt(&instr);
			break;

		case ZYDIS_MNEMONIC_SMSW:        BAD;
		case ZYDIS_MNEMONIC_STC:
			cpu->jit->stc(&instr);
			break;

		case ZYDIS_MNEMONIC_STD:
			cpu->jit->std(&instr);
			break;

		case ZYDIS_MNEMONIC_STI:
			cpu->jit->sti(&instr);
			break;

		case ZYDIS_MNEMONIC_STOSB:
		case ZYDIS_MNEMONIC_STOSD:
		case ZYDIS_MNEMONIC_STOSW:
			cpu->jit->stos(&instr);
			break;

		case ZYDIS_MNEMONIC_STR:
			cpu->jit->str(&instr);
			break;

		case ZYDIS_MNEMONIC_SUB:
			cpu->jit->sub(&instr);
			break;

		case ZYDIS_MNEMONIC_SYSENTER:    BAD;
		case ZYDIS_MNEMONIC_SYSEXIT:     BAD;
		case ZYDIS_MNEMONIC_TEST:
			cpu->jit->test(&instr);
			break;

		case ZYDIS_MNEMONIC_UD1:         BAD;
		case ZYDIS_MNEMONIC_UD2:         BAD;
		case ZYDIS_MNEMONIC_VERR:
			cpu->jit->verr(&instr);
			break;

		case ZYDIS_MNEMONIC_VERW:
			cpu->jit->verw(&instr);
			break;

		case ZYDIS_MNEMONIC_WBINVD:
			cpu->jit->wbinvd(&instr);
			break;

		case ZYDIS_MNEMONIC_WRMSR:
			cpu->jit->wrmsr(&instr);
			break;

		case ZYDIS_MNEMONIC_XADD:
			cpu->jit->xadd(&instr);
			break;

		case ZYDIS_MNEMONIC_XCHG:
			cpu->jit->xchg(&instr);
			break;

		case ZYDIS_MNEMONIC_XLAT:
			cpu->jit->xlat(&instr);
			break;

		case ZYDIS_MNEMONIC_XOR:
			cpu->jit->xor_(&instr);
			break;

		case ZYDIS_MNEMONIC_XORPS:
			cpu->jit->xorps(&instr);
			break;

		default:
			BAD;
		}

		cpu->virt_pc += cpu->instr_bytes;
		cpu->tc->size += cpu->instr_bytes;

	} while ((cpu->translate_next | (disas_ctx->flags & (DISAS_FLG_PAGE_CROSS | DISAS_FLG_ONE_INSTR | DISAS_FLG_PAGE_CROSS_NEXT))) == 1);
}

uint32_t
cpu_do_int(cpu_ctx_t *cpu_ctx, uint32_t int_flg)
{
	if (int_flg & CPU_ABORT_INT) {
		// this also happens when the user closes the debugger window
		cpu_ctx->cpu->clear_int_fn(cpu_ctx, CPU_ABORT_INT);
		throw lc86_exp_abort("Received abort signal, terminating the emulation", lc86_status::success);
	}

	if (int_flg & CPU_SUSPEND_INT) {
		cpu_ctx->cpu->clear_int_fn(cpu_ctx, CPU_SUSPEND_INT);
		cpu_ctx->cpu->is_suspended.test_and_set();
		if (cpu_ctx->cpu->suspend_should_throw.load() && cpu_ctx->cpu->suspend_flg.test()) {
			throw lc86_exp_abort("Received pause signal, suspending the emulation", lc86_status::paused);
		}
		else {
			cpu_ctx->cpu->suspend_flg.wait(true);
		}
		cpu_ctx->cpu->is_suspended.clear();
		if (cpu_ctx->cpu->state_loaded) {
			cpu_ctx->cpu->state_loaded = false;
			return CPU_NON_HW_INT;
		}
	}

	if (int_flg & (CPU_A20_INT | CPU_REGION_INT)) {
		cpu_t *cpu = cpu_ctx->cpu;
		uint32_t int_clear_flg;
		if (int_flg & CPU_A20_INT) {
			int_clear_flg = CPU_A20_INT;
			cpu->a20_mask = cpu->new_a20;
			tlb_flush(cpu);
			tc_cache_clear(cpu);
			if (int_flg & CPU_REGION_INT) {
				// the a20 interrupt has already flushed the tlb and the code cache, so just update the as object
				int_clear_flg |= CPU_REGION_INT;
				std::for_each(cpu->regions_changed.begin(), cpu->regions_changed.end(), [cpu](auto &pair) {
					if (pair.first) {
						cpu->memory_space_tree->insert(std::move(pair.second));
					}
					else {
						cpu->memory_space_tree->erase(pair.second->start, pair.second->end);
					}
					});
				cpu->regions_changed.clear();
			}
		}
		else {
			int_clear_flg = CPU_REGION_INT;
			std::for_each(cpu->regions_changed.begin(), cpu->regions_changed.end(), [cpu](auto &pair) {
				addr_t start = pair.second->start, end = pair.second->end;
				if (pair.first) {
					cpu->memory_space_tree->insert(std::move(pair.second));
				}
				else {
					cpu->memory_space_tree->erase(start, end);
				}
				// avoid flushing the tlb and subpages for every region, but instead only do it once outside the loop
				tc_should_clear_cache_and_tlb<false>(cpu, start, end);
			});
			tlb_flush(cpu);
			cpu->regions_changed.clear();
		}
		cpu_ctx->cpu->clear_int_fn(cpu_ctx, int_clear_flg);
		return CPU_NON_HW_INT;
	}

	if (((int_flg & CPU_HW_INT) | (cpu_ctx->regs.eflags & IF_MASK) | (cpu_ctx->hflags & HFLG_INHIBIT_INT)) == (IF_MASK | CPU_HW_INT)) {
		cpu_ctx->exp_info.exp_data.fault_addr = 0;
		cpu_ctx->exp_info.exp_data.code = 0;
		cpu_ctx->exp_info.exp_data.idx = cpu_ctx->cpu->get_int_vec();
		cpu_ctx->exp_info.exp_data.eip = cpu_ctx->regs.eip;
		cpu_raise_exception<false, true>(cpu_ctx);
		return CPU_HW_INT;
	}

	return CPU_NO_INT;
}

// forward declare for cpu_main_loop
translated_code_t *tc_run_code(cpu_ctx_t *cpu_ctx, translated_code_t *tc);

template<bool is_tramp>
void cpu_suppress_trampolines(cpu_t *cpu)
{
	if constexpr (is_tramp) {
		// we need to remove the HFLG_TRAMP after we have searched the tc cache, but before executing the guest code, so that successive tc's
		// can still call hooks, if the trampolined function happens to make calls to other hooked functions internally
		cpu->cpu_ctx.hflags &= ~HFLG_TRAMP;
	}
}

template<bool is_tramp, bool is_trap, typename T>
void cpu_main_loop(cpu_t *cpu, T &&lambda)
{
	translated_code_t *prev_tc = nullptr, *ptr_tc = nullptr;
	addr_t virt_pc, pc;

	// main cpu loop
	while (lambda()) {

		retry:
		try {
			virt_pc = get_pc(&cpu->cpu_ctx);
			cpu_check_data_watchpoints(cpu, virt_pc, 1, DR7_TYPE_INSTR, cpu->cpu_ctx.regs.eip);
			pc = get_code_addr(cpu, virt_pc, cpu->cpu_ctx.regs.eip);
		}
		catch (host_exp_t type) {
			assert((type == host_exp_t::pf_exp) || (type == host_exp_t::db_exp));
			cpu_suppress_trampolines<is_tramp>(cpu);

			// this is either a page fault or a debug exception. In both cases, we have to call the exception handler
			retry_exp:
			try {
				// the exception handler always returns nullptr
				prev_tc = cpu_raise_exception(&cpu->cpu_ctx);
			}
			catch (host_exp_t type) {
				assert((type == host_exp_t::pf_exp) || (type == host_exp_t::db_exp));

				// page fault or debug exception while delivering another exception
				goto retry_exp;
			}

			goto retry;
		}

		if constexpr (!is_trap) {
			// if we are executing a trapped instr, we must always emit a new tc to run it and not consider other tc's in the cache. Doing so avoids having to invalidate
			// the tc in the cache that contains the trapped instr
			ptr_tc = tc_cache_search(cpu, pc);
		}

		if (ptr_tc == nullptr) {

			// code block for this pc not present, we need to translate new code
			std::unique_ptr<translated_code_t> tc(new translated_code_t);

			cpu->tc = tc.get();
			cpu->jit->gen_tc_prologue();

			// prepare the disas ctx
			cpu->disas_ctx.flags = ((cpu->cpu_ctx.hflags & HFLG_CS32) >> CS32_SHIFT) |
				((cpu->cpu_ctx.hflags & HFLG_SS32) >> (SS32_SHIFT - 1)) |
				(cpu->cpu_ctx.hflags & HFLG_PE_MODE) |
				((cpu->cpu_ctx.hflags & HFLG_INHIBIT_INT) >> 11) |
				(cpu->cpu_flags & CPU_DISAS_ONE) |
				((cpu->cpu_flags & CPU_SINGLE_STEP) >> 3) |
				((cpu->cpu_ctx.regs.eflags & RF_MASK) >> 9) | // if rf is set, we need to clear it after the first instr executed
				((cpu->cpu_ctx.regs.eflags & TF_MASK) >> 1) | // if tf is set, we need to raise a DB exp after every instruction
				((cpu->cpu_ctx.hflags & HFLG_INHIBIT_INT) >> 7); // if interrupts are inhibited, we need to enable them after the first instr executed
			cpu->disas_ctx.virt_pc = virt_pc;
			cpu->disas_ctx.pc = pc;

			if constexpr (is_trap) {
				// don't take hooks if we are executing a trapped instr. Otherwise, if the trapped instr is also hooked, we will take the hook instead of executing it
				cpu_translate(cpu);
			}
			else {
				const auto it = cpu->hook_map.find(cpu->disas_ctx.virt_pc);
				bool take_hook;
				if constexpr (is_tramp) {
					take_hook = (it != cpu->hook_map.end()) && !(cpu->cpu_ctx.hflags & HFLG_TRAMP);
				}
				else {
					take_hook = it != cpu->hook_map.end();
				}

				if (take_hook) {
					cpu->instr_eip = cpu->disas_ctx.virt_pc - cpu->cpu_ctx.regs.cs_hidden.base;
					cpu->jit->gen_hook(it->second);
				}
				else {
					// start guest code translation
					cpu_translate(cpu);
				}
			}

			cpu->jit->gen_tc_epilogue();

			cpu->tc->pc = pc;
			cpu->tc->virt_pc = virt_pc;
			cpu->tc->cs_base = cpu->cpu_ctx.regs.cs_hidden.base;
			cpu->tc->guest_flags = (cpu->cpu_ctx.hflags & HFLG_CONST) | (cpu->cpu_ctx.regs.eflags & EFLAGS_CONST);
			ptr_tc = cpu->tc;

			if (cpu->disas_ctx.flags & (DISAS_FLG_PAGE_CROSS | DISAS_FLG_ONE_INSTR)) {
				if (cpu->cpu_flags & CPU_FORCE_INSERT) {
					if ((cpu->num_tc) == CODE_CACHE_MAX_SIZE) {
						tc_cache_purge(cpu);
						prev_tc = nullptr;
					}
					cpu->jit->gen_code_block();
					tc_cache_insert(cpu, pc, std::move(tc));

					// if the tc is forcefully inserted, then we can still link it
					tc_link_prev(cpu, prev_tc, ptr_tc);
				}
				else {
					cpu->jit->gen_code_block();
				}

				uint32_t cpu_flags = cpu->cpu_flags;
				cpu_suppress_trampolines<is_tramp>(cpu);
				cpu->cpu_flags &= ~(CPU_DISAS_ONE | CPU_ALLOW_CODE_WRITE | CPU_FORCE_INSERT);
				prev_tc = tc_run_code(&cpu->cpu_ctx, ptr_tc);
				if (!(cpu_flags & CPU_FORCE_INSERT)) {
					cpu->jit->free_code_block(reinterpret_cast<void *>(ptr_tc->jmp_offset[2]));
					prev_tc = nullptr;
				}
				continue;
			}
			else {
				if ((cpu->num_tc) == CODE_CACHE_MAX_SIZE) {
					tc_cache_purge(cpu);
					prev_tc = nullptr;
				}
				cpu->jit->gen_code_block();
				tc_cache_insert(cpu, pc, std::move(tc));
			}
		}

		cpu_suppress_trampolines<is_tramp>(cpu);

		// see if we can link the previous tc with the current one
		tc_link_prev(cpu, prev_tc, ptr_tc);

		prev_tc = tc_run_code(&cpu->cpu_ctx, ptr_tc);
	}
}

translated_code_t *
tc_run_code(cpu_ctx_t *cpu_ctx, translated_code_t *tc)
{
	try {
		// run the translated code
		return tc->ptr_code(cpu_ctx);
	}
	catch (host_exp_t type) {
		switch (type)
		{
		case host_exp_t::pf_exp: {
			// page fault while excecuting the translated code
			retry_exp:
			try {
				// the exception handler always returns nullptr
				return cpu_raise_exception(cpu_ctx);
			}
			catch (host_exp_t type) {
				assert((type == host_exp_t::pf_exp) || (type == host_exp_t::db_exp));

				// page fault or debug exception while delivering another exception
				goto retry_exp;
			}
		}
		break;

		case host_exp_t::db_exp: {
			// debug exception trap (mem/io r/w watch) while executing the translated code.
			// We set CPU_DBG_TRAP, so that we can execute the trapped instruction without triggering again a de exp,
			// and then jump to the debug handler. Note that eip points to the trapped instr, so we can execute it.
			assert(cpu_ctx->exp_info.exp_data.idx == EXP_DB);

			cpu_ctx->cpu->cpu_flags |= CPU_DISAS_ONE;
			cpu_ctx->hflags |= HFLG_DBG_TRAP;
			cpu_ctx->regs.eip = cpu_ctx->exp_info.exp_data.eip;
			// run the main loop only once, since we only execute the trapped instr
			int i = 0;
			cpu_main_loop<false, true>(cpu_ctx->cpu, [&i]() { return i++ == 0; });
			return nullptr;
		}

		case host_exp_t::halt_tc:
			return nullptr;

		default:
			LIB86CPU_ABORT_msg("Unknown host exception in %s", __func__);
		}
	}

	LIB86CPU_ABORT();
}

template<bool run_forever>
lc86_status cpu_start(cpu_t *cpu)
{
	if ((cpu->cpu_flags & CPU_DBG_PRESENT) && cpu->dbg_first_run) [[unlikely]] {
		cpu->dbg_first_run = false;
		std::promise<bool> promise;
		std::future<bool> fut = promise.get_future();
		std::thread(dbg_main_wnd, cpu, std::ref(promise)).detach();
		bool has_err = fut.get();
		if (has_err) {
			// When this fails, last_error is set to a custom message
			return lc86_status::internal_error;
		}
		// wait until the debugger continues execution, so that users have a chance to set breakpoints and/or inspect the guest code
		guest_running.wait(false);
	}

	if (cpu->is_suspended.test()) {
		if (cpu->suspend_flg.test()) {
			return set_last_error(lc86_status::paused);
		}

		// suspend_flg was cleared by cpu_resume, so we can clear is_suspended too
		cpu->is_suspended.clear();
	}

	// NOTE: doesn't place this in cpu_main_loop to prevent the thread id from being overwritten when a trampoline is called
	cpu->cpu_thr_id = std::this_thread::get_id();

	try {
		if constexpr (run_forever) {
			cpu_main_loop<false, false>(cpu, []() { return true; });
		}
		else {
			cpu->cpu_ctx.hflags |= HFLG_TIMEOUT;
			cpu_timer_set_now(cpu);
			cpu->cpu_ctx.exit_requested = 0;
			if (cpu->cpu_ctx.is_halted) {
				// if the cpu was previously halted, then we must keep waiting until the next hw int
				halt_loop(cpu);
				if (cpu->cpu_ctx.is_halted) {
					// if it is still halted, then it must be a timeout
					cpu->cpu_ctx.hflags &= ~HFLG_TIMEOUT;
					return set_last_error(lc86_status::timeout);
				}
			}
			cpu_main_loop<false, false>(cpu, [cpu]() { return !cpu->cpu_ctx.exit_requested; });
			cpu->cpu_ctx.hflags &= ~HFLG_TIMEOUT;
			cpu->cpu_thr_id = std::thread::id();
			return set_last_error(lc86_status::timeout);
		}
	}
	catch (lc86_exp_abort &exp) {
		if (cpu->cpu_flags & CPU_DBG_PRESENT) {
			dbg_should_close();
		}

		cpu->cpu_thr_id = std::thread::id();
		last_error = exp.what();
		return exp.get_code();
	}

	assert(0);

	return set_last_error(lc86_status::internal_error);
}

void
cpu_exec_trampoline(cpu_t *cpu, const uint32_t ret_eip)
{
	// set the trampoline flag, so that we can call the trampoline tc instead of the hook tc
	cpu->cpu_ctx.hflags |= HFLG_TRAMP;
	cpu_main_loop<true, false>(cpu, [cpu, ret_eip]() { return cpu->cpu_ctx.regs.eip != ret_eip; });
}

void
dbg_exec_original_instr(cpu_t *cpu)
{
	cpu->cpu_flags |= CPU_DISAS_ONE;
	// run the main loop only once, since we only execute the original instr that was replaced by int3
	int i = 0;
	cpu_main_loop<false, false>(cpu, [&i]() { return i++ == 0; });
}

template translated_code_t *cpu_raise_exception<0, true>(cpu_ctx_t *cpu_ctx);
template translated_code_t *cpu_raise_exception<1, true>(cpu_ctx_t *cpu_ctx);
template translated_code_t *cpu_raise_exception<2, true>(cpu_ctx_t *cpu_ctx);
template translated_code_t *cpu_raise_exception<3, true>(cpu_ctx_t *cpu_ctx);
template translated_code_t *cpu_raise_exception<0, false>(cpu_ctx_t *cpu_ctx);
template translated_code_t *cpu_raise_exception<1, false>(cpu_ctx_t *cpu_ctx);
template translated_code_t *cpu_raise_exception<2, false>(cpu_ctx_t *cpu_ctx);
template translated_code_t *cpu_raise_exception<3, false>(cpu_ctx_t *cpu_ctx);
template void tc_should_clear_cache_and_tlb<true>(cpu_t *cpu, addr_t start, addr_t end);
template lc86_status cpu_start<true>(cpu_t *cpu);
template lc86_status cpu_start<false>(cpu_t *cpu);
