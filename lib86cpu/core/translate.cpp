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

#ifdef XBOX_CPU
#include "ipt.h"
#endif

#define BAD LIB86CPU_ABORT_msg("Encountered unimplemented instruction %s", log_instr(disas_ctx->virt_pc - cpu->instr_bytes, &instr).c_str())

// Make sure we can safely use memset on the register structs
static_assert(std::is_trivially_copyable_v<regs_t>);
static_assert(std::is_trivially_copyable_v<msr_t>);


#ifdef XBOX_CPU
template<typename T>
void memory_region_t<T>::cpu_rom_deinit(uint8_t *rom_ptr, uint8_t *rom_alias_ptr, addr_t start)
{
	if constexpr (std::is_same_v<T, addr_t>) {
		ipt_rom_deinit(rom_ptr, rom_alias_ptr, start);
	}
}

template void memory_region_t<addr_t>::cpu_rom_deinit(uint8_t *rom_ptr, uint8_t *rom_alias_ptr, addr_t start);
template void memory_region_t<port_t>::cpu_rom_deinit(uint8_t *rom_ptr, uint8_t *rom_alias_ptr, addr_t start);
#endif

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
	cpu->cpu_ctx.shadow_mxcsr = cpu->cpu_ctx.regs.mxcsr;
	cpu->cpu_ctx.lazy_eflags.result = 0x100; // make zf=0
	cpu->a20_mask = 0xFFFFFFFF; // gate closed
	cpu->cpu_ctx.exp_info.old_exp = EXP_INVALID;
	cpu->msr.ebl_cr_poweron = 0xC5040000; // system bus frequency = 133 MHz, clock frequency ratio = 5.5, low power mode enabled
	cpu->msr.mcg_cap = (MCG_NUM_BANKS | MCG_CTL_P | MCG_SER_P);
	cpu->msr.mcg_ctl = MCG_CTL_ENABLE;
	for (unsigned i = 0; i < MCG_NUM_BANKS; ++i) {
		cpu->msr.mca_banks[i][MCi_CTL] = MCi_CTL_ENABLE;
	}
	tsc_init(cpu);
	fpu_init(cpu);
	tlb_flush_g(cpu);
	tc_cache_purge(cpu);
}

static std::string
exp_idx_to_str(unsigned idx)
{
	switch (idx)
	{
	case EXP_DE:
		return "DE";

	case EXP_DB:
		return "DB";

	case EXP_NMI:
		return "NMI";

	case EXP_BP:
		return "BP";

	case EXP_OF:
		return "OF";

	case EXP_BR:
		return "BR";

	case EXP_UD:
		return "UD";

	case EXP_NM:
		return "NM";

	case EXP_DF:
		return "DF";

	case EXP_TS:
		return "TS";

	case EXP_NP:
		return "NP";

	case EXP_SS:
		return "SS";

	case EXP_GP:
		return "GP";

	case EXP_PF:
		return "PF";

	case EXP_MF:
		return "MF";

	case EXP_AC:
		return "AC";

	case EXP_MC:
		return "MC";

	case EXP_XF:
		return "XF";

	case EXP_INVALID:
		return "NOTHING";

	default:
		return std::to_string(idx);
	}
}

static void
check_dbl_exp(cpu_ctx_t *cpu_ctx)
{
	uint16_t idx = cpu_ctx->exp_info.exp_data.idx;
	bool old_contributory = cpu_ctx->exp_info.old_exp == 0 || (cpu_ctx->exp_info.old_exp >= 10 && cpu_ctx->exp_info.old_exp <= 13);
	bool curr_contributory = idx == 0 || (idx >= 10 && idx <= 13);

	LOG(log_level::info, "Exception thrown -> old: %s new %s", exp_idx_to_str(cpu_ctx->exp_info.old_exp).c_str(), exp_idx_to_str(idx).c_str());

	if (cpu_ctx->exp_info.old_exp == EXP_DF) {
		throw lc86_exp_abort("The guest has triple faulted, cannot continue", lc86_status::success);
	}

	if ((old_contributory && curr_contributory) || (cpu_ctx->exp_info.old_exp == EXP_PF && (curr_contributory || (idx == EXP_PF)))) {
		cpu_ctx->exp_info.exp_data.code = 0;
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
	// If lib86dbg is present, we will forward to it all debug and breakpoint exceptions and let it handle them
	if (cpu_ctx->cpu->cpu_flags & CPU_DBG_PRESENT) [[unlikely]] {
		uint32_t idx = cpu_ctx->exp_info.exp_data.idx;
		if ((idx == EXP_DB) || (idx == EXP_BP)) {
			dbg_exp_handler(cpu_ctx);
			return nullptr;
		}
	}

	// is_intn -> not a int instruction(0), int3(1), intn(2), into(3), is_hw_int -> hardware interrupt
	if constexpr (!(is_intn) && !(is_hw_int)) {
		check_dbl_exp(cpu_ctx);
	}

	cpu_t *cpu = cpu_ctx->cpu;
	uint32_t fault_addr = cpu_ctx->exp_info.exp_data.fault_addr;
	uint16_t code = cpu_ctx->exp_info.exp_data.code;
	uint32_t idx = cpu_ctx->exp_info.exp_data.idx;
	uint32_t eip = cpu_ctx->regs.eip;
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
			uint16_t offset = mem_read_helper<uint16_t>(cpu_ctx, cpu_ctx->regs.tr_hidden.base + 102, 0);
			uint8_t io_int_table_byte = mem_read_helper<uint8_t>(cpu_ctx, cpu_ctx->regs.tr_hidden.base + offset - 32 + idx / 8, 0);
			if ((io_int_table_byte & (1 << (idx % 8))) == 0) {
				if (iopl < 3) {
					old_eflags = ((old_eflags & VIF_MASK) >> 10) | (old_eflags & ~(IF_MASK | IOPL_MASK)) | IOPL_MASK;
				}
				uint32_t esp = cpu_ctx->regs.esp;
				uint32_t stack_mask = cpu_ctx->hflags & HFLG_SS32 ? 0xFFFFFFFF : 0xFFFF;
				uint32_t stack_base = cpu_ctx->regs.ss_hidden.base;
				esp -= 2;
				mem_write_helper<uint16_t>(cpu_ctx, stack_base + (esp & stack_mask), old_eflags, 0);
				esp -= 2;
				mem_write_helper<uint16_t>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.cs, 0);
				esp -= 2;
				mem_write_helper<uint16_t>(cpu_ctx, stack_base + (esp & stack_mask), eip, 0);
				uint32_t vec_entry = mem_read_helper<uint32_t>(cpu_ctx, idx * 4, 0);
				uint32_t eflags_mask = TF_MASK;
				cpu_ctx->regs.esp = (cpu_ctx->regs.esp & ~stack_mask) | (esp & stack_mask);
				cpu_ctx->regs.cs = vec_entry >> 16;
				cpu_ctx->regs.cs_hidden.base = cpu_ctx->regs.cs << 4;
				cpu_ctx->regs.eip = vec_entry & 0xFFFF;
				if (iopl == 3) {
					eflags_mask |= (IF_MASK | VIF_MASK);
				}
				cpu_ctx->regs.eflags &= ~eflags_mask;
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

		uint64_t desc = mem_read_helper<uint64_t>(cpu_ctx, cpu_ctx->regs.idtr_hidden.base + idx * 8, 2);
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
		if (read_seg_desc_helper(cpu, sel, code_desc_addr, code_desc)) {
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

		set_access_flg_seg_desc_helper(cpu, code_desc, code_desc_addr);

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

				if (read_stack_ptr_from_tss_helper(cpu, dpl, new_esp, new_ss, is_vm86 ? 2 : 0)) {
					cpu_ctx->exp_info.exp_data.code += ext_flg;
					return true;
				}

				if ((new_ss >> 2) == 0) {
					cpu_ctx->exp_info.exp_data.code = ext_flg;
					cpu_ctx->exp_info.exp_data.idx = EXP_TS;
					return true;
				}

				if (read_seg_desc_helper(cpu, new_ss, ss_desc_addr, ss_desc)) {
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

				set_access_flg_seg_desc_helper(cpu, ss_desc, ss_desc_addr);

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
					mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.gs, 2);
					esp -= push_size;
					mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.fs, 2);
					esp -= push_size;
					mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.ds, 2);
					esp -= push_size;
					mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.es, 2);
					esp -= push_size;
					mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.ss, 2);
					esp -= push_size;
					mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.esp, 2);
					esp -= push_size;
					mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), old_eflags, 2);
					esp -= push_size;
					mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.cs, 2);
					esp -= push_size;
					mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), eip, 2);
					if (exp_has_code()) {
						esp -= push_size;
						mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), code, 2);
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
				mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.ss, is_priv);
				esp -= push_size;
				mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.esp, is_priv);
			}
			esp -= push_size;
			mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), old_eflags, is_priv);
			esp -= push_size;
			mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.cs, is_priv);
			esp -= push_size;
			mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), eip, is_priv);
			if (has_code) {
				esp -= push_size;
				mem_write_helper<T>(cpu_ctx, stack_base + (esp & stack_mask), code, is_priv);
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

			uint32_t ss_is_zero = stack_base ? 0 : HFLG_SS_IS_ZERO;
			uint32_t ss_flags = read_seg_desc_flags_helper(cpu, ss_desc);
			cpu_ctx->regs.ss = (new_ss & ~3) | dpl;
			cpu_ctx->regs.ss_hidden.base = stack_base;
			cpu_ctx->regs.ss_hidden.limit = read_seg_desc_limit_helper(cpu, ss_desc);
			cpu_ctx->regs.ss_hidden.flags = ss_flags;
			cpu_ctx->hflags = (((ss_flags & SEG_HIDDEN_DB) >> 19) | ss_is_zero) | (cpu_ctx->hflags & ~(HFLG_SS32 | HFLG_SS_IS_ZERO));
		}
		else {
			if (type) { // push 32, not priv
				push_regs.template operator()<true, false>(cpu_ctx, esp, stack_mask, stack_base, 0);
			}
			else { // push 16, not priv
				push_regs.template operator()<false, false>(cpu_ctx, esp, stack_mask, stack_base, 0);
			}
		}

		uint32_t cs_is_zero = seg_base ? 0 : HFLG_CS_IS_ZERO;
		cpu_ctx->regs.eflags = (eflags & ~(VM_MASK | RF_MASK | NT_MASK | TF_MASK));
		cpu_ctx->regs.esp = (cpu_ctx->regs.esp & ~stack_mask) | (esp & stack_mask);
		cpu_ctx->regs.cs = (sel & ~3) | dpl;
		cpu_ctx->regs.cs_hidden.base = seg_base;
		cpu_ctx->regs.cs_hidden.limit = seg_limit;
		cpu_ctx->regs.cs_hidden.flags = seg_flags;
		cpu_ctx->hflags = (((seg_flags & SEG_HIDDEN_DB) >> 20) | dpl | cs_is_zero) | (cpu_ctx->hflags & ~(HFLG_CS32 | HFLG_CPL | HFLG_CS_IS_ZERO));
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

		uint32_t vec_entry = mem_read_helper<uint32_t>(cpu_ctx, cpu_ctx->regs.idtr_hidden.base + idx * 4, 0);
		uint32_t stack_mask = 0xFFFF;
		uint32_t stack_base = cpu_ctx->regs.ss_hidden.base;
		uint32_t esp = cpu_ctx->regs.esp;
		esp -= 2;
		mem_write_helper<uint16_t>(cpu_ctx, stack_base + (esp & stack_mask), old_eflags, 0);
		esp -= 2;
		mem_write_helper<uint16_t>(cpu_ctx, stack_base + (esp & stack_mask), cpu_ctx->regs.cs, 0);
		esp -= 2;
		mem_write_helper<uint16_t>(cpu_ctx, stack_base + (esp & stack_mask), eip, 0);

		cpu_ctx->regs.eflags &= ~(AC_MASK | RF_MASK | IF_MASK | TF_MASK);
		cpu_ctx->regs.esp = (cpu_ctx->regs.esp & ~stack_mask) | (esp & stack_mask);
		cpu_ctx->regs.cs = vec_entry >> 16;
		cpu_ctx->regs.cs_hidden.base = cpu_ctx->regs.cs << 4;
		cpu_ctx->regs.eip = vec_entry & 0xFFFF;
		uint32_t cs_is_zero = cpu_ctx->regs.cs_hidden.base ? 0 : HFLG_CS_IS_ZERO;
		cpu_ctx->hflags = cs_is_zero | (cpu_ctx->hflags & ~HFLG_CS_IS_ZERO);
	}

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

translated_code_t::translated_code_t() noexcept
{
	size = 0;
	flags = 0;
	ptr_code = nullptr;
}

static inline uint32_t
tc_hash(addr_t pc)
{
	return pc & (CODE_CACHE_MAX_SIZE - 1);
}

void
tc_unlink(cpu_t *cpu, addr_t virt_pc)
{
	if (auto it_map = cpu->jmp_page_map.find(virt_pc >> PAGE_SHIFT); it_map != cpu->jmp_page_map.end()) {
		if (auto it_set = it_map->second.find(virt_pc); it_set != it_map->second.end()) {
			it_map->second.erase(it_set);
			if (it_map->second.empty()) {
				cpu->jmp_page_map.erase(it_map);
			}
			uint32_t idx = virt_pc & JMP_TABLE_MASK;
			jmp_table_elem *jmp_elem_off = (jmp_table_elem *)&cpu->cpu_ctx.jmp_table[idx * JMP_TABLE_ELEMENT_SIZE];
			jmp_elem_off->guest_flags = HFLG_INVALID;
		}
	}
}

void
tc_unlink_page(cpu_t *cpu, addr_t virt_pc)
{
	if (auto it_map = cpu->jmp_page_map.find(virt_pc >> PAGE_SHIFT); it_map != cpu->jmp_page_map.end()) {
		for (auto addr : it_map->second) {
			uint32_t idx = addr & JMP_TABLE_MASK;
			jmp_table_elem *jmp_elem_off = (jmp_table_elem *)&cpu->cpu_ctx.jmp_table[idx * JMP_TABLE_ELEMENT_SIZE];
			jmp_elem_off->guest_flags = HFLG_INVALID;
		}
		cpu->jmp_page_map.erase(it_map);
	}
}

void
tc_unlink_all(cpu_t *cpu)
{
	cpu->jmp_page_map.clear();
	for (unsigned i = 0; i < (sizeof(cpu->cpu_ctx.jmp_table) / JMP_TABLE_ELEMENT_SIZE); ++i) {
		*((uint32_t *)(cpu->cpu_ctx.jmp_table + 8 + i * JMP_TABLE_ELEMENT_SIZE)) = HFLG_INVALID;
	}
}

template<bool remove_hook>
void tc_invalidate(cpu_ctx_t *cpu_ctx, addr_t phys_addr, [[maybe_unused]] uint8_t size)
{
	bool halt_tc = false;

	// find all tc in the page phys_addr belongs to
	auto it_map = cpu_ctx->cpu->tc_page_map.find(phys_addr >> PAGE_SHIFT);
	if (it_map != cpu_ctx->cpu->tc_page_map.end()) {
		auto it_set = it_map->second.begin();
		uint32_t flags = (cpu_ctx->hflags & HFLG_CONST) | (cpu_ctx->regs.eflags & EFLAGS_CONST);
		std::vector<std::unordered_set<translated_code_t *>::iterator> tc_to_delete;
		// iterate over all tc's found in the page
		while (it_set != it_map->second.end()) {
			translated_code_t *tc_in_page = *it_set;
			// only invalidate the tc if phys_addr is included in the translated address range of the tc
			// hook tc have a zero guest code size, so they are unaffected by guest writes and do not need to be considered by tc_invalidate
			bool remove_tc;
			if constexpr (remove_hook) {
				remove_tc = !tc_in_page->size && (tc_in_page->pc == phys_addr);
			}
			else {
				remove_tc = tc_in_page->size && !(std::min(phys_addr + size - 1, tc_in_page->pc + tc_in_page->size - 1) < std::max(phys_addr, tc_in_page->pc));
			}

			if (remove_tc) {
				// unlink this tc from the others
				tc_unlink(cpu_ctx->cpu, tc_in_page->virt_pc);

				// delete the found tc from the code cache
				uint32_t idx = tc_hash(tc_in_page->pc);
				auto it = cpu_ctx->cpu->code_cache[idx].begin();
				while (it != cpu_ctx->cpu->code_cache[idx].end()) {
					if (it->get() == tc_in_page) {
						try {
							if (it->get()->cs_base == cpu_ctx->regs.cs_hidden.base &&
								it->get()->pc == get_code_addr(cpu_ctx->cpu, get_pc(cpu_ctx)) &&
								it->get()->guest_flags == flags) {
								// worst case: the write overlaps with the tc we are currently executing
								halt_tc = true;
							}
						}
						catch (host_exp_t) {
							// the current tc cannot fault
							LIB86CPU_ABORT_msg("%s: unexpected page fault while touching address 0x%08X", __func__, get_pc(cpu_ctx));
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

		// delete the found tc from tc_page_map
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
		cpu_ctx->cpu->raise_int_fn(cpu_ctx, CPU_HALT_TC_INT);
	}
}

template void tc_invalidate<true>(cpu_ctx_t *cpu_ctx, addr_t phys_addr, [[maybe_unused]] uint8_t size);
template void tc_invalidate<false>(cpu_ctx_t *cpu_ctx, addr_t phys_addr, [[maybe_unused]] uint8_t size);

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

void
tc_clear_cache_and_tlb(cpu_t *cpu)
{
	tc_cache_clear(cpu);
	tlb_flush_g(cpu);
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

	// Because all tc have been invalidated, we must unlink them all
	tc_unlink_all(cpu);
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
tc_link_jmp(cpu_t *cpu, translated_code_t *ptr_tc)
{
	uint32_t idx = ptr_tc->virt_pc & JMP_TABLE_MASK;
	jmp_table_elem *jmp_elem_off = (jmp_table_elem *)&cpu->cpu_ctx.jmp_table[idx * JMP_TABLE_ELEMENT_SIZE];

	// If there is an existing entry in the table, we must flush it first before inserting the new entry
	if (!(jmp_elem_off->guest_flags & HFLG_INVALID)) {
		auto it_map = cpu->jmp_page_map.find(jmp_elem_off->virt_pc >> PAGE_SHIFT);
		assert(it_map != cpu->jmp_page_map.end());
		auto it_set = it_map->second.find(jmp_elem_off->virt_pc);
		assert(it_set != it_map->second.end());
		it_map->second.erase(it_set);
		if (it_map->second.empty()) {
			cpu->jmp_page_map.erase(it_map);
		}
	}

	jmp_elem_off->virt_pc = ptr_tc->virt_pc;
	jmp_elem_off->cs_base = ptr_tc->cs_base;
	jmp_elem_off->guest_flags = ptr_tc->guest_flags;
	jmp_elem_off->ptr_code = ptr_tc->ptr_code;
	cpu->jmp_page_map[ptr_tc->virt_pc >> PAGE_SHIFT].insert(ptr_tc->virt_pc);
}

static void
tc_link_prev(cpu_t *cpu, translated_code_t *prev_tc, translated_code_t *ptr_tc)
{
	// see if we can link the previous tc with the current one
	if (prev_tc != nullptr) {
		switch (prev_tc->flags)
		{

		case TC_FLG_JMP:
		case TC_FLG_RET:
			tc_link_jmp(cpu, ptr_tc);
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
		catch ([[maybe_unused]] host_exp_t type) {
			// this happens on instr breakpoints (not int3)
			assert(type == host_exp_t::db_exp);
			cpu->jit->gen_raise_exp_inline(0, 0, EXP_DB);
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
				cpu->jit->gen_raise_exp_inline(0, 0, EXP_UD);
				return;

			case ZYDIS_STATUS_NO_MORE_DATA:
				// buffer < 15 bytes
				cpu->cpu_flags &= ~CPU_DISAS_ONE;
				if (disas_ctx->exp_data.idx == EXP_PF) {
					// buffer size reduced because of page fault on second page
					disas_ctx->flags |= DISAS_FLG_FETCH_FAULT;
					cpu->jit->gen_raise_exp_inline(disas_ctx->exp_data.fault_addr, disas_ctx->exp_data.code, disas_ctx->exp_data.idx);
					return;
				}
				else {
					// buffer size reduced because ram/rom region ended
					LIB86CPU_ABORT_msg("Attempted to execute code outside of ram/rom!");
				}

			case ZYDIS_STATUS_INSTRUCTION_TOO_LONG: {
				// instruction length > 15 bytes
				cpu->cpu_flags &= ~CPU_DISAS_ONE;
				volatile addr_t addr = get_code_addr<true>(cpu, disas_ctx->virt_pc + X86_MAX_INSTR_LENGTH, &disas_ctx->exp_data);
				if (disas_ctx->exp_data.idx == EXP_PF) {
					disas_ctx->flags |= DISAS_FLG_FETCH_FAULT;
					cpu->jit->gen_raise_exp_inline(disas_ctx->exp_data.fault_addr, disas_ctx->exp_data.code, disas_ctx->exp_data.idx);
				}
				else {
					cpu->jit->gen_raise_exp_inline(0, 0, EXP_GP);
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

		case ZYDIS_MNEMONIC_ADDSS:
			cpu->jit->addss(&instr);
			break;

		case ZYDIS_MNEMONIC_ADDPS:
			cpu->jit->addps(&instr);
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

		case ZYDIS_MNEMONIC_CVTTSS2SI:
			cpu->jit->cvttss2si(&instr);
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

		case ZYDIS_MNEMONIC_FADD:
		case ZYDIS_MNEMONIC_FADDP:
		case ZYDIS_MNEMONIC_FIADD:
			cpu->jit->fadd(&instr);
			break;

		case ZYDIS_MNEMONIC_FCHS:
			cpu->jit->fchs(&instr);
			break;

		case ZYDIS_MNEMONIC_FCOM:
		case ZYDIS_MNEMONIC_FCOMP:
		case ZYDIS_MNEMONIC_FCOMPP:
			cpu->jit->fcom(&instr);
			break;

		case ZYDIS_MNEMONIC_FDIV:
		case ZYDIS_MNEMONIC_FDIVP:
		case ZYDIS_MNEMONIC_FIDIV:
			cpu->jit->fdiv(&instr);
			break;

		case ZYDIS_MNEMONIC_FDIVR:
		case ZYDIS_MNEMONIC_FDIVRP:
		case ZYDIS_MNEMONIC_FIDIVR:
			cpu->jit->fdivr(&instr);
			break;

		case ZYDIS_MNEMONIC_FILD:
			cpu->jit->fild(&instr);
			break;

		case ZYDIS_MNEMONIC_FIST:
		case ZYDIS_MNEMONIC_FISTP:
			cpu->jit->fistp(&instr);
			break;

		case ZYDIS_MNEMONIC_FLD:
			cpu->jit->fld(&instr);
			break;

		case ZYDIS_MNEMONIC_FLD1:
			cpu->jit->fld1(&instr);
			break;

		case ZYDIS_MNEMONIC_FLDCW:
			cpu->jit->fldcw(&instr);
			break;

		case ZYDIS_MNEMONIC_FLDL2E:
			cpu->jit->fldl2e(&instr);
			break;

		case ZYDIS_MNEMONIC_FLDL2T:
			cpu->jit->fldl2t(&instr);
			break;

		case ZYDIS_MNEMONIC_FLDLG2:
			cpu->jit->fldlg2(&instr);
			break;

		case ZYDIS_MNEMONIC_FLDLN2:
			cpu->jit->fldln2(&instr);
			break;

		case ZYDIS_MNEMONIC_FLDPI:
			cpu->jit->fldpi(&instr);
			break;

		case ZYDIS_MNEMONIC_FLDZ:
			cpu->jit->fldz(&instr);
			break;

		case ZYDIS_MNEMONIC_FMUL:
		case ZYDIS_MNEMONIC_FMULP:
		case ZYDIS_MNEMONIC_FIMUL:
			cpu->jit->fmul(&instr);
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

		case ZYDIS_MNEMONIC_FPATAN:
			cpu->jit->fpatan(&instr);
			break;

		case ZYDIS_MNEMONIC_FSINCOS:
			cpu->jit->fsincos(&instr);
			break;

		case ZYDIS_MNEMONIC_FST:
		case ZYDIS_MNEMONIC_FSTP:
			cpu->jit->fstp(&instr);
			break;

		case ZYDIS_MNEMONIC_FSUB:
		case ZYDIS_MNEMONIC_FSUBP:
		case ZYDIS_MNEMONIC_FISUB:
			cpu->jit->fsub(&instr);
			break;

		case ZYDIS_MNEMONIC_FSUBR:
		case ZYDIS_MNEMONIC_FSUBRP:
		case ZYDIS_MNEMONIC_FISUBR:
			cpu->jit->fsubr(&instr);
			break;

		case ZYDIS_MNEMONIC_FWAIT:
			cpu->jit->fwait(&instr);
			break;

		case ZYDIS_MNEMONIC_FXCH:
			cpu->jit->fxch(&instr);
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

		case ZYDIS_MNEMONIC_MOVSS:
			cpu->jit->movss(&instr);
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

		case ZYDIS_MNEMONIC_MULSS:
			cpu->jit->mulss(&instr);
			break;

		case ZYDIS_MNEMONIC_MULPS:
			cpu->jit->mulps(&instr);
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

		case ZYDIS_MNEMONIC_RCPPS:
			cpu->jit->rcpps(&instr);
			break;

		case ZYDIS_MNEMONIC_RCPSS:
			cpu->jit->rcpss(&instr);
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

		case ZYDIS_MNEMONIC_RSQRTPS:
			cpu->jit->rsqrtps(&instr);
			break;

		case ZYDIS_MNEMONIC_RSQRTSS:
			cpu->jit->rsqrtss(&instr);
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

		case ZYDIS_MNEMONIC_SHUFPS:
			cpu->jit->shufps(&instr);
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

		// Only generate an interrupt check if the current instruction didn't terminate this tc. Terminating instructions already check for interrupts
		if (cpu->translate_next == 1) {
			cpu->jit->gen_interrupt_check<true>();
		}

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

	if (int_flg & CPU_NON_HW_INT) {
		cpu_t *cpu = cpu_ctx->cpu;
		uint32_t int_clear_flg = CPU_MASKED_INT | CPU_HALT_TC_INT;
		if (int_flg & CPU_DBG_TRAP_INT) {
			int_clear_flg |= CPU_DBG_TRAP_INT;
			if (cpu_ctx->exp_info.exp_data.idx != EXP_DB) {
				// This happens when another exception is generated by the instruction after a debug trap exception was detected by a memory handler. Since the info of the trap
				// was overwritten by the new exception, we forget the trap here
				// FIXME: this is wrong, the Intel docs document the priority among different exceptions/interrupts when they happen simultaneously in the same
				// instruction, and debug traps have higher priority than almost all the others. However, since this feature was never implemented before, it's not
				// a regression for now
				LOG(log_level::warn, "Forgetting debug trap exception");
			}
			else {
				cpu_raise_exception<false, false>(cpu_ctx);
			}
		}

		if (int_flg & CPU_HANDLER_INT) {
			int_clear_flg |= CPU_HANDLER_INT;
			std::for_each(cpu->regions_updated.begin(), cpu->regions_updated.end(), [cpu](const auto &data) {
				if (data.io_space) {
					auto io = const_cast<memory_region_t<port_t> *>(cpu->io_space_tree->search(data.start));
					if (io->type == mem_type::pmio) {
						io->handlers = data.handlers;
						io->opaque = data.opaque;
					}
				}
				else {
					auto mmio = const_cast<memory_region_t<addr_t> *>(cpu->memory_space_tree->search(data.start));
					if (mmio->type == mem_type::mmio) {
						mmio->handlers = data.handlers;
						mmio->opaque = data.opaque;
					}
				}
				});
			cpu->regions_updated.clear();
		}

		if (int_flg & CPU_A20_INT) {
			int_clear_flg |= CPU_A20_INT;
			cpu->a20_mask = cpu->new_a20;
			tc_clear_cache_and_tlb(cpu);
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
		else if (int_flg & CPU_REGION_INT) {
			int_clear_flg |= CPU_REGION_INT;
			std::for_each(cpu->regions_changed.begin(), cpu->regions_changed.end(), [cpu](auto &pair) {
				addr_t start = pair.second->start, end = pair.second->end;
				if (pair.first) {
					cpu->memory_space_tree->insert(std::move(pair.second));
				}
				else {
					cpu->memory_space_tree->erase(start, end);
				}
			});
			tc_clear_cache_and_tlb(cpu);
			cpu->regions_changed.clear();
		}

		if (int_flg & CPU_SUSPEND_INT) {
			int_clear_flg |= CPU_SUSPEND_INT;
			cpu_ctx->cpu->is_suspended.test_and_set();
			if (cpu_ctx->cpu->suspend_should_throw.load() && cpu_ctx->cpu->suspend_flg.test()) {
				cpu_ctx->cpu->clear_int_fn(cpu_ctx, int_clear_flg);
				throw lc86_exp_abort("Received pause signal, suspending the emulation", lc86_status::paused);
			}
			else {
				cpu_ctx->cpu->suspend_flg.wait(true);
			}
			cpu_ctx->cpu->is_suspended.clear();
			if (cpu_ctx->cpu->state_loaded) {
				cpu_ctx->cpu->state_loaded = false;
			}
		}

		cpu_ctx->cpu->clear_int_fn(cpu_ctx, int_clear_flg);
		return CPU_NON_HW_INT;
	}

	if (((int_flg & CPU_HW_INT) | (cpu_ctx->regs.eflags & IF_MASK)) == (IF_MASK | CPU_HW_INT)) {
		cpu_ctx->exp_info.exp_data.fault_addr = 0;
		cpu_ctx->exp_info.exp_data.code = 0;
		cpu_ctx->exp_info.exp_data.idx = cpu_ctx->cpu->int_data.first(cpu_ctx->cpu->int_data.second);
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

template<bool is_tramp, typename T>
void cpu_main_loop(cpu_t *cpu, T &&lambda)
{
	translated_code_t *prev_tc = nullptr, *ptr_tc = nullptr;
	addr_t virt_pc, pc;

	// main cpu loop
	while (lambda()) {

		retry:
		try {
			virt_pc = get_pc(&cpu->cpu_ctx);
			cpu_check_data_watchpoints(cpu, virt_pc, 1, DR7_TYPE_INSTR);
			pc = get_code_addr(cpu, virt_pc);
		}
		catch ([[maybe_unused]] host_exp_t type) {
			assert((type == host_exp_t::pf_exp) || (type == host_exp_t::db_exp));
			cpu_suppress_trampolines<is_tramp>(cpu);

			// this is either a page fault or a debug exception. In both cases, we have to call the exception handler
			retry_exp:
			try {
				// the exception handler always returns nullptr
				prev_tc = cpu_raise_exception(&cpu->cpu_ctx);
			}
			catch ([[maybe_unused]] host_exp_t type) {
				assert((type == host_exp_t::pf_exp) || (type == host_exp_t::db_exp));

				// page fault or debug exception while delivering another exception
				goto retry_exp;
			}

			goto retry;
		}

		ptr_tc = tc_cache_search(cpu, pc);

		if (ptr_tc == nullptr) {

			// code block for this pc not present, we need to translate new code
			std::unique_ptr<translated_code_t> tc(new translated_code_t);

			cpu->tc = tc.get();
			cpu->jit->gen_tc_prologue();

			// prepare the disas ctx
			cpu->disas_ctx.flags = ((cpu->cpu_ctx.hflags & HFLG_CS32) >> CS32_SHIFT) |
				((cpu->cpu_ctx.hflags & HFLG_SS32) >> (SS32_SHIFT - 1)) |
				(cpu->cpu_ctx.hflags & HFLG_PE_MODE) |
				(cpu->cpu_flags & CPU_DISAS_ONE) |
				((cpu->cpu_flags & CPU_SINGLE_STEP) >> 3) |
				((cpu->cpu_ctx.regs.eflags & RF_MASK) >> 9) | // if rf is set, we need to clear it after the first instr executed
				((cpu->cpu_ctx.regs.eflags & TF_MASK) >> 1); // if tf is set, we need to raise a DB exp after every instruction
			cpu->disas_ctx.virt_pc = virt_pc;
			cpu->disas_ctx.pc = pc;

			const auto it = cpu->hook_map.find(cpu->disas_ctx.virt_pc);
			bool take_hook;
			if constexpr (is_tramp) {
				take_hook = (it != cpu->hook_map.end()) && !(cpu->cpu_ctx.hflags & HFLG_TRAMP);
			}
			else {
				take_hook = it != cpu->hook_map.end();
			}

			if (take_hook) {
				cpu->jit->gen_hook(it->second);
			}
			else {
				// start guest code translation
				cpu_translate(cpu);
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
				cpu->cpu_flags &= ~(CPU_DISAS_ONE | CPU_FORCE_INSERT);
				prev_tc = tc_run_code(&cpu->cpu_ctx, ptr_tc);
				if (!(cpu_flags & CPU_FORCE_INSERT)) {
					cpu->jit->free_code_block(reinterpret_cast<void *>(ptr_tc->ptr_exit));
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
#ifdef XBOX_CPU
		return ipt_run_guarded_code(cpu_ctx, tc);
#else
		return tc->ptr_code(cpu_ctx);
#endif
	}
	catch (host_exp_t type) {
		switch (type)
		{
		case host_exp_t::pf_exp: {
			// page fault while executing the translated code
			retry_exp:
			try {
				// the exception handler always returns nullptr
				return cpu_raise_exception(cpu_ctx);
			}
			catch ([[maybe_unused]] host_exp_t type) {
				assert(type == host_exp_t::pf_exp);

				// page fault exception while delivering another exception
				goto retry_exp;
			}
		}
		break;

		case host_exp_t::db_exp:
			// because debug trap exceptions are handled at runtime with the debug interrupt, this cannot happen, so it must be a bug
			LIB86CPU_ABORT_msg("Unexpected debug trap exception while running code");
			break;

		default:
			LIB86CPU_ABORT_msg("Unknown host exception in %s", __func__);
		}
	}

	LIB86CPU_ABORT();
}

template<bool run_forever>
lc86_status cpu_start(cpu_t *cpu)
{
	if ((cpu->cpu_flags & (CPU_DBG_PRESENT | CPU_TIMEOUT)) == CPU_DBG_PRESENT) [[unlikely]] {
		// This check is necessary because the debugger will show disassembled instructions when first run, and HLT is translated differently depending on CPU_TIMEOUT
		if constexpr (run_forever == false) {
			cpu->cpu_flags |= CPU_TIMEOUT;
		}
		std::promise<bool> promise;
		std::future<bool> fut = promise.get_future();
		std::thread(dbg_main_wnd, cpu, std::ref(promise)).detach();
		bool has_err = fut.get();
		if (has_err) {
			return set_last_error(lc86_status::internal_error);
		}
		// wait until the debugger continues execution, so that users have a chance to set breakpoints and/or inspect the guest code
		g_guest_running.wait(false);
	}

	if constexpr (run_forever == false) {
		cpu->cpu_flags |= CPU_TIMEOUT;
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
			cpu_main_loop<false>(cpu, []() { return true; });
		}
		else {
			cpu_timer_set_now(cpu);
			cpu->exit_requested = false;
			if (cpu->is_halted) {
				// if the cpu was previously halted, then we must keep waiting until the next hw int
				hlt_helper<true>(&cpu->cpu_ctx);
				if (cpu->is_halted) {
					// if it is still halted, then it must be a timeout
					return set_last_error(lc86_status::timeout);
				}
			}
			cpu_main_loop<false>(cpu, [cpu]() { return !cpu->exit_requested; });
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
	cpu_main_loop<true>(cpu, [cpu, ret_eip]() { return cpu->cpu_ctx.regs.eip != ret_eip; });
}

void
dbg_exec_original_instr(cpu_t *cpu)
{
	cpu->cpu_flags |= CPU_DISAS_ONE;
	// run the main loop only once, since we only execute the original instr that was replaced by int3
	int i = 0;
	cpu_main_loop<false>(cpu, [&i]() { return i++ == 0; });
}

template JIT_API translated_code_t *cpu_raise_exception<0, true>(cpu_ctx_t *cpu_ctx);
template JIT_API translated_code_t *cpu_raise_exception<1, true>(cpu_ctx_t *cpu_ctx);
template JIT_API translated_code_t *cpu_raise_exception<2, true>(cpu_ctx_t *cpu_ctx);
template JIT_API translated_code_t *cpu_raise_exception<3, true>(cpu_ctx_t *cpu_ctx);
template JIT_API translated_code_t *cpu_raise_exception<0, false>(cpu_ctx_t *cpu_ctx);
template JIT_API translated_code_t *cpu_raise_exception<1, false>(cpu_ctx_t *cpu_ctx);
template JIT_API translated_code_t *cpu_raise_exception<2, false>(cpu_ctx_t *cpu_ctx);
template JIT_API translated_code_t *cpu_raise_exception<3, false>(cpu_ctx_t *cpu_ctx);
template lc86_status cpu_start<true>(cpu_t *cpu);
template lc86_status cpu_start<false>(cpu_t *cpu);
