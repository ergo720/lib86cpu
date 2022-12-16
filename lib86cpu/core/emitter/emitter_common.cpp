/*
 * shared functions among all emitters
 *
 * ergo720                Copyright (c) 2022
 */

#include "emitter_common.h"
#include "instructions.h"
#include "memory.h"
#include "debugger.h"
#include "clock.h"

#define JIT_LOCAL_VARS_STACK_SIZE  0x30 // must be a multiple of 16
#define JIT_REG_ARGS_STACK_SIZE    0x20


// The following calculates how much stack is needed to hold the stack arguments for any callable function from the jitted code. This value is then
// increased of a fixed amount to hold the stack local variables of the main jitted function and the register args of the calles
// NOTE1: the jitted main() and exit() are also called during code linking, but those only use register args
// NOTE2: this assumes the Windows x64 calling convention
constexpr auto all_callable_funcs = std::make_tuple(
	cpu_raise_exception<true, true>,
	cpu_raise_exception<true, false>,
	cpu_raise_exception<false, true>,
	cpu_raise_exception<false, false>,
	cpu_timer_helper<true>,
	cpu_timer_helper<false>,
	cpu_do_int,
	link_indirect_handler,
	mem_read_helper<uint32_t>,
	mem_read_helper<uint16_t>,
	mem_read_helper<uint8_t>,
	mem_write_helper<uint32_t>,
	mem_write_helper<uint16_t>,
	mem_write_helper<uint8_t>,
	io_read_helper<uint32_t>,
	io_read_helper<uint16_t>,
	io_read_helper<uint8_t>,
	io_write_helper<uint32_t>,
	io_write_helper<uint16_t>,
	io_write_helper<uint8_t>,
	ljmp_pe_helper,
	lcall_pe_helper,
	lret_pe_helper<true>,
	lret_pe_helper<false>,
	iret_real_helper,
	lldt_helper,
	ltr_helper,
	verrw_helper<true>,
	verrw_helper<false>,
	update_crN_helper,
	update_drN_helper,
	mov_sel_pe_helper<SS_idx>,
	mov_sel_pe_helper<DS_idx>,
	mov_sel_pe_helper<ES_idx>,
	mov_sel_pe_helper<FS_idx>,
	mov_sel_pe_helper<GS_idx>,
	cpu_rdtsc_helper,
	msr_read_helper,
	msr_write_helper,
	divd_helper,
	divw_helper,
	divb_helper,
	idivd_helper,
	idivw_helper,
	idivb_helper,
	cpuid_helper,
	hlt_helper,
	cpu_runtime_abort,
	dbg_update_exp_hook
);

template<typename R, typename... Args>
consteval std::integral_constant<size_t, sizeof...(Args)>
get_arg_count(R(*f)(Args...))
{
	return std::integral_constant<size_t, sizeof...(Args)>{};
}

template<size_t idx>
consteval size_t
max_stack_required_for_func()
{
	if constexpr (constexpr size_t num_args = decltype(get_arg_count(std::get<idx>(all_callable_funcs)))::value; num_args > 4) {
		return (num_args - 4) * 8;
	}

	return 0;
}

template<size_t idx>
struct max_stack_required
{
	static constexpr size_t stack = std::max(max_stack_required<idx - 1>::stack, max_stack_required_for_func<idx>());
};

template<>
struct max_stack_required<0>
{
	static constexpr size_t stack = max_stack_required_for_func<0>();
};

consteval size_t
get_tot_args_stack_required()
{
	// on WIN64, the stack is 16 byte aligned
	return (max_stack_required<std::tuple_size_v<decltype(all_callable_funcs)> - 1>::stack + 15) & ~15;
}

constexpr size_t local_vars_size = JIT_LOCAL_VARS_STACK_SIZE;
constexpr size_t reg_args_size = JIT_REG_ARGS_STACK_SIZE;
constexpr size_t stack_args_size = get_tot_args_stack_required();
constexpr size_t tot_arg_size = stack_args_size + reg_args_size + local_vars_size;

size_t
get_jit_stack_required()
{
	return tot_arg_size;
}

size_t
get_jit_reg_args_size()
{
	return reg_args_size;
}

size_t
get_jit_stack_args_size()
{
	return stack_args_size;
}

size_t
get_jit_local_vars_size()
{
	return local_vars_size;
}

static const std::unordered_map<ZydisRegister, const std::pair<int, size_t>> zydis_to_reg_offset_table = {
	{ ZYDIS_REGISTER_AL,         { EAX_idx,       CPU_CTX_EAX     }  },
	{ ZYDIS_REGISTER_CL,         { ECX_idx,       CPU_CTX_ECX     }  },
	{ ZYDIS_REGISTER_DL,         { EDX_idx,       CPU_CTX_EDX     }  },
	{ ZYDIS_REGISTER_BL,         { EBX_idx,       CPU_CTX_EBX     }  },
	{ ZYDIS_REGISTER_AH,         { EAX_idx,       CPU_CTX_EAX + 1 }  },
	{ ZYDIS_REGISTER_CH,         { ECX_idx,       CPU_CTX_ECX + 1 }  },
	{ ZYDIS_REGISTER_DH,         { EDX_idx,       CPU_CTX_EDX + 1 }  },
	{ ZYDIS_REGISTER_BH,         { EBX_idx,       CPU_CTX_EBX + 1 }  },
	{ ZYDIS_REGISTER_AX,         { EAX_idx,       CPU_CTX_EAX     }  },
	{ ZYDIS_REGISTER_CX,         { ECX_idx,       CPU_CTX_ECX     }  },
	{ ZYDIS_REGISTER_DX,         { EDX_idx,       CPU_CTX_EDX     }  },
	{ ZYDIS_REGISTER_BX,         { EBX_idx,       CPU_CTX_EBX     }  },
	{ ZYDIS_REGISTER_SP,         { ESP_idx,       CPU_CTX_ESP     }  },
	{ ZYDIS_REGISTER_BP,         { EBP_idx,       CPU_CTX_EBP     }  },
	{ ZYDIS_REGISTER_SI,         { ESI_idx,       CPU_CTX_ESI     }  },
	{ ZYDIS_REGISTER_DI,         { EDI_idx,       CPU_CTX_EDI     }  },
	{ ZYDIS_REGISTER_EAX,        { EAX_idx,       CPU_CTX_EAX     }  },
	{ ZYDIS_REGISTER_ECX,        { ECX_idx,       CPU_CTX_ECX     }  },
	{ ZYDIS_REGISTER_EDX,        { EDX_idx,       CPU_CTX_EDX     }  },
	{ ZYDIS_REGISTER_EBX,        { EBX_idx,       CPU_CTX_EBX     }  },
	{ ZYDIS_REGISTER_ESP,        { ESP_idx,       CPU_CTX_ESP     }  },
	{ ZYDIS_REGISTER_EBP,        { EBP_idx,       CPU_CTX_EBP     }  },
	{ ZYDIS_REGISTER_ESI,        { ESI_idx,       CPU_CTX_ESI     }  },
	{ ZYDIS_REGISTER_EDI,        { EDI_idx,       CPU_CTX_EDI     }  },
	{ ZYDIS_REGISTER_ES,         { ES_idx,        CPU_CTX_ES      }  },
	{ ZYDIS_REGISTER_CS,         { CS_idx,        CPU_CTX_CS      }  },
	{ ZYDIS_REGISTER_SS,         { SS_idx,        CPU_CTX_SS      }  },
	{ ZYDIS_REGISTER_DS,         { DS_idx,        CPU_CTX_DS      }  },
	{ ZYDIS_REGISTER_FS,         { FS_idx,        CPU_CTX_FS      }  },
	{ ZYDIS_REGISTER_GS,         { GS_idx,        CPU_CTX_GS      }  },
	{ ZYDIS_REGISTER_CR0,        { CR0_idx,       CPU_CTX_CR0     }  },
	{ ZYDIS_REGISTER_CR1,        { CR1_idx,       CPU_CTX_CR1     }  },
	{ ZYDIS_REGISTER_CR2,        { CR2_idx,       CPU_CTX_CR2     }  },
	{ ZYDIS_REGISTER_CR3,        { CR3_idx,       CPU_CTX_CR3     }  },
	{ ZYDIS_REGISTER_CR4,        { CR4_idx,       CPU_CTX_CR4     }  },
	{ ZYDIS_REGISTER_DR0,        { DR0_idx,       CPU_CTX_DR0     }  },
	{ ZYDIS_REGISTER_DR1,        { DR1_idx,       CPU_CTX_DR1     }  },
	{ ZYDIS_REGISTER_DR2,        { DR2_idx,       CPU_CTX_DR2     }  },
	{ ZYDIS_REGISTER_DR3,        { DR3_idx,       CPU_CTX_DR3     }  },
	{ ZYDIS_REGISTER_DR4,        { DR4_idx,       CPU_CTX_DR4     }  },
	{ ZYDIS_REGISTER_DR5,        { DR5_idx,       CPU_CTX_DR5     }  },
	{ ZYDIS_REGISTER_DR6,        { DR6_idx,       CPU_CTX_DR6     }  },
	{ ZYDIS_REGISTER_DR7,        { DR7_idx,       CPU_CTX_DR7     }  },
	{ ZYDIS_REGISTER_EFLAGS,     { EFLAGS_idx,    CPU_CTX_EFLAGS  }  },
	{ ZYDIS_REGISTER_EIP,        { EIP_idx,       CPU_CTX_EIP     }  },
	{ ZYDIS_REGISTER_IDTR,       { IDTR_idx,      CPU_CTX_IDTR    }  },
	{ ZYDIS_REGISTER_GDTR,       { GDTR_idx,      CPU_CTX_GDTR    }  },
	{ ZYDIS_REGISTER_LDTR,       { LDTR_idx,      CPU_CTX_LDTR    }  },
	{ ZYDIS_REGISTER_TR,         { TR_idx,        CPU_CTX_TR      }  },
	{ ZYDIS_REGISTER_MM0,        { R0_idx,        CPU_CTX_MM0     }  },
	{ ZYDIS_REGISTER_MM1,        { R1_idx,        CPU_CTX_MM1     }  },
	{ ZYDIS_REGISTER_MM2,        { R2_idx,        CPU_CTX_MM2     }  },
	{ ZYDIS_REGISTER_MM3,        { R3_idx,        CPU_CTX_MM3     }  },
	{ ZYDIS_REGISTER_MM4,        { R4_idx,        CPU_CTX_MM4     }  },
	{ ZYDIS_REGISTER_MM5,        { R5_idx,        CPU_CTX_MM5     }  },
	{ ZYDIS_REGISTER_MM6,        { R6_idx,        CPU_CTX_MM6     }  },
	{ ZYDIS_REGISTER_MM7,        { R7_idx,        CPU_CTX_MM7     }  },
	{ ZYDIS_REGISTER_X87STATUS,  { ST_idx,        CPU_CTX_ST      }  },
	{ ZYDIS_REGISTER_X87TAG,     { TAG_idx,       CPU_CTX_TAG     }  },
};


size_t
get_reg_offset(ZydisRegister reg)
{
	if (auto it = zydis_to_reg_offset_table.find(reg); it != zydis_to_reg_offset_table.end()) {
		return it->second.second;
	}

	LIB86CPU_ABORT_msg("Unhandled register %d in %s", reg, __func__);
}

int
get_reg_idx(ZydisRegister reg)
{
	if (auto it = zydis_to_reg_offset_table.find(reg); it != zydis_to_reg_offset_table.end()) {
		return it->second.first;
	}

	LIB86CPU_ABORT_msg("Unhandled register %d in %s", reg, __func__);
}

const std::pair<int, size_t>
get_reg_pair(ZydisRegister reg)
{
	if (auto it = zydis_to_reg_offset_table.find(reg); it != zydis_to_reg_offset_table.end()) {
		return it->second;
	}

	LIB86CPU_ABORT_msg("Unhandled register %d in %s", reg, __func__);
}

size_t
get_seg_prfx_offset(ZydisDecodedInstruction *instr)
{
	// This is to be used for instructions that have hidden operands, for which zydis does not guarantee
	// their position in the operand array

	if (!(instr->attributes & ZYDIS_ATTRIB_HAS_SEGMENT)) {
		return CPU_CTX_DS;
	}
	else if (instr->attributes & ZYDIS_ATTRIB_HAS_SEGMENT_CS) {
		return CPU_CTX_CS;
	}
	else if (instr->attributes & ZYDIS_ATTRIB_HAS_SEGMENT_SS) {
		return CPU_CTX_SS;
	}
	else if (instr->attributes & ZYDIS_ATTRIB_HAS_SEGMENT_DS) {
		return CPU_CTX_DS;
	}
	else if (instr->attributes & ZYDIS_ATTRIB_HAS_SEGMENT_ES) {
		return CPU_CTX_ES;
	}
	else if (instr->attributes & ZYDIS_ATTRIB_HAS_SEGMENT_FS) {
		return CPU_CTX_FS;
	}
	else if (instr->attributes & ZYDIS_ATTRIB_HAS_SEGMENT_GS) {
		return CPU_CTX_GS;
	}
	else {
		LIB86CPU_ABORT();
	}
}
