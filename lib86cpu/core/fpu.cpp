/*
 * x87 fpu support
 *
 * ergo720                Copyright (c) 2023
 */

#include "internal.h"


void
fpu_init(cpu_t *cpu)
{
	// other fpu regs are already zeroed out by cpu_reset
	cpu->cpu_ctx.regs.fctrl = 0x40;
	cpu->cpu_ctx.regs.fstatus = 0;
	cpu->cpu_ctx.fpu_data.ftop = 0;
	cpu->cpu_ctx.fpu_data.frp = cpu->cpu_ctx.regs.fctrl | FPU_EXP_ALL;
	for (auto &tag : cpu->cpu_ctx.regs.ftags) {
		tag = FPU_TAG_ZERO;
	}
}

template<bool is_push>
void fpu_update_tag(cpu_ctx_t *cpu_ctx, uint32_t idx)
{
	if constexpr (is_push) {
		uint16_t exp = cpu_ctx->regs.fr[idx].high & 0x7FFF;
		uint64_t mant = cpu_ctx->regs.fr[idx].low;
		if (exp == 0 && mant == 0) { // zero
			cpu_ctx->regs.ftags[idx] = FPU_TAG_ZERO;
		}
		else if ((exp == 0) || // denormal
			(exp == 0x7FFF) || // NaN or infinity
			((mant & (1ULL << 63)) == 0)) { // unnormal
			cpu_ctx->regs.ftags[idx] = FPU_TAG_SPECIAL;
		}
		else { // normal
			cpu_ctx->regs.ftags[idx] = FPU_TAG_VALID;
		}
	}
	else {
		cpu_ctx->regs.ftags[idx] = FPU_TAG_EMPTY;
	}
}

template<bool is_push, fpu_instr_t instr_type>
uint32_t fpu_stack_check(cpu_ctx_t *cpu_ctx, uint32_t *sw, uint80_t *inv_val)
{
	// this function returns the fpu stack top after the push/pop, and the flags of the status word following a stack fault. It also writes
	// an appropriate indefinite value when it detects a masked stack exception
	// NOTE: we only support masked stack exceptions for now

	uint32_t ftop, fstatus = cpu_ctx->regs.fstatus;
	*sw = fstatus;
	bool no_stack_fault;
	if constexpr (is_push) {
		// detect stack overflow
		ftop = cpu_ctx->fpu_data.ftop;
		ftop -= 1;
		ftop &= 7;
		no_stack_fault = cpu_ctx->regs.ftags[ftop] == FPU_TAG_EMPTY;
	}
	else {
		// detect stack underflow
		ftop = cpu_ctx->fpu_data.ftop;
		no_stack_fault = cpu_ctx->regs.ftags[ftop] != FPU_TAG_EMPTY;
		ftop += 1;
		ftop &= 7;
	}

	if (!no_stack_fault) {
		uint16_t fctrl = cpu_ctx->regs.fctrl;
		fctrl &= FPU_EXP_INVALID;
		if ((cpu_ctx->regs.fctrl & FPU_EXP_INVALID) == 0) {
			static const char *abort_msg = "Unmasked fpu stack exception not supported";
			cpu_runtime_abort(abort_msg); // won't return
		}
		// stack fault exception masked, write an indefinite value, so that the fpu instr uses it
		fstatus |= (FPU_FLG_IE | FPU_FLG_SF | (is_push ? (1 << FPU_C1_SHIFT) : (0 << FPU_C1_SHIFT)));
		*sw = fstatus;

		switch (instr_type)
		{
		case fpu_instr_t::integer8:
			inv_val->low = FPU_INTEGER_INDEFINITE8;
			break;

		case fpu_instr_t::integer16:
			inv_val->low = FPU_INTEGER_INDEFINITE16;
			break;

		case fpu_instr_t::integer32:
			inv_val->low = FPU_INTEGER_INDEFINITE32;
			break;

		case fpu_instr_t::integer64:
			inv_val->low = FPU_INTEGER_INDEFINITE64;
			break;

		case fpu_instr_t::float_:
			inv_val->low = FPU_QNAN_FLOAT_INDEFINITE64;
			inv_val->high = FPU_QNAN_FLOAT_INDEFINITE16;
			break;

		case fpu_instr_t::bcd:
			inv_val->low = FPU_BCD_INDEFINITE64;
			inv_val->high = FPU_BCD_INDEFINITE16;
			break;

		default:
			LIB86CPU_ABORT();
		}
	}

	return ftop;
}

template uint32_t fpu_stack_check<true, fpu_instr_t::integer8>(cpu_ctx_t *cpu_ctx, uint32_t *sw, uint80_t *inv_val);
template uint32_t fpu_stack_check<false, fpu_instr_t::integer8>(cpu_ctx_t *cpu_ctx, uint32_t *sw, uint80_t *inv_val);
template uint32_t fpu_stack_check<true, fpu_instr_t::integer16>(cpu_ctx_t *cpu_ctx, uint32_t *sw, uint80_t *inv_val);
template uint32_t fpu_stack_check<false, fpu_instr_t::integer16>(cpu_ctx_t *cpu_ctx, uint32_t *sw, uint80_t *inv_val);
template uint32_t fpu_stack_check<true, fpu_instr_t::integer32>(cpu_ctx_t *cpu_ctx, uint32_t *sw, uint80_t *inv_val);
template uint32_t fpu_stack_check<false, fpu_instr_t::integer32>(cpu_ctx_t *cpu_ctx, uint32_t *sw, uint80_t *inv_val);
template uint32_t fpu_stack_check<true, fpu_instr_t::integer64>(cpu_ctx_t *cpu_ctx, uint32_t *sw, uint80_t *inv_val);
template uint32_t fpu_stack_check<false, fpu_instr_t::integer64>(cpu_ctx_t *cpu_ctx, uint32_t *sw, uint80_t *inv_val);
template uint32_t fpu_stack_check<true, fpu_instr_t::float_>(cpu_ctx_t *cpu_ctx, uint32_t *sw, uint80_t *inv_val);
template uint32_t fpu_stack_check<false, fpu_instr_t::float_>(cpu_ctx_t *cpu_ctx, uint32_t *sw, uint80_t *inv_val);
template uint32_t fpu_stack_check<true, fpu_instr_t::bcd>(cpu_ctx_t *cpu_ctx, uint32_t *sw, uint80_t *inv_val);
template uint32_t fpu_stack_check<false, fpu_instr_t::bcd>(cpu_ctx_t *cpu_ctx, uint32_t *sw, uint80_t *inv_val);
template void fpu_update_tag<true>(cpu_ctx_t *cpu_ctx, uint32_t idx);
template void fpu_update_tag<false>(cpu_ctx_t *cpu_ctx, uint32_t idx);
