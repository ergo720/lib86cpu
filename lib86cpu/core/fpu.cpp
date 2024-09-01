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

static void
fpu_push(cpu_ctx_t *cpu_ctx)
{
	cpu_ctx->fpu_data.ftop = (cpu_ctx->fpu_data.ftop - 1) & 7;
}

static void
fpu_pop(cpu_ctx_t *cpu_ctx)
{
	cpu_ctx->regs.ftags[cpu_ctx->fpu_data.ftop] = FPU_TAG_EMPTY;
	cpu_ctx->fpu_data.ftop = (cpu_ctx->fpu_data.ftop + 1) & 7;
}

template<bool is_push>
void fpu_update_tag(cpu_ctx_t *cpu_ctx, uint32_t st_num)
{
	uint32_t idx = (st_num + cpu_ctx->fpu_data.ftop) & 7;
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

uint32_t
fpu_is_tag_empty(cpu_ctx_t *cpu_ctx, uint32_t st_num)
{
	return cpu_ctx->regs.ftags[(st_num + cpu_ctx->fpu_data.ftop) & 7] == FPU_TAG_EMPTY;
}

void
fpu_update_ptr(cpu_ctx_t *cpu_ctx, uint64_t instr_info)
{
	cpu_ctx->regs.fcs = cpu_ctx->regs.cs;
	cpu_ctx->regs.fip = cpu_ctx->regs.eip;
	cpu_ctx->regs.fop = ((instr_info >> 48) & 0x7FF);
	if (instr_info & (1ULL << 63)) {
		cpu_ctx->regs.fds = *(uint16_t *)(((instr_info >> 32) & 0xFFFF) + (uint8_t *)cpu_ctx);
		cpu_ctx->regs.fdp = instr_info & 0xFFFFFFFF;
	}
}

void
fpu_stack_fault(cpu_ctx_t *cpu_ctx, uint32_t exception)
{
	assert(exception & FPU_EXP_INVALID);

	exception &= (FPU_EXP_ALL | FPU_FLG_SF | FPU_FLG_C1);
	uint32_t unmasked = (exception & ~cpu_ctx->regs.fctrl) & FPU_EXP_ALL;
	if (unmasked) {
		cpu_ctx->regs.fstatus |= FPU_FLG_ES;
	}

	cpu_ctx->regs.fstatus |= exception;
	if (exception & FPU_FLG_SF) {
		if (!(exception & FPU_FLG_C1)) {
			cpu_ctx->regs.fstatus &= ~FPU_FLG_C1;
		}
	}
}

void
fpu_stack_overflow(cpu_ctx_t *cpu_ctx)
{
	if (cpu_ctx->regs.fctrl & FPU_EXP_INVALID) {
		// masked stack fault response
		fpu_push(cpu_ctx);
		uint32_t idx =  cpu_ctx->fpu_data.ftop;
		cpu_ctx->regs.fr[idx].low = FPU_QNAN_FLOAT80_LOW;
		cpu_ctx->regs.fr[idx].high = FPU_QNAN_FLOAT80_HIGH;
		cpu_ctx->regs.ftags[idx] = FPU_TAG_SPECIAL;
	}

	fpu_stack_fault(cpu_ctx, FPU_STACK_OVERFLOW);
}

void
fpu_stack_underflow(cpu_ctx_t *cpu_ctx, uint32_t st_num, uint32_t should_pop)
{
	if (cpu_ctx->regs.fctrl & FPU_EXP_INVALID) {
		// masked stack fault response
		uint32_t idx = (st_num + cpu_ctx->fpu_data.ftop) & 7;
		cpu_ctx->regs.fr[idx].low = FPU_QNAN_FLOAT80_LOW;
		cpu_ctx->regs.fr[idx].high = FPU_QNAN_FLOAT80_HIGH;
		cpu_ctx->regs.ftags[idx] = FPU_TAG_SPECIAL;
		if (should_pop) {
			fpu_pop(cpu_ctx);
		}
	}

	fpu_stack_fault(cpu_ctx, FPU_STACK_UNDERFLOW);
}

template JIT_API void fpu_update_tag<true>(cpu_ctx_t *cpu_ctx, uint32_t idx);
template JIT_API void fpu_update_tag<false>(cpu_ctx_t *cpu_ctx, uint32_t idx);
