/*
 * common functions used by the library
 *
 * ergo720                Copyright (c) 2020
 */

#include "support.h"
#include "internal.h"
#include "instructions.h"
#include "clock.h"
#include <cstdarg>

// This should be updated whenever cpu members that need to be saved are added/removed
#define SAVE_STATE_ID 1


void
cpu_runtime_abort(const char *msg)
{
	cpu_abort(static_cast<int32_t>(lc86_status::internal_error), msg);
}

void
cpu_abort(int32_t code, const char *msg, ...)
{
	std::va_list args;
	va_start(args, msg);
	int size = std::vsnprintf(nullptr, 0, msg, args);
	std::string str(size + 1, '\0');
	std::vsnprintf(str.data(), str.length(), msg, args);
	va_end(args);
	throw lc86_exp_abort(str, static_cast<lc86_status>(code));
}

void
discard_log(log_level lv, const unsigned count, const char *msg, ...) {}

static std::string_view
lc86status_to_str(lc86_status status)
{
	switch (status)
	{
	case lc86_status::not_supported:
		return "The operation is not supported";

	case lc86_status::timeout:
		return "The operation timed out";

	case lc86_status::paused:
		return "The emulation is suspended";

	case lc86_status::internal_error:
		return "An unspecified error internal to lib86cpu has occurred";

	case lc86_status::no_memory:
		return "The operation failed because of insufficient memory";

	case lc86_status::invalid_parameter:
		return "An invalid parameter was specified";

	case lc86_status::not_found:
		return "The specified object could not be found";

	case lc86_status::guest_exp:
		return "A guest exception was raised by lib86cpu while executing the operation";

	case lc86_status::success:
		return "The operation completed successfully";

	default:
		return "Unknown error code";
	}
}

lc86_status
set_last_error(lc86_status status)
{
	last_error = lc86status_to_str(status);
	return status;
}

uint16_t
default_get_int_vec()
{
	LOG(log_level::warn, "Unexpected hardware interrupt");
	return EXP_INVALID;
}

lc86_status
cpu_save_state(cpu_t *cpu, cpu_save_state_t *cpu_state, ram_save_state_t *ram_state)
{
	cpu_state->id = SAVE_STATE_ID;
	cpu_state->size = sizeof(cpu_save_state_t);
	cpu_state->regs = cpu->cpu_ctx.regs;
	cpu_state->msr = cpu->msr;
	cpu_state->eflags_res = cpu->cpu_ctx.lazy_eflags.result;
	cpu_state->eflags_aux = cpu->cpu_ctx.lazy_eflags.auxbits;
	cpu_state->ftop = cpu->cpu_ctx.fpu_data.ftop;
	cpu_state->fes = cpu->cpu_ctx.fpu_data.fes;
	cpu_state->frp = cpu->cpu_ctx.fpu_data.frp;
	cpu_state->is_halted = cpu->cpu_ctx.is_halted;
	cpu_state->microcode_updated = cpu->microcode_updated;
	cpu_state->hflags = (cpu->cpu_ctx.hflags & HFLG_SAVED_MASK);
	cpu_state->cpu_flags = (cpu->cpu_flags & CPU_SAVED_FLG_MASK);
	cpu_state->a20_mask = cpu->a20_mask;
	uint32_t old_edx = cpu->cpu_ctx.regs.edx;
	uint32_t old_eax = cpu->cpu_ctx.regs.eax;
	cpu_rdtsc_helper(&cpu->cpu_ctx);
	cpu_state->tsc_offset = (static_cast<uint64_t>(cpu->cpu_ctx.regs.edx) << 32) | cpu->cpu_ctx.regs.eax;
	cpu->cpu_ctx.regs.edx = old_edx;
	cpu->cpu_ctx.regs.eax = old_eax;

	ram_state->id = SAVE_STATE_ID;
	ram_state->ram = cpu->ram;

	return lc86_status::success;
}

lc86_status
cpu_load_state(cpu_t *cpu, cpu_save_state_t *cpu_state, ram_save_state_t *ram_state, fp_int int_fn)
{
	if ((cpu_state->id != SAVE_STATE_ID) || (ram_state->id != SAVE_STATE_ID) || (cpu_state->size != sizeof(cpu_save_state_t))) {
		return set_last_error(lc86_status::invalid_parameter);
	}

	cpu->cpu_ctx.regs = cpu_state->regs;
	cpu->msr = cpu_state->msr;
	cpu->cpu_ctx.lazy_eflags.result = cpu_state->eflags_res;
	cpu->cpu_ctx.lazy_eflags.auxbits = cpu_state->eflags_aux;
	cpu->cpu_ctx.fpu_data.ftop = cpu_state->ftop;
	cpu->cpu_ctx.fpu_data.fes = cpu_state->fes;
	cpu->cpu_ctx.fpu_data.frp = cpu_state->frp;
	cpu->cpu_ctx.is_halted = cpu->cpu_ctx.is_halted;
	cpu->microcode_updated = cpu_state->microcode_updated;
	cpu->cpu_ctx.hflags = cpu_state->hflags;
	cpu->cpu_flags = cpu_state->cpu_flags;
	cpu->a20_mask = cpu_state->a20_mask;
	cpu->tsc_clock.offset = cpu_state->tsc_offset;
	cpu->tsc_clock.last_host_ticks = get_current_time();

	cpu->ram = ram_state->ram;

	cpu->get_int_vec = int_fn ? int_fn : default_get_int_vec;
	cpu->clear_int_fn(&cpu->cpu_ctx);
	update_drN_helper(&cpu->cpu_ctx, 0, cpu->cpu_ctx.regs.dr[0]);
	update_drN_helper(&cpu->cpu_ctx, 1, cpu->cpu_ctx.regs.dr[1]);
	update_drN_helper(&cpu->cpu_ctx, 2, cpu->cpu_ctx.regs.dr[2]);
	update_drN_helper(&cpu->cpu_ctx, 3, cpu->cpu_ctx.regs.dr[3]);
	update_drN_helper(&cpu->cpu_ctx, 7, cpu->cpu_ctx.regs.dr[7]);
	tc_cache_clear(cpu);
	tlb_flush(cpu);

	return lc86_status::success;
}
