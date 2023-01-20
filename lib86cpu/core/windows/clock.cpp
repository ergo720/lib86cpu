/*
 * cpu tsc clock and host timer
 *
 * ergo720                Copyright (c) 2021
 */

#include "clock.h"
#include "internal.h"
#include "Windows.h"


void
tsc_init(cpu_t *cpu)
{
	LARGE_INTEGER freq, now;
	QueryPerformanceFrequency(&freq);
	cpu->timer.host_freq = freq.QuadPart;
	QueryPerformanceCounter(&now);
	cpu->tsc_clock.last_host_ticks = now.QuadPart;
}

void
cpu_rdtsc_helper(cpu_ctx_t *cpu_ctx)
{
	LARGE_INTEGER now;
	QueryPerformanceCounter(&now);
	uint64_t elapsed_us = static_cast<uint64_t>(now.QuadPart) - cpu_ctx->cpu->tsc_clock.last_host_ticks;
	elapsed_us *= 1000000;
	elapsed_us /= cpu_ctx->cpu->timer.host_freq;
	uint64_t elapsed_ticks = elapsed_us / 1000000;
	elapsed_ticks *= cpu_ctx->cpu->tsc_clock.cpu_freq;
	cpu_ctx->regs.edx = (elapsed_ticks >> 32);
	cpu_ctx->regs.eax = elapsed_ticks;
}

void
cpu_timer_set_now(cpu_t *cpu)
{
	LARGE_INTEGER now;
	QueryPerformanceCounter(&now);
	cpu->timer.last_time = now.QuadPart;
}

uint32_t
cpu_timer_helper(cpu_ctx_t *cpu_ctx)
{
	// always check for interrupts first. Otherwise, if the cpu consistently timeouts at every code block, it will never check for interrupts
	if (uint32_t ret = cpu_do_int(cpu_ctx, cpu_ctx->cpu->read_int_fn(cpu_ctx))) {
		return ret;
	}

	LARGE_INTEGER now;
	QueryPerformanceCounter(&now);
	uint64_t elapsed_us = static_cast<uint64_t>(now.QuadPart) - cpu_ctx->cpu->timer.last_time;
	elapsed_us *= 1000000;
	elapsed_us /= cpu_ctx->cpu->timer.host_freq;
	if (elapsed_us >= cpu_ctx->cpu->timer.timeout_time) {
		return CPU_TIMEOUT_INT;
	}

	return CPU_NO_INT;
}
