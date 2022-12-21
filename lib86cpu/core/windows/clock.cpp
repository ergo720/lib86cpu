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
	cpu->tsc_clock.tsc = 0;
}

void
cpu_rdtsc_helper(cpu_ctx_t *cpu_ctx)
{
	LARGE_INTEGER now;
	QueryPerformanceCounter(&now);
	uint64_t elapsed_ns = static_cast<uint64_t>(now.QuadPart) - cpu_ctx->cpu->tsc_clock.last_host_ticks;
	cpu_ctx->cpu->tsc_clock.last_host_ticks = now.QuadPart;
	elapsed_ns *= 1000000000;
	elapsed_ns /= cpu_ctx->cpu->timer.host_freq;
	uint64_t elapsed_ticks = elapsed_ns / 1000000000;
	elapsed_ticks *= cpu_ctx->cpu->tsc_clock.cpu_freq;
	cpu_ctx->cpu->tsc_clock.tsc += elapsed_ticks;
	cpu_ctx->regs.edx = (cpu_ctx->cpu->tsc_clock.tsc >> 32);
	cpu_ctx->regs.eax = cpu_ctx->cpu->tsc_clock.tsc;
}

void
cpu_timer_set_now(cpu_t *cpu)
{
	LARGE_INTEGER now;
	QueryPerformanceCounter(&now);
	cpu->timer.last_time = now.QuadPart;
	cpu->timer.tot_time_us = 0;
}

uint32_t
cpu_timer_helper(cpu_ctx_t *cpu_ctx)
{
	// always check for interrupts first. Otherwise, if the cpu consistently timeouts at every code block, it will never check for interrupts
	if (cpu_do_int(cpu_ctx, cpu_ctx->cpu->read_int_fn(cpu_ctx))) {
		return TIMER_HW_INT;
	}

	LARGE_INTEGER now;
	QueryPerformanceCounter(&now);
	uint64_t elapsed_us = static_cast<uint64_t>(now.QuadPart) - cpu_ctx->cpu->timer.last_time;
	cpu_ctx->cpu->timer.last_time = now.QuadPart;
	elapsed_us *= 1000000;
	elapsed_us /= cpu_ctx->cpu->timer.host_freq;
	cpu_ctx->cpu->timer.tot_time_us += elapsed_us;
	if (cpu_ctx->cpu->timer.tot_time_us > cpu_ctx->cpu->timer.timeout_time) {
		return TIMER_TIMEOUT;
	}

	return TIMER_NO_CHANGE;
}
