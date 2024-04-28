/*
 * x86 debug breakpoint/watchpoint functions
 *
 * ergo720                Copyright (c) 2021
 */

#include "internal.h"
#include "breakpoint.h"


bool
cpu_check_watchpoint_enabled(cpu_t *cpu, int idx)
{
	// we don't support task switches, so local and global enable flags are the same for now
	return (cpu->cpu_ctx.regs.dr[7] >> (idx * 2)) & 3;
}

int
cpu_get_watchpoint_type(cpu_t *cpu, int idx)
{
	return (cpu->cpu_ctx.regs.dr[7] >> (DR7_TYPE_SHIFT + idx * 4)) & 3;
}

size_t
cpu_get_watchpoint_length(cpu_t *cpu, int idx)
{
	size_t len = ((cpu->cpu_ctx.regs.dr[7] >> (DR7_LEN_SHIFT + idx * 4)) & 3);
	return (len == 2) ? 8 : len + 1;
}

static bool
cpu_check_watchpoint_overlap(cpu_t *cpu, addr_t addr, size_t size, int idx)
{
	size_t watch_len = cpu_get_watchpoint_length(cpu, idx);
	addr_t watch_addr = cpu->cpu_ctx.regs.dr[idx] & ~(watch_len - 1);
	addr_t watch_end = watch_addr + watch_len - 1;
	addr_t end = addr + size - 1;

	return (watch_addr <= end) && (addr <= watch_end);
}

static void
cpu_check_watchpoints(cpu_t *cpu, addr_t addr, int dr_idx, int type, uint32_t eip)
{
	bool match = false;
	int dr7_type = cpu_get_watchpoint_type(cpu, dr_idx);
	if (type == DR7_TYPE_DATA_W) {
		if (((dr7_type == DR7_TYPE_DATA_W) || (dr7_type == DR7_TYPE_DATA_RW)) && !(cpu->cpu_flags & CPU_INHIBIT_DBG_TRAP)) {
			match = true;
		}
	}
	else if (type == DR7_TYPE_INSTR) {
		if (!(cpu->cpu_ctx.regs.eflags & RF_MASK)) {
			match = true;
		}
	}
	else if ((type == dr7_type) && !(cpu->cpu_flags & CPU_INHIBIT_DBG_TRAP)) { // either DR7_TYPE_IO_RW or DR7_TYPE_DATA_RW
		match = true;
	}

	if (match) {
		cpu->cpu_ctx.regs.dr[6] |= (1 << dr_idx);
		cpu->cpu_ctx.exp_info.exp_data.fault_addr = addr;
		cpu->cpu_ctx.exp_info.exp_data.code = 0;
		cpu->cpu_ctx.exp_info.exp_data.idx = EXP_DB;
		cpu->cpu_ctx.exp_info.exp_data.eip = eip;
		throw host_exp_t::db_exp;
	}
}

void
cpu_check_data_watchpoints(cpu_t *cpu, addr_t addr, size_t size, int type, uint32_t eip)
{
	for (const auto &wp : cpu->wp_data) {
		if ((wp.watch_addr <= (addr + size - 1)) && (addr <= wp.watch_end)) [[unlikely]] {
			cpu_check_watchpoints(cpu, addr, wp.dr_idx, type, eip);
		}
	}
}

void
cpu_check_io_watchpoints(cpu_t *cpu, port_t port, size_t size, int type, uint32_t eip)
{
	for (const auto &wp : cpu->wp_io) {
		if ((wp.watch_addr <= (port + size - 1)) && (port <= wp.watch_end)) [[unlikely]] {
			cpu_check_watchpoints(cpu, port, wp.dr_idx, type, eip);
		}
	}
}
