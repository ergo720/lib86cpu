/*
 * ergo720                Copyright (c) 2022
 */

#pragma once


enum class brk_t : int {
	breakpoint,
	watchpoint,
};

void read_breakpoints_file(cpu_t *cpu);
void write_breakpoints_file(cpu_t *cpu);
void dbg_update_bp_hook(cpu_ctx_t *cpu_ctx);
void dbg_update_bp_hook(cpu_ctx_t *cpu_ctx, uint32_t old_base);
std::vector<std::pair<addr_t, std::string>> dbg_disas_code_block(cpu_t *cpu, addr_t pc, unsigned instr_num);
void dbg_sw_breakpoint_handler(cpu_ctx_t *cpu_ctx);

inline std::atomic_flag guest_running;
inline std::atomic_uint32_t break_pc;
