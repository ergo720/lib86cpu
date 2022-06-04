/*
 * ergo720                Copyright (c) 2022
 */

#pragma once

#include <array>


enum class brk_t : int {
	breakpoint,
	watchpoint,
};

void read_breakpoints_file(cpu_t *cpu);
void write_breakpoints_file(cpu_t *cpu);
bool dbg_insert_sw_breakpoint(cpu_t *cpu, addr_t addr);
void dbg_apply_sw_breakpoints(cpu_t *cpu);
void dbg_remove_sw_breakpoints(cpu_t *cpu);
void dbg_update_bp_hook(cpu_ctx_t *cpu_ctx);
void dbg_add_bp_hook(cpu_ctx_t *cpu_ctx);
std::vector<std::pair<addr_t, std::string>> dbg_disas_code_block(cpu_t *cpu, addr_t pc, unsigned instr_num);
void dbg_sw_breakpoint_handler(cpu_ctx_t *cpu_ctx);

inline std::atomic_flag guest_running;
inline std::uint32_t break_pc;

inline std::unordered_map<addr_t, uint8_t> break_list;
inline std::array<std::pair<addr_t, size_t>, 4> watch_list;
