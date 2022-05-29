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
std::vector<std::pair<addr_t, std::string>> dbg_disas_code_block(cpu_t *cpu, unsigned instr_num);
