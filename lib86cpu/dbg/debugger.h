/*
 * ergo720                Copyright (c) 2022
 */

#pragma once

#include <array>


enum class brk_t : int {
	breakpoint,
	watchpoint,
};

void read_setting_files(cpu_t *cpu);
void write_setting_files(cpu_t *cpu);
bool dbg_insert_sw_breakpoint(cpu_t *cpu, addr_t addr);
void dbg_apply_sw_breakpoints(cpu_t *cpu);
void dbg_remove_sw_breakpoints(cpu_t *cpu);
void dbg_update_exp_hook(cpu_ctx_t *cpu_ctx);
void dbg_add_exp_hook(cpu_ctx_t *cpu_ctx);
std::vector<std::pair<addr_t, std::string>> dbg_disas_code_block(cpu_t *cpu, addr_t pc, unsigned instr_num);
void dbg_exp_handler(cpu_ctx_t *cpu_ctx);
void dbg_ram_read(cpu_t *cpu, uint8_t *buff);
void dbg_ram_write(uint8_t *data, size_t off, uint8_t val);

inline cpu_t *g_cpu;
inline bool mem_editor_update = true;
inline std::atomic_flag guest_running;
inline uint32_t break_pc;
inline uint32_t mem_pc;

inline std::unordered_map<addr_t, uint8_t> break_list;
inline std::array<std::pair<addr_t, size_t>, 4> watch_list;

inline int main_wnd_w = 1280;
inline int main_wnd_h = 720;

inline float text_col[3] = { 1.0f, 1.0f, 1.0f }; // default text color: white
inline float break_col[3] = { 1.0f, 0.0f, 0.0f }; // default breakpoint color: red
inline float bk_col[3] = { 0.0f, 0.0f, 0.0f }; // default background color: black
