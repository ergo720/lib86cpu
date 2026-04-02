/*
 * ergo720                Copyright (c) 2022
 */

#pragma once

#include <array>
#include <optional>


enum class brk_t : int {
	breakpoint,
	step_over,
};

struct brk_info {
	uint8_t original_byte;
	brk_t type;
};

void read_dbg_opt(cpu_t *cpu);
void write_dbg_opt(cpu_t *cpu);
void dbg_setup_sw_breakpoints(cpu_t *cpu);
void dbg_apply_sw_breakpoints(cpu_t *cpu);
void dbg_copy_registers(cpu_t *cpu);
std::optional<uint8_t> dbg_insert_sw_breakpoint(cpu_t *cpu, addr_t addr);
void dbg_remove_sw_breakpoints(cpu_t *cpu);
void dbg_remove_sw_breakpoints(cpu_t *cpu, addr_t addr);
std::vector<std::pair<addr_t, std::string>> dbg_disas_code_block(cpu_t *cpu, addr_t pc, unsigned instr_num);
void dbg_exp_handler(cpu_ctx_t *cpu_ctx);
void dbg_ram_read(cpu_t *cpu, uint8_t *buff);
void dbg_ram_write(uint8_t *data, size_t off, uint8_t val);
void dbg_exec_original_instr(cpu_t *cpu);
void dbg_update_watchpoint(cpu_t *cpu, uint32_t dr_idx, addr_t addr, uint32_t brk_type_rw, uint32_t brk_type_size, bool enable);
void dbg_apply_watchpoints(cpu_t *cpu);

inline cpu_t *g_cpu;
inline bool g_mem_editor_update = true;
inline std::atomic_flag g_guest_running;
inline uint32_t g_break_pc;
inline uint32_t g_mem_pc[4];
inline uint32_t g_mem_active;
inline bool g_step_out_active = false;
inline std::array<char, 9> g_mem_button_text("Memory ");
inline std::map<addr_t, brk_info> g_break_list;

inline int g_main_wnd_w;
inline int g_main_wnd_h;

inline float g_txt_col[3]; // rgb
inline float g_brk_col[3]; // rgb
inline float g_bkg_col[3]; // rgb
inline float g_reg_col[3]; // rgb
