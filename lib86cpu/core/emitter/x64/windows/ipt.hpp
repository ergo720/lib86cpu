/*
* inline page table declarations
*
* ergo720                Copyright (c) 2024
*/

#include "lib86cpu_priv.h"


inline bool is_multi_nop_supported = false;

void ipt_ram_init(cpu_t *cpu, uint64_t ramsize);
lc86_status ipt_rom_init(cpu_t *cpu, uint64_t romsize, memory_region_t<addr_t> *rom, uint8_t *buffer);
void ipt_ram_deinit(cpu_t *cpu);
void ipt_rom_deinit(uint8_t *rom_ptr, uint8_t *rom_alias_ptr, addr_t start);
translated_code_t *ipt_run_guarded_code(cpu_ctx_t *cpu_ctx, translated_code_t *tc);
void ipt_protect_code_page(cpu_t *cpu, addr_t phys_addr);
void ipt_protect_debug_page(cpu_t *cpu, addr_t addr, addr_t addr_end);
void ipt_flush(cpu_t *cpu);
void ipt_flush(cpu_t *cpu, addr_t virt_addr);
