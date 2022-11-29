/*
 * lib86cpu types
 *
 * ergo720                Copyright (c) 2019
 */

#pragma once

#include "config.h"
#include "platform.h"
#include <stdint.h>
#include "types.h"
#include <string>
#include <vector>
#include <functional>

// lib86cpu error flags
enum class lc86_status : int32_t {
	internal_error = -5,
	no_memory,
	invalid_parameter,
	not_found,
	guest_exp,
	success,
};

enum class log_level {
	debug,
	info,
	warn,
	error,
};

enum class host_exp_t : int {
	pf_exp,
	de_exp,
	cpu_mode_changed,
	halt_tc,
	region_changed,
	a20_changed,
};

using logfn_t = void(*)(log_level, const unsigned, const char *, ...);

#define LC86_SUCCESS(status) (static_cast<lc86_status>(status) == lc86_status::success)

#define CPU_INTEL_SYNTAX        (1 << 1)
#define CPU_DBG_PRESENT         (1 << 11)

// mmio/pmio access handlers
using fp_read8 = uint8_t (*)(addr_t addr, void *opaque);
using fp_read16 = uint16_t(*)(addr_t addr, void *opaque);
using fp_read32 = uint32_t(*)(addr_t addr, void *opaque);
using fp_read64 = uint64_t(*)(addr_t addr, void *opaque);
using fp_write8 = void (*)(addr_t addr, const uint8_t value, void *opaque);
using fp_write16 = void (*)(addr_t addr, const uint16_t value, void *opaque);
using fp_write32 = void (*)(addr_t addr, const uint32_t value, void *opaque);
using fp_write64 = void (*)(addr_t addr, const uint64_t value, void *opaque);

struct io_handlers_t {
	fp_read8 fnr8;
	fp_read16 fnr16;
	fp_read32 fnr32;
	fp_read64 fnr64;
	fp_write8 fnw8;
	fp_write16 fnw16;
	fp_write32 fnw32;
	fp_write64 fnw64;
};

// forward declare
struct cpu_t;

// cpu api
API_FUNC lc86_status cpu_new(size_t ramsize, cpu_t *&out, const char *debuggee = nullptr);
API_FUNC void cpu_free(cpu_t *cpu);
API_FUNC lc86_status cpu_run(cpu_t *cpu);
API_FUNC void cpu_sync_state(cpu_t *cpu);
API_FUNC lc86_status cpu_set_flags(cpu_t *cpu, uint32_t flags);
API_FUNC void cpu_set_a20(cpu_t *cpu, bool closed, bool should_throw = false);

// register api
API_FUNC regs_t *get_regs_ptr(cpu_t *cpu);
API_FUNC uint32_t read_eflags(cpu_t *cpu);
API_FUNC void write_eflags(cpu_t *cpu, uint32_t value, bool reg32 = true);

// memory api
API_FUNC uint8_t *get_ram_ptr(cpu_t *cpu);
API_FUNC uint8_t* get_host_ptr(cpu_t *cpu, addr_t addr);
API_FUNC lc86_status mem_init_region_ram(cpu_t *cpu, addr_t start, size_t size, bool should_throw = false);
API_FUNC lc86_status mem_init_region_io(cpu_t *cpu, addr_t start, size_t size, bool io_space, io_handlers_t handlers, void *opaque, bool should_throw = false);
API_FUNC lc86_status mem_init_region_alias(cpu_t *cpu, addr_t alias_start, addr_t ori_start, size_t ori_size, bool should_throw = false);
API_FUNC lc86_status mem_init_region_rom(cpu_t *cpu, addr_t start, size_t size, uint8_t *buffer, bool should_throw = false);
API_FUNC lc86_status mem_destroy_region(cpu_t *cpu, addr_t start, size_t size, bool io_space, bool should_throw = false);
API_FUNC lc86_status mem_read_block(cpu_t *cpu, addr_t addr, size_t size, uint8_t *out, size_t *actual_size = nullptr);
API_FUNC lc86_status mem_write_block(cpu_t *cpu, addr_t addr, size_t size, const void *buffer, size_t *actual_size = nullptr);
API_FUNC lc86_status mem_fill_block(cpu_t *cpu, addr_t addr, size_t size, int val, size_t *actual_size = nullptr);
API_FUNC uint8_t io_read_8(cpu_t *cpu, port_t port);
API_FUNC uint16_t io_read_16(cpu_t *cpu, port_t port);
API_FUNC uint32_t io_read_32(cpu_t *cpu, port_t port);
API_FUNC void io_write_8(cpu_t *cpu, port_t port, uint8_t value);
API_FUNC void io_write_16(cpu_t *cpu, port_t port, uint16_t value);
API_FUNC void io_write_32(cpu_t *cpu, port_t port, uint32_t value);
API_FUNC void tlb_invalidate(cpu_t *cpu, addr_t addr_start, addr_t addr_end);

// hook api
API_FUNC lc86_status hook_add(cpu_t *cpu, addr_t addr, void *hook_addr);
API_FUNC lc86_status hook_remove(cpu_t *cpu, addr_t addr);
API_FUNC void trampoline_call(cpu_t *cpu, const uint32_t ret_eip);

// logging api
API_FUNC void register_log_func(logfn_t logger);
API_FUNC std::string get_last_error();
