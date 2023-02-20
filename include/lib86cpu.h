/*
 * lib86cpu types
 *
 * ergo720                Copyright (c) 2019
 */

#pragma once

#include "types.h"
#include <string>
#include <vector>
#include <functional>

// lib86cpu error flags
enum class lc86_status : int32_t {
	not_supported = -7,
	timeout,
	internal_error,
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

using logfn_t = void(*)(log_level, const unsigned, const char *, ...);
using hook_t = void(*)();

#define LC86_SUCCESS(status) (static_cast<lc86_status>(status) == lc86_status::success)

#define CPU_INTEL_SYNTAX        (1 << 1)   // use intel syntax for instruction decoding
#define CPU_DBG_PRESENT         (1 << 11)  // start with the debugger attached
#define CPU_ABORT_ON_HLT        (1 << 12)  // the HLT instruction will terminate the emulation

// mmio/pmio access handlers
using fp_read8 = uint8_t(*)(addr_t addr, void *opaque);
using fp_read16 = uint16_t(*)(addr_t addr, void *opaque);
using fp_read32 = uint32_t(*)(addr_t addr, void *opaque);
using fp_read64 = uint64_t(*)(addr_t addr, void *opaque);
using fp_write8 = void(*)(addr_t addr, const uint8_t value, void *opaque);
using fp_write16 = void(*)(addr_t addr, const uint16_t value, void *opaque);
using fp_write32 = void(*)(addr_t addr, const uint32_t value, void *opaque);
using fp_write64 = void(*)(addr_t addr, const uint64_t value, void *opaque);

// hw interrupt callback, used to get the interrupt vector
using fp_int = uint16_t(*)();

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
API_FUNC lc86_status cpu_new(uint32_t ramsize, cpu_t *&out, fp_int int_fn = nullptr, const char *debuggee = nullptr);
API_FUNC void cpu_free(cpu_t *cpu);
API_FUNC lc86_status cpu_run(cpu_t *cpu);
API_FUNC lc86_status cpu_run_until(cpu_t *cpu, uint64_t timeout_time);
API_FUNC void cpu_set_timeout(cpu_t *cpu, uint64_t timeout_time);
API_FUNC void cpu_exit(cpu_t *cpu);
API_FUNC void cpu_sync_state(cpu_t *cpu);
API_FUNC lc86_status cpu_set_flags(cpu_t *cpu, uint32_t flags);
API_FUNC void cpu_set_a20(cpu_t *cpu, bool closed, bool should_int = false);
API_FUNC void cpu_raise_hw_int_line(cpu_t *cpu);
API_FUNC void cpu_lower_hw_int_line(cpu_t *cpu);

// register api
API_FUNC regs_t *get_regs_ptr(cpu_t *cpu);
API_FUNC uint32_t read_eflags(cpu_t *cpu);
API_FUNC void write_eflags(cpu_t *cpu, uint32_t value, bool reg32 = true);
API_FUNC uint16_t read_ftags(cpu_t *cpu);
API_FUNC void write_ftags(cpu_t *cpu, uint16_t value);
API_FUNC uint16_t read_fstatus(cpu_t *cpu);
API_FUNC void write_fstatus(cpu_t *cpu, uint16_t value);

// memory api
API_FUNC uint8_t *get_ram_ptr(cpu_t *cpu);
API_FUNC uint8_t* get_host_ptr(cpu_t *cpu, addr_t addr);
API_FUNC lc86_status mem_init_region_ram(cpu_t *cpu, addr_t start, uint32_t size, bool should_int = false);
API_FUNC lc86_status mem_init_region_io(cpu_t *cpu, addr_t start, uint32_t size, bool io_space, io_handlers_t handlers, void *opaque, bool should_int = false);
API_FUNC lc86_status mem_init_region_alias(cpu_t *cpu, addr_t alias_start, addr_t ori_start, uint32_t ori_size, bool should_int = false);
API_FUNC lc86_status mem_init_region_rom(cpu_t *cpu, addr_t start, uint32_t size, uint8_t *buffer, bool should_int = false);
API_FUNC lc86_status mem_destroy_region(cpu_t *cpu, addr_t start, uint32_t size, bool io_space, bool should_int = false);
API_FUNC lc86_status mem_read_block_virt(cpu_t *cpu, addr_t addr, uint32_t size, uint8_t *out, uint32_t *actual_size = nullptr);
API_FUNC lc86_status mem_read_block_phys(cpu_t *cpu, addr_t addr, uint32_t size, uint8_t *out, uint32_t *actual_size = nullptr);
API_FUNC lc86_status mem_write_block_virt(cpu_t *cpu, addr_t addr, uint32_t size, const void *buffer, uint32_t *actual_size = nullptr);
API_FUNC lc86_status mem_write_block_phys(cpu_t *cpu, addr_t addr, uint32_t size, const void *buffer, uint32_t *actual_size = nullptr);
API_FUNC lc86_status mem_fill_block_virt(cpu_t *cpu, addr_t addr, uint32_t size, int val, uint32_t *actual_size = nullptr);
API_FUNC lc86_status mem_fill_block_phys(cpu_t *cpu, addr_t addr, uint32_t size, int val, uint32_t *actual_size = nullptr);
API_FUNC lc86_status io_read_8(cpu_t *cpu, port_t port, uint8_t &out);
API_FUNC lc86_status io_read_16(cpu_t *cpu, port_t port, uint16_t &out);
API_FUNC lc86_status io_read_32(cpu_t *cpu, port_t port, uint32_t &out);
API_FUNC lc86_status io_write_8(cpu_t *cpu, port_t port, uint8_t value);
API_FUNC lc86_status io_write_16(cpu_t *cpu, port_t port, uint16_t value);
API_FUNC lc86_status io_write_32(cpu_t *cpu, port_t port, uint32_t value);
API_FUNC void tlb_invalidate(cpu_t *cpu, addr_t addr);

// hook api
API_FUNC lc86_status hook_add(cpu_t *cpu, addr_t addr, hook_t hook_addr);
API_FUNC lc86_status hook_remove(cpu_t *cpu, addr_t addr);
API_FUNC void trampoline_call(cpu_t *cpu, const uint32_t ret_eip);

// logging api
API_FUNC void register_log_func(logfn_t logger);
API_FUNC std::string get_last_error();
