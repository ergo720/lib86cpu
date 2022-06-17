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
	internal_error = -7,
	no_memory,
	invalid_parameter,
	already_exist,
	not_found,
	guest_exp,
	too_many,
	success,
};

enum class log_level {
	debug,
	info,
	warn,
	error,
};

using logfn_t = void(*)(log_level, const unsigned, const char *, ...);

// argument types used by the host function that hooks a guest function, its return type must be void
enum class arg_types {
	i8,
	i16,
	i32,
	i64,
	ptr,
};

// args_t: argument types of the host function that is called instead of the original guest function
// args_val: values to pass as arguments to the host function, their number must match the number of argument types specified in args_t
// name: the name of the host function to call
// addr: the address of the host function to call
struct hook {
	std::vector<arg_types> args_t;
	std::vector<uint64_t> args_val;
	std::string name;
	void *addr;
};

#define LIB86CPU_CHECK_SUCCESS(status) (static_cast<lc86_status>(status) == lc86_status::success)

#define CPU_INTEL_SYNTAX        (1 << 1)
#define CPU_CODEGEN_OPTIMIZE    (1 << 3)
#define CPU_PRINT_IR            (1 << 4)
#define CPU_PRINT_IR_OPTIMIZED  (1 << 5)
#define CPU_DBG_PRESENT         (1 << 11)

// mmio/pmio access handlers
using fp_read = uint64_t (*)(addr_t addr, size_t size, void *opaque);
using fp_write = void (*)(addr_t addr, size_t size, const uint64_t value, void *opaque);

// forward declare
struct cpu_t;

// cpu api
API_FUNC lc86_status cpu_new(size_t ramsize, cpu_t *&out, const char *debuggee = nullptr);
API_FUNC void cpu_free(cpu_t *cpu);
API_FUNC lc86_status cpu_run(cpu_t *cpu);
API_FUNC void cpu_sync_state(cpu_t *cpu);
API_FUNC lc86_status cpu_set_flags(cpu_t *cpu, uint32_t flags);

// register api
API_FUNC regs_t *get_regs_ptr(cpu_t *cpu);
API_FUNC uint32_t read_eflags(cpu_t *cpu);
API_FUNC void write_eflags(cpu_t *cpu, uint32_t value, bool reg32 = true);

// memory api
API_FUNC uint8_t *get_ram_ptr(cpu_t *cpu);
API_FUNC uint8_t* get_host_ptr(cpu_t *cpu, addr_t addr);
API_FUNC lc86_status mem_init_region_ram(cpu_t *cpu, addr_t start, size_t size, int priority);
API_FUNC lc86_status mem_init_region_io(cpu_t *cpu, addr_t start, size_t size, bool io_space, fp_read read_func, fp_write write_func, void *opaque, int priority);
API_FUNC lc86_status mem_init_region_alias(cpu_t *cpu, addr_t alias_start, addr_t ori_start, size_t ori_size, int priority);
API_FUNC lc86_status mem_init_region_rom(cpu_t *cpu, addr_t start, size_t size, int priority, std::unique_ptr<uint8_t[]> buffer);
API_FUNC lc86_status mem_destroy_region(cpu_t *cpu, addr_t start, size_t size, bool io_space);
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
API_FUNC lc86_status hook_add(cpu_t *cpu, addr_t addr, std::unique_ptr<hook> obj);
API_FUNC lc86_status hook_remove(cpu_t *cpu, addr_t addr);
API_FUNC void trampoline_call(cpu_t *cpu, const uint32_t ret_eip);

// logging api
API_FUNC void register_log_func(logfn_t logger);
API_FUNC std::string get_last_error();
