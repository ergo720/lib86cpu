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
#include <any>
#include <vector>
#include <functional>

// convenience macros to cast a trampoline argument to the appropriate type
#define ANY_I8s(x) static_cast<uint8_t>(x)
#define ANY_I16s(x) static_cast<uint16_t>(x)
#define ANY_I32s(x) static_cast<uint32_t>(x)
#define ANY_I64s(x) static_cast<uint64_t>(x)
#define ANY_I8r(x) reinterpret_cast<uint8_t>(x)
#define ANY_I16r(x) reinterpret_cast<uint16_t>(x)
#define ANY_I32r(x) reinterpret_cast<uint32_t>(x)
#define ANY_I64r(x) reinterpret_cast<uint64_t>(x)
#define ANY_VEC(...) std::vector<std::any> { __VA_ARGS__ }

// lib86cpu error flags
enum class lc86_status : int32_t {
	internal_error = -6,
	no_memory,
	invalid_parameter,
	already_exist,
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

enum class call_conv {
	x86_stdcall,
	x86_fastcall,
	x86_cdecl,
};

// NOTE: avoid using a VOID type because it's possible that the client includes a header (e.g. Windows.h) which defines a VOID macro and thus will
// conflict with our type
enum class arg_types {
	i8,
	i16,
	i32,
	i64,
	void_,
	ptr,
	ptr2,
};

// forward declare
struct cpu_t;
struct translated_code_t;
using trmp_call_fn_t = void(*)(cpu_t *, std::any &, std::vector<uint32_t *> &);

struct hook_info {
	std::vector<arg_types> args;
	std::string name;
	void *addr;
};

struct hook {
	call_conv d_conv;
	call_conv o_conv;
	hook_info info;
	std::weak_ptr<translated_code_t> hook_tc_flags;
	std::weak_ptr<translated_code_t> trmp_tc_flags;
	std::function<void(cpu_t *, std::vector<std::any> &, uint32_t *)> trmp_fn;
	std::vector<trmp_call_fn_t> trmp_vec;
	uint32_t cdecl_arg_size;
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
API_FUNC lc86_status mem_init_region_rom(cpu_t *cpu, addr_t start, size_t size, uint32_t offset, int priority, const char *rom_path, uint8_t *&out);
API_FUNC lc86_status mem_destroy_region(cpu_t *cpu, addr_t start, size_t size, bool io_space);
API_FUNC lc86_status mem_read_block(cpu_t *cpu, addr_t addr, size_t size, uint8_t *out);
API_FUNC lc86_status mem_write_block(cpu_t *cpu, addr_t addr, size_t size, const void *buffer);
API_FUNC lc86_status mem_fill_block(cpu_t *cpu, addr_t addr, size_t size, int val);
API_FUNC uint8_t io_read_8(cpu_t *cpu, port_t port);
API_FUNC uint16_t io_read_16(cpu_t *cpu, port_t port);
API_FUNC uint32_t io_read_32(cpu_t *cpu, port_t port);
API_FUNC void io_write_8(cpu_t *cpu, port_t port, uint8_t value);
API_FUNC void io_write_16(cpu_t *cpu, port_t port, uint16_t value);
API_FUNC void io_write_32(cpu_t *cpu, port_t port, uint32_t value);
API_FUNC void tlb_invalidate(cpu_t *cpu, addr_t addr_start, addr_t addr_end);

// hook api
API_FUNC lc86_status hook_add(cpu_t *cpu, addr_t addr, std::unique_ptr<hook> obj);
API_FUNC lc86_status trampoline_call(cpu_t *cpu, addr_t addr, std::any &ret, std::vector<std::any> args);

// logging api
API_FUNC void register_log_func(logfn_t logger);
API_FUNC std::string get_last_error();
