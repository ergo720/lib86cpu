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
#include "expected.hpp"

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
	INTERNAL_ERROR = -6,
	NO_MEMORY,
	INVALID_PARAMETER,
	ALREADY_EXIST,
	NOT_FOUND,
	PAGE_FAULT,
	SUCCESS,
};

enum class call_conv {
	X86_STDCALL,
	X86_FASTCALL,
	X86_CDECL,
};

// NOTE: avoid using a VOID type because it's possible that the client includes a header (e.g. Windows.h) which defines a VOID macro and thus will
// conflict with our type
enum class arg_types {
	I8,
	I16,
	I32,
	I64,
	EMPTY,
	PTR,
	PTR2,
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

#define LIB86CPU_CHECK_SUCCESS(status) (static_cast<lc86_status>(status) == lc86_status::SUCCESS)
#define LIB86CPU_EXPECTED(success, fail) try { \
success \
} \
catch (const tl::bad_expected_access<lc86_status> &e) { \
fail \
}

#define CPU_INTEL_SYNTAX        (1 << 1)
#define CPU_CODEGEN_OPTIMIZE    (1 << 3)
#define CPU_PRINT_IR            (1 << 4)
#define CPU_PRINT_IR_OPTIMIZED  (1 << 5)

#define REG_EAX     0
#define REG_ECX     1
#define REG_EDX     2
#define REG_EBX     3
#define REG_ESP     4
#define REG_EBP     5
#define REG_ESI     6
#define REG_EDI     7
#define REG_ES      8
#define REG_CS      9
#define REG_SS      10
#define REG_DS      11
#define REG_FS      12
#define REG_GS      13
#define REG_CR0     14
#define REG_CR1     15
#define REG_CR2     16
#define REG_CR3     17
#define REG_CR4     18
#define REG_DR0     19
#define REG_DR1     20
#define REG_DR2     21
#define REG_DR3     22
#define REG_DR4     23
#define REG_DR5     24
#define REG_DR6     25
#define REG_DR7     26
#define REG_EFLAGS  27
#define REG_EIP     28
#define REG_IDTR    29
#define REG_GDTR    30
#define REG_LDTR    31
#define REG_TR      32

#define REG32       0
#define REG16       1
#define REG8H       2
#define REG8L       3

#define SEG_SEL     0
#define SEG_BASE    1
#define SEG_LIMIT   2
#define SEG_FLG     3

// mmio/pmio access handlers
using fp_read = std::vector<uint8_t> (*)(addr_t addr, size_t size, void *opaque);
using fp_write = void (*)(addr_t addr, size_t size, const void *buffer, void *opaque);

// cpu api
API_FUNC tl::expected<cpu_t *, lc86_status> cpu_new(size_t ramsize);
API_FUNC void cpu_free(cpu_t *cpu);
API_FUNC lc86_status cpu_run(cpu_t *cpu);
API_FUNC void cpu_sync_state(cpu_t *cpu);
API_FUNC lc86_status cpu_set_flags(cpu_t *cpu, uint32_t flags);
API_FUNC std::string cpu_get_exit_str(cpu_t *cpu);
API_FUNC lc86_status read_reg(cpu_t *cpu, uint32_t *value, int reg, int size_or_sel = REG32);
API_FUNC lc86_status write_reg(cpu_t *cpu, uint32_t value, int reg, int size_or_sel = REG32);

// memory api
API_FUNC uint8_t *get_ram_ptr(cpu_t *cpu);
API_FUNC lc86_status mem_init_region_ram(cpu_t *cpu, addr_t start, size_t size, int priority);
API_FUNC lc86_status mem_init_region_io(cpu_t *cpu, addr_t start, size_t size, bool io_space, fp_read read_func, fp_write write_func, void *opaque, int priority);
API_FUNC lc86_status mem_init_region_alias(cpu_t *cpu, addr_t alias_start, addr_t ori_start, size_t ori_size, int priority);
API_FUNC lc86_status mem_init_region_rom(cpu_t *cpu, addr_t start, size_t size, uint32_t offset, int priority, const char *rom_path, uint8_t *&out);
API_FUNC lc86_status mem_destroy_region(cpu_t *cpu, addr_t start, size_t size, bool io_space);
API_FUNC tl::expected<std::vector<uint8_t>, lc86_status> mem_read_block(cpu_t *cpu, addr_t addr, size_t size);
API_FUNC lc86_status mem_write_block(cpu_t *cpu, addr_t addr, size_t size, const void *buffer);
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
