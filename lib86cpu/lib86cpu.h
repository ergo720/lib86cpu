/*
 * lib86cpu types
 *
 * ergo720                Copyright (c) 2019
 * the libcpu developers  Copyright (c) 2009-2010
 */

#pragma once

#include "config.h"
#include "platform.h"
#include <stdint.h>
#include <forward_list>
#include "types.h"
#include "interval_tree.h"
#include <unordered_set>
#include <string>
#include <any>
#include "expected.hpp"


namespace llvm {
	class LLVMContext;
	class BasicBlock;
	class Function;
	class Module;
	class PointerType;
	class StructType;
	class Value;
	class DataLayout;
	class GlobalVariable;
}

// lib86cpu error flags
enum class lc86_status {
	NO_MEMORY = -5,
	INVALID_PARAMETER,
	ALREADY_EXIST,
	NOT_FOUND,
	PAGE_FAULT,
	SUCCESS,
};

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

enum class call_conv {
	X86_STDCALL,
	X86_FASTCALL,
	X86_CDECL,
};

enum class arg_types {
	I8,
	I16,
	I32,
	I64,
	VOID,
	PTR,
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

#define CPU_FLAG_SWAPMEM        (1 << 0)
#define CPU_INTEL_SYNTAX        (1 << 1)
#define CPU_FLAG_FP80           (1 << 2)
#define CPU_CODEGEN_OPTIMIZE    (1 << 3)
#define CPU_PRINT_IR            (1 << 4)
#define CPU_PRINT_IR_OPTIMIZED  (1 << 5)
#define CPU_IGNORE_TC           (1 << 6)
#define CPU_DISAS_ONE           (1 << 7)
#define CPU_ALLOW_CODE_WRITE    (1 << 8)
#define CPU_FORCE_INSERT        (1 << 9)

#define CPU_INTEL_SYNTAX_SHIFT  1

#define CPU_NUM_REGS 33

#define CODE_CACHE_MAX_SIZE (1 << 15)
#define TLB_MAX_SIZE (1 << 20)

#ifdef DEBUG_LOG
#define LOG(...) do { printf(__VA_ARGS__); } while(0)
#else
#define LOG(...)
#endif

#define LIB86CPU_ABORT() \
do {\
    std::printf("%s:%d: lib86cpu fatal error in function %s\n", __FILE__, __LINE__, __func__);\
    std::exit(1);\
} while (0)

#define LIB86CPU_ABORT_msg(...) \
do {\
    std::printf(__VA_ARGS__);\
    std::exit(1);\
} while (0)

// used to generate the parity table
// borrowed from Bit Twiddling Hacks by Sean Eron Anderson (public domain)
// http://graphics.stanford.edu/~seander/bithacks.html#ParityLookupTable
#define P2(n) n, n ^ 1, n ^ 1, n
#define P4(n) P2(n), P2(n ^ 1), P2(n ^ 1), P2(n)
#define P6(n) P4(n), P4(n ^ 1), P4(n ^ 1), P4(n)
#define GEN_TABLE P6(0), P6(1), P6(1), P6(0)

// mmio/pmio access handlers
typedef uint32_t  (*fp_read)(addr_t addr, size_t size, void *opaque);
typedef void      (*fp_write)(addr_t addr, size_t size, uint32_t value, void *opaque);

// memory region type
enum class mem_type {
	UNMAPPED,
	RAM,
	MMIO,
	PMIO,
	ALIAS,
	ROM,
};

template<typename T>
struct memory_region_t {
	T start;
	T end;
	mem_type type;
	int priority;
	fp_read read_handler;
	fp_write write_handler;
	void *opaque;
	addr_t alias_offset;
	memory_region_t<T> *aliased_region;
	int rom_idx;
	memory_region_t() : start(0), end(0), alias_offset(0), type(mem_type::UNMAPPED), priority(0), read_handler(nullptr), write_handler(nullptr),
		opaque(nullptr), aliased_region(nullptr), rom_idx(-1) {};
};

template<typename T>
struct sort_by_priority
{
	bool operator() (const std::reference_wrapper<std::unique_ptr<memory_region_t<T>>> &lhs, const std::reference_wrapper<std::unique_ptr<memory_region_t<T>>> &rhs) const
	{
		return lhs.get()->priority > rhs.get()->priority;
	}
};

struct exp_data_t {
	uint32_t fault_addr;    // only used during page faults
	uint16_t code;          // error code used by the exception (if any)
	uint16_t idx;           // index number of the exception
	uint32_t eip;           // eip of the instr that generated the exception
};

struct exp_info_t {
	exp_data_t exp_data;
	uint8_t exp_in_flight;  // one when servicing an exception, zero otherwise
};

// forward declare
struct cpu_ctx_t;
using entry_t = translated_code_t *(*)(cpu_ctx_t *cpu_ctx);
using raise_exp_t = translated_code_t *(*)(cpu_ctx_t *cpu_ctx, exp_data_t *exp_data);

struct translated_code_ctx_t {
	addr_t cs_base;
	addr_t pc;
	uint32_t cpu_flags;
	entry_t ptr_code;
	entry_t jmp_offset[3];
	uint32_t flags;
	uint32_t size;
};

struct translated_code_t {
	std::forward_list<translated_code_t *> linked_tc;
	cpu_t *cpu;
	translated_code_ctx_t tc_ctx;
	explicit translated_code_t(cpu_t *cpu) noexcept;
	~translated_code_t();
};

struct disas_ctx_t {
	uint8_t flags;
	addr_t virt_pc, start_pc, pc;
	addr_t instr_page_addr;
#if DEBUG_LOG
	uint8_t instr_bytes[15];
	uint8_t byte_idx;
#endif
};

struct regs_layout_t {
	const unsigned bits_size;
	const unsigned idx;
	const char *name;
};

struct lazy_eflags_t {
	uint32_t result;
	uint32_t auxbits;
	// returns 1 when parity is odd, 0 if even
	uint8_t parity[256] = { GEN_TABLE };
};

// this struct should contain all cpu variables which need to be visible from the llvm generated code
struct cpu_ctx_t {
	cpu_t *cpu;
	regs_t regs;
	lazy_eflags_t lazy_eflags;
	uint32_t hflags;
	uint32_t tlb[TLB_MAX_SIZE];
	uint8_t *ram;
	raise_exp_t exp_fn;
	exp_info_t *ptr_exp_info;
};

// forward declare
class lc86_jit;
struct cpu_t {
	uint32_t cpu_flags;
	const char *cpu_name;
	const regs_layout_t *regs_layout;
	cpu_ctx_t cpu_ctx;
	translated_code_t *tc; // tc for which we are currently generating code
	std::unique_ptr<interval_tree<addr_t, std::unique_ptr<memory_region_t<addr_t>>>> memory_space_tree;
	std::unique_ptr<interval_tree<port_t, std::unique_ptr<memory_region_t<port_t>>>> io_space_tree;
	std::set<std::reference_wrapper<std::unique_ptr<memory_region_t<addr_t>>>, sort_by_priority<addr_t>> memory_out;
	std::set<std::reference_wrapper<std::unique_ptr<memory_region_t<port_t>>>, sort_by_priority<port_t>> io_out;
	std::forward_list<std::shared_ptr<translated_code_t>> code_cache[CODE_CACHE_MAX_SIZE];
	std::unordered_map<uint32_t, std::unordered_set<translated_code_t *>> tc_page_map;
	std::vector<std::pair<std::unique_ptr<uint8_t[]>, int>> vec_rom;
	std::unordered_map<addr_t, std::unique_ptr<hook>> hook_map;
	uint16_t num_tc;
	exp_info_t exp_info;

	// llvm specific variables
	std::unique_ptr<lc86_jit> jit;
	llvm::DataLayout *dl;
	llvm::LLVMContext *ctx;
	llvm::Module *mod;
	llvm::Value *ptr_cpu_ctx;
	llvm::Value *ptr_regs;
	llvm::Value *ptr_eflags;
	llvm::Value *ptr_hflags;
	llvm::Value *ptr_tlb;
	llvm::Value *ptr_ram;
	llvm::Value *ptr_exp_fn;
	llvm::Value *ptr_invtc_fn;
	llvm::Value *instr_eip;
	llvm::BasicBlock *bb; // bb to which we are currently adding llvm instructions
	llvm::Function *ptr_mem_ldfn[7];
	llvm::Function *ptr_mem_stfn[7];
	llvm::GlobalVariable *exp_data;
};

// cpu api
API_FUNC tl::expected<cpu_t *, lc86_status> cpu_new(size_t ramsize);
API_FUNC void cpu_free(cpu_t *cpu);
API_FUNC void cpu_sync_state(cpu_t *cpu);
[[noreturn]] API_FUNC void cpu_run(cpu_t *cpu);

// memory api
API_FUNC lc86_status memory_init_region_ram(cpu_t *cpu, addr_t start, size_t size, int priority);
API_FUNC lc86_status memory_init_region_io(cpu_t *cpu, addr_t start, size_t size, bool io_space, fp_read read_func, fp_write write_func, void *opaque, int priority);
API_FUNC lc86_status memory_init_region_alias(cpu_t *cpu, addr_t alias_start, addr_t ori_start, size_t ori_size, int priority);
API_FUNC lc86_status memory_init_region_rom(cpu_t *cpu, addr_t start, size_t size, uint32_t offset, int priority, const char *rom_path, uint8_t *&out);
API_FUNC lc86_status memory_destroy_region(cpu_t *cpu, addr_t start, size_t size, bool io_space);
API_FUNC tl::expected<uint8_t, lc86_status> mem_read_8(cpu_t *cpu, addr_t addr);
API_FUNC tl::expected<uint16_t, lc86_status> mem_read_16(cpu_t *cpu, addr_t addr);
API_FUNC tl::expected<uint32_t, lc86_status> mem_read_32(cpu_t *cpu, addr_t addr);
API_FUNC tl::expected<uint64_t, lc86_status> mem_read_64(cpu_t *cpu, addr_t addr);
API_FUNC lc86_status mem_write_8(cpu_t *cpu, addr_t addr, uint8_t value);
API_FUNC lc86_status mem_write_16(cpu_t *cpu, addr_t addr, uint16_t value);
API_FUNC lc86_status mem_write_32(cpu_t *cpu, addr_t addr, uint32_t value);
API_FUNC lc86_status mem_write_64(cpu_t *cpu, addr_t addr, uint64_t value);
API_FUNC uint8_t io_read_8(cpu_t *cpu, port_t port);
API_FUNC uint16_t io_read_16(cpu_t *cpu, port_t port);
API_FUNC uint32_t io_read_32(cpu_t *cpu, port_t port);
API_FUNC lc86_status io_write_8(cpu_t *cpu, port_t port, uint8_t value);
API_FUNC lc86_status io_write_16(cpu_t *cpu, port_t port, uint16_t value);
API_FUNC lc86_status io_write_32(cpu_t *cpu, port_t port, uint32_t value);

// hook api
API_FUNC lc86_status hook_add(cpu_t *cpu, addr_t addr, std::unique_ptr<hook> obj);
API_FUNC lc86_status trampoline_call(cpu_t *cpu, addr_t addr, std::any &ret, std::vector<std::any> args);
