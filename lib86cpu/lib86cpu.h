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


namespace llvm {
	class LLVMContext;
	class BasicBlock;
	class Function;
	class Module;
	class PointerType;
	class StructType;
	class Value;
	class DataLayout;
	namespace orc {
		class LLJIT;
	}
}

using namespace llvm;

// lib86cpu error flags
enum lib86cpu_status {
	LIB86CPU_NO_MEMORY = -6,
	LIB86CPU_INVALID_PARAMETER,
	LIB86CPU_LLVM_ERROR,
	LIB86CPU_UNKNOWN_INSTR,
	LIB86CPU_OP_NOT_IMPLEMENTED,
	LIB86CPU_UNREACHABLE,
	LIB86CPU_SUCCESS,
};

#define LIB86CPU_CHECK_SUCCESS(status) (static_cast<lib86cpu_status>(status) == 0)

#define CPU_FLAG_SWAPMEM        (1 << 0)
#define CPU_INTEL_SYNTAX        (1 << 1)
#define CPU_FLAG_FP80           (1 << 2)
#define CPU_CODEGEN_OPTIMIZE    (1 << 3)
#define CPU_PRINT_IR            (1 << 4)
#define CPU_PRINT_IR_OPTIMIZED  (1 << 5)

#define CPU_INTEL_SYNTAX_SHIFT  1

#define CPU_NUM_REGS 30

#define CODE_CACHE_MAX_SIZE (1 << 15)

#ifdef DEBUG_LOG
#define LOG(...) do { printf(__VA_ARGS__); } while(0)
#else
#define LOG(...)
#endif

// used to generate the parity table
#define P2(n) n, n ^ 1, n ^ 1, n
#define P4(n) P2(n), P2(n ^ 1), P2(n ^ 1), P2(n)
#define P6(n) P4(n), P4(n ^ 1), P4(n ^ 1), P4(n)
#define GEN_TABLE P6(0), P6(1), P6(1), P6(0)

// mmio/pmio access handlers
typedef uint32_t  (*fp_read)(addr_t addr, size_t size, void *opaque);
typedef void      (*fp_write)(addr_t addr, size_t size, uint32_t value, void *opaque);

// memory region type
enum mem_type_t {
	MEM_UNMAPPED,
	MEM_RAM,
	MEM_MMIO,
	MEM_PMIO,
	MEM_ALIAS,
};

template<typename T>
struct memory_region_t {
	T start;
	int type;
	int priority;
	fp_read read_handler;
	fp_write write_handler;
	void *opaque;
	addr_t alias_offset;
	memory_region_t<T> *aliased_region;
	memory_region_t() : start(0), alias_offset(0), type(MEM_UNMAPPED), priority(0), read_handler(nullptr), write_handler(nullptr),
		opaque(nullptr), aliased_region(nullptr) {};
};

template<typename T>
struct sort_by_priority
{
	bool operator() (const std::tuple<T, T, const std::unique_ptr<memory_region_t<T>> &> &lhs, const std::tuple<T, T, const std::unique_ptr<memory_region_t<T>> &> &rhs) const
	{
		return std::get<2>(lhs)->priority > std::get<2>(rhs)->priority;
	}
};

struct translated_code_t {
	LLVMContext *ctx;
	Module *mod;
	addr_t cs_base;
	addr_t pc;
	void *ptr_code;
	void *jmp_offset[3];
	size_t jmp_code_size;
	std::vector<addr_t> profiling_vec;
};

struct disas_ctx_t {
	Function *func;
	BasicBlock *bb;
	Value *next_pc;
	uint8_t flags;
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

struct cpu_t {
	uint32_t cpu_flags;
	const char *cpu_name;
	const regs_layout_t *regs_layout;
	regs_t regs;
	lazy_eflags_t lazy_eflags;
	uint8_t *ram;
	std::unique_ptr<interval_tree<addr_t, std::unique_ptr<memory_region_t<addr_t>>>> memory_space_tree;
	std::unique_ptr<interval_tree<io_port_t, std::unique_ptr<memory_region_t<io_port_t>>>> io_space_tree;
	std::set<std::tuple<addr_t, addr_t, const std::unique_ptr<memory_region_t<addr_t>> &>, sort_by_priority<addr_t>> memory_out;
	std::set<std::tuple<io_port_t, io_port_t, const std::unique_ptr<memory_region_t<io_port_t>> &>, sort_by_priority<io_port_t>> io_out;
	std::forward_list<std::unique_ptr<translated_code_t>> code_cache[CODE_CACHE_MAX_SIZE];

	/* llvm specific variables */
	std::unique_ptr<orc::LLJIT> jit;
	DataLayout *dl;
	Value *ptr_cpu;
	Value *ptr_regs;
	Value *ptr_eflags;
	Function *ptr_mem_ldfn[3];
	Function *ptr_mem_stfn[6];
	Function *exp_fn;
	Function *profiling_fn;
};

// cpu api
API_FUNC lib86cpu_status cpu_new(size_t ramsize, cpu_t *&out);
API_FUNC void cpu_free(cpu_t *cpu);
API_FUNC lib86cpu_status cpu_run(cpu_t *cpu);

// memory api
API_FUNC lib86cpu_status memory_init_region_ram(cpu_t *cpu, addr_t start, size_t size, int priority);
API_FUNC lib86cpu_status memory_init_region_io(cpu_t *cpu, addr_t start, size_t size, bool io_space, fp_read read_func, fp_write write_func, void *opaque, int priority);
API_FUNC lib86cpu_status memory_init_region_alias(cpu_t *cpu, addr_t alias_start, addr_t ori_start, size_t ori_size, int priority);
API_FUNC lib86cpu_status memory_destroy_region(cpu_t *cpu, addr_t start, size_t size, bool io_space);
