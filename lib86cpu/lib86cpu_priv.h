/*
 * private implemnetaion of cpu_t
 *
 * ergo720                Copyright (c) 2020
 */

#pragma once

#include <forward_list>
#include "interval_tree.h"
#include <unordered_set>
#include "lib86cpu.h"

#define CODE_CACHE_MAX_SIZE (1 << 15)
#define TLB_MAX_SIZE (1 << 20)

 // used to generate the parity table
 // borrowed from Bit Twiddling Hacks by Sean Eron Anderson (public domain)
 // http://graphics.stanford.edu/~seander/bithacks.html#ParityLookupTable
#define P2(n) n, n ^ 1, n ^ 1, n
#define P4(n) P2(n), P2(n ^ 1), P2(n ^ 1), P2(n)
#define P6(n) P4(n), P4(n ^ 1), P4(n ^ 1), P4(n)
#define GEN_TABLE P6(0), P6(1), P6(1), P6(0)


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

 // memory region type
enum class mem_type {
	unmapped,
	ram,
	mmio,
	pmio,
	alias,
	rom,
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
	memory_region_t() : start(0), end(0), alias_offset(0), type(mem_type::unmapped), priority(0), read_handler(nullptr), write_handler(nullptr),
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
	uint32_t fault_addr;    // addr that caused the exception
	uint16_t code;          // error code used by the exception (if any)
	uint16_t idx;           // index number of the exception
	uint32_t eip;           // eip of the instr that generated the exception
};

struct exp_info_t {
	exp_data_t exp_data;
	uint8_t exp_in_flight;  // one when servicing an exception, zero otherwise
};

struct cpu_ctx_t;
using entry_t = translated_code_t * (*)(cpu_ctx_t *cpu_ctx);
using raise_exp_t = entry_t;

struct translated_code_t {
	std::forward_list<translated_code_t *> linked_tc;
	cpu_t *cpu;
	addr_t cs_base;
	addr_t pc;
	uint32_t cpu_flags;
	entry_t ptr_code;
	entry_t jmp_offset[3];
	uint32_t flags;
	uint32_t size;
	explicit translated_code_t(cpu_t *cpu) noexcept;
	~translated_code_t();
};

struct disas_ctx_t {
	uint8_t flags;
	addr_t virt_pc, pc;
	size_t instr_buff_size;
	exp_data_t exp_data;
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
	exp_info_t exp_info;
};

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
	struct {
		uint64_t tsc;
		static constexpr uint64_t freq = 733333333;
		uint64_t last_host_ticks;
		uint64_t host_freq;
	} clock;
	struct {
		struct {
			uint64_t base;
			uint64_t mask;
		} phys_var[8];
	} mtrr;

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
	llvm::Value *ptr_abort_fn;
	llvm::Value *instr_eip;
	llvm::BasicBlock *bb; // bb to which we are currently adding llvm instructions
	llvm::Function *ptr_mem_ldfn[7];
	llvm::Function *ptr_mem_stfn[7];
};
