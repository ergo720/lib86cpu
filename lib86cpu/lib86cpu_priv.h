/*
 * private implementation of cpu_t
 *
 * ergo720                Copyright (c) 2020
 */

#pragma once

#include <forward_list>
#include <unordered_set>
#include <bitset>
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
	io_handlers_t handlers;
	void *opaque;
	addr_t alias_offset;
	memory_region_t<T> *aliased_region;
	int rom_idx;
	memory_region_t() : start(0), end(0), alias_offset(0), type(mem_type::unmapped), handlers{},
		opaque(nullptr), aliased_region(nullptr), rom_idx(-1) {};
};

#include "as.h"

// the meaning of this struct depends on whether (1) or not (2) a single region covers an entire page
// 1.ram/unmapped: not used
// 1.rom: holds the phys addr of the page and points to the rom that backs it
// 1.mmio: holds the phys addr of the page and points to the mmio that backs it
// 2: holds the phys addr of the page and points to a PAGE_SIZE array of indices used to find the region addr refers to
struct subpage_t {
	addr_t phys_addr;
	uint16_t *cached_region_idx;
	subpage_t() : phys_addr(0), cached_region_idx(nullptr) {}
	~subpage_t() { delete[] cached_region_idx; }
};

struct exp_data_t {
	uint32_t fault_addr;    // addr that caused the exception
	uint16_t code;          // error code used by the exception (if any)
	uint16_t idx;           // index number of the exception
	uint32_t eip;           // eip to return to after the exception is serviced
};

struct exp_info_t {
	exp_data_t exp_data;
	uint16_t old_exp;       // the exception we were previously servicing
};

struct cpu_ctx_t;
struct translated_code_t;
using entry_t = translated_code_t * (*)(cpu_ctx_t *cpu_ctx);
using raise_int_t = void (*)(cpu_ctx_t *cpu_ctx, uint8_t int_flg);
using iret_t = entry_t; // could just return void

// jmp_offset functions: 0,1 -> used for direct linking (either points to exit or &next_tc), 2 -> exit, 3 -> dbg int, 4 -> hw int
struct translated_code_t {
	std::forward_list<translated_code_t *> linked_tc;
	addr_t cs_base;
	addr_t pc;
	addr_t virt_pc;
	uint32_t cpu_flags;
	entry_t ptr_code;
	entry_t jmp_offset[5];
	uint32_t flags;
	uint32_t size;
	explicit translated_code_t() noexcept;
};

struct disas_ctx_t {
	uint8_t flags;
	addr_t virt_pc, pc;
	size_t instr_buff_size;
	exp_data_t exp_data;
};

// the lazy eflags idea comes from reading these two papers:
// How Bochs Works Under the Hood (2nd edition) http://bochs.sourceforge.net/How%20the%20Bochs%20works%20under%20the%20hood%202nd%20edition.pdf
// A Proposal for Hardware-Assisted Arithmetic Overflow Detection for Array and Bitfield Operations http://www.emulators.com/docs/LazyOverflowDetect_Final.pdf
struct lazy_eflags_t {
	uint32_t result;
	uint32_t auxbits;
	// returns 1 when parity is odd, 0 if even
	uint8_t parity[256] = { GEN_TABLE };
};

// this struct should contain all cpu variables which need to be visible from the jitted code
struct cpu_ctx_t {
	cpu_t *cpu;
	regs_t regs;
	lazy_eflags_t lazy_eflags;
	uint32_t hflags;
	uint32_t tlb[TLB_MAX_SIZE];
	uint8_t *ram;
	exp_info_t exp_info;
	uint8_t int_pending;
};

class lc86_jit;
struct cpu_t {
	uint32_t cpu_flags;
	const char *cpu_name;
	cpu_ctx_t cpu_ctx;
	translated_code_t *tc; // tc for which we are currently generating code
	std::unique_ptr<lc86_jit> jit;
	std::unique_ptr<address_space<addr_t>> memory_space_tree;
	std::unique_ptr<address_space<port_t>> io_space_tree;
	std::list<std::unique_ptr<translated_code_t>> code_cache[CODE_CACHE_MAX_SIZE];
	std::unordered_map<uint32_t, std::unordered_set<translated_code_t *>> tc_page_map;
	std::unordered_map<addr_t, translated_code_t *> ibtc;
	std::unordered_map<addr_t, void *> hook_map;
	std::vector<uint8_t *> vec_rom;
	std::vector<subpage_t> subpages;
	std::vector<const memory_region_t<addr_t> *> cached_regions;
	std::bitset<std::numeric_limits<port_t>::max() + 1> iotable;
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
	raise_int_t int_fn;
	std::string dbg_name;
	addr_t bp_addr;
	addr_t db_addr;
	addr_t instr_eip;
	addr_t virt_pc;
	size_t instr_bytes;
	uint8_t size_mode;
	uint8_t addr_mode;
	uint8_t translate_next;
	uint32_t a20_mask;
};
