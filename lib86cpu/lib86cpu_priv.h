/*
 * private implementation of cpu_t
 *
 * ergo720                Copyright (c) 2020
 */

#pragma once

#include <forward_list>
#include <unordered_set>
#include <bitset>
#include <random>
#include <memory>
#include <list>
#include <cinttypes>
#include "lib86cpu.h"

#ifdef LIB86CPU_X64_EMITTER
#ifdef _MSC_VER
#  define MS_ABI /* Nothing */
#else
#  define MS_ABI __attribute__((__ms_abi__))
#endif
#  define JIT_API MS_ABI
#endif


#define CODE_CACHE_MAX_SIZE (1 << 15)
#define SMC_MAX_SIZE (1 << 20)
// itlb: 512 sets * 8 lines = 4096 entries -> offset 12 bits, index 9 bites, tag 11 bits
#define ITLB_NUM_SETS (1 << 9)
#define ITLB_NUM_LINES (1 << 3)
// dtlb: 2048 sets * 4 lines = 8192 entries -> offset 12 bits, index 11 bits, tag 9 bits
#define DTLB_NUM_SETS (1 << 11)
#define DTLB_NUM_LINES (1 << 2)

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

enum class host_exp_t : int {
	pf_exp,
	db_exp,
	halt_tc,
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
	uint8_t *rom_ptr;
	addr_t buff_off_start;
	memory_region_t() : start(0), end(0), alias_offset(0), buff_off_start(0), type(mem_type::unmapped), handlers{},
		opaque(nullptr), aliased_region(nullptr), rom_ptr(nullptr) {};
	memory_region_t(T s, T e) : memory_region_t() { start = buff_off_start = s; end = e; }
};

#include "as.h"

struct tlb_t {
	uint64_t entry;
	memory_region_t<addr_t> *region;
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
using entry_t = translated_code_t *(JIT_API *)(cpu_ctx_t *cpu_ctx);
using read_int_t = uint32_t(JIT_API *)(cpu_ctx_t *cpu_ctx);
using clear_int_t = void(JIT_API *)(cpu_ctx_t *cpu_ctx);
using raise_int_t = void(JIT_API *)(cpu_ctx_t *cpu_ctx, uint32_t int_flg);

// jmp_offset functions: 0,1 -> used for direct linking (either points to exit or &next_tc), 2 -> exit
struct translated_code_t {
	std::forward_list<translated_code_t *> linked_tc;
	addr_t cs_base;
	addr_t pc;
	addr_t virt_pc;
	uint32_t guest_flags;
	entry_t ptr_code;
	entry_t jmp_offset[3];
	translated_code_t *ibtc[3];
	uint32_t flags;
	uint32_t size;
	explicit translated_code_t() noexcept;
	explicit translated_code_t(uint32_t flags) noexcept : translated_code_t() { guest_flags = flags; }
};

struct disas_ctx_t {
	uint8_t flags;
	addr_t virt_pc, pc;
	uint64_t instr_buff_size;
	exp_data_t exp_data;
};

template<typename T>
struct wp_info {
	int dr_idx;
	T watch_addr;
	T watch_end;
	wp_info() : dr_idx(0), watch_addr(0), watch_end(0) {}
	wp_info(int idx, T addr, T end) : dr_idx(idx), watch_addr(addr), watch_end(end) {}
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

struct fpu_data_t {
	uint16_t ftop; // these are the top of stack pointer bits of fstatus
	uint16_t fes; // pending unmasked exception flag that is, es bit of fstatus
	uint16_t frp; // current rounding and precision set in fctrl | FPU_EXP_ALL
};

// this struct should contain all cpu variables which need to be visible from the jitted code
struct cpu_ctx_t {
	cpu_t *cpu;
	regs_t regs;
	lazy_eflags_t lazy_eflags;
	uint32_t hflags;
	uint8_t *ram;
	exp_info_t exp_info;
	uint32_t int_pending;
	uint8_t exit_requested;
	uint8_t is_halted;
	fpu_data_t fpu_data;
};

// int_pending must be 4 byte aligned to ensure atomicity
static_assert(alignof(decltype(cpu_ctx_t::int_pending)) == 4);

class lc86_jit;
struct cpu_t {
	uint32_t cpu_flags;
	const char *cpu_name;
	cpu_ctx_t cpu_ctx;
	disas_ctx_t disas_ctx;
	translated_code_t *tc; // tc for which we are currently generating code
	std::mt19937 rng_gen;
	std::unique_ptr<lc86_jit> jit;
	std::unique_ptr<address_space<addr_t>> memory_space_tree;
	std::unique_ptr<address_space<port_t>> io_space_tree;
	std::list<std::unique_ptr<translated_code_t>> code_cache[CODE_CACHE_MAX_SIZE];
	std::unordered_map<uint32_t, std::unordered_set<translated_code_t *>> tc_page_map;
	std::unordered_map<addr_t, hook_t> hook_map;
	std::vector<wp_info<addr_t>> wp_data;
	std::vector<wp_info<port_t>> wp_io;
	std::vector<std::pair<bool, std::unique_ptr<memory_region_t<addr_t>>>> regions_changed;
	std::bitset<SMC_MAX_SIZE> smc; // self-modifying code tracking
	tlb_t itlb[ITLB_NUM_SETS][ITLB_NUM_LINES]; // instruction tlb
	tlb_t dtlb[DTLB_NUM_SETS][DTLB_NUM_LINES]; // data tlb
	uint16_t num_tc; // num of tc actually emitted, tc's might not be present in the code cache
	uint8_t microcode_updated;
	struct _tsc_clock {
		uint64_t last_host_ticks;
		static constexpr uint64_t cpu_freq = 733333333;
	} tsc_clock;
	struct _timer {
		uint64_t last_time;
		uint64_t host_freq;
		uint64_t timeout_time;
	} timer;
	msr_t msr;
	read_int_t read_int_fn;
	clear_int_t clear_int_fn;
	raise_int_t raise_int_fn;
	clear_int_t lower_hw_int_fn;
	fp_int get_int_vec;
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
	uint32_t new_a20;
};
