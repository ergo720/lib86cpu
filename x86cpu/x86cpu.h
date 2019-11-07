/*
 * x86cpu types
 *
 * ergo720                Copyright (c) 2019
 * the libcpu developers  Copyright (c) 2009-2010
 */

#pragma once

#include "config.h"
#include "platform.h"
#include <stdint.h>
#include "types.h"
#include "interval_tree.h"


namespace llvm {
	class LLVMContext;
	class BasicBlock;
	class ExecutionEngine;
	class Function;
	class Module;
	class PointerType;
	class StructType;
	class Value;
	class DataLayout;
	namespace orc {
		class LLLazyJIT;
	}
}

using namespace llvm;

// x86cpu error flags
enum x86cpu_status {
	X86CPU_NO_MEMORY = -3,
	X86CPU_INVALID_PARAMETER,
	X86CPU_LLVM_INTERNAL_ERROR,
	X86CPU_SUCCESS,
};

#define X86CPU_CHECK_SUCCESS(status) (((x86cpu_status)(status)) == 0)

#define CPU_FLAG_SWAPMEM  (1 << 0)
#define CPU_INTEL_SYNTAX  (1 << 1)

#define CPU_INTEL_SYNTAX_SHIFT  1

// mmio/pmio access handlers
typedef uint32_t(*fp_read)(addr_t addr, size_t size, void *opaque);
typedef void        (*fp_write)(addr_t addr, size_t size, uint32_t value, void *opaque);

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
	bool operator() (const std::tuple<T, T, const std::unique_ptr<memory_region_t<T>> &> &lhs, const std::tuple<T, T, const std::unique_ptr<memory_region_t<T>> &> &rhs)
	{
		return std::get<2>(lhs)->priority > std::get<2>(rhs)->priority;
	}
};

// memory region type
enum mem_type_t {
	MEM_UNMAPPED,
	MEM_RAM,
	MEM_MMIO,
	MEM_PMIO,
	MEM_ALIAS,
};

typedef struct cpu {
	uint32_t flags;

	gpr_t gpr;
	fpr_t fpr;
	uint8_t *RAM;
	std::unique_ptr<interval_tree<addr_t, std::unique_ptr<memory_region_t<addr_t>>>> memory_space_tree;
	std::unique_ptr<interval_tree<io_port_t, std::unique_ptr<memory_region_t<io_port_t>>>> io_space_tree;
	std::set<std::tuple<addr_t, addr_t, const std::unique_ptr<memory_region_t<addr_t>> &>, sort_by_priority<addr_t>> memory_out;
	std::set<std::tuple<io_port_t, io_port_t, const std::unique_ptr<memory_region_t<io_port_t>> &>, sort_by_priority<io_port_t>> io_out;
} cpu_t;

// cpu api
API_FUNC x86cpu_status cpu_new(size_t ramsize, cpu_t *&out);
API_FUNC void cpu_free(cpu_t *cpu);

// memory api
API_FUNC x86cpu_status memory_init_region_ram(cpu_t *cpu, addr_t start, size_t size, int priority);
API_FUNC x86cpu_status memory_init_region_io(cpu_t *cpu, addr_t start, size_t size, bool io_space, fp_read read_func, fp_write write_func, void *opaque, int priority);
API_FUNC x86cpu_status memory_init_region_alias(cpu_t *cpu, addr_t alias_start, addr_t ori_start, size_t ori_size, int priority);
API_FUNC x86cpu_status memory_destroy_region(cpu_t *cpu, addr_t start, size_t size, bool io_space);
