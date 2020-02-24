/*
 * memory accessors
 *
 * ergo720                Copyright (c) 2019
 */

#pragma once

#include "llvm/support/SwapByteOrder.h"
#include "lib86cpu.h"

#define AS_RESOLVE_ALIAS() 	addr_t alias_offset = region->alias_offset; \
while (region->aliased_region) { \
	region = region->aliased_region; \
	alias_offset += region->alias_offset; \
}

inline void *get_ram_host_ptr(cpu_t *cpu, memory_region_t<addr_t> *ram, addr_t pc);
void check_instr_length(cpu_t *cpu, addr_t start_pc, addr_t pc, size_t size);
JIT_EXTERNAL_CALL_C uint8_t mem_read8(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip);
JIT_EXTERNAL_CALL_C uint16_t mem_read16(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip);
JIT_EXTERNAL_CALL_C uint32_t mem_read32(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip);
JIT_EXTERNAL_CALL_C uint64_t mem_read64(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip);
JIT_EXTERNAL_CALL_C void mem_write8(cpu_ctx_t *cpu_ctx, addr_t addr, uint8_t value, uint32_t eip);
JIT_EXTERNAL_CALL_C void mem_write16(cpu_ctx_t *cpu_ctx, addr_t addr, uint16_t value, uint32_t eip);
JIT_EXTERNAL_CALL_C void mem_write32(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t value, uint32_t eip);
JIT_EXTERNAL_CALL_C void mem_write64(cpu_ctx_t * cpu_ctx, addr_t addr, uint64_t value, uint32_t eip);
JIT_EXTERNAL_CALL_C uint8_t io_read8(cpu_ctx_t *cpu_ctx, port_t port, uint32_t eip);
JIT_EXTERNAL_CALL_C uint16_t io_read16(cpu_ctx_t *cpu_ctx, port_t port, uint32_t eip);
JIT_EXTERNAL_CALL_C uint32_t io_read32(cpu_ctx_t *cpu_ctx, port_t port, uint32_t eip);
JIT_EXTERNAL_CALL_C void io_write8(cpu_ctx_t *cpu_ctx, port_t port, uint8_t value, uint32_t eip);
JIT_EXTERNAL_CALL_C void io_write16(cpu_ctx_t *cpu_ctx, port_t port, uint16_t value, uint32_t eip);
JIT_EXTERNAL_CALL_C void io_write32(cpu_ctx_t *cpu_ctx, port_t port, uint32_t value, uint32_t eip);
template<typename T> T ram_read(cpu_t *cpu, void *ram_ptr);
template<typename T> void ram_write(cpu_t *cpu, void *ram_ptr, T value);


/*
 * address space helpers
 */
template<typename T>
memory_region_t<addr_t> *as_memory_search_addr(cpu_t *cpu, addr_t addr)
{
	addr_t end = addr + sizeof(T) - 1;
	cpu->memory_space_tree->search(addr, end, cpu->memory_out);
	return cpu->memory_out.begin()->get().get();
}

template<typename T>
memory_region_t<port_t> *as_io_search_port(cpu_t *cpu, port_t port)
{
	port_t end = port + sizeof(T) - 1;
	cpu->io_space_tree->search(port, end, cpu->io_out);
	return cpu->io_out.begin()->get().get();
}

template<typename T>
T as_memory_dispatch_read(cpu_t *cpu, addr_t addr, memory_region_t<addr_t> *region)
{
	if ((addr >= region->start) && ((addr + sizeof(T) - 1) <= region->end)) {
		switch (region->type)
		{
		case MEM_RAM:
			return ram_read<T>(cpu, get_ram_host_ptr(cpu, region, addr));

		case MEM_MMIO:
			return region->read_handler(addr, sizeof(T), region->opaque);

		case MEM_ALIAS: {
			memory_region_t<addr_t> *alias = region;
			AS_RESOLVE_ALIAS();
			return as_memory_dispatch_read<T>(cpu, region->start + alias_offset + (addr - alias->start), region);
		}
		break;

		case MEM_UNMAPPED:
			LOG("Memory read to unmapped memory at address %#010x with size %d\n", addr, sizeof(T));
			return std::numeric_limits<T>::max();

		default:
			LIB86CPU_ABORT();
		}
	}
	else {
		LOG("Memory read at address %#010x with size %d is not completely inside a memory region\n", addr, sizeof(T));
		return std::numeric_limits<T>::max();
	}
}

template<typename T>
T as_ram_dispatch_read(cpu_t *cpu, addr_t addr, memory_region_t<addr_t> *region)
{
	if ((addr >= region->start) && ((addr + sizeof(T) - 1) <= region->end)) {
		switch (region->type)
		{
		case MEM_RAM:
			return ram_read<T>(cpu, get_ram_host_ptr(cpu, region, addr));

		case MEM_ALIAS: {
			memory_region_t<addr_t> *alias = region;
			AS_RESOLVE_ALIAS();
			return as_ram_dispatch_read<T>(cpu, region->start + alias_offset + (addr - alias->start), region);
		}
		break;

		default:
			LIB86CPU_ABORT_msg("Attempted to execute code outside of ram!\n");
		}
	}
	else {
		LOG("Memory read at address %#010x with size %d is not completely inside a memory region\n", addr, sizeof(T));
		return std::numeric_limits<T>::max();
	}
}

template<typename T>
void as_memory_dispatch_write(cpu_t *cpu, addr_t addr, T value, memory_region_t<addr_t> *region)
{
	if ((addr >= region->start) && ((addr + sizeof(T) - 1) <= region->end)) {
		switch (region->type)
		{
		case MEM_RAM:
			ram_write<T>(cpu, get_ram_host_ptr(cpu, region, addr), value);
			break;

		case MEM_MMIO:
			region->write_handler(addr, sizeof(T), value, region->opaque);
			break;

		case MEM_ALIAS: {
			memory_region_t<addr_t> *alias = region;
			AS_RESOLVE_ALIAS();
			as_memory_dispatch_write<T>(cpu, region->start + alias_offset + (addr - alias->start), value, region);
		}
		break;

		case MEM_UNMAPPED:
			LOG("Memory write to unmapped memory at address %#010x with size %d\n", addr, sizeof(T));
			break;

		default:
			LIB86CPU_ABORT();
		}
	}
	else {
		LOG("Memory write at address %#010x with size %d is not completely inside a memory region\n", addr, sizeof(T));
	}
}

template<typename T>
T as_io_dispatch_read(cpu_t *cpu, port_t port, memory_region_t<port_t> *region)
{
	if ((port >= region->start) && ((port + sizeof(T) - 1) <= region->end)) {
		switch (region->type)
		{
		case MEM_PMIO:
			return region->read_handler(port, sizeof(T), region->opaque);

		case MEM_UNMAPPED:
			LOG("Memory read to unmapped memory at port %#06hx with size %d\n", port, sizeof(T));
			return std::numeric_limits<T>::max();

		default:
			LIB86CPU_ABORT();
		}
	}
	else {
		LOG("Memory read at port %#06hx with size %d is not completely inside a memory region\n", port, sizeof(T));
		return std::numeric_limits<T>::max();
	}
}

template<typename T>
void as_io_dispatch_write(cpu_t *cpu, port_t port, T value, memory_region_t<port_t> *region)
{
	if ((port >= region->start) && ((port + sizeof(T) - 1) <= region->end)) {
		switch (region->type)
		{
		case MEM_PMIO:
			region->write_handler(port, sizeof(T), value, region->opaque);
			break;

		case MEM_UNMAPPED:
			LOG("Memory write to unmapped memory at port %#06hx with size %d\n", port, sizeof(T));
			break;

		default:
			LIB86CPU_ABORT();
		}
	}
	else {
		LOG("Memory write at port %#06hx with size %d is not completely inside a memory region\n", port, sizeof(T));
	}
}

/*
 * ram specific accessors
 */
void *
get_ram_host_ptr(cpu_t *cpu, memory_region_t<addr_t> *ram, addr_t pc)
{
	return &cpu->ram[pc - ram->start];
}

template<typename T>
T ram_read_le(cpu_t *cpu, void *ram_ptr)
{
	T value;
	memcpy(&value, ram_ptr, sizeof(T));
	return value;
}

template<typename T>
T ram_read_be(cpu_t *cpu, void *ram_ptr)
{
	T value;
	memcpy(&value, ram_ptr, sizeof(T));
	sys::swapByteOrder<T>(value);
	return value;
}

template<typename T>
void ram_write_le(cpu_t *cpu, void *ram_ptr, T value)
{
	memcpy(ram_ptr, &value, sizeof(T));
}

template<typename T>
void ram_write_be(cpu_t *cpu, void *ram_ptr, T value)
{
	sys::swapByteOrder<T>(value);
	memcpy(ram_ptr, &value, sizeof(T));
}

template<typename T>
using fp_ram_read = T(*)(cpu_t *, void *);
template<typename T>
using fp_ram_write = void(*)(cpu_t *, void *, T);

inline constexpr std::tuple<fp_ram_read<uint8_t>, fp_ram_read<uint16_t>, fp_ram_read<uint32_t>, fp_ram_read<uint64_t>,
	fp_ram_write<uint8_t>, fp_ram_write<uint16_t>, fp_ram_write<uint32_t>, fp_ram_write<uint64_t>> ram_func[2] = {
		{ ram_read_le<uint8_t>, ram_read_le<uint16_t>, ram_read_le<uint32_t>, ram_read_le<uint64_t>,
		ram_write_le<uint8_t>, ram_write_le<uint16_t>, ram_write_le<uint32_t>, ram_write_le<uint64_t> },
		{ ram_read_be<uint8_t>, ram_read_be<uint16_t>, ram_read_be<uint32_t>, ram_read_be<uint64_t>,
		ram_write_be<uint8_t>, ram_write_be<uint16_t>, ram_write_be<uint32_t>, ram_write_be<uint64_t> },
};

// borrowed from Bit Twiddling Hacks by Sean Eron Anderson (public domain)
// http://graphics.stanford.edu/~seander/bithacks.html#IntegerLogDeBruijn
inline constexpr int MultiplyDeBruijnBitPosition2[32] =
{
  0, 1, 28, 2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4, 8,
  31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6, 11, 5, 10, 9
};

template<typename T>
T ram_read(cpu_t *cpu, void *ram_ptr)
{
	return (*std::get<MultiplyDeBruijnBitPosition2[static_cast<uint32_t>(sizeof(T) * 0x077CB531U) >> 27]>(ram_func[cpu->cpu_flags & CPU_FLAG_SWAPMEM]))(cpu, ram_ptr);
}

template<typename T>
void ram_write(cpu_t *cpu, void *ram_ptr, T value)
{
	(*std::get<MultiplyDeBruijnBitPosition2[static_cast<uint32_t>(sizeof(T) * 0x077CB531U) >> 27] + 4>(ram_func[cpu->cpu_flags & CPU_FLAG_SWAPMEM]))(cpu, ram_ptr, value);
}

template<typename T>
T ram_fetch(cpu_t *cpu, disas_ctx_t *disas_ctx, uint8_t page_cross)
{
	T value = 0;

	if (page_cross) {
		uint8_t i = 0;
		memory_region_t<addr_t> *region;
		check_instr_length(cpu, disas_ctx->start_pc, disas_ctx->virt_pc, sizeof(T));
		while (i < sizeof(T)) {
			disas_ctx->pc = mmu_translate_addr(cpu, disas_ctx->virt_pc, 0, disas_ctx->start_pc - cpu->cpu_ctx.regs.cs_hidden.base, cpu_throw_exception);
			region = as_memory_search_addr<T>(cpu, disas_ctx->pc);
			value |= (static_cast<T>(as_ram_dispatch_read<uint8_t>(cpu, disas_ctx->pc, region)) << (i * 8));
			disas_ctx->virt_pc++;
			i++;
		}
		disas_ctx->pc++;
		if (cpu->cpu_flags & CPU_FLAG_SWAPMEM) {
			sys::swapByteOrder<T>(value);
		}
	}
	else {
		check_instr_length(cpu, disas_ctx->start_pc, disas_ctx->virt_pc, sizeof(T));
		value = as_ram_dispatch_read<T>(cpu, disas_ctx->pc, as_memory_search_addr<T>(cpu, disas_ctx->pc));
		disas_ctx->pc += sizeof(T);
		disas_ctx->virt_pc += sizeof(T);
	}

#if DEBUG_LOG
	memcpy(&disas_ctx->instr_bytes[disas_ctx->byte_idx], &value, sizeof(T));
	disas_ctx->byte_idx += sizeof(T);
#endif

	return value;
}

/*
 * generic memory accessors
 */
template<typename T>
T mem_read(cpu_t *cpu, addr_t addr, uint32_t eip)
{
	addr_t phys_addr;
	if ((addr & ~PAGE_MASK) != ((addr + sizeof(T) - 1) & ~PAGE_MASK)) {
		T buffer = 0;
		uint8_t i = 0;
		memory_region_t<addr_t> *region;
		while (i < sizeof(T)) {
			phys_addr = mmu_translate_addr(cpu, addr, 0, eip, cpu_raise_exception);
			region = as_memory_search_addr<T>(cpu, phys_addr);
			buffer |= (static_cast<T>(as_memory_dispatch_read<uint8_t>(cpu, phys_addr, region)) << (i * 8));
			addr++;
			i++;
		}
		if (cpu->cpu_flags & CPU_FLAG_SWAPMEM) {
			sys::swapByteOrder<T>(buffer);
		}
		return buffer;
	}
	else {
		phys_addr = mmu_translate_addr(cpu, addr, 0, eip, cpu_raise_exception);
		return as_memory_dispatch_read<T>(cpu, phys_addr, as_memory_search_addr<T>(cpu, phys_addr));
	}
}

template<typename T>
void mem_write(cpu_t *cpu, addr_t addr, T value, uint32_t eip)
{
	addr_t phys_addr;
	if ((addr & ~PAGE_MASK) != ((addr + sizeof(T) - 1) & ~PAGE_MASK)) {
		int8_t i = sizeof(T) - 1;
		memory_region_t<addr_t> *region;
		if (cpu->cpu_flags & CPU_FLAG_SWAPMEM) {
			sys::swapByteOrder<T>(value);
		}
		while (i >= 0) {
			phys_addr = mmu_translate_addr(cpu, addr, 1, eip, cpu_raise_exception);
			region = as_memory_search_addr<T>(cpu, phys_addr);
			as_memory_dispatch_write<uint8_t>(cpu, phys_addr, value >> (i * 8), region);
			addr++;
			i--;
		}
	}
	else {
		phys_addr = mmu_translate_addr(cpu, addr, 1, eip, cpu_raise_exception);
		as_memory_dispatch_write<T>(cpu, phys_addr, value, as_memory_search_addr<T>(cpu, phys_addr));
	}
}

/*
 * pmio specific accessors
 */
template<typename T>
T io_read(cpu_t *cpu, port_t port)
{
	return as_io_dispatch_read<T>(cpu, port, as_io_search_port<T>(cpu, port));
}

template<typename T>
void io_write(cpu_t *cpu, port_t port, T value)
{
	as_io_dispatch_write<T>(cpu, port, value, as_io_search_port<T>(cpu, port));
}
