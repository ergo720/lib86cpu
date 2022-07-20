/*
 * memory accessors
 *
 * ergo720                Copyright (c) 2019
 */

#pragma once

#include "llvm/support/SwapByteOrder.h"
#include "lib86cpu_priv.h"
#include "internal.h"

#define AS_RESOLVE_ALIAS() 	addr_t alias_offset = region->alias_offset; \
while (region->aliased_region) { \
	region = region->aliased_region; \
	alias_offset += region->alias_offset; \
}

void tlb_flush(cpu_t *cpu, int n);
void iotlb_fill(cpu_t * cpu, port_t port, memory_region_t<port_t> *io);
void iotlb_flush(cpu_t * cpu, memory_region_t<port_t> *io);
inline void *get_rom_host_ptr(cpu_t *cpu, memory_region_t<addr_t> *rom, addr_t addr);
inline void *get_ram_host_ptr(cpu_t *cpu, memory_region_t<addr_t> *ram, addr_t addr);
addr_t get_read_addr(cpu_t *cpu, addr_t addr, uint8_t is_priv, uint32_t eip);
addr_t get_write_addr(cpu_t *cpu, addr_t addr, uint8_t is_priv, uint32_t eip, uint8_t *is_code);
addr_t get_code_addr(cpu_t *cpu, addr_t addr, uint32_t eip);
addr_t get_code_addr(cpu_t * cpu, addr_t addr, uint32_t eip, uint32_t is_code, disas_ctx_t *disas_ctx);
uint8_t io_read8(cpu_ctx_t *cpu_ctx, port_t port);
uint16_t io_read16(cpu_ctx_t *cpu_ctx, port_t port);
uint32_t io_read32(cpu_ctx_t *cpu_ctx, port_t port);
void io_write8(cpu_ctx_t *cpu_ctx, port_t port, uint8_t value);
void io_write16(cpu_ctx_t *cpu_ctx, port_t port, uint16_t value);
void io_write32(cpu_ctx_t *cpu_ctx, port_t port, uint32_t value);
template<typename T> T ram_read(cpu_t *cpu, void *ram_ptr);
template<typename T> void ram_write(cpu_t *cpu, void *ram_ptr, T value);
void ram_fetch(cpu_t *cpu, disas_ctx_t *disas_ctx, uint8_t *buffer);
size_t as_ram_dispatch_read(cpu_t *cpu, addr_t addr, size_t size, memory_region_t<addr_t> *region, uint8_t *buffer);
void rom_flush_cached(cpu_t * cpu, memory_region_t<addr_t> *rom);
void mmio_flush_cached(cpu_t * cpu, memory_region_t<addr_t> *mmio);
template<typename T> T mem_read_helper(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip, uint8_t is_priv);
template<typename T> void mem_write_helper(cpu_ctx_t *cpu_ctx, addr_t addr, T val, uint32_t eip, uint8_t is_priv);

inline const uint8_t tlb_access[2][4] = {
	{ TLB_SUP_READ, TLB_SUP_READ, TLB_SUP_READ, TLB_USER_READ },
	{ TLB_SUP_WRITE, TLB_SUP_WRITE, TLB_SUP_WRITE, TLB_USER_WRITE }
};


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
		case mem_type::ram:
			return ram_read<T>(cpu, get_ram_host_ptr(cpu, region, addr));

		case mem_type::rom:
			return ram_read<T>(cpu, get_rom_host_ptr(cpu, region, addr));

		case mem_type::mmio:
			return static_cast<T>(region->read_handler(addr, sizeof(T), region->opaque));

		case mem_type::alias: {
			memory_region_t<addr_t> *alias = region;
			AS_RESOLVE_ALIAS();
			return as_memory_dispatch_read<T>(cpu, region->start + alias_offset + (addr - alias->start), region);
		}
		break;

		case mem_type::unmapped:
			LOG(log_level::warn, "Memory read to unmapped memory at address %#010x with size %d", addr, sizeof(T));
			return std::numeric_limits<T>::max();

		default:
			LIB86CPU_ABORT();
		}
	}
	else {
		LOG(log_level::warn, "Memory read at address %#010x with size %d is not completely inside a memory region", addr, sizeof(T));
		return std::numeric_limits<T>::max();
	}
}

template<typename T>
void as_memory_dispatch_write(cpu_t *cpu, addr_t addr, T value, memory_region_t<addr_t> *region)
{
	if ((addr >= region->start) && ((addr + sizeof(T) - 1) <= region->end)) {
		switch (region->type)
		{
		case mem_type::ram:
			ram_write<T>(cpu, get_ram_host_ptr(cpu, region, addr), value);
			break;

		case mem_type::rom:
			break;

		case mem_type::mmio:
			region->write_handler(addr, sizeof(T), value, region->opaque);
			break;

		case mem_type::alias: {
			memory_region_t<addr_t> *alias = region;
			AS_RESOLVE_ALIAS();
			as_memory_dispatch_write<T>(cpu, region->start + alias_offset + (addr - alias->start), value, region);
		}
		break;

		case mem_type::unmapped:
			LOG(log_level::warn, "Memory write to unmapped memory at address %#010x with size %d", addr, sizeof(T));
			break;

		default:
			LIB86CPU_ABORT();
		}
	}
	else {
		LOG(log_level::warn, "Memory write at address %#010x with size %d is not completely inside a memory region", addr, sizeof(T));
	}
}

template<typename T>
T as_io_dispatch_read(cpu_t *cpu, port_t port, memory_region_t<port_t> *region)
{
	if ((port >= region->start) && ((port + sizeof(T) - 1) <= region->end)) {
		switch (region->type)
		{
		case mem_type::pmio:
		case mem_type::unmapped:
			return static_cast<T>(region->read_handler(port, sizeof(T), region->opaque));

		default:
			LIB86CPU_ABORT();
		}
	}
	else {
		LOG(log_level::warn, "Memory read at port %#06hx with size %d is not completely inside a memory region", port, sizeof(T));
		return std::numeric_limits<T>::max();
	}
}

template<typename T>
void as_io_dispatch_write(cpu_t *cpu, port_t port, T value, memory_region_t<port_t> *region)
{
	if ((port >= region->start) && ((port + sizeof(T) - 1) <= region->end)) {
		switch (region->type)
		{
		case mem_type::pmio:
		case mem_type::unmapped:
			region->write_handler(port, sizeof(T), value, region->opaque);
			break;

		default:
			LIB86CPU_ABORT();
		}
	}
	else {
		LOG(log_level::warn, "Memory write at port %#06hx with size %d is not completely inside a memory region", port, sizeof(T));
	}
}

/*
 * ram/rom specific accessors
 */
void *
get_rom_host_ptr(cpu_t *cpu, memory_region_t<addr_t> *rom, addr_t addr)
{
	return &cpu->vec_rom[rom->rom_idx][addr - rom->start];
}

void *
get_ram_host_ptr(cpu_t *cpu, memory_region_t<addr_t> *ram, addr_t addr)
{
	return &cpu->cpu_ctx.ram[addr - ram->start];
}

template<typename T>
T ram_read(cpu_t *cpu, void *ram_ptr)
{
	T value;
	memcpy(&value, ram_ptr, sizeof(T));
	if constexpr (is_big_endian) {
		sys::swapByteOrder<T>(value);
	}
	return value;
}

template<typename T>
void ram_write(cpu_t *cpu, void *ram_ptr, T value)
{
	if constexpr (is_big_endian) {
		sys::swapByteOrder<T>(value);
	}
	memcpy(ram_ptr, &value, sizeof(T));
}

/*
 * generic memory accessors
 */
// NOTE: flags: bit 0 -> is_phys, bit 1 -> is_priv 
template<typename T>
T mem_read(cpu_t *cpu, addr_t addr, uint32_t eip, uint8_t flags)
{
	if (!(flags & 1)) {
		// NOTE: is_phys can only be set if TLB_WATCH is not set
		cpu_check_data_watchpoints(cpu, addr, sizeof(T), DR7_TYPE_DATA_RW, eip);
		if ((sizeof(T) != 1) && ((addr & ~PAGE_MASK) != ((addr + sizeof(T) - 1) & ~PAGE_MASK))) {
			T value = 0;
			uint8_t i = 0;
			addr_t phys_addr_s = get_read_addr(cpu, addr, flags & 2, eip);
			addr_t phys_addr_e = get_read_addr(cpu, addr + sizeof(T) - 1, flags & 2, eip);
			addr_t phys_addr = phys_addr_s;
			uint8_t bytes_in_page = ((addr + sizeof(T) - 1) & ~PAGE_MASK) - addr;
			while (i < sizeof(T)) {
				memory_region_t<addr_t> *region = as_memory_search_addr<T>(cpu, phys_addr);
				value |= (static_cast<T>(as_memory_dispatch_read<uint8_t>(cpu, phys_addr, region)) << (i * 8));
				phys_addr++;
				i++;
				if (i == bytes_in_page) {
					phys_addr = phys_addr_e & ~PAGE_MASK;
				}
			}
			if constexpr (is_big_endian) {
				sys::swapByteOrder<T>(value);
			}
			return value;
		}
		else {
			addr_t phys_addr = get_read_addr(cpu, addr, flags & 2, eip);
			return as_memory_dispatch_read<T>(cpu, phys_addr, as_memory_search_addr<T>(cpu, phys_addr));
		}
	}
	else {
		return as_memory_dispatch_read<T>(cpu, addr, as_memory_search_addr<T>(cpu, addr));
	}
}

template<typename T>
void mem_write(cpu_t *cpu, addr_t addr, T value, uint32_t eip, uint8_t flags)
{
	// NOTE: is_phys is never set because tc_invalidate needs a virtual address
	cpu_check_data_watchpoints(cpu, addr, sizeof(T), DR7_TYPE_DATA_W, eip);
	if ((sizeof(T) != 1) && ((addr & ~PAGE_MASK) != ((addr + sizeof(T) - 1) & ~PAGE_MASK))) {
		uint8_t is_code1, is_code2;
		uint8_t i = 0;
		int8_t j = sizeof(T) - 1;
		addr_t phys_addr_s = get_write_addr(cpu, addr, flags & 2, eip, &is_code1);
		addr_t phys_addr_e = get_write_addr(cpu, addr + sizeof(T) - 1, flags & 2, eip, &is_code2);
		addr_t phys_addr = phys_addr_s;
		uint8_t bytes_in_page = ((addr + sizeof(T) - 1) & ~PAGE_MASK) - addr;
		if (is_code1) {
			tc_invalidate(&cpu->cpu_ctx, addr, bytes_in_page, eip);
		}
		if (is_code2) {
			tc_invalidate(&cpu->cpu_ctx, addr + sizeof(T) - 1, sizeof(T) - bytes_in_page, eip);
		}
		if constexpr (is_big_endian) {
			sys::swapByteOrder<T>(value);
		}
		while (i < sizeof(T)) {
			memory_region_t<addr_t> *region = as_memory_search_addr<T>(cpu, phys_addr);
			as_memory_dispatch_write<uint8_t>(cpu, phys_addr, value >> (j * 8), region);
			phys_addr++;
			i++;
			j--;
			if (i == bytes_in_page) {
				phys_addr = phys_addr_e & ~PAGE_MASK;
			}
		}
	}
	else {
		uint8_t is_code;
		addr_t phys_addr = get_write_addr(cpu, addr, flags & 2, eip, &is_code);
		if (is_code) {
			tc_invalidate(&cpu->cpu_ctx, addr, sizeof(T), eip);
		}
		as_memory_dispatch_write<T>(cpu, phys_addr, value, as_memory_search_addr<T>(cpu, phys_addr));
	}
}

/*
 * pmio specific accessors
 */
template<typename T>
T io_read(cpu_t *cpu, port_t port)
{
	const auto region = as_io_search_port<T>(cpu, port);
	iotlb_fill(cpu, port, region);
	return as_io_dispatch_read<T>(cpu, port, region);
}

template<typename T>
void io_write(cpu_t *cpu, port_t port, T value)
{
	const auto region = as_io_search_port<T>(cpu, port);
	iotlb_fill(cpu, port, region);
	as_io_dispatch_write<T>(cpu, port, value, region);
}
