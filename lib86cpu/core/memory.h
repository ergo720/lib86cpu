/*
 * memory accessors
 *
 * ergo720                Copyright (c) 2019
 */

#pragma once

#include "lib86cpu_priv.h"
#include "internal.h"
#include <algorithm>

#define AS_RESOLVE_ALIAS() 	addr_t alias_offset = region->alias_offset; \
while (region->aliased_region) { \
	region = region->aliased_region; \
	alias_offset += region->alias_offset; \
}

void tlb_flush(cpu_t *cpu, int n);
inline void *get_rom_host_ptr(const memory_region_t<addr_t> *rom, addr_t addr);
inline void *get_ram_host_ptr(cpu_t *cpu, addr_t addr);
addr_t get_read_addr(cpu_t *cpu, addr_t addr, uint8_t is_priv, uint32_t eip);
addr_t get_write_addr(cpu_t *cpu, addr_t addr, uint8_t is_priv, uint32_t eip, uint8_t *is_code);
addr_t get_code_addr(cpu_t *cpu, addr_t addr, uint32_t eip);
addr_t get_code_addr(cpu_t * cpu, addr_t addr, uint32_t eip, uint32_t is_code, disas_ctx_t *disas_ctx);
template<typename T> T ram_read(cpu_t *cpu, void *ram_ptr);
template<typename T> void ram_write(cpu_t *cpu, void *ram_ptr, T value);
void ram_fetch(cpu_t *cpu, disas_ctx_t *disas_ctx, uint8_t *buffer);
size_t as_ram_dispatch_read(cpu_t *cpu, addr_t addr, size_t size, const memory_region_t<addr_t> *region, uint8_t *buffer);
template<typename T> T mem_read_helper(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t eip, uint8_t is_priv);
template<typename T> void mem_write_helper(cpu_ctx_t *cpu_ctx, addr_t addr, T val, uint32_t eip, uint8_t is_priv);
template<typename T> T io_read_helper(cpu_ctx_t * cpu_ctx, port_t port);
template<typename T> void io_write_helper(cpu_ctx_t * cpu_ctx, port_t port, T val);

inline const uint8_t tlb_access[2][4] = {
	{ TLB_SUP_READ, TLB_SUP_READ, TLB_SUP_READ, TLB_USER_READ },
	{ TLB_SUP_WRITE, TLB_SUP_WRITE, TLB_SUP_WRITE, TLB_USER_WRITE }
};


/*
 * address space helpers
 */
inline const memory_region_t<addr_t> *
as_memory_search_addr(cpu_t *cpu, addr_t addr)
{
	return cpu->memory_space_tree->search(addr);
}

inline const memory_region_t<port_t> *
as_io_search_port(cpu_t *cpu, port_t port)
{
	return cpu->io_space_tree->search(port);
}

template<typename T>
T as_memory_dispatch_read(cpu_t *cpu, addr_t addr, const memory_region_t<addr_t> *region)
{
	switch (region->type)
	{
	case mem_type::ram:
		return ram_read<T>(cpu, get_ram_host_ptr(cpu, addr));

	case mem_type::rom:
		if ((addr + sizeof(T) - 1) > region->end) [[unlikely]] {
			// avoid rom buffer overflow
			T value = 0;
			unsigned i = 0;
			while (addr <= region->end) {
				const memory_region_t<addr_t> *region = as_memory_search_addr(cpu, addr);
				value |= (static_cast<T>(as_memory_dispatch_read<uint8_t>(cpu, addr, region)) << (i * 8));
				++addr;
				++i;
			}
			return value;
		}
		else {
			return ram_read<T>(cpu, get_rom_host_ptr(region, addr));
		}

	case mem_type::mmio:
		if constexpr (sizeof(T) == 1) {
			return region->handlers.fnr8(addr, region->opaque);
		}
		else if constexpr (sizeof(T) == 2) {
			return region->handlers.fnr16(addr, region->opaque);
		}
		else if constexpr (sizeof(T) == 4) {
			return region->handlers.fnr32(addr, region->opaque);
		}
		else if constexpr (sizeof(T) == 8) {
			return region->handlers.fnr64(addr, region->opaque);
		}
		else {
			LIB86CPU_ABORT_msg("Unexpected size %u in %s", sizeof(T), __func__);
		}

	case mem_type::alias: {
		const memory_region_t<addr_t> *alias = region;
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

template<typename T>
void as_memory_dispatch_write(cpu_t *cpu, addr_t addr, T value, const memory_region_t<addr_t> *region)
{
	switch (region->type)
	{
	case mem_type::ram:
		ram_write<T>(cpu, get_ram_host_ptr(cpu, addr), value);
		break;

	case mem_type::rom:
		break;

	case mem_type::mmio:
		if constexpr (sizeof(T) == 1) {
			region->handlers.fnw8(addr, value, region->opaque);
		}
		else if constexpr (sizeof(T) == 2) {
			region->handlers.fnw16(addr, value, region->opaque);
		}
		else if constexpr (sizeof(T) == 4) {
			region->handlers.fnw32(addr, value, region->opaque);
		}
		else if constexpr (sizeof(T) == 8) {
			region->handlers.fnw64(addr, value, region->opaque);
		}
		else {
			LIB86CPU_ABORT_msg("Unexpected size %u in %s", sizeof(T), __func__);
		}
		break;

	case mem_type::alias: {
		const memory_region_t<addr_t> *alias = region;
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

template<typename T>
T as_io_dispatch_read(cpu_t *cpu, port_t port, const memory_region_t<port_t> *region)
{
	switch (region->type)
	{
	case mem_type::pmio:
		if constexpr (sizeof(T) == 1) {
			return region->handlers.fnr8(port, region->opaque);
		}
		else if constexpr (sizeof(T) == 2) {
			return region->handlers.fnr16(port, region->opaque);
		}
		else if constexpr (sizeof(T) == 4) {
			return region->handlers.fnr32(port, region->opaque);
		}
		else {
			LIB86CPU_ABORT_msg("Unexpected size %u in %s", sizeof(T), __func__);
		}

	case mem_type::unmapped:
		LOG(log_level::warn, "Io read to unmapped memory at port %#06x with size %d", port, sizeof(T));
		return std::numeric_limits<T>::max();

	default:
		LIB86CPU_ABORT();
	}
}

template<typename T>
void as_io_dispatch_write(cpu_t *cpu, port_t port, T value, const memory_region_t<port_t> *region)
{
	switch (region->type)
	{
	case mem_type::pmio:
		if constexpr (sizeof(T) == 1) {
			region->handlers.fnw8(port, value, region->opaque);
		}
		else if constexpr (sizeof(T) == 2) {
			region->handlers.fnw16(port, value, region->opaque);
		}
		else if constexpr (sizeof(T) == 4) {
			region->handlers.fnw32(port, value, region->opaque);
		}
		else {
			LIB86CPU_ABORT_msg("Unexpected size %u in %s", sizeof(T), __func__);
		}
		break;

	case mem_type::unmapped:
		LOG(log_level::warn, "Io write to unmapped memory at port %#06x with size %d", port, sizeof(T));
		return;

	default:
		LIB86CPU_ABORT();
	}
}

/*
 * ram/rom specific accessors
 */
void *
get_rom_host_ptr(const memory_region_t<addr_t> *rom, addr_t addr)
{
	return &rom->rom_ptr[addr - rom->start];
}

void *
get_ram_host_ptr(cpu_t *cpu, addr_t addr)
{
	return &cpu->cpu_ctx.ram[addr - cpu->ram_start];
}

template<typename T>
T ram_read(cpu_t *cpu, void *ram_ptr)
{
	T value;
	memcpy(&value, ram_ptr, sizeof(T));
	if constexpr (is_big_endian) {
		swap_byte_order<T>(value);
	}
	return value;
}

template<typename T>
void ram_write(cpu_t *cpu, void *ram_ptr, T value)
{
	if constexpr (is_big_endian) {
		swap_byte_order<T>(value);
	}
	memcpy(ram_ptr, &value, sizeof(T));
}

/*
 * memory accessors
 */
template<typename T>
T mem_read_slow(cpu_t *cpu, addr_t addr, uint32_t eip, uint8_t is_priv)
{
	cpu_check_data_watchpoints(cpu, addr, sizeof(T), DR7_TYPE_DATA_RW, eip);
	if ((sizeof(T) != 1) && ((addr & ~PAGE_MASK) != ((addr + sizeof(T) - 1) & ~PAGE_MASK))) {
		T value = 0;
		uint8_t i = 0;
		addr_t phys_addr_s = get_read_addr(cpu, addr, is_priv, eip);
		addr_t phys_addr_e = get_read_addr(cpu, addr + sizeof(T) - 1, is_priv, eip);
		addr_t phys_addr = phys_addr_s;
		uint8_t bytes_in_page = ((addr + sizeof(T) - 1) & ~PAGE_MASK) - addr;
		while (i < sizeof(T)) {
			const memory_region_t<addr_t> *region = as_memory_search_addr(cpu, phys_addr);
			value |= (static_cast<T>(as_memory_dispatch_read<uint8_t>(cpu, phys_addr, region)) << (i * 8));
			phys_addr++;
			i++;
			if (i == bytes_in_page) {
				phys_addr = phys_addr_e & ~PAGE_MASK;
			}
		}
		if constexpr (is_big_endian) {
			swap_byte_order<T>(value);
		}
		return value;
	}
	else {
		addr_t phys_addr = get_read_addr(cpu, addr, is_priv, eip);
		return as_memory_dispatch_read<T>(cpu, phys_addr, as_memory_search_addr(cpu, phys_addr));
	}
}

template<typename T>
void mem_write_slow(cpu_t *cpu, addr_t addr, T value, uint32_t eip, uint8_t is_priv)
{
	cpu_check_data_watchpoints(cpu, addr, sizeof(T), DR7_TYPE_DATA_W, eip);
	if ((sizeof(T) != 1) && ((addr & ~PAGE_MASK) != ((addr + sizeof(T) - 1) & ~PAGE_MASK))) {
		uint8_t is_code1, is_code2;
		uint8_t i = 0;
		int8_t j = sizeof(T) - 1;
		addr_t phys_addr_s = get_write_addr(cpu, addr, is_priv, eip, &is_code1);
		addr_t phys_addr_e = get_write_addr(cpu, addr + sizeof(T) - 1, is_priv, eip, &is_code2);
		addr_t phys_addr = phys_addr_s;
		uint8_t bytes_in_page = ((addr + sizeof(T) - 1) & ~PAGE_MASK) - addr;
		if (is_code1) {
			tc_invalidate(&cpu->cpu_ctx, addr, bytes_in_page, eip);
		}
		if (is_code2) {
			tc_invalidate(&cpu->cpu_ctx, addr + sizeof(T) - 1, sizeof(T) - bytes_in_page, eip);
		}
		if constexpr (is_big_endian) {
			swap_byte_order<T>(value);
		}
		while (i < sizeof(T)) {
			const memory_region_t<addr_t> *region = as_memory_search_addr(cpu, phys_addr);
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
		addr_t phys_addr = get_write_addr(cpu, addr, is_priv, eip, &is_code);
		if (is_code) {
			tc_invalidate(&cpu->cpu_ctx, addr, sizeof(T), eip);
		}
		as_memory_dispatch_write<T>(cpu, phys_addr, value, as_memory_search_addr(cpu, phys_addr));
	}
}

template<typename T>
T mem_read(cpu_t *cpu, addr_t addr, uint32_t eip, uint8_t is_priv)
{
	return mem_read_helper<T>(&cpu->cpu_ctx, addr, eip, is_priv);
}

template<typename T>
void mem_write(cpu_t *cpu, addr_t addr, T val, uint32_t eip, uint8_t is_priv)
{
	mem_write_helper<T>(&cpu->cpu_ctx, addr, val, eip, is_priv);
}

/*
 * pmio specific accessors
 */
template<typename T>
T io_read(cpu_t *cpu, port_t port)
{
	return as_io_dispatch_read<T>(cpu, port, as_io_search_port(cpu, port));
}

template<typename T>
void io_write(cpu_t *cpu, port_t port, T value)
{
	as_io_dispatch_write<T>(cpu, port, value, as_io_search_port(cpu, port));
}
