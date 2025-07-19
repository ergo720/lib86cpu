/*
 * memory accessors
 *
 * ergo720                Copyright (c) 2019
 */

#pragma once

#include "lib86cpu_priv.h"
#include "internal.h"
#include <algorithm>
#include <cstring>

#define AS_RESOLVE_ALIAS() 	addr_t alias_offset = region->alias_offset; \
while (region->aliased_region) { \
	region = region->aliased_region; \
	alias_offset += region->alias_offset; \
}

void tlb_flush_g_l(cpu_t *cpu); // flushes global entries and undoes tc links
void tlb_flush_g(cpu_t *cpu); // flushes global entries
void tlb_flush_l(cpu_t *cpu); // undoes tc links
inline void *get_rom_host_ptr(const memory_region_t<addr_t> *rom, addr_t addr);
inline void *get_ram_host_ptr(cpu_t *cpu, const memory_region_t<addr_t> *ram, addr_t addr);
addr_t get_read_addr_slow(cpu_t * cpu, addr_t addr, uint8_t is_priv);
addr_t get_read_addr(cpu_t *cpu, addr_t addr, uint8_t is_priv);
addr_t get_read_addr(cpu_t *cpu, addr_t addr, uint8_t is_priv, exp_data_t *exp_data);
addr_t query_read_addr(cpu_t *cpu, addr_t addr, uint8_t is_priv, exp_data_t *exp_data, uint32_t *page_info);
addr_t get_write_addr_slow(cpu_t * cpu, addr_t addr, uint8_t is_priv, bool* is_code);
addr_t get_write_addr(cpu_t *cpu, addr_t addr, uint8_t is_priv, bool *is_code);
addr_t get_write_addr(cpu_t *cpu, addr_t addr, uint8_t is_priv, bool *is_code, exp_data_t *exp_data);
addr_t query_write_addr(cpu_t *cpu, addr_t addr, uint8_t is_priv, bool *is_code, exp_data_t *exp_data, uint32_t *page_info);
addr_t get_code_addr(cpu_t *cpu, addr_t addr);
template<bool set_smc> addr_t get_code_addr(cpu_t * cpu, addr_t addr, exp_data_t *exp_data);
template<typename T> T ram_read(cpu_t *cpu, void *ram_ptr);
template<typename T> void ram_write(cpu_t *cpu, void *ram_ptr, T value);
void ram_fetch(cpu_t *cpu, disas_ctx_t *disas_ctx, uint8_t *buffer);
uint64_t as_ram_dispatch_read(cpu_t *cpu, addr_t addr, uint64_t size, const memory_region_t<addr_t> *region, uint8_t *buffer);
template<typename T> T mem_read_helper(cpu_ctx_t *cpu_ctx, addr_t addr, uint8_t is_priv);
template<typename T, bool dont_write = false> void mem_write_helper(cpu_ctx_t *cpu_ctx, addr_t addr, T val, uint8_t is_priv);
template<typename T> JIT_API T mem_read_jit_helper(cpu_ctx_t *cpu_ctx, addr_t addr);
template<typename T, bool dont_write = false> JIT_API void mem_write_jit_helper(cpu_ctx_t *cpu_ctx, addr_t addr, T val);
template<typename T> JIT_API T io_read_helper(cpu_ctx_t * cpu_ctx, port_t port);
template<typename T> JIT_API void io_write_helper(cpu_ctx_t * cpu_ctx, port_t port, T val);

inline constexpr uint64_t tlb_access[2][4] = {
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
	constexpr auto type_size = sizeof_type<T>();

	switch (region->type)
	{
	case mem_type::ram:
		return ram_read<T>(cpu, get_ram_host_ptr(cpu, region, addr));

	case mem_type::rom:
		if ((addr + type_size - 1) > region->end) [[unlikely]] {
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
		if constexpr (type_size == 1) {
			return region->handlers.fnr8(addr, region->opaque);
		}
		else if constexpr (type_size == 2) {
			return region->handlers.fnr16(addr, region->opaque);
		}
		else if constexpr (type_size == 4) {
			return region->handlers.fnr32(addr, region->opaque);
		}
		else if constexpr (type_size == 8) {
			return region->handlers.fnr64(addr, region->opaque);
		}
		else {
			LIB86CPU_ABORT_msg("Unexpected size %u in %s", type_size, __func__);
		}

	case mem_type::alias: {
		const memory_region_t<addr_t> *alias = region;
		AS_RESOLVE_ALIAS();
		return as_memory_dispatch_read<T>(cpu, region->start + alias_offset + (addr - alias->start), region);
	}
	break;

	case mem_type::unmapped:
		return log_unhandled_read<T, mem_type::unmapped>(addr);

	default:
		LIB86CPU_ABORT();
	}
}

template<typename T>
void as_memory_dispatch_write(cpu_t *cpu, addr_t addr, T value, const memory_region_t<addr_t> *region)
{
	constexpr auto type_size = sizeof_type<T>();

	switch (region->type)
	{
	case mem_type::ram:
		ram_write<T>(cpu, get_ram_host_ptr(cpu, region, addr), value);
		break;

	case mem_type::rom:
		break;

	case mem_type::mmio:
		if constexpr (type_size == 1) {
			region->handlers.fnw8(addr, value, region->opaque);
		}
		else if constexpr (type_size == 2) {
			region->handlers.fnw16(addr, value, region->opaque);
		}
		else if constexpr (type_size == 4) {
			region->handlers.fnw32(addr, value, region->opaque);
		}
		else if constexpr (type_size == 8) {
			region->handlers.fnw64(addr, value, region->opaque);
		}
		else {
			LIB86CPU_ABORT_msg("Unexpected size %u in %s", type_size, __func__);
		}
		break;

	case mem_type::alias: {
		const memory_region_t<addr_t> *alias = region;
		AS_RESOLVE_ALIAS();
		as_memory_dispatch_write<T>(cpu, region->start + alias_offset + (addr - alias->start), value, region);
	}
	break;

	case mem_type::unmapped:
		log_unhandled_write<T, mem_type::unmapped>(addr, value);
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
			LIB86CPU_ABORT_msg("Unexpected size %u in %s", sizeof_type<T>(), __func__);
		}

	case mem_type::unmapped:
		return log_unhandled_read<T, mem_type::unmapped, true>(port);

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
			LIB86CPU_ABORT_msg("Unexpected size %u in %s", sizeof_type<T>(), __func__);
		}
		break;

	case mem_type::unmapped:
		log_unhandled_write<T, mem_type::unmapped, true>(port, value);
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
	return &rom->rom_ptr[addr - rom->buff_off_start];
}

void *
get_ram_host_ptr(cpu_t *cpu, const memory_region_t<addr_t> *ram, addr_t addr)
{
	return &cpu->ram[addr - ram->buff_off_start];
}

template<typename T>
T ram_read(cpu_t *cpu, void *ram_ptr)
{
	T value;
	memcpy(&value, ram_ptr, sizeof_type<T>());
	return value;
}

template<typename T>
void ram_write(cpu_t *cpu, void *ram_ptr, T value)
{
	memcpy(ram_ptr, &value, sizeof_type<T>());
}

/*
 * memory accessors
 */
template<typename T>
T mem_read_slow(cpu_t *cpu, addr_t addr, uint8_t is_priv)
{
	constexpr auto type_size = sizeof_type<T>();

	if ((type_size != 1) && ((addr & ~PAGE_MASK) != ((addr + type_size - 1) & ~PAGE_MASK))) {
		T value = 0;
		uint8_t i = 0;
		addr_t phys_addr_s = get_read_addr_slow(cpu, addr, is_priv);
		addr_t phys_addr_e = get_read_addr_slow(cpu, addr + type_size - 1, is_priv);
		cpu_check_data_watchpoints(cpu, addr, type_size, DR7_TYPE_DATA_RW);
		addr_t phys_addr = phys_addr_s;
		uint8_t bytes_in_page = ((addr + type_size - 1) & ~PAGE_MASK) - addr;
		while (i < type_size) {
			const memory_region_t<addr_t> *region = as_memory_search_addr(cpu, phys_addr);
			value |= (static_cast<T>(as_memory_dispatch_read<uint8_t>(cpu, phys_addr, region)) << (i * 8));
			phys_addr++;
			i++;
			if (i == bytes_in_page) {
				phys_addr = phys_addr_e & ~PAGE_MASK;
			}
		}
		return value;
	}
	else {
		addr_t phys_addr = get_read_addr_slow(cpu, addr, is_priv);
		cpu_check_data_watchpoints(cpu, addr, type_size, DR7_TYPE_DATA_RW);
		return as_memory_dispatch_read<T>(cpu, phys_addr, as_memory_search_addr(cpu, phys_addr));
	}
}

template<typename T>
void mem_write_slow(cpu_t *cpu, addr_t addr, T value, uint8_t is_priv)
{
	constexpr auto type_size = sizeof_type<T>();

	if ((type_size != 1) && ((addr & ~PAGE_MASK) != ((addr + type_size - 1) & ~PAGE_MASK))) {
		bool is_code1, is_code2;
		uint8_t i = 0;
		addr_t phys_addr_s = get_write_addr_slow(cpu, addr, is_priv, &is_code1);
		addr_t phys_addr_e = get_write_addr_slow(cpu, addr + type_size - 1, is_priv, &is_code2);
		cpu_check_data_watchpoints(cpu, addr, type_size, DR7_TYPE_DATA_W);
		addr_t phys_addr = phys_addr_s;
		uint8_t bytes_in_page = ((addr + type_size - 1) & ~PAGE_MASK) - addr;
		if (is_code1) {
			tc_invalidate(&cpu->cpu_ctx, phys_addr_s, bytes_in_page);
		}
		if (is_code2) {
			tc_invalidate(&cpu->cpu_ctx, phys_addr_e, type_size - bytes_in_page);
		}
		while (i < type_size) {
			const memory_region_t<addr_t> *region = as_memory_search_addr(cpu, phys_addr);
			as_memory_dispatch_write<uint8_t>(cpu, phys_addr, static_cast<uint8_t>(value >> (i * 8)), region);
			phys_addr++;
			i++;
			if (i == bytes_in_page) {
				phys_addr = phys_addr_e & ~PAGE_MASK;
			}
		}
	}
	else {
		bool is_code;
		addr_t phys_addr = get_write_addr_slow(cpu, addr, is_priv, &is_code);
		cpu_check_data_watchpoints(cpu, addr, type_size, DR7_TYPE_DATA_W);
		if (is_code) {
			tc_invalidate(&cpu->cpu_ctx, phys_addr, type_size);
		}
		as_memory_dispatch_write<T>(cpu, phys_addr, value, as_memory_search_addr(cpu, phys_addr));
	}
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
