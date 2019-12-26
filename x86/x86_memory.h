/*
 * memory accessors
 *
 * ergo720                Copyright (c) 2019
 */

#pragma once

#include "llvm/support/SwapByteOrder.h"
#include "lib86cpu.h"


addr_t get_ram_addr(cpu_t *cpu, addr_t pc);
JIT_EXTERNAL_CALL_C uint8_t mem_read8(uint8_t *cpu, addr_t addr);
JIT_EXTERNAL_CALL_C uint16_t mem_read16(uint8_t *cpu, addr_t addr);
JIT_EXTERNAL_CALL_C uint32_t mem_read32(uint8_t *cpu, addr_t addr);
JIT_EXTERNAL_CALL_C void mem_write8(uint8_t *cpu, addr_t addr, uint8_t value);
JIT_EXTERNAL_CALL_C void mem_write16(uint8_t *cpu, addr_t addr, uint16_t value);
JIT_EXTERNAL_CALL_C void mem_write32(uint8_t *cpu, addr_t addr, uint32_t value);
JIT_EXTERNAL_CALL_C void io_write8(uint8_t *cpu, io_port_t port, uint8_t value);
JIT_EXTERNAL_CALL_C void io_write16(uint8_t *cpu, io_port_t port, uint16_t value);
JIT_EXTERNAL_CALL_C void io_write32(uint8_t *cpu, io_port_t port, uint32_t value);

/*
 * ram specific accessors
 */
template<typename T>
T ram_read(cpu_t *cpu, addr_t *pc)
{
	T value;

	memcpy(&value, &cpu->ram[*pc], sizeof(T));
	*pc = *pc + sizeof(T);

	if (cpu->cpu_flags & CPU_FLAG_SWAPMEM && sizeof(T) != 1) {
		switch (sizeof(T)) {
		case 4: {
			value = sys::SwapByteOrder_32(value);
		}
		break;

		case 2: {
			value = sys::SwapByteOrder_16(value);
		}
		break;

		default:
			LIB86CPU_ABORT();
		}
	}

	return value;
}

template<typename T>
void ram_write(cpu_t *cpu, addr_t *pc, T value)
{
	if (cpu->cpu_flags & CPU_FLAG_SWAPMEM && sizeof(T) != 1) {
		switch (sizeof(T)) {
		case 4: {
			value = sys::SwapByteOrder_32(value);
		}
		break;

		case 2: {
			value = sys::SwapByteOrder_16(value);
		}
		break;

		default:
			LIB86CPU_ABORT();
		}
	}

	memcpy(&cpu->ram[*pc], &value, sizeof(T));
	*pc = *pc + sizeof(T);
}

/*
 * generic memory accessors
 */
template<typename T>
T mem_read(cpu_t *cpu, addr_t addr)
{
	addr_t end;

	end = addr + sizeof(T) - 1;
	cpu->memory_space_tree->search(addr, end, cpu->memory_out);

	if ((addr >= std::get<0>(*cpu->memory_out.begin())) && (end <= std::get<1>(*cpu->memory_out.begin()))) {
		switch (std::get<2>(*cpu->memory_out.begin())->type)
		{
		case MEM_RAM: {
			return ram_read<T>(cpu, &addr);
		}
		break;

		case MEM_MMIO: {
			memory_region_t<addr_t> *region = std::get<2>(*cpu->memory_out.begin()).get();
			return region->read_handler(addr, sizeof(T), region->opaque);;
		}
		break;

		case MEM_ALIAS: {
			memory_region_t<addr_t> *region = std::get<2>(*cpu->memory_out.begin()).get();
			addr_t alias_offset = region->alias_offset;
			while (region->aliased_region) {
				region = region->aliased_region;
				alias_offset += region->alias_offset;
			}
			return mem_read<T>(cpu, region->start + alias_offset + (addr - std::get<0>(*cpu->memory_out.begin())));
		}
		break;

		case MEM_UNMAPPED: {
			LOG("Memory read to unmapped memory at address %#010x with size %d\n", addr, sizeof(T));
			return 0xFFFFFFFF;
		}
		break;

		default:
			LIB86CPU_ABORT();
		}
	}
	else {
		LOG("Memory read at address %#010x with size %d is not completely inside a memory region\n", addr, sizeof(T));
		return 0xFFFFFFFF;
	}
}

template<typename T>
void mem_write(cpu_t *cpu, addr_t addr, T value)
{
	addr_t end;

	end = addr + sizeof(T) - 1;
	cpu->memory_space_tree->search(addr, end, cpu->memory_out);

	if ((addr >= std::get<0>(*cpu->memory_out.begin())) && (end <= std::get<1>(*cpu->memory_out.begin()))) {
		switch (std::get<2>(*cpu->memory_out.begin())->type)
		{
		case MEM_RAM: {
			ram_write<T>(cpu, &addr, value);
		}
		break;

		case MEM_MMIO: {
			memory_region_t<addr_t> *region = std::get<2>(*cpu->memory_out.begin()).get();
			region->write_handler(addr, sizeof(T), value, region->opaque);
		}
		break;

		case MEM_ALIAS: {
			memory_region_t<addr_t> *region = std::get<2>(*cpu->memory_out.begin()).get();
			addr_t alias_offset = region->alias_offset;
			while (region->aliased_region) {
				region = region->aliased_region;
				alias_offset += region->alias_offset;
			}
			mem_write<T>(cpu, region->start + alias_offset + (addr - std::get<0>(*cpu->memory_out.begin())), value);
		}
		break;

		case MEM_UNMAPPED: {
			LOG("Memory write to unmapped memory at address %#010x with size %d\n", addr, sizeof(T));
			return;
		}
		break;

		default:
			LIB86CPU_ABORT();
		}
	}
	else {
		LOG("Memory write at address %#010x with size %d is not completely inside a memory region\n", addr, sizeof(T));
		return;
	}
}

/*
 * pmio specific accessors
 */
template<typename T>
T io_read(cpu_t *cpu, io_port_t port)
{
	io_port_t end;

	end = port + sizeof(T) - 1;
	cpu->io_space_tree->search(port, end, cpu->io_out);

	if ((port >= std::get<0>(*cpu->io_out.begin())) && (end <= std::get<1>(*cpu->io_out.begin()))) {
		switch (std::get<2>(*cpu->io_out.begin())->type)
		{
		case MEM_PMIO: {
			memory_region_t<io_port_t> *region = std::get<2>(*cpu->io_out.begin()).get();
			return region->read_handler(port, sizeof(T), region->opaque);;
		}
		break;

		case MEM_UNMAPPED: {
			LOG("Memory read to unmapped memory at port %#06hx with size %d\n", port, sizeof(T));
			return 0xFFFFFFFF;
		}
		break;

		default:
			LIB86CPU_ABORT();
		}
	}
	else {
		LOG("Memory read at address %#06hx with size %d is not completely inside a memory region\n", port, sizeof(T));
		return 0xFFFFFFFF;
	}
}

template<typename T>
void io_write(cpu_t *cpu, io_port_t port, T value)
{
	io_port_t end;

	end = port + sizeof(T) - 1;
	cpu->io_space_tree->search(port, end, cpu->io_out);

	if ((port >= std::get<0>(*cpu->io_out.begin())) && (end <= std::get<1>(*cpu->io_out.begin()))) {
		switch (std::get<2>(*cpu->io_out.begin())->type)
		{
		case MEM_PMIO: {
			memory_region_t<io_port_t> *region = std::get<2>(*cpu->io_out.begin()).get();
			region->write_handler(port, sizeof(T), value, region->opaque);
		}
		break;

		case MEM_UNMAPPED: {
			LOG("Memory write to unmapped memory at port %#06hx with size %d\n", port, sizeof(T));
			return;
		}
		break;

		default:
			LIB86CPU_ABORT();
		}
	}
	else {
		LOG("Memory write at port %#06hx with size %d is not completely inside a memory region\n", port, sizeof(T));
		return;
	}
}
