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
			printf("%s: invalid size %u specified\n", __func__, sizeof(T));
			exit(1);
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
			printf("%s: invalid size %u specified\n", __func__, sizeof(T));
			exit(1);
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
			T value = 0;
			memory_region_t<addr_t> *region = std::get<2>(*cpu->memory_out.begin()).get();
			if (region->read_handler) {
				value = region->read_handler(addr, sizeof(T), region->opaque);
			}
			else {
				printf("%s: unhandled MMIO read at address %#02x with size %d\n", __func__, addr, sizeof(T));
			}
			return value;
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
			// TODO: handle this properly instead of just aborting
			printf("%s: memory access to unmapped memory at address %#02x with size %d\n", __func__, addr, sizeof(T));
			exit(1);
		}
		break;

		default:
			// TODO: handle this properly instead of just aborting
			printf("%s: unknown region type\n", __func__);
			exit(1);
		}
	}
	else {
		// TODO: handle this properly instead of just aborting
		printf("%s: memory access at address %#02x with size %d is not completely inside a memory region\n", __func__, addr, sizeof(T));
		exit(1);
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
			if (region->write_handler) {
				region->write_handler(addr, sizeof(T), value, region->opaque);
			}
			else {
				printf("%s: unhandled MMIO write at address %#02x with size %d\n", __func__, addr, sizeof(T));
			}
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
			// TODO: handle this properly instead of just aborting
			printf("%s: memory access to unmapped memory at address %#02x with size %d\n", __func__, addr, sizeof(T));
			exit(1);
		}
		break;

		default:
			// TODO: handle this properly instead of just aborting
			printf("%s: unknown region type\n", __func__);
			exit(1);
		}
	}
	else {
		// TODO: handle this properly instead of just aborting
		printf("%s: memory access at address %#02x with size %d is not completely inside a memory region\n", __func__, addr, sizeof(T));
		exit(1);
	}
}

/*
 * pmio specific accessors
 */
template<typename T>
T io_read(cpu_t *cpu, io_port_t addr)
{
	io_port_t end;

	end = addr + sizeof(T) - 1;
	cpu->io_space_tree->search(addr, end, cpu->io_out);

	if ((addr >= std::get<0>(*cpu->io_out.begin())) && (end <= std::get<1>(*cpu->io_out.begin()))) {
		switch (std::get<2>(*cpu->io_out.begin())->type)
		{
		case MEM_PMIO: {
			T value = 0;
			memory_region_t<io_port_t> *region = std::get<2>(*cpu->io_out.begin()).get();
			if (region->read_handler) {
				value = region->read_handler(addr, sizeof(T), region->opaque);
			}
			else {
				printf("%s: unhandled PMIO read at address %#02hx with size %d\n", __func__, addr, sizeof(T));
			}
			return value;
		}
		break;

		case MEM_UNMAPPED: {
			// TODO: handle this properly instead of just aborting
			printf("%s: memory access to unmapped memory at address %#02hx with size %d\n", __func__, addr, sizeof(T));
			exit(1);
		}
		break;

		default:
			// TODO: handle this properly instead of just aborting
			printf("%s: unknown region type\n", __func__);
			exit(1);
		}
	}
	else {
		// TODO: handle this properly instead of just aborting
		printf("%s: io access at address %#02hx with size %d is not completely inside a memory region\n", __func__, addr, sizeof(T));
		exit(1);
	}
}

template<typename T>
void io_write(cpu_t *cpu, io_port_t addr, T value)
{
	io_port_t end;

	end = addr + sizeof(T) - 1;
	cpu->io_space_tree->search(addr, end, cpu->io_out);

	if ((addr >= std::get<0>(*cpu->io_out.begin())) && (end <= std::get<1>(*cpu->io_out.begin()))) {
		switch (std::get<2>(*cpu->io_out.begin())->type)
		{
		case MEM_PMIO: {
			memory_region_t<io_port_t> *region = std::get<2>(*cpu->io_out.begin()).get();
			if (region->write_handler) {
				region->write_handler(addr, sizeof(T), value, region->opaque);
			}
			else {
				printf("%s: unhandled PMIO write at address %#02hx with size %d\n", __func__, addr, sizeof(T));
			}
		}
		break;

		case MEM_UNMAPPED: {
			// TODO: handle this properly instead of just aborting
			printf("%s: memory access to unmapped memory at address %#02hx with size %d\n", __func__, addr, sizeof(T));
			exit(1);
		}
		break;

		default:
			printf("%s: unknown region type\n", __func__);
			exit(1);
		}
	}
	else {
		// TODO: handle this properly instead of just aborting
		printf("%s: io access at address %#02hx with size %d is not completely inside a memory region\n", __func__, addr, sizeof(T));
		exit(1);
	}
}
