/*
 * memory support
 *
 * ergo720                Copyright (c) 2019
 */

#include "x86_memory.h"


addr_t
get_ram_addr(cpu_t *cpu, addr_t pc)
{
	cpu->memory_space_tree->search(pc, pc, cpu->memory_out);

	if ((pc >= std::get<0>(*cpu->memory_out.begin())) && (pc <= std::get<1>(*cpu->memory_out.begin()))) {
		switch (std::get<2>(*cpu->memory_out.begin())->type)
		{
		case MEM_RAM: {
			return pc;
		}
		break;

		case MEM_ALIAS: {
			memory_region_t<addr_t> *region = std::get<2>(*cpu->memory_out.begin()).get();
			addr_t alias_offset = region->alias_offset;
			while (region->aliased_region) {
				region = region->aliased_region;
				alias_offset += region->alias_offset;
			}
			return get_ram_addr(cpu, region->start + alias_offset + (pc - std::get<0>(*cpu->memory_out.begin())));
		}
		break;

		default:
			// TODO: handle this properly instead of just aborting
			printf("%s: pc is not inside ram region. pc was %#02x\n", __func__, pc);
			exit(1);
		}
	}
	else {
		// TODO: handle this properly instead of just aborting
		printf("%s: instruction fetching at address %#02x is not completely inside a memory region\n", __func__, pc);
		exit(1);
	}
}

uint8_t
mem_read8(uint8_t *cpu, addr_t addr)
{
	return mem_read<uint8_t>(reinterpret_cast<cpu_t *>(cpu), addr);
}

uint16_t
mem_read16(uint8_t *cpu, addr_t addr)
{
	return mem_read<uint16_t>(reinterpret_cast<cpu_t *>(cpu), addr);
}

uint32_t
mem_read32(uint8_t *cpu, addr_t addr)
{
	return mem_read<uint32_t>(reinterpret_cast<cpu_t *>(cpu), addr);
}

void
mem_write8(uint8_t *cpu, addr_t addr, uint8_t value)
{
	mem_write<uint8_t>(reinterpret_cast<cpu_t *>(cpu), addr, value);
}

void
mem_write16(uint8_t *cpu, addr_t addr, uint16_t value)
{
	mem_write<uint16_t>(reinterpret_cast<cpu_t *>(cpu), addr, value);
}

void
mem_write32(uint8_t *cpu, addr_t addr, uint32_t value)
{
	mem_write<uint32_t>(reinterpret_cast<cpu_t *>(cpu), addr, value);
}


void
io_write8(uint8_t *cpu, io_port_t port, uint8_t value)
{
	io_write<uint8_t>(reinterpret_cast<cpu_t *>(cpu), port, value);
}

void
io_write16(uint8_t *cpu, io_port_t port, uint16_t value)
{
	io_write<uint16_t>(reinterpret_cast<cpu_t *>(cpu), port, value);
}

void
io_write32(uint8_t *cpu, io_port_t port, uint32_t value)
{
	io_write<uint32_t>(reinterpret_cast<cpu_t *>(cpu), port, value);
}
