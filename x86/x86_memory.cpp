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
		LIB86CPU_ABORT();
	}
}

uint8_t
mem_read8(cpu_ctx_t *cpu_ctx, addr_t addr)
{
	return mem_read<uint8_t>(cpu_ctx->cpu, addr);
}

uint16_t
mem_read16(cpu_ctx_t *cpu_ctx, addr_t addr)
{
	return mem_read<uint16_t>(cpu_ctx->cpu, addr);
}

uint32_t
mem_read32(cpu_ctx_t *cpu_ctx, addr_t addr)
{
	return mem_read<uint32_t>(cpu_ctx->cpu, addr);
}

void
mem_write8(cpu_ctx_t *cpu_ctx, addr_t addr, uint8_t value)
{
	mem_write<uint8_t>(cpu_ctx->cpu, addr, value);
}

void
mem_write16(cpu_ctx_t *cpu_ctx, addr_t addr, uint16_t value)
{
	mem_write<uint16_t>(cpu_ctx->cpu, addr, value);
}

void
mem_write32(cpu_ctx_t *cpu_ctx, addr_t addr, uint32_t value)
{
	mem_write<uint32_t>(cpu_ctx->cpu, addr, value);
}


void
io_write8(cpu_ctx_t *cpu_ctx, io_port_t port, uint8_t value)
{
	io_write<uint8_t>(cpu_ctx->cpu, port, value);
}

void
io_write16(cpu_ctx_t *cpu_ctx, io_port_t port, uint16_t value)
{
	io_write<uint16_t>(cpu_ctx->cpu, port, value);
}

void
io_write32(cpu_ctx_t *cpu_ctx, io_port_t port, uint32_t value)
{
	io_write<uint32_t>(cpu_ctx->cpu, port, value);
}
