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
