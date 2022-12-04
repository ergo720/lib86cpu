/*
 * lib86cpu test386 app test generator (https://github.com/barotto/test386.asm)
 *
 * ergo720                Copyright (c) 2021
 */

#include "run.h"
#include <fstream>

#define TEST386_POST_PORT 0x190
#define TEST386_EE_PORT 0x55


static void
test386_write_handler(addr_t addr, const uint8_t value, void *opaque)
{
	switch (addr)
	{
	case TEST386_POST_PORT:
		printf("Test number is 0x%X\n", static_cast<const uint8_t>(value));
		break;

	case TEST386_EE_PORT: {
		static std::string str = "";
		if (static_cast<const char>(value) == '\n') {
			printf("%s", (str + '\n').c_str());
			str.clear();
		}
		else {
			str += static_cast<const char>(value);
		}
	}
	break;

	default:
		printf("Unhandled i/o write at port %d\n", addr);
	}
}

bool
gen_test386asm_test(const std::string &executable)
{
	addr_t code_start = 0xF0000;
	size_t ramsize = 1 * 1024 * 1024;

	/* load code */
	std::ifstream ifs(executable, std::ios_base::in | std::ios_base::binary);
	if (!ifs.is_open()) {
		printf("Could not open binary file \"%s\"!\n", executable.c_str());
		return false;
	}
	ifs.seekg(0, ifs.end);
	std::streampos length = ifs.tellg();
	ifs.seekg(0, ifs.beg);

	/* Sanity checks */
	if (length == 0) {
		printf("Size of binary file \"%s\" detected as zero!\n", executable.c_str());
		return false;
	}
	else if (length > ramsize - code_start) {
		printf("Binary file \"%s\" doesn't fit inside RAM!\n", executable.c_str());
		return false;
	}

	if (!LC86_SUCCESS(cpu_new(ramsize, cpu))) {
		printf("Failed to initialize lib86cpu!\n");
		return false;
	}

	uint8_t *ram = get_ram_ptr(cpu);

	ifs.read((char *)&ram[code_start], length);
	ifs.close();

	if (!LC86_SUCCESS(mem_init_region_ram(cpu, 0, ramsize))) {
		printf("Failed to initialize ram memory for test386.asm!\n");
		return false;
	}

	if (!LC86_SUCCESS(mem_init_region_alias(cpu, 0xFFFF0000, 0xF0000, 0x10000))) {
		printf("Failed to initialize aliased ram memory for test386.asm!\n");
		return false;
	}

	if (!LC86_SUCCESS(mem_init_region_io(cpu, TEST386_POST_PORT, 1, true, io_handlers_t{ .fnw8 = test386_write_handler }, nullptr))) {
		printf("Failed to initialize post i/o port for test386.asm!\n");
		return false;
	}

	if (!LC86_SUCCESS(mem_init_region_io(cpu, TEST386_EE_PORT, 1, true, io_handlers_t{ .fnw8 = test386_write_handler }, nullptr))) {
		printf("Failed to initialize i/o port used by test 0xEE for test386.asm!\n");
		return false;
	}

	return true;
}
