/*
 * lib86cpu test386 app test generator (https://github.com/barotto/test386.asm)
 *
 * ergo720                Copyright (c) 2021
 */

#include "run.h"

#define TEST386_POST_PORT 0x190
#define TEST386_EE_PORT 0x55


static void
test386_write_handler(addr_t addr, size_t size, const uint64_t value, void *opaque)
{
	switch (addr)
	{
	case TEST386_POST_PORT: {
		if (size == 1) {
			printf("Test number is 0x%X\n", static_cast<const uint8_t>(value));
		}
		else {
			printf("Unhandled i/o port size at port %d\n", TEST386_POST_PORT);
		}
	}
	break;

	case TEST386_EE_PORT: {
		static std::string str = "";
		if (size == 1) {
			if (static_cast<const char>(value) == '\n') {
				printf("%s", (str + '\n').c_str());
				str.clear();
			}
			else {
				str += static_cast<const char>(value);
			}
		}
		else {
			printf("Unhandled i/o port size at port %d\n", TEST386_EE_PORT);
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

	if (create_cpu(executable, ram, ramsize, code_start) == false) {
		return false;
	}

	if (!LIB86CPU_CHECK_SUCCESS(mem_init_region_ram(cpu, 0, ramsize, 1))) {
		printf("Failed to initialize ram memory for test386.asm!\n");
		return false;
	}

	if (!LIB86CPU_CHECK_SUCCESS(mem_init_region_alias(cpu, 0xFFFF0000, 0xF0000, 0x10000, 1))) {
		printf("Failed to initialize aliased ram memory for test386.asm!\n");
		return false;
	}

	if (!LIB86CPU_CHECK_SUCCESS(mem_init_region_io(cpu, TEST386_POST_PORT, 0x1, true, nullptr, test386_write_handler, nullptr, 1))) {
		printf("Failed to initialize post i/o port for test386.asm!\n");
		return false;
	}

	if (!LIB86CPU_CHECK_SUCCESS(mem_init_region_io(cpu, TEST386_EE_PORT, 0x1, true, nullptr, test386_write_handler, nullptr, 1))) {
		printf("Failed to initialize i/o port used by test 0xEE for test386.asm!\n");
		return false;
	}

	return true;
}
