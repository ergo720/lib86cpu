/*
 * lib86cpu test app loader
 *
 * ergo720                Copyright (c) 2019
 * the libcpu developers  Copyright (c) 2009-2010
 */

#include "lib86cpu.h"
#include <cstdio>
#include <string>
#include <fstream>


void print_help()
{
	static const char *help =
		"usage: [options] <path of the binary to run>\n\
options: \n\
-p         Print llvm IR code\n\
-i         Use Intel syntax (default is AT&T)\n\
-c <addr>  Start address of code\n\
-e <addr>  Address of first instruction\n\
-s <size>  Size (in bytes) to allocate for RAM\n\
-h         Print this message\n";

	printf("%s", help);
}

int
main(int argc, char **argv)
{
	cpu_t *cpu;
	size_t ramsize, length;
	addr_t code_start, code_entry;
	std::string executable;
	int print_ir = 0;
	int intel_syntax = 0;

	ramsize = 1 * 1024 * 1024;
	code_start = 0;
	code_entry = 0;

	/* parameter parsing */
	if (argc < 2) {
		print_help();
		return 0;
	}

	for (int idx = 1; idx < argc; idx++) {
		try {
			std::string arg_str(argv[idx]);
			if (arg_str.size() == 2 && arg_str.front() == '-') {
				switch (arg_str.at(1))
				{
				case 'p':
					print_ir = 1;
					break;

				case 'i':
					intel_syntax = 1;
					break;

				case 'c':
					if (++idx == argc || argv[idx][0] == '-') {
						printf("Missing argument for option \"c\"\n");
						return 0;
					}
					code_start = std::stoull(std::string(argv[idx]), nullptr, 0);
					break;

				case 'e':
					if (++idx == argc || argv[idx][0] == '-') {
						printf("Missing argument for option \"e\"\n");
						return 0;
					}
					code_entry = std::stoull(std::string(argv[idx]), nullptr, 0);
					break;

				case 's':
					if (++idx == argc || argv[idx][0] == '-') {
						printf("Missing argument for option \"s\"\n");
						return 0;
					}
					ramsize = std::stoull(std::string(argv[idx]), nullptr, 0);
					break;

				case 'h':
					print_help();
					return 0;

				default:
					printf("Unknown option %s\n", arg_str.c_str());
					print_help();
					return 0;
				}
			}
			else if ((idx + 1) == argc) {
				executable = std::move(arg_str);
				break;
			}
			else {
				printf("Unknown option %s\n", arg_str.c_str());
				print_help();
				return 0;
			}
		}
		/* Handle exceptions thrown by std::stoull */
		catch (std::exception &e) {
			printf("Failed to parse addr and/or size arguments. The error was: %s\n", e.what());
			return 1;
		}
	}

#if TEST386_ASM

	ramsize = 1 * 1024 * 1024;
	code_start = 0xF0000;

#endif

	/* load code */
	std::ifstream ifs(executable, std::ios_base::in | std::ios_base::binary);
	if (!ifs.is_open()) {
		printf("Could not open binary file \"%s\"!\n", executable.c_str());
		return 1;
	}
	ifs.seekg(0, ifs.end);
	length = ifs.tellg();
	ifs.seekg(0, ifs.beg);

	/* Sanity checks */
	if (length == 0) {
		printf("Size of binary file \"%s\" detected as zero!\n", executable.c_str());
		return 1;
	}
	else if (length > ramsize - code_start) {
		printf("Binary file \"%s\" doesn't fit inside RAM!\n", executable.c_str());
		return 1;
	}

	if (!LIB86CPU_CHECK_SUCCESS(cpu_new(ramsize, cpu))) {
		printf("Failed to initialize lib86cpu!\n");
		return 1;
	}

	ifs.read((char *)&cpu->ram[code_start], length);
	ifs.close();

	cpu->cpu_flags = (CPU_PRINT_IR | CPU_PRINT_IR_OPTIMIZED | CPU_CODEGEN_OPTIMIZE);

#if TEST386_ASM

	if (!LIB86CPU_CHECK_SUCCESS(memory_init_region_ram(cpu, 0, ramsize, 1))) {
		printf("Failed to initialize ram memory!\n");
		return 1;
	}

	if (!LIB86CPU_CHECK_SUCCESS(memory_init_region_alias(cpu, 0xFFFF0000, 0xF0000, 0x10000, 1))) {
		printf("Failed to initialize aliased ram memory!\n");
		return 1;
	}

#else

	cpu->regs.cs = 0;
	cpu->regs.cs_hidden.base = 0;
	cpu->regs.eip = code_entry;

	if (!LIB86CPU_CHECK_SUCCESS(memory_init_region_ram(cpu, 0, ramsize, 1))) {
		printf("Failed to initialize ram memory!\n");
		return 1;
	}

#endif

	cpu_run(cpu);

	cpu_free(cpu);

	return 0;
}
