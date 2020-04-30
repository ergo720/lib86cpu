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

#define TEST386_POST_PORT 0x190
cpu_t *cpu = nullptr;

#if _WIN32
#define HAS_HOOK_TEST 1
#endif

#if HAS_HOOK_TEST
#if _WIN32
#define FASTCALL __fastcall
#define STDCALL __stdcall
#endif
#endif


#ifdef HAS_HOOK_TEST

uint64_t
FASTCALL test1(uint64_t a, uint16_t b, uint8_t c, uint32_t d)
{
	printf("Hook called with args: %llu, %hu, %u, %u\n", a, b, c, d);

	std::any ret;
	if (!LIB86CPU_CHECK_SUCCESS(trampoline_call(cpu, 0x17, ret, ANY_VEC(a, ANY_I32s(b), c, d)))) {
		printf("Failed to call trampoline at address 0x17!\n");
	}

	printf("Trampoline at address 0x17 returned %llu\n", std::any_cast<uint64_t>(ret));

	if (!LIB86CPU_CHECK_SUCCESS(trampoline_call(cpu, 0x17, ret, ANY_VEC(a, ANY_I32s(b), c, d)))) {
		printf("Failed to call trampoline at address 0x17!\n");
	}

	printf("Trampoline at address 0x17 returned %llu\n", std::any_cast<uint64_t>(ret));
	return 0;
}

uint64_t
STDCALL test2(uint64_t a, uint16_t b, uint8_t c, uint32_t d)
{
	printf("Hook called with args: %llu, %hu, %u, %u\n", a, b, c, d);
	return 6;
}

#endif

void
test386_write_handler(addr_t addr, size_t size, uint32_t value, void *opaque)
{
	switch (addr)
	{
	case TEST386_POST_PORT: {
		if (size == 1) {
			printf("Test number is %d\n", value);
		}
		else {
			printf("Unhandled i/o port size at port %d\n", TEST386_POST_PORT);
		}
	}
	break;

	default:
		printf("Unhandled i/o write at port %d\n", addr);
	}
}

static void
print_help()
{
	static const char *help =
		"usage: [options] <path of the binary to run>\n\
options: \n\
-p         Print llvm IR code\n\
-i         Use Intel syntax (default is AT&T)\n\
-c <addr>  Start address of code\n\
-e <addr>  Address of first instruction\n\
-s <size>  Size (in bytes) to allocate for RAM\n\
-t <num>   Run a default test specified by num\n\
-h         Print this message\n";

	printf("%s", help);
}

static bool
create_cpu(const std::string &executable, size_t ramsize, addr_t code_start)
{
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

	if (!LIB86CPU_CHECK_SUCCESS(cpu_new(ramsize, cpu))) {
		printf("Failed to initialize lib86cpu!\n");
		return false;
	}

	ifs.read((char *)&cpu->cpu_ctx.ram[code_start], length);
	ifs.close();

	return true;
}

static bool
gen_test386asm_test(const std::string &executable)
{
	addr_t code_start = 0xF0000;
	size_t ramsize = 1 * 1024 * 1024;

	bool ret = create_cpu(executable, ramsize, code_start);
	if (ret == false) {
		return false;
	}

	if (!LIB86CPU_CHECK_SUCCESS(memory_init_region_ram(cpu, 0, ramsize, 1))) {
		printf("Failed to initialize ram memory for test386.asm!\n");
		return false;
	}

	if (!LIB86CPU_CHECK_SUCCESS(memory_init_region_alias(cpu, 0xFFFF0000, 0xF0000, 0x10000, 1))) {
		printf("Failed to initialize aliased ram memory for test386.asm!\n");
		return false;
	}

	if (!LIB86CPU_CHECK_SUCCESS(memory_init_region_io(cpu, TEST386_POST_PORT, 0x1, true, nullptr, test386_write_handler, nullptr, 1))) {
		printf("Failed to initialize post i/o port for test386.asm!\n");
		return false;
	}

	return true;
}

#ifdef HAS_HOOK_TEST

unsigned char hook_binary[106] = {
	0x6A, 0x07, 0x6A, 0x00, 0x6A, 0x02, 0xB2, 0x03, 0xB9, 0x04, 0x00, 0x00,
	0x00, 0xE8, 0x05, 0x00, 0x00, 0x00, 0xE9, 0x20, 0x00, 0x00, 0x00, 0x55,
	0x8B, 0xEC, 0x83, 0xEC, 0x48, 0x53, 0x56, 0x57, 0x88, 0x55, 0xF8, 0x66,
	0x89, 0x4D, 0xFC, 0xB8, 0x09, 0x00, 0x00, 0x00, 0x33, 0xD2, 0x5F, 0x5E,
	0x5B, 0x8B, 0xE5, 0x5D, 0xC2, 0x0C, 0x00, 0x50, 0x6A, 0x03, 0x6A, 0x04,
	0x6A, 0x00, 0x6A, 0x02, 0xE8, 0x05, 0x00, 0x00, 0x00, 0xE9, 0x19, 0x00,
	0x00, 0x00, 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x40, 0x53, 0x56, 0x57, 0xB8,
	0x06, 0x00, 0x00, 0x00, 0x33, 0xD2, 0x5F, 0x5E, 0x5B, 0x8B, 0xE5, 0x5D,
	0xC2, 0x14, 0x00, 0xFA, 0xF4, 0xE9, 0x96, 0xFF, 0xFF, 0xFF
};

static bool
gen_hook_test()
{
	size_t ramsize = 8 * 1024;

	if (!LIB86CPU_CHECK_SUCCESS(cpu_new(ramsize, cpu))) {
		printf("Failed to initialize lib86cpu!\n");
		return false;
	}

	std::memcpy(cpu->cpu_ctx.ram, hook_binary, sizeof(hook_binary));

	if (!LIB86CPU_CHECK_SUCCESS(memory_init_region_ram(cpu, 0, ramsize, 1))) {
		printf("Failed to initialize ram memory for hook test!\n");
		return false;
	}

	if (!LIB86CPU_CHECK_SUCCESS(hook_add(cpu, 0x17, std::unique_ptr<hook>(new hook({ call_conv::X86_FASTCALL, call_conv::X86_FASTCALL,
		{ std::vector<arg_types> { arg_types::I64, arg_types::I64, arg_types::I16, arg_types::I8, arg_types::I32 }, "test1", &test1 } }))))) {
		printf("Failed to install hook!\n");
		return false;
	}

	if (!LIB86CPU_CHECK_SUCCESS(hook_add(cpu, 0x4a, std::unique_ptr<hook>(new hook({ call_conv::X86_STDCALL, call_conv::X86_STDCALL,
	{ std::vector<arg_types> { arg_types::I64, arg_types::I64, arg_types::I16, arg_types::I8, arg_types::I32 }, "test2", &test2 } }))))) {
		printf("Failed to install hook!\n");
		return false;
	}

	cpu->cpu_ctx.regs.cr0 |= 1;
	cpu->cpu_ctx.regs.eip = 0;
	cpu->cpu_ctx.regs.cs = 0;
	cpu->cpu_ctx.regs.cs_hidden.base = 0;
	cpu->cpu_ctx.regs.cs_hidden.flags = (1 << 22);
	cpu->cpu_ctx.regs.ss_hidden.flags = (1 << 22);
	cpu->cpu_ctx.regs.esp = cpu->cpu_ctx.regs.ebp = ramsize;

	return true;
}

#endif


int
main(int argc, char **argv)
{
	size_t ramsize;
	addr_t code_start, code_entry;
	std::string executable;
	int print_ir = 0;
	int intel_syntax = 0;
	int test_num = -1;

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
					code_start = std::stoul(std::string(argv[idx]), nullptr, 0);
					break;

				case 'e':
					if (++idx == argc || argv[idx][0] == '-') {
						printf("Missing argument for option \"e\"\n");
						return 0;
					}
					code_entry = std::stoul(std::string(argv[idx]), nullptr, 0);
					break;

				case 's':
					if (++idx == argc || argv[idx][0] == '-') {
						printf("Missing argument for option \"s\"\n");
						return 0;
					}
					ramsize = std::stoul(std::string(argv[idx]), nullptr, 0);
					break;

				case 't':
					if (++idx == argc || argv[idx][0] == '-') {
						printf("Missing argument for option \"t\"\n");
						return 0;
					}
					test_num = std::stoi(std::string(argv[idx]), nullptr, 0);
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
		/* handle possible exceptions thrown by std::stoul */
		catch (std::exception &e) {
			printf("Failed to parse addr and/or size arguments. The error was: %s\n", e.what());
			return 1;
		}
	}

	switch (test_num)
	{
	case 0:
		if (gen_test386asm_test(executable) == false) {
			return 1;
		}
		break;

#ifdef HAS_HOOK_TEST
	case 1:
		if (gen_hook_test() == false) {
			return 1;
		}
		break;
#endif

	default:
		if (create_cpu(executable, ramsize, code_start) == false) {
			return 1;
		}

		cpu->cpu_ctx.regs.cs = 0;
		cpu->cpu_ctx.regs.cs_hidden.base = 0;
		cpu->cpu_ctx.regs.eip = code_entry;

		if (!LIB86CPU_CHECK_SUCCESS(memory_init_region_ram(cpu, 0, ramsize, 1))) {
			printf("Failed to initialize ram memory!\n");
			return 1;
		}
	}

	cpu->cpu_flags |= (print_ir ? (CPU_PRINT_IR | CPU_PRINT_IR_OPTIMIZED) : 0) |
		(intel_syntax ? CPU_INTEL_SYNTAX : 0) | CPU_CODEGEN_OPTIMIZE;

	cpu_run(cpu);
	cpu_free(cpu);

	return 0;
}
