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
#include <cstdarg>
#include <iostream>

#define TEST386_POST_PORT 0x190
#define TEST386_EE_PORT 0x55
cpu_t *cpu = nullptr;
uint8_t *ram = nullptr;


#if _MSC_VER
#define FASTCALL __fastcall
#define STDCALL __stdcall
#define CDECL __cdecl
#else
#error Do not know how to specify calling conventions with this compiler
#endif


uint64_t
FASTCALL test_fastcall(uint64_t a, uint16_t b, uint8_t c, uint32_t d)
{
	printf("test_fastcall called with args: %llu, %hu, %u, %u\n", a, b, c, d);

	std::vector<uint8_t> vec(0x2000, 0xAA);
	mem_write_block(cpu, 0x2800, 0x2000, vec.data());
	mem_read_block(cpu, 0, 0x3800, vec);
	// should print 0x6A, uninitialzed value, 0xAA
	printf("vec[0x0] = 0x%X, vec[0x27FF] = 0x%X, vec[0x2800] = 0x%X\n", vec[0x0], vec[0x27FF], vec[0x2800]);

	std::any ret;
	if (!LIB86CPU_CHECK_SUCCESS(trampoline_call(cpu, 0x17, ret, ANY_VEC(a, ANY_I32s(b), c, d)))) {
		printf("Failed to call trampoline at address 0x17!\n");
		return 0;
	}

	printf("Trampoline at address 0x17 returned %llu\n", std::any_cast<uint64_t>(ret));

	if (!LIB86CPU_CHECK_SUCCESS(trampoline_call(cpu, 0x17, ret, ANY_VEC(a, ANY_I32s(b), c, d)))) {
		printf("Failed to call trampoline at address 0x17!\n");
		return 0;
	}

	printf("Trampoline at address 0x17 returned %llu\n", std::any_cast<uint64_t>(ret));
	return 0;
}

uint64_t
STDCALL test_stdcall(uint64_t a, uint16_t b, uint8_t c, uint32_t d)
{
	printf("test_stdcall called with args: %llu, %hu, %u, %u\n", a, b, c, d);
	return 6;
}

uint64_t
CDECL test_cdecl(uint8_t a, uint16_t b, uint32_t c, uint64_t d)
{
	printf("test_cdecl called with args: %u, %hu, %u, %llu\n", a, b, c, d);

	std::any ret;
	if (!LIB86CPU_CHECK_SUCCESS(trampoline_call(cpu, 0x7a, ret, ANY_VEC(ANY_I32s(a), ANY_I32s(b), c, d)))) {
		printf("Failed to call trampoline at address 0x7a!\n");
		return d;
	}

	printf("Trampoline at address 0x7a returned %llu\n", std::any_cast<uint64_t>(ret));

	return d;
}

void
CDECL test_double_ptr(int **a, int *b)
{
	printf("test_double_ptr called with args: 0x%p, 0x%p\n", a, b);

	std::any ret;
	if (!LIB86CPU_CHECK_SUCCESS(trampoline_call(cpu, 0x96, ret, ANY_VEC(ANY_I32r(a), ANY_I32r(b))))) {
		printf("Failed to call trampoline at address 0x96!\n");
		return;
	}
}

void
test386_write_handler(addr_t addr, size_t size, const void *buffer, void *opaque)
{
	switch (addr)
	{
	case TEST386_POST_PORT: {
		if (size == 1) {
			printf("Test number is 0x%X\n", *static_cast<const uint8_t *>(buffer));
		}
		else {
			printf("Unhandled i/o port size at port %d\n", TEST386_POST_PORT);
		}
	}
	break;

	case TEST386_EE_PORT: {
		static std::string str = "";
		if (size == 1) {
			if (*static_cast<const char *>(buffer) == '\n') {
				printf("%s", (str + '\n').c_str());
				str.clear();
			}
			else {
				str += *static_cast<const char *>(buffer);
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
	ram = get_ram_ptr(cpu);

	ifs.read((char *)&ram[code_start], length);
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

unsigned char hook_binary[] = {
	0x6A, 0x07, 0x6A, 0x00, 0x6A, 0x02, 0xB2, 0x03, 0xB9, 0x04, 0x00, 0x00,
	0x00, 0xE8, 0x05, 0x00, 0x00, 0x00, 0xE9, 0x20, 0x00, 0x00, 0x00, 0x55,
	0x8B, 0xEC, 0x83, 0xEC, 0x48, 0x53, 0x56, 0x57, 0x88, 0x55, 0xF8, 0x66,
	0x89, 0x4D, 0xFC, 0xB8, 0x09, 0x00, 0x00, 0x00, 0x33, 0xD2, 0x5F, 0x5E,
	0x5B, 0x8B, 0xE5, 0x5D, 0xC2, 0x0C, 0x00, 0x50, 0x6A, 0x03, 0x6A, 0x04,
	0x6A, 0x00, 0x6A, 0x02, 0xE8, 0x05, 0x00, 0x00, 0x00, 0xE9, 0x19, 0x00,
	0x00, 0x00, 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x40, 0x53, 0x56, 0x57, 0xB8,
	0x06, 0x00, 0x00, 0x00, 0x33, 0xD2, 0x5F, 0x5E, 0x5B, 0x8B, 0xE5, 0x5D,
	0xC2, 0x14, 0x00, 0x6A, 0x00, 0x6A, 0x04, 0x6A, 0x03, 0x6A, 0x02, 0x6A,
	0x01, 0xE8, 0x08, 0x00, 0x00, 0x00, 0x83, 0xC4, 0x14, 0xE9, 0x0B, 0x00,
	0x00, 0x00, 0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x14, 0x8B, 0x55, 0x18, 0x5D,
	0xC3, 0x6A, 0x00, 0x6A, 0x00, 0xE8, 0x08, 0x00, 0x00, 0x00, 0x83, 0xC4,
	0x08, 0xE9, 0x05, 0x00, 0x00, 0x00, 0x55, 0x8B, 0xEC, 0x5D, 0xC3, 0xFA,
	0xF4, 0xE9, 0x96, 0xFF, 0xFF, 0xFF
};

static bool
gen_hook_test()
{
	size_t ramsize = 5 * 4096;

	if (!LIB86CPU_CHECK_SUCCESS(cpu_new(ramsize, cpu))) {
		printf("Failed to initialize lib86cpu!\n");
		return false;
	}
	ram = get_ram_ptr(cpu);
	std::memcpy(ram, hook_binary, sizeof(hook_binary));

	if (!LIB86CPU_CHECK_SUCCESS(mem_init_region_ram(cpu, 0, ramsize, 1))) {
		printf("Failed to initialize ram memory for hook test!\n");
		return false;
	}

	if (!LIB86CPU_CHECK_SUCCESS(hook_add(cpu, 0x17, std::unique_ptr<hook>(new hook({ call_conv::x86_fastcall, call_conv::x86_fastcall,
		{ std::vector<arg_types> { arg_types::i64, arg_types::i64, arg_types::i16, arg_types::i8, arg_types::i32 }, "test_fastcall", &test_fastcall } }))))) {
		printf("Failed to install hook!\n");
		return false;
	}

	if (!LIB86CPU_CHECK_SUCCESS(hook_add(cpu, 0x4a, std::unique_ptr<hook>(new hook({ call_conv::x86_stdcall, call_conv::x86_stdcall,
	{ std::vector<arg_types> { arg_types::i64, arg_types::i64, arg_types::i16, arg_types::i8, arg_types::i32 }, "test_stdcall", &test_stdcall } }))))) {
		printf("Failed to install hook!\n");
		return false;
	}

	if (!LIB86CPU_CHECK_SUCCESS(hook_add(cpu, 0x7a, std::unique_ptr<hook>(new hook({ call_conv::x86_cdecl, call_conv::x86_cdecl,
	{ std::vector<arg_types> { arg_types::i64, arg_types::i8, arg_types::i16, arg_types::i32, arg_types::i64 }, "test_cdecl", &test_cdecl } }))))) {
		printf("Failed to install hook!\n");
		return false;
	}

	if (!LIB86CPU_CHECK_SUCCESS(hook_add(cpu, 0x96, std::unique_ptr<hook>(new hook({ call_conv::x86_cdecl, call_conv::x86_cdecl,
	{ std::vector<arg_types> { arg_types::void_, arg_types::ptr2, arg_types::ptr }, "test_double_ptr", &test_double_ptr } }))))) {
		printf("Failed to install hook!\n");
		return false;
	}

	uint32_t cr0;
	read_reg(cpu, &cr0, REG_CR0);
	cr0 |= 1;
	write_reg(cpu, cr0, REG_CR0);
	write_reg(cpu, 0, REG_EIP);
	write_reg(cpu, 0, REG_CS, SEG_SEL);
	write_reg(cpu, 0, REG_CS, SEG_BASE);
	write_reg(cpu, 1 << 22, REG_CS, SEG_FLG);
	write_reg(cpu, 1 << 22, REG_SS, SEG_FLG);
	write_reg(cpu, ramsize, REG_ESP);
	write_reg(cpu, ramsize, REG_EBP);

	return true;
}

void
logger(log_level lv, const unsigned count, const char *msg, ...)
{
	static const std::unordered_map<log_level, std::string> lv_to_str = {
		{log_level::debug, "DBG:  "},
		{log_level::info,  "INFO: "},
		{log_level::warn,  "WARN: "}
	};

	std::string str;
	auto it = lv_to_str.find(lv);
	if (it == lv_to_str.end()) {
		str = std::string("UNK: ") + msg + '\n';
	}
	else {
		str = it->second + msg + '\n';
	}

	if (count > 0) {
		std::va_list args;
		va_start(args, msg);
		std::vprintf(str.c_str(), args);
		va_end(args);
	}
	else {
		std::cout << str;
	}
}

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

	case 1:
		if (gen_hook_test() == false) {
			return 1;
		}
		break;

	default:
		if (create_cpu(executable, ramsize, code_start) == false) {
			return 1;
		}

		write_reg(cpu, 0, REG_CS, SEG_SEL);
		write_reg(cpu, 0, REG_CS, SEG_BASE);
		write_reg(cpu, code_entry, REG_EIP);

		if (!LIB86CPU_CHECK_SUCCESS(mem_init_region_ram(cpu, 0, ramsize, 1))) {
			printf("Failed to initialize ram memory!\n");
			return 1;
		}
	}

	register_log_func(logger);
	cpu_set_flags(cpu, (print_ir ? (CPU_PRINT_IR | CPU_PRINT_IR_OPTIMIZED) : 0) |
		(intel_syntax ? CPU_INTEL_SYNTAX : 0) | CPU_CODEGEN_OPTIMIZE);

	lc86_status code = cpu_run(cpu);
	std::printf("Emulation terminated with status %d. The error was \"%s\"\n", code, get_last_error().c_str());
	cpu_free(cpu);

	return 0;
}
