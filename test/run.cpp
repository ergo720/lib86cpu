/*
 * lib86cpu test app loader
 *
 * ergo720                Copyright (c) 2019
 */

#include "run.h"
#include <cstdarg>
#include <iostream>


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

static void
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

	case 2:
		if (gen_dbg_test() == false) {
			return 1;
		}
		break;

	default:
		printf("Unknown test option specified\n");
		return 1;
	}

	register_log_func(logger);
	cpu_set_flags(cpu, (print_ir ? (CPU_PRINT_IR | CPU_PRINT_IR_OPTIMIZED) : 0) |
		(intel_syntax ? CPU_INTEL_SYNTAX : 0) | CPU_CODEGEN_OPTIMIZE);

	lc86_status code = cpu_run(cpu);
	std::printf("Emulation terminated with status %d. The error was \"%s\"\n", code, get_last_error().c_str());
	cpu_free(cpu);

	return 0;
}
