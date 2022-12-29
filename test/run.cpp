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
		"usage: [options] <path of the binary to run (if required)>\n\
options: \n\
-i         Use Intel syntax (default is AT&T)\n\
-d         Start with debugger\n\
-t <num>   Run a test specified by num\n\
-h         Print this message\n";

	printf("%s", help);
}

static void
logger(log_level lv, const unsigned count, const char *msg, ...)
{
	static const std::unordered_map<log_level, std::string> lv_to_str = {
		{log_level::debug, "DBG:   "},
		{log_level::info,  "INFO:  "},
		{log_level::warn,  "WARN:  "},
		{log_level::error, "ERROR: "},
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
	std::string executable;
	int intel_syntax = 0;
	int use_dbg = 0;
	int test_num = -1;

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
				case 'i':
					intel_syntax = 1;
					break;

				case 'd':
					use_dbg = 1;
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
		/* handle possible exceptions thrown by std::stoi */
		catch (std::exception &e) {
			printf("Failed to parse \"t\" option. The error was: %s\n", e.what());
			return 1;
		}
	}

	register_log_func(logger);

	switch (test_num)
	{
	case 0:
		if (gen_test386asm_test(executable) == false) {
			if (cpu) {
				cpu_free(cpu);
			}
			return 1;
		}
		break;

	case 1:
		if (gen_hook_test() == false) {
			if (cpu) {
				cpu_free(cpu);
			}
			return 1;
		}
		break;

	case 2:
		if (gen_dbg_test() == false) {
			if (cpu) {
				cpu_free(cpu);
			}
			return 1;
		}
		break;

	case 3:
		if (gen_cxbxrkrnl_test(executable) == false) {
			if (cpu) {
				cpu_free(cpu);
			}
			return 1;
		}
		break;

	case 4:
		gen_test80186_test(executable, intel_syntax, use_dbg);
		return 0;

	default:
		printf("Unknown test option specified\n");
		return 1;
	}

	cpu_set_flags(cpu, (intel_syntax ? CPU_INTEL_SYNTAX : 0) | (use_dbg ? CPU_DBG_PRESENT : 0) | CPU_ABORT_ON_HLT);

	lc86_status code = cpu_run(cpu);
	std::printf("Emulation terminated with status %d. The error was \"%s\"\n", code, get_last_error().c_str());
	cpu_free(cpu);

	return 0;
}
