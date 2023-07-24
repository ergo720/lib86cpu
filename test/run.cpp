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
-s <num>   Specify assembly syntax (default is AT&T)\n\
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
	int syntax = CPU_ATT_SYNTAX;
	int use_dbg = 0;
	int test_num = -1;
	char option = ' ';

	/* parameter parsing */
	if (argc < 2) {
		print_help();
		return 0;
	}

	for (int idx = 1; idx < argc; idx++) {
		try {
			option = ' ';
			std::string arg_str(argv[idx]);
			if (arg_str.size() == 2 && arg_str.front() == '-') {
				switch (option = arg_str.at(1))
				{
				case 's':
					if (++idx == argc || argv[idx][0] == '-') {
						printf("Missing argument for option \"s\"\n");
						return 0;
					}
					switch (syntax = std::stoi(std::string(argv[idx]), nullptr, 0))
					{
					case CPU_ATT_SYNTAX:
					case CPU_INTEL_SYNTAX:
					case CPU_MASM_SYNTAX:
						break;

					default:
						printf("Unknown syntax specified by option \"%c\"\n", option);
						return 0;
					}
					break;

				case 'd':
					use_dbg = 1;
					break;

				case 't':
					if (++idx == argc || argv[idx][0] == '-') {
						printf("Missing argument for option \"%c\"\n", option);
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
		catch (const std::exception &e) {
			printf("Failed to parse \"%c\" option. The error was: %s\n", option, e.what());
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
		gen_test80186_test(executable, syntax, use_dbg);
		return 0;

	default:
		printf("Unknown test option specified\n");
		return 1;
	}

	cpu_set_flags(cpu, syntax | (use_dbg ? CPU_DBG_PRESENT : 0) | CPU_ABORT_ON_HLT);

	lc86_status code = cpu_run(cpu);
	std::printf("Emulation terminated with status %d. The error was \"%s\"\n", static_cast<int32_t>(code), get_last_error().c_str());
	cpu_free(cpu);

	return 0;
}
