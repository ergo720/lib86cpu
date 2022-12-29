/*
 * lib86cpu test80186 app test generator
 *
 * ergo720                Copyright (c) 2022
 */

#include "run.h"
#include <fstream>


void
gen_test80186_test(const std::string &path, int intel_syntax, int use_dbg)
{
	for (const auto &test_name : { "rotate", "add", "sub", "jump1", "jump2", "bitwise", "control", "cmpneg", "rep", "shifts", "strings", "interrupt",
		"jmpmov", "datatrnf", "segpr", "bcdcnv", "mul", "div" }) {

		addr_t code_start = 0xF0000;
		size_t ramsize = 1 * 1024 * 1024;

		/* load code */
		std::ifstream ifs(path + test_name + ".bin", std::ios_base::in | std::ios_base::binary);
		if (!ifs.is_open()) {
			std::printf("Could not open binary file \"%s.bin\"!\n", test_name);
			continue;
		}
		ifs.seekg(0, ifs.end);
		std::streampos length = ifs.tellg();
		ifs.seekg(0, ifs.beg);

		/* Sanity checks */
		if (length == 0) {
			std::printf("Size of binary file \"%s\" detected as zero!\n", test_name);
			continue;
		}
		else if (length > ramsize - code_start) {
			std::printf("Binary file \"%s\" doesn't fit inside RAM!\n", test_name);
			continue;
		}

		if (!LC86_SUCCESS(cpu_new(ramsize, cpu))) {
			std::printf("Failed to initialize lib86cpu!\n");
			continue;
		}

		uint8_t *ram = get_ram_ptr(cpu);

		ifs.read((char *)&ram[code_start], length);
		ifs.close();

		if (!LC86_SUCCESS(mem_init_region_ram(cpu, 0, ramsize))) {
			std::printf("Failed to initialize ram memory for test80186!\n");
			cpu_free(cpu);
			return;
		}

		if (!LC86_SUCCESS(mem_init_region_alias(cpu, 0xFFFF0000, 0xF0000, 0x10000))) {
			std::printf("Failed to initialize aliased ram memory for test80186!\n");
			cpu_free(cpu);
			return;
		}

		cpu_set_flags(cpu, (intel_syntax ? CPU_INTEL_SYNTAX : 0) | (use_dbg ? CPU_DBG_PRESENT : 0) | CPU_ABORT_ON_HLT);

		std::printf("Starting test %s\n", test_name);
		lc86_status code = cpu_run(cpu);
		std::printf("Emulation terminated with status %d. The error was \"%s\"\n", code, get_last_error().c_str());

		// special test case without result
		if (test_name == "jmpmov") {
			std::printf("Testing byte 0 of ram for jmpmov test\n");
			if ((uint8_t)ram[0] == static_cast<uint8_t>(0x4001)) {
				std::printf("Test jmpmov succeeded\n");
			}
			else {
				std::printf("Test jmpmov failed\n");
			}
			cpu_free(cpu);
			continue;
		}

		// all normal tests
		ifs = std::ifstream(path + "res_" + std::string(test_name) + ".bin", std::ios_base::in | std::ios_base::binary);
		if (!ifs.is_open()) {
			std::printf("Could not open binary file \"%s.bin\"!\n", ("res_" + std::string(test_name)).c_str());
			cpu_free(cpu);
			continue;
		}
		ifs.seekg(0, ifs.end);
		std::streampos res_length = ifs.tellg();
		ifs.seekg(0, ifs.beg);
		std::unique_ptr<uint8_t[]> res_buff(new uint8_t[res_length]);
		ifs.read((char *)&res_buff[0], res_length);

		for (unsigned i = 0; i < res_length; ++i) {
			std::printf("Testing byte #%u: ", i);
			uint8_t expected = res_buff[i];
			uint8_t actual = ram[i];
			std::printf("%d\n", expected == actual);
		}

		cpu_free(cpu);
	}
}
