/*
 * lib86cpu debugger
 *
 * ergo720                Copyright (c) 2022
 */

#include "internal.h"
#include "debugger.h"
#include <fstream>
#include <charconv>
#include <array>


static std::unordered_set<addr_t> break_list;
static std::array<std::pair<addr_t, size_t>, 4> watch_list;


void
read_breakpoints_file(cpu_t *cpu)
{
	int watch_num = 0;
	std::string brk_file = cpu->dbg_name + ".ini";
	std::ifstream ifs(brk_file, std::ios_base::in);
	if (ifs.is_open()) {
		std::string line;
		while (std::getline(ifs, line)) {
			addr_t addr;
			int brk_type;
			size_t watch_size;
			if ((line.size() < 2) || (line[0] != '0') || (line[1] != 'x')) {
				// missing 0x prefix or garbage line
				LOG(log_level::error, "Ignoring invalid line %s", line.c_str());
				continue;
			}
			auto ret = std::from_chars(line.data() + 2, line.data() + line.size(), addr, 16);
			if ((ret.ec == std::errc::invalid_argument) || (ret.ptr == line.data() + line.size())) {
				// missing comma delimiter or garbage line
				LOG(log_level::error, "Ignoring invalid line %s", line.c_str());
				continue;
			}
			ret = std::from_chars(ret.ptr + 1, line.data() + line.size(), brk_type, 10);
			if ((ret.ec == std::errc::invalid_argument) || ((static_cast<brk_t>(brk_type) != brk_t::breakpoint) && (static_cast<brk_t>(brk_type) != brk_t::watchpoint))) {
				// invalid break/watchpoint type or garbage line
				LOG(log_level::error, "Ignoring invalid line %s", line.c_str());
				continue;
			}
			if (static_cast<brk_t>(brk_type) == brk_t::watchpoint) {
				if ((ret.ptr != line.data() + line.size()) && watch_num < 4) {
					ret = std::from_chars(ret.ptr + 1, line.data() + line.size(), watch_size, 10);
					if ((ret.ec == std::errc::invalid_argument) || ((watch_size != 1U) && (watch_size != 2U) && (watch_size != 4U) && (watch_size != 8U))) {
						// invalid watchpoint size or garbage line
						LOG(log_level::error, "Ignoring invalid line %s", line.c_str());
						continue;
					}
					watch_list[watch_num] = std::make_pair(addr, watch_size);
					++watch_num;
					continue;
				}
				else {
					// missing watch size or more than four watchpoints
					LOG(log_level::error, "Ignoring invalid line %s", line.c_str());
					continue;
				}
			}
			break_list.emplace(addr);
		}
	}
	else {
		LOG(log_level::info, "Could not open breakpoint file %s", brk_file.c_str());
	}
}

void
write_breakpoints_file(cpu_t *cpu)
{
	std::string brk_file = cpu->dbg_name + ".ini";
	std::ofstream ofs(brk_file, std::ios_base::out | std::ios_base::trunc);
	if (ofs.is_open()) {
		std::for_each(break_list.begin(), break_list.end(), [&ofs](addr_t addr) {
			std::array<char, 14> line;
			line[0] = '0';
			line[1] = 'x';
			auto ret = std::to_chars(line.data() + 2, line.data() + line.size(), addr, 16);
			assert(ret.ec == std::errc());
			*ret.ptr++ = ',';
			*ret.ptr++ = '0';
			*ret.ptr++ = '\n';
			*ret.ptr = '\0';
			ofs << std::string_view(line.data(), ret.ptr);
			});

		for (const auto &[addr, watch_size] : watch_list) {
			if (watch_size) {
				std::array<char, 16> line;
				line[0] = '0';
				line[1] = 'x';
				auto ret = std::to_chars(line.data() + 2, line.data() + line.size(), addr, 16);
				assert(ret.ec == std::errc());
				*ret.ptr++ = ',';
				*ret.ptr++ = '1';
				*ret.ptr++ = ',';
				ret = std::to_chars(ret.ptr, line.data() + line.size(), watch_size, 10);
				assert(ret.ec == std::errc());
				*ret.ptr++ = '\n';
				*ret.ptr = '\0';
				ofs << std::string_view(line.data(), ret.ptr);
			}
		}
	}
	else {
		LOG(log_level::error, "Could not save breakpoint file %s", brk_file.c_str());
	}

	break_list.clear();
	watch_list.fill(std::make_pair(0, 0));
}
