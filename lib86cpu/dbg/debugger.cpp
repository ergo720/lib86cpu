/*
 * lib86cpu debugger
 *
 * ergo720                Copyright (c) 2022
 */

#include "lib86cpu_priv.h"
#include "debugger.h"
#include "memory.h"
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

static std::vector<std::pair<addr_t, std::string>>
dbg_disas_code_block(cpu_t *cpu, disas_ctx_t *disas_ctx, ZydisDecoder *decoder, unsigned instr_num, uint32_t tlb_entry)
{
	size_t bytes_last_instr = 0;
	std::vector<std::pair<addr_t, std::string>> disas_data;
	while (instr_num) {
		ZydisDecodedInstruction instr;
		ZyanStatus status = decode_instr(cpu, disas_ctx, decoder, &instr);
		if (ZYAN_SUCCESS(status)) {
			disas_data.push_back(std::make_pair(disas_ctx->virt_pc, log_instr(disas_ctx->virt_pc, &instr)));
			instr_num--;
			size_t bytes = bytes_last_instr = instr.length;
			addr_t next_pc = disas_ctx->virt_pc + bytes;
			if ((disas_ctx->virt_pc & ~PAGE_MASK) != ((next_pc - 1) & ~PAGE_MASK)) {
				// page crossing, needs to translate virt_pc again and disable debug exp in the new page
				disas_ctx->pc = get_code_addr(cpu, next_pc, disas_ctx->virt_pc - cpu->cpu_ctx.regs.cs_hidden.base, disas_ctx);
				cpu->cpu_ctx.tlb[disas_ctx->virt_pc >> PAGE_SHIFT] = tlb_entry;
				if (disas_ctx->exp_data.idx == EXP_PF) {
					// page fault in the new page, cannot display remaining instr
					return disas_data;
				}
				tlb_entry = cpu->cpu_ctx.tlb[next_pc >> PAGE_SHIFT];
				cpu->cpu_ctx.tlb[next_pc >> PAGE_SHIFT] &= ~TLB_WATCH;
				if (!instr_num) {
					return disas_data;
				}
			}
			else {
				disas_ctx->pc += bytes;
			}
			disas_ctx->virt_pc = next_pc;
		}
		else {
			// decoding failed, cannot display remaining instr
			cpu->cpu_ctx.tlb[disas_ctx->virt_pc >> PAGE_SHIFT] = tlb_entry;
			return disas_data;
		}
	}
	cpu->cpu_ctx.tlb[(disas_ctx->virt_pc - bytes_last_instr) >> PAGE_SHIFT] = tlb_entry;
	return disas_data;
}

std::vector<std::pair<addr_t, std::string>>
dbg_disas_code_block(cpu_t *cpu, unsigned instr_num)
{
	// setup common disas context
	disas_ctx_t disas_ctx;
	disas_ctx.flags = ((cpu->cpu_ctx.hflags & HFLG_CS32) >> CS32_SHIFT) |
		((cpu->cpu_ctx.hflags & HFLG_PE_MODE) >> (PE_MODE_SHIFT - 1));
	disas_ctx.virt_pc = get_pc(&cpu->cpu_ctx);
	disas_ctx.pc = get_code_addr(cpu, disas_ctx.virt_pc, cpu->cpu_ctx.regs.eip, &disas_ctx);
	if (disas_ctx.exp_data.idx == EXP_PF) {
		// page fault, cannot display instr
		return {};
	}

	// disable debug exp since we only want to disassemble them for displying them
	uint32_t tlb_entry = cpu->cpu_ctx.tlb[disas_ctx.virt_pc >> PAGE_SHIFT];
	cpu->cpu_ctx.tlb[disas_ctx.virt_pc >> PAGE_SHIFT] &= ~TLB_WATCH;

	ZydisDecoder decoder;
	init_instr_decoder(&disas_ctx, &decoder);
	return dbg_disas_code_block(cpu, &disas_ctx, &decoder, instr_num, tlb_entry);
}
