/*
 * lib86cpu debugger
 *
 * ergo720                Copyright (c) 2022
 */

#include "memory_management.h"
#include "debugger.h"
#include "instructions.h"
#include "main_wnd.h"
#include <fstream>
#include <charconv>


template<typename T>
static void
read_value_from_ini(std::ifstream *ifs, std::string_view key, T *value)
{
	std::string line;
	if (std::getline(*ifs, line)) {
		if (line.starts_with(key)) {
			auto ret = std::from_chars(line.data() + key.size(), line.data() + line.size(), *value);
			if ((ret.ec == std::errc::invalid_argument) || (ret.ec == std::errc::result_out_of_range)) {
				// missing value or garbage line
				LOG(log_level::error, "Ignoring invalid line %s", line.c_str());
				return;
			}
		}
		else {
			// missing prefix or garbage line
			LOG(log_level::error, "Ignoring invalid line %s", line.c_str());
		}
	}
	else {
		// missing key option
		LOG(log_level::error, "Missing option with key %s", key.data());
	}
}

static void
read_ini_file()
{
	std::ifstream ifs("lib86dbg.ini", std::ios_base::in);
	if (ifs.is_open()) {
		read_value_from_ini(&ifs, "width=", &main_wnd_w);
		read_value_from_ini(&ifs, "height=", &main_wnd_h);
		read_value_from_ini(&ifs, "text_r=", &text_col[0]);
		read_value_from_ini(&ifs, "text_g=", &text_col[1]);
		read_value_from_ini(&ifs, "text_b=", &text_col[2]);
		read_value_from_ini(&ifs, "break_r=", &break_col[0]);
		read_value_from_ini(&ifs, "break_g=", &break_col[1]);
		read_value_from_ini(&ifs, "break_b=", &break_col[2]);
		read_value_from_ini(&ifs, "bk_r=", &bk_col[0]);
		read_value_from_ini(&ifs, "bk_g=", &bk_col[1]);
		read_value_from_ini(&ifs, "bk_b=", &bk_col[2]);
	}
	else {
		LOG(log_level::info, "Could not open lib86dbg.ini file");
	}
}

static void
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
			if ((ret.ec == std::errc::invalid_argument) || (ret.ec == std::errc::result_out_of_range)) {
				// missing comma delimiter or garbage line
				LOG(log_level::error, "Ignoring invalid line %s", line.c_str());
				continue;
			}
			ret = std::from_chars(ret.ptr + 1, line.data() + line.size(), brk_type, 10);
			if ((ret.ec == std::errc::invalid_argument) || (ret.ec == std::errc::result_out_of_range) ||
				((static_cast<brk_t>(brk_type) != brk_t::breakpoint) && (static_cast<brk_t>(brk_type) != brk_t::watchpoint))) {
				// invalid break/watchpoint type or garbage line
				LOG(log_level::error, "Ignoring invalid line %s", line.c_str());
				continue;
			}
			if (static_cast<brk_t>(brk_type) == brk_t::watchpoint) {
				if ((ret.ptr != line.data() + line.size()) && watch_num < 4) {
					ret = std::from_chars(ret.ptr + 1, line.data() + line.size(), watch_size, 10);
					if ((ret.ec == std::errc::invalid_argument) || (ret.ec == std::errc::result_out_of_range) ||
						((watch_size != 1U) && (watch_size != 2U) && (watch_size != 4U) && (watch_size != 8U))) {
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
			break_list.emplace(addr, brk_info{ 0, brk_t::breakpoint });
		}
	}
	else {
		LOG(log_level::info, "Could not open breakpoint file %s", brk_file.c_str());
	}
}

void
read_setting_files(cpu_t *cpu)
{
	read_ini_file();
	read_breakpoints_file(cpu);
}

template<typename T>
static void
write_value_to_ini(std::ofstream *ofs, std::string_view key, T value)
{
	std::array<char, 50> line; // hopefully large enough to store any value
	std::copy(key.begin(), key.end(), line.begin());
	auto ret = std::to_chars(line.data() + key.size(), line.data() + line.size(), value);
	assert(ret.ec == std::errc());
	*ret.ptr++ = '\n';
	*ret.ptr = '\0';
	*ofs << std::string_view(line.data(), ret.ptr);
}

static void
write_ini_file()
{
	std::ofstream ofs("lib86dbg.ini", std::ios_base::out | std::ios_base::trunc);
	if (ofs.is_open()) {
		write_value_to_ini(&ofs, "width=", main_wnd_w);
		write_value_to_ini(&ofs, "height=", main_wnd_h);
		write_value_to_ini(&ofs, "text_r=", text_col[0]);
		write_value_to_ini(&ofs, "text_g=", text_col[1]);
		write_value_to_ini(&ofs, "text_b=", text_col[2]);
		write_value_to_ini(&ofs, "break_r=", break_col[0]);
		write_value_to_ini(&ofs, "break_g=", break_col[1]);
		write_value_to_ini(&ofs, "break_b=", break_col[2]);
		write_value_to_ini(&ofs, "bk_r=", bk_col[0]);
		write_value_to_ini(&ofs, "bk_g=", bk_col[1]);
		write_value_to_ini(&ofs, "bk_b=", bk_col[2]);
	}
	else {
		LOG(log_level::info, "Could not save lib86dbg.ini file");
	}
}

static void
write_breakpoints_file(cpu_t *cpu)
{
	std::string brk_file = cpu->dbg_name + ".ini";
	std::ofstream ofs(brk_file, std::ios_base::out | std::ios_base::trunc);
	if (ofs.is_open()) {
		std::for_each(break_list.begin(), break_list.end(), [&ofs](const std::pair<addr_t, brk_info> &elem) {
			std::array<char, 14> line;
			line[0] = '0';
			line[1] = 'x';
			auto ret = std::to_chars(line.data() + 2, line.data() + line.size(), elem.first, 16);
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

void
write_setting_files(cpu_t *cpu)
{
	write_ini_file();
	write_breakpoints_file(cpu);
}

static std::vector<std::pair<addr_t, std::string>>
dbg_disas_code_block(cpu_t *cpu, disas_ctx_t *disas_ctx, ZydisDecoder *decoder, unsigned instr_num)
{
	std::vector<std::pair<addr_t, std::string>> disas_data;
	while (instr_num) {
		decoded_instr instr;
		ZyanStatus status = decode_instr(cpu, disas_ctx, decoder, &instr);
		if (ZYAN_SUCCESS(status)) {
			disas_data.push_back(std::make_pair(disas_ctx->virt_pc, log_instr(disas_ctx->virt_pc, &instr)));
			--instr_num;
			uint32_t bytes = instr.i.length;
			addr_t next_pc = disas_ctx->virt_pc + bytes;
			if ((disas_ctx->virt_pc & ~PAGE_MASK) != ((next_pc - 1) & ~PAGE_MASK)) {
				// page crossing, needs to translate virt_pc again
				disas_ctx->pc = get_code_addr<false>(cpu, next_pc, &disas_ctx->exp_data);
				if (disas_ctx->exp_data.idx == EXP_PF) {
					// page fault in the new page, cannot display remaining instr
					disas_ctx->virt_pc = next_pc;
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
			return disas_data;
		}
	}
	return disas_data;
}

std::vector<std::pair<addr_t, std::string>>
dbg_disas_code_block(cpu_t *cpu, addr_t pc, unsigned instr_num)
{
	// setup common disas context
	disas_ctx_t disas_ctx;
	disas_ctx.flags = ((cpu->cpu_ctx.hflags & HFLG_CS32) >> CS32_SHIFT) |
		((cpu->cpu_ctx.hflags & HFLG_SS32) >> (SS32_SHIFT - 1)) |
		(cpu->cpu_ctx.hflags & HFLG_PE_MODE);
	disas_ctx.virt_pc = pc;
	disas_ctx.pc = get_code_addr<false>(cpu, disas_ctx.virt_pc, &disas_ctx.exp_data);
	if (disas_ctx.exp_data.idx == EXP_PF) {
		// page fault, cannot display instr
		return {};
	}

	// disable debug exp since we only want to disassemble instr for displaying them
	std::vector<wp_info<addr_t>> wp_data;
	std::vector<wp_info<port_t>> wp_io;
	wp_data.swap(cpu->wp_data);
	wp_io.swap(cpu->wp_io);

	ZydisDecoder decoder;
	init_instr_decoder(&disas_ctx, &decoder);
	const auto &ret = dbg_disas_code_block(cpu, &disas_ctx, &decoder, instr_num);
	break_pc = disas_ctx.virt_pc;
	wp_data.swap(cpu->wp_data);
	wp_io.swap(cpu->wp_io);
	return ret;
}

void
dbg_ram_read(cpu_t *cpu, uint8_t *buff)
{
	uint64_t actual_size;
	if (!LC86_SUCCESS(mem_read_block_virt(cpu, mem_pc, PAGE_SIZE, buff, &actual_size))) {
		std::memset(&buff[actual_size], 0, PAGE_SIZE - actual_size);
		LOG(log_level::info, "Failed to read at address 0x%08" PRIX32, mem_pc);
	}
}

void
dbg_ram_write(uint8_t *data, size_t off, uint8_t val)
{
	// NOTE: off is the offset from the address that is displayed in the memory editor

	addr_t addr = static_cast<addr_t>(off) + mem_pc;

	// clear wp of cr0, so that we can write to read-only pages
	uint32_t old_wp = g_cpu->cpu_ctx.regs.cr0 & CR0_WP_MASK;
	g_cpu->cpu_ctx.regs.cr0 &= ~CR0_WP_MASK;

	try {
		bool is_code;
		addr_t phys_addr = get_write_addr(g_cpu, addr, 2, &is_code);
		const memory_region_t<addr_t> *region = as_memory_search_addr(g_cpu, phys_addr);

		retry:
		switch (region->type)
		{
		case mem_type::ram:
			ram_write<uint8_t>(g_cpu, get_ram_host_ptr(g_cpu, region, phys_addr), val);
			if (is_code) {
				tc_invalidate(&g_cpu->cpu_ctx, phys_addr, 1);
				g_cpu->clear_int_fn(&g_cpu->cpu_ctx, CPU_HALT_TC_INT);
			}
			// also update the read mem buffer used by dbg_ram_read
			data[off] = val;
			break;

		case mem_type::rom:
			break;

		case mem_type::alias: {
			const memory_region_t<addr_t> *alias = region;
			AS_RESOLVE_ALIAS();
			phys_addr = region->start + alias_offset + (phys_addr - alias->start);
			goto retry;
		}
		break;

		}
	}
	catch (host_exp_t) {
		// NOTE: debug exceptions cannot happen here because we are not accessing any memory here, only translating an address 
		LOG(log_level::info, "Failed to write to address 0x%08" PRIX32, addr);
	}

	(g_cpu->cpu_ctx.regs.cr0 &= ~CR0_WP_MASK) |= old_wp;
}

static void
dbg_single_step_handler(cpu_ctx_t *cpu_ctx)
{
	// NOTE: this is called from the emulation thread

	cpu_ctx->regs.dr[6] &= ~DR6_BS_MASK;

	// disable all breakpoints so that we can show the original instructions in the disassembler
	dbg_remove_sw_breakpoints(cpu_ctx->cpu);

	// wait until the debugger continues execution
	break_pc = mem_pc = cpu_ctx->regs.cs_hidden.base + cpu_ctx->regs.eip;
	mem_editor_update = true;
	guest_running.clear();
	guest_running.notify_one();
	guest_running.wait(false);
	dbg_apply_sw_breakpoints(cpu_ctx->cpu);
}

static void
dbg_sw_breakpoint_handler(cpu_ctx_t *cpu_ctx)
{
	// NOTE: this is called from the emulation thread

	addr_t pc = cpu_ctx->regs.cs_hidden.base + cpu_ctx->regs.eip - 1; // if this is our int3, it will always be one byte large
	if (auto it = break_list.find(pc); it != break_list.end()) {
		// disable all breakpoints so that we can show the original instructions in the disassembler
		dbg_remove_sw_breakpoints(cpu_ctx->cpu);
		if (it->second.type == brk_t::step_over) {
			break_list.erase(it);
		}

		// wait until the debugger continues execution
		break_pc = mem_pc = pc;
		mem_editor_update = true;
		guest_running.clear();
		guest_running.notify_one();
		guest_running.wait(false);

		cpu_ctx->regs.eip -= 1;
		dbg_remove_sw_breakpoints(cpu_ctx->cpu, pc);
		dbg_exec_original_instr(cpu_ctx->cpu);
		dbg_apply_sw_breakpoints(cpu_ctx->cpu);
	}
}

void
dbg_exp_handler(cpu_ctx_t *cpu_ctx)
{
	// NOTE: task switches are currently not supported, so we don't check for DR6_BT_MASK

	if (cpu_ctx->regs.dr[6] & (DR6_B0_MASK | DR6_B1_MASK | DR6_B2_MASK | DR6_B3_MASK | DR6_BD_MASK)) {
		// If it is an instruction breakpoint or a general detect condition, clear the corresponding flags in dr6/7, to avoid triggering the exception again
		uint32_t dr7_mask = DR7_GD_MASK, dr7 = cpu_ctx->regs.dr[7];
		for (int i = 0; i < 4; ++i) {
			int dr7_type = cpu_get_watchpoint_type(cpu_ctx->cpu, i);
			if (dr7_type == DR7_TYPE_INSTR) {
				dr7_mask |= (3 << i);
			}
		}

		cpu_ctx->regs.dr[6] &= ~(DR6_B0_MASK | DR6_B1_MASK | DR6_B2_MASK | DR6_B3_MASK | DR6_BD_MASK);
		cpu_ctx->regs.dr[7] &= ~dr7_mask;
		update_drN_helper(cpu_ctx, 7, cpu_ctx->regs.dr[7]);
	}

	try {
		if (cpu_ctx->regs.dr[6] & DR6_BS_MASK) {
			dbg_single_step_handler(cpu_ctx);
		} else {
			dbg_sw_breakpoint_handler(cpu_ctx);
		}
	}
	catch (host_exp_t) {
		// this happens when there is an unhandled exception while attempting to update the breakpoints
		LIB86CPU_ABORT_msg("Failed to update breakpoints");
	}
}

template<typename T>
static void dbg_update_sw_breakpoints(cpu_t *cpu, T &&lambda)
{
	// set cpl to zero and clear wp of cr0, so that we can write to read-only pages
	uint8_t old_cpl = cpu->cpu_ctx.hflags & HFLG_CPL;
	cpu->cpu_ctx.hflags &= ~HFLG_CPL;
	uint32_t old_wp = cpu->cpu_ctx.regs.cr0 & CR0_WP_MASK;
	cpu->cpu_ctx.regs.cr0 &= ~CR0_WP_MASK;

	// disable debug exp since we only want to insert a breakpoint
	std::vector<wp_info<addr_t>> wp_data;
	std::vector<wp_info<port_t>> wp_io;
	wp_data.swap(cpu->wp_data);
	wp_io.swap(cpu->wp_io);

	lambda(cpu);

	(cpu->cpu_ctx.hflags &= ~HFLG_CPL) |= old_cpl;
	(cpu->cpu_ctx.regs.cr0 &= ~CR0_WP_MASK) |= old_wp;
	wp_data.swap(cpu->wp_data);
	wp_io.swap(cpu->wp_io);
}

void
dbg_setup_sw_breakpoints(cpu_t *cpu)
{
	dbg_update_sw_breakpoints(cpu, [](cpu_t *cpu) {
		for (const auto &elem : break_list) {
			addr_t addr = elem.first;
			uint8_t original_byte = mem_read_helper<uint8_t>(&cpu->cpu_ctx, addr, 0);
			break_list.insert_or_assign(addr, brk_info{ original_byte, brk_t::breakpoint });
		}
		});
}

std::optional<uint8_t>
dbg_insert_sw_breakpoint(cpu_t *cpu, addr_t addr)
{
	// we don't need to disable debug exp because query_write_addr does not access memory
	// set cpl to zero and clear wp of cr0, so that we can write to read-only pages
	bool inserted = false;
	uint8_t original_byte, old_cpl = cpu->cpu_ctx.hflags & HFLG_CPL;
	cpu->cpu_ctx.hflags &= ~HFLG_CPL;
	uint32_t old_wp = cpu->cpu_ctx.regs.cr0 & CR0_WP_MASK;
	cpu->cpu_ctx.regs.cr0 &= ~CR0_WP_MASK;

	bool is_code;
	exp_data_t exp_data{0, 0, EXP_INVALID};
	uint32_t page_info;
	addr_t phys_addr = query_write_addr(cpu, addr, 0, &is_code, &exp_data, &page_info);
	if (exp_data.idx == EXP_INVALID) {
		retry:
		auto region = as_memory_search_addr(cpu, phys_addr);
		if (region->type == mem_type::ram) { // we can only set breakpoints in ram
			inserted = true;
			original_byte = as_memory_dispatch_read<uint8_t>(cpu, phys_addr, region);
		}
		else if (region->type == mem_type::alias) { // if it's an alias to ram, we can still insert it
			const memory_region_t<addr_t> *alias = region;
			AS_RESOLVE_ALIAS();
			phys_addr = region->start + alias_offset + (phys_addr - alias->start);
			goto retry;
		}
	}

	(cpu->cpu_ctx.hflags &= ~HFLG_CPL) |= old_cpl;
	(cpu->cpu_ctx.regs.cr0 &= ~CR0_WP_MASK) |= old_wp;

	return inserted ? std::optional<uint8_t>(original_byte) : std::nullopt;
}

static void
dbg_apply_sw_breakpoints(cpu_t *cpu, addr_t addr, brk_t type)
{
	uint8_t original_byte = mem_read_helper<uint8_t>(&cpu->cpu_ctx, addr, 0);
	if (original_byte != 0xCC) {
		// NOTE: original_byte can be 0xCC (=int3) when applying a breakpoint on an existing int3 on the guest. It can also happen if this was already called by a nested
		// call to dbg_sw_breakpoint_handler from dbg_single_step_handler, that is, single-stepping a breakpoint
		mem_write_helper<uint8_t>(&cpu->cpu_ctx, addr, 0xCC, 0); // write int3
		cpu->clear_int_fn(&g_cpu->cpu_ctx, CPU_HALT_TC_INT);
		break_list.insert_or_assign(addr, brk_info{ original_byte, type });
	}
}

void
dbg_apply_sw_breakpoints(cpu_t *cpu)
{
	dbg_update_sw_breakpoints(cpu, [](cpu_t *cpu) {
		for (const auto &elem : break_list) {
			dbg_apply_sw_breakpoints(cpu, elem.first, elem.second.type);
		}
		});
}

static void
dbg_remove_sw_breakpoints(cpu_t *cpu, addr_t addr, uint8_t original_byte)
{
	mem_write_helper<uint8_t>(&cpu->cpu_ctx, addr, original_byte, 0); // restore original byte
	cpu->clear_int_fn(&g_cpu->cpu_ctx, CPU_HALT_TC_INT);
}

void
dbg_remove_sw_breakpoints(cpu_t *cpu)
{
	dbg_update_sw_breakpoints(cpu, [](cpu_t *cpu) {
		for (const auto &elem : break_list) {
			dbg_remove_sw_breakpoints(cpu, elem.first, elem.second.original_byte);
		}
		});
}

void
dbg_remove_sw_breakpoints(cpu_t *cpu, addr_t addr)
{
	dbg_update_sw_breakpoints(cpu, [&](cpu_t *cpu) {
		if (const auto it = break_list.find(addr); it != break_list.end()) {
			dbg_remove_sw_breakpoints(cpu, it->first, it->second.original_byte);
		}
		});
}
