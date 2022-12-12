/*
 * lib86cpu debugger
 *
 * ergo720                Copyright (c) 2022
 */

#include "memory.h"
#include "debugger.h"
#include "instructions.h"
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
			break_list.emplace(addr, 0);
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
		std::for_each(break_list.begin(), break_list.end(), [&ofs](const std::pair<addr_t, uint8_t> &elem) {
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

void
dbg_update_exp_hook(cpu_ctx_t *cpu_ctx)
{
	hook_remove(cpu_ctx->cpu, cpu_ctx->cpu->bp_addr);
	hook_remove(cpu_ctx->cpu, cpu_ctx->cpu->db_addr);
	dbg_add_exp_hook(cpu_ctx);
}

void
dbg_add_exp_hook(cpu_ctx_t *cpu_ctx)
{
	try {
		// NOTE: we don't need to change the cpl and wp of cr0 because we only perform privileged read accesses
		if (cpu_ctx->hflags & HFLG_PE_MODE) {
			if (EXP_BP * 8 + 7 > cpu_ctx->regs.idtr_hidden.limit) {
				LOG(log_level::warn, "Failed to install hook for the exception handler: IDT limit exceeded");
				return;
			}
			unsigned exp_idx = EXP_BP;
			for (int i = 0; i < 2; ++i) {
				uint64_t desc = mem_read<uint64_t>(cpu_ctx->cpu, cpu_ctx->regs.idtr_hidden.base + exp_idx * 8, cpu_ctx->regs.eip, 2);
				uint16_t type = (desc >> 40) & 0x1F;
				uint32_t new_eip, new_base;
				switch (type)
				{
				case 6:  // interrupt gate, 16 bit
				case 14: // interrupt gate, 32 bit
					new_eip = ((desc & 0xFFFF000000000000) >> 32) | (desc & 0xFFFF);
					break;

				case 7:  // trap gate, 16 bit
				case 15: // trap gate, 32 bit
					new_eip = ((desc & 0xFFFF000000000000) >> 32) | (desc & 0xFFFF);
					break;

				default:
					// task gates are not supported
					LOG(log_level::warn, "Failed to install hook for the exception handler: unknown IDT descriptor type");
					return;
				}
				if ((desc & SEG_DESC_P) == 0) {
					LOG(log_level::warn, "Failed to install hook for the exception handler: IDT descriptor not present");
					return;
				}
				uint16_t sel = (desc & 0xFFFF0000) >> 16;
				if ((sel & 0xFFFC) == 0) {
					LOG(log_level::warn, "Failed to install hook for the exception handler: selector specified by the IDT descriptor points to the null GDT descriptor");
					return;
				}
				uint16_t sel_idx = sel >> 3;
				uint32_t base, limit;
				if (sel & 4) {
					base = cpu_ctx->regs.ldtr_hidden.base;
					limit = cpu_ctx->regs.ldtr_hidden.limit;
				}
				else {
					base = cpu_ctx->regs.gdtr_hidden.base;
					limit = cpu_ctx->regs.gdtr_hidden.limit;
				}

				if (sel_idx * 8 + 7 > limit) {
					LOG(log_level::warn, "Failed to install hook for the exception handler: GDT or LDT limit exceeded");
					return;
				}
				desc = mem_read<uint64_t>(cpu_ctx->cpu, base + sel_idx * 8, cpu_ctx->regs.eip, 2);
				if ((desc & SEG_DESC_P) == 0) {
					LOG(log_level::warn, "Failed to install hook for the exception handler: GDT or LDT descriptor not present");
					return;
				}
				new_base = ((desc & 0xFFFF0000) >> 16) | ((desc & 0xFF00000000) >> 16) | ((desc & 0xFF00000000000000) >> 32);
				if (exp_idx == EXP_BP) {
					cpu_ctx->cpu->bp_addr = new_base + new_eip;
					exp_idx = EXP_DB;
				}
				else {
					cpu_ctx->cpu->db_addr = new_base + new_eip;
				}
			}
		}
		else {
			if (EXP_BP * 4 + 3 > cpu_ctx->regs.idtr_hidden.limit) {
				LOG(log_level::warn, "Failed to install hook for the exception handler: IDT limit exceeded");
				return;
			}
			uint32_t vec_bp_entry = mem_read<uint32_t>(cpu_ctx->cpu, cpu_ctx->regs.idtr_hidden.base + EXP_BP * 4, cpu_ctx->regs.eip, 0);
			cpu_ctx->cpu->bp_addr = ((vec_bp_entry >> 16) << 4) + (vec_bp_entry & 0xFFFF);
			uint32_t vec_db_entry = mem_read<uint32_t>(cpu_ctx->cpu, cpu_ctx->regs.idtr_hidden.base + EXP_DB * 4, cpu_ctx->regs.eip, 0);
			cpu_ctx->cpu->db_addr = ((vec_db_entry >> 16) << 4) + (vec_db_entry & 0xFFFF);
		}
	}
	catch (host_exp_t type) {
		// this is either a page fault or a debug exception
		LOG(log_level::warn, "Failed to install hook for the exception handler: a guest exception was raised");
		return;
	}

	hook_add(cpu_ctx->cpu, cpu_ctx->cpu->bp_addr, &dbg_exp_handler);
	hook_add(cpu_ctx->cpu, cpu_ctx->cpu->db_addr, &dbg_exp_handler);
}

static std::vector<std::pair<addr_t, std::string>>
dbg_disas_code_block(cpu_t *cpu, disas_ctx_t *disas_ctx, ZydisDecoder *decoder, unsigned instr_num, uint32_t tlb_entry)
{
	std::vector<std::pair<addr_t, std::string>> disas_data;
	while (instr_num) {
		ZydisDecodedInstruction instr;
		ZyanStatus status = decode_instr(cpu, disas_ctx, decoder, &instr);
		if (ZYAN_SUCCESS(status)) {
			disas_data.push_back(std::make_pair(disas_ctx->virt_pc, log_instr(disas_ctx->virt_pc, &instr)));
			instr_num--;
			size_t bytes = instr.length;
			addr_t next_pc = disas_ctx->virt_pc + bytes;
			if ((disas_ctx->virt_pc & ~PAGE_MASK) != ((next_pc - 1) & ~PAGE_MASK)) {
				// page crossing, needs to translate virt_pc again and disable debug exp in the new page
				disas_ctx->pc = get_code_addr(cpu, next_pc, disas_ctx->virt_pc - cpu->cpu_ctx.regs.cs_hidden.base, 0, disas_ctx);
				cpu->cpu_ctx.tlb[disas_ctx->virt_pc >> PAGE_SHIFT] = tlb_entry;
				if (disas_ctx->exp_data.idx == EXP_PF) {
					// page fault in the new page, cannot display remaining instr
					disas_ctx->virt_pc = next_pc;
					return disas_data;
				}
				tlb_entry = cpu->cpu_ctx.tlb[next_pc >> PAGE_SHIFT];
				cpu->cpu_ctx.tlb[next_pc >> PAGE_SHIFT] &= ~TLB_WATCH;
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
	cpu->cpu_ctx.tlb[disas_ctx->virt_pc >> PAGE_SHIFT] = tlb_entry;
	return disas_data;
}

std::vector<std::pair<addr_t, std::string>>
dbg_disas_code_block(cpu_t *cpu, addr_t pc, unsigned instr_num)
{
	// setup common disas context
	disas_ctx_t disas_ctx;
	disas_ctx.flags = ((cpu->cpu_ctx.hflags & HFLG_CS32) >> CS32_SHIFT) |
		((cpu->cpu_ctx.hflags & HFLG_PE_MODE) >> (PE_MODE_SHIFT - 1));
	disas_ctx.virt_pc = pc;
	disas_ctx.pc = get_code_addr(cpu, disas_ctx.virt_pc, cpu->cpu_ctx.regs.eip, 0, &disas_ctx);
	if (disas_ctx.exp_data.idx == EXP_PF) {
		// page fault, cannot display instr
		return {};
	}

	// disable debug exp since we only want to disassemble instr for displying them
	uint32_t tlb_entry = cpu->cpu_ctx.tlb[disas_ctx.virt_pc >> PAGE_SHIFT];
	cpu->cpu_ctx.tlb[disas_ctx.virt_pc >> PAGE_SHIFT] &= ~TLB_WATCH;

	ZydisDecoder decoder;
	init_instr_decoder(&disas_ctx, &decoder);
	const auto &ret = dbg_disas_code_block(cpu, &disas_ctx, &decoder, instr_num, tlb_entry);
	break_pc = disas_ctx.virt_pc;
	return ret;
}

void
dbg_ram_read(cpu_t *cpu, uint8_t *buff)
{
	uint32_t actual_size;
	if (!LC86_SUCCESS(mem_read_block_virt(cpu, mem_pc, PAGE_SIZE, buff, &actual_size))) {
		std::memset(&buff[actual_size], 0, PAGE_SIZE - actual_size);
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
		uint8_t is_code;
		addr_t phys_addr = get_write_addr(g_cpu, addr, 2, addr - g_cpu->cpu_ctx.regs.cs_hidden.base, &is_code);
		const memory_region_t<addr_t> *region = as_memory_search_addr(g_cpu, phys_addr);

		retry:
		switch (region->type)
		{
		case mem_type::ram:
			ram_write<uint8_t>(g_cpu, get_ram_host_ptr(g_cpu, phys_addr), val);
			if (is_code) {
				tc_invalidate(&g_cpu->cpu_ctx, addr, 1, g_cpu->cpu_ctx.regs.eip);
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
	catch (host_exp_t type) {
		// just fallthrough
		if (type == host_exp_t::halt_tc) {
			g_cpu->cpu_flags &= ~(CPU_DISAS_ONE | CPU_ALLOW_CODE_WRITE);
		}
	}

	(g_cpu->cpu_ctx.regs.cr0 &= ~CR0_WP_MASK) |= old_wp;
}

static void
dbg_single_step_handler(cpu_ctx_t *cpu_ctx)
{
	// NOTE1: this is called from the emulation thread
	// NOTE2: since the cpu has just pushed the ret_eip on the stack of the exception handler and no other guest code runs before we are called
	// in this hook, then mem_read cannot raise page faults now
	uint32_t ret_eip = mem_read<uint32_t>(cpu_ctx->cpu, cpu_ctx->regs.esp, 0, 0);
	addr_t pc = cpu_ctx->regs.cs_hidden.base + ret_eip;
	if (cpu_ctx->cpu->cpu_flags & CPU_SINGLE_STEP) {
		// disable all breakpoints so that we can show the original instructions in the disassembler
		dbg_remove_sw_breakpoints(cpu_ctx->cpu);

		// wait until the debugger continues execution
		break_pc = mem_pc = pc;
		mem_editor_update = true;
		guest_running.clear();
		guest_running.notify_one();
		guest_running.wait(false);

		cpu_ctx->regs.dr[6] &= ~DR6_BS_MASK;

		try {
			// execute an iret instruction so that we can correctly return to the interrupted code
			if	(cpu_ctx->hflags & HFLG_PE_MODE) {
				if (lret_pe_helper<true>(cpu_ctx, (cpu_ctx->hflags & HFLG_CS32) ? SIZE32 : SIZE16, cpu_ctx->regs.eip)) {
					// we can't handle an exception here, so abort
					LIB86CPU_ABORT_msg("Unhandled exception while returning from a single step");
				}
			}
			else {
				iret_real_helper(cpu_ctx, (cpu_ctx->hflags & HFLG_CS32) ? SIZE32 : SIZE16, cpu_ctx->regs.eip);
			}
		}
		catch (host_exp_t type) {
			// we can't handle an exception here, so abort
			LIB86CPU_ABORT_msg("Unhandled exception while returning from a single step");
		}
	}
	else {
		// this debug exception wasn't generated by the debugger, so handle control back to the guest
		cpu_exec_trampoline(cpu_ctx->cpu, ret_eip);
	}
}

static void
dbg_sw_breakpoint_handler(cpu_ctx_t *cpu_ctx)
{
	// NOTE1: this is called from the emulation thread
	// NOTE2: since the cpu has just pushed the ret_eip on the stack of the exception handler and no other guest code runs before we are called
	// in this hook, then mem_read cannot raise page faults now
	uint32_t ret_eip = mem_read<uint32_t>(cpu_ctx->cpu, cpu_ctx->regs.esp, 0, 0);
	addr_t pc = cpu_ctx->regs.cs_hidden.base + ret_eip - 1; // if this is our int3, it will always be one byte large
	if (break_list.contains(pc)) {
		// disable all breakpoints so that we can show the original instructions in the disassembler
		dbg_remove_sw_breakpoints(cpu_ctx->cpu);

		// wait until the debugger continues execution
		break_pc = mem_pc = pc;
		mem_editor_update = true;
		guest_running.clear();
		guest_running.notify_one();
		guest_running.wait(false);

		try {
			// execute an iret instruction so that we can correctly return to the interrupted code
			if (cpu_ctx->hflags & HFLG_PE_MODE) {
				if (lret_pe_helper<true>(cpu_ctx, (cpu_ctx->hflags & HFLG_CS32) ? SIZE32 : SIZE16, cpu_ctx->regs.eip)) {
					// we can't handle an exception here, so abort
					LIB86CPU_ABORT_msg("Unhandled exception while returning from a breakpoint");
				}
			}
			else {
				iret_real_helper(cpu_ctx, (cpu_ctx->hflags & HFLG_CS32) ? SIZE32 : SIZE16, cpu_ctx->regs.eip);
			}
			cpu_ctx->regs.eip = ret_eip - 1;
		}
		catch (host_exp_t type) {
			// we can't handle an exception here, so abort
			LIB86CPU_ABORT_msg("Unhandled exception while returning from a breakpoint");
		}
	}
	else {
		// this breakpoint exception wasn't generated by the debugger, so handle control back to the guest
		cpu_exec_trampoline(cpu_ctx->cpu, ret_eip);
	}
}

void
dbg_exp_handler(cpu_ctx_t *cpu_ctx)
{
	// NOTE: the guest could be using the same exception handler for both DB and BP exceptions, so we distinguish them by looking at dr6
	if (cpu_ctx->regs.dr[6] & DR6_BS_MASK) {
		dbg_single_step_handler(cpu_ctx);
	}
	else {
		dbg_sw_breakpoint_handler(cpu_ctx);
	}
}

bool
dbg_insert_sw_breakpoint(cpu_t *cpu, addr_t addr)
{
	// we don't need to disable debug exp because get_write_addr does not access memory
	// set cpl to zero and clear wp of cr0, so that we can write to read-only pages
	bool inserted;
	uint8_t old_cpl = cpu->cpu_ctx.hflags & HFLG_CPL;
	cpu->cpu_ctx.hflags &= ~HFLG_CPL;
	uint32_t old_wp = cpu->cpu_ctx.regs.cr0 & CR0_WP_MASK;
	cpu->cpu_ctx.regs.cr0 &= ~CR0_WP_MASK;

	try {
		uint8_t is_code;
		volatile addr_t phys_addr = get_write_addr(cpu, addr, 0, cpu->cpu_ctx.regs.eip, &is_code);
		if (cpu->cpu_ctx.tlb[addr >> PAGE_SHIFT] & TLB_RAM) {
			inserted = true;
		}
		else {
			// we can only set breakpoints in ram
			inserted = false;
		}
	}
	catch (host_exp_t type) {
		// page fault while trying to insert the breakpoint, this can only happen if the page is invalid
		assert(type == host_exp_t::pf_exp);
		inserted = false;
	}

	(cpu->cpu_ctx.hflags &= ~HFLG_CPL) |= old_cpl;
	(cpu->cpu_ctx.regs.cr0 &= ~CR0_WP_MASK) |= old_wp;

	return inserted;
}

void
dbg_apply_sw_breakpoints(cpu_t *cpu)
{
	// set cpl to zero and clear wp of cr0, so that we can write to read-only pages
	uint8_t old_cpl = cpu->cpu_ctx.hflags & HFLG_CPL;
	cpu->cpu_ctx.hflags &= ~HFLG_CPL;
	uint32_t old_wp = cpu->cpu_ctx.regs.cr0 & CR0_WP_MASK;
	cpu->cpu_ctx.regs.cr0 &= ~CR0_WP_MASK;

	for (const auto &elem : break_list) {
		// disable debug exp since we only want to insert a breakpoint
		addr_t addr = elem.first;
		uint32_t tlb_entry = cpu->cpu_ctx.tlb[addr >> PAGE_SHIFT];
		cpu->cpu_ctx.tlb[addr >> PAGE_SHIFT] &= ~TLB_WATCH;

		// the mem accesses below cannot raise page faults since break_list can only contain valid pages because of the checks done in insert_sw_breakpoint
		uint8_t original_byte = mem_read<uint8_t>(cpu, addr, cpu->cpu_ctx.regs.eip, 0);
		mem_write<uint8_t>(cpu, addr, 0xCC, cpu->cpu_ctx.regs.eip, 0);
		break_list.insert_or_assign(addr, original_byte);

		cpu->cpu_ctx.tlb[addr >> PAGE_SHIFT] = tlb_entry;
	}

	(cpu->cpu_ctx.hflags &= ~HFLG_CPL) |= old_cpl;
	(cpu->cpu_ctx.regs.cr0 &= ~CR0_WP_MASK) |= old_wp;
}

void
dbg_remove_sw_breakpoints(cpu_t *cpu)
{
	// set cpl to zero and clear wp of cr0, so that we can write to read-only pages
	uint8_t old_cpl = cpu->cpu_ctx.hflags & HFLG_CPL;
	cpu->cpu_ctx.hflags &= ~HFLG_CPL;
	uint32_t old_wp = cpu->cpu_ctx.regs.cr0 & CR0_WP_MASK;
	cpu->cpu_ctx.regs.cr0 &= ~CR0_WP_MASK;

	for (const auto &elem : break_list) {
		// disable debug exp since we only want to remove a breakpoint
		const auto &[addr, original_byte] = elem;
		uint32_t tlb_entry = cpu->cpu_ctx.tlb[addr >> PAGE_SHIFT];
		cpu->cpu_ctx.tlb[addr >> PAGE_SHIFT] &= ~TLB_WATCH;

		try {
			mem_write<uint8_t>(cpu, addr, original_byte, cpu->cpu_ctx.regs.eip, 0);
		}
		catch (host_exp_t type) {
			// this can only happen when the page is invalid
		}

		cpu->cpu_ctx.tlb[addr >> PAGE_SHIFT] = tlb_entry;
	}

	(cpu->cpu_ctx.hflags &= ~HFLG_CPL) |= old_cpl;
	(cpu->cpu_ctx.regs.cr0 &= ~CR0_WP_MASK) |= old_wp;
}
