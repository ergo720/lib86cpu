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
#if XBOX_CPU
#include "ipt.h"
#endif


void
read_dbg_opt(cpu_t *cpu)
{
	g_dbg_opt.lock.lock();
	g_main_wnd_w = g_dbg_opt.width;
	g_main_wnd_h = g_dbg_opt.height;
	g_txt_col[0] = g_dbg_opt.txt_col[0];
	g_txt_col[1] = g_dbg_opt.txt_col[1];
	g_txt_col[2] = g_dbg_opt.txt_col[2];
	g_brk_col[0] = g_dbg_opt.brk_col[0];
	g_brk_col[1] = g_dbg_opt.brk_col[1];
	g_brk_col[2] = g_dbg_opt.brk_col[2];
	g_bkg_col[0] = g_dbg_opt.bkg_col[0];
	g_bkg_col[1] = g_dbg_opt.bkg_col[1];
	g_bkg_col[2] = g_dbg_opt.bkg_col[2];
	g_reg_col[0] = g_dbg_opt.reg_col[0];
	g_reg_col[1] = g_dbg_opt.reg_col[1];
	g_reg_col[2] = g_dbg_opt.reg_col[2];
	for (unsigned i = 0; i < 4; ++i) {
		g_mem_pc[i] = g_dbg_opt.mem_editor_addr[i];
	}
	g_mem_active = g_dbg_opt.mem_active & 3;
	g_mem_button_text[g_mem_button_text.size() - 2] = '0' + g_mem_active;
	std::for_each(g_dbg_opt.brk_vec.begin(), g_dbg_opt.brk_vec.end(), [](const decltype(g_dbg_opt.brk_vec)::value_type &elem) {
		g_break_list.emplace(elem, brk_info{ 0, brk_t::breakpoint });
	});
	for (unsigned idx = 0; idx < 4; ++idx) {
		addr_t addr = g_dbg_opt.wp_arr[idx].addr;
		uint32_t size = g_dbg_opt.wp_arr[idx].size;
		uint32_t type = g_dbg_opt.wp_arr[idx].type;
		if (type == DR7_TYPE_INSTR) { // considered as invalid as the debugger never sets this
			cpu->cpu_ctx.regs.dr[7] &= ~(3 << (idx * 2));
			continue;
		}
		uint32_t enable_shift = idx * 2;
		uint32_t rw_shift = DR7_TYPE_SHIFT + idx * 4;
		uint32_t size_shift = DR7_LEN_SHIFT + idx * 4;
		uint32_t dr7 = cpu->cpu_ctx.regs.dr[7] & ~((3 << enable_shift) | (3 << rw_shift) | (3 << size_shift));
		dr7 |= (3 << enable_shift);
		dr7 |= (type << rw_shift);
		dr7 |= (size << size_shift);
		cpu->cpu_ctx.regs.dr[7] = dr7;
		cpu->cpu_ctx.regs.dr[idx] = addr;
	}
	update_drN_helper(&cpu->cpu_ctx, 7, cpu->cpu_ctx.regs.dr[7]);
	g_dbg_opt.lock.unlock();
}

void
write_dbg_opt(cpu_t *cpu)
{
	g_dbg_opt.lock.lock();
	g_dbg_opt.width = g_main_wnd_w;
	g_dbg_opt.height = g_main_wnd_h;
	g_dbg_opt.txt_col[0] = g_txt_col[0];
	g_dbg_opt.txt_col[1] = g_txt_col[1];
	g_dbg_opt.txt_col[2] = g_txt_col[2];
	g_dbg_opt.brk_col[0] = g_brk_col[0];
	g_dbg_opt.brk_col[1] = g_brk_col[1];
	g_dbg_opt.brk_col[2] = g_brk_col[2];
	g_dbg_opt.bkg_col[0] = g_bkg_col[0];
	g_dbg_opt.bkg_col[1] = g_bkg_col[1];
	g_dbg_opt.bkg_col[2] = g_bkg_col[2];
	g_dbg_opt.reg_col[0] = g_reg_col[0];
	g_dbg_opt.reg_col[1] = g_reg_col[1];
	g_dbg_opt.reg_col[2] = g_reg_col[2];
	for (unsigned i = 0; i < 4; ++i) {
		g_dbg_opt.mem_editor_addr[i] = g_mem_pc[i];
	}
	g_dbg_opt.mem_active = g_mem_active;
	g_dbg_opt.brk_vec.clear();
	std::for_each(g_break_list.begin(), g_break_list.end(), [](const decltype(g_break_list)::value_type &elem) {
		brk_t brk_type = elem.second.type;
		if (brk_type == brk_t::breakpoint) {
			g_dbg_opt.brk_vec.emplace_back(elem.first);
		}
	});
	for (unsigned idx = 0; idx < 4; ++idx) {
		addr_t addr = 0;
		uint32_t size = 0;
		uint32_t type = DR7_TYPE_INSTR; // considered as invalid as the debugger never sets this
		if (cpu_check_watchpoint_enabled(cpu, idx)) {
			size = cpu_get_watchpoint_length(cpu, idx);
			size = (size == 8) ? 2 : size - 1;
			type = cpu_get_watchpoint_type(cpu, idx);
			addr = cpu->cpu_ctx.regs.dr[idx];
		}
		g_dbg_opt.wp_arr[idx] = { .addr = addr, .size = size, .type = type };
	}
	g_dbg_opt.lock.unlock();
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
	g_break_pc = disas_ctx.virt_pc;
	wp_data.swap(cpu->wp_data);
	wp_io.swap(cpu->wp_io);
	return ret;
}

void
dbg_ram_read(cpu_t *cpu, uint8_t *buff)
{
	uint64_t actual_size;
	if (!LC86_SUCCESS(mem_read_block_virt(cpu, g_mem_pc[g_mem_active], PAGE_SIZE, buff, &actual_size))) {
		std::memset(&buff[actual_size], 0, PAGE_SIZE - actual_size);
		LOG(log_level::info, "Failed to read at address 0x%08" PRIX32, g_mem_pc[g_mem_active]);
	}
}

void
dbg_ram_write(uint8_t *data, size_t off, uint8_t val)
{
	// NOTE: off is the offset from the address that is displayed in the memory editor

	addr_t addr = static_cast<addr_t>(off) + g_mem_pc[g_mem_active];

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
		for (const auto &elem : g_break_list) {
			addr_t addr = elem.first;
			uint8_t original_byte = mem_read_helper<uint8_t>(&cpu->cpu_ctx, addr, 0);
			g_break_list.insert_or_assign(addr, brk_info{ original_byte, brk_t::breakpoint });
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
		g_break_list.insert_or_assign(addr, brk_info{ original_byte, type });
	}
}

void
dbg_apply_sw_breakpoints(cpu_t *cpu)
{
	dbg_update_sw_breakpoints(cpu, [](cpu_t *cpu) {
		for (const auto &elem : g_break_list) {
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
		for (const auto &elem : g_break_list) {
			dbg_remove_sw_breakpoints(cpu, elem.first, elem.second.original_byte);
		}
		});
}

void
dbg_remove_sw_breakpoints(cpu_t *cpu, addr_t addr)
{
	dbg_update_sw_breakpoints(cpu, [&](cpu_t *cpu) {
		if (const auto it = g_break_list.find(addr); it != g_break_list.end()) {
			dbg_remove_sw_breakpoints(cpu, it->first, it->second.original_byte);
		}
		});
}

static void
dbg_update_sw_breakpoints(cpu_t *cpu)
{
	dbg_update_sw_breakpoints(cpu, [](cpu_t *cpu) {
		for (auto &elem : g_break_list) {
			uint8_t original_byte = mem_read_helper<uint8_t>(&cpu->cpu_ctx, elem.first, 0);
			if (original_byte != 0xCC) {
				// Because this is called before the breakpoints are removed, if the byte read is not 0xCC, then it means the running sw has overwritten it.
				// In this case we update the original byte with the new updated value that the sw has written to memory.
				elem.second.original_byte = original_byte;
			}
		}
		});
}

void
dbg_update_watchpoint(cpu_t *cpu, uint32_t dr_idx, addr_t addr, uint32_t brk_type_rw, uint32_t brk_type_size, bool enable)
{
	assert(brk_type_rw != DR7_TYPE_INSTR);
	assert(dr_idx < 4);

	uint32_t enable_shift = dr_idx * 2;
	uint32_t rw_shift = DR7_TYPE_SHIFT + dr_idx * 4;
	uint32_t size_shift = DR7_LEN_SHIFT + dr_idx * 4;
	uint32_t dr7 = cpu->cpu_ctx.regs.dr[7] & ~((3 << enable_shift) | (3 << rw_shift) | (3 << size_shift));
	dr7 |= (enable ? 3 : 0) << enable_shift;
	dr7 |= (brk_type_rw << rw_shift);
	dr7 |= (brk_type_size << size_shift);
	cpu->cpu_ctx.regs.dr[7] = dr7;
	cpu->cpu_ctx.regs.dr[dr_idx] = addr;
}

void
dbg_apply_watchpoints(cpu_t *cpu)
{
	update_drN_helper(&cpu->cpu_ctx, 7, cpu->cpu_ctx.regs.dr[7]);
}

static void
dbg_wait(cpu_ctx_t *cpu_ctx)
{
	// disable all breakpoints so that we can show the original instructions in the disassembler
	dbg_update_sw_breakpoints(cpu_ctx->cpu);
	dbg_remove_sw_breakpoints(cpu_ctx->cpu);

	// wait until the debugger continues execution
	g_break_pc = cpu_ctx->regs.cs_hidden.base + cpu_ctx->regs.eip;
	g_mem_editor_update = true;
	g_guest_running.clear();
	g_guest_running.notify_one();
	g_guest_running.wait(false);
	dbg_apply_sw_breakpoints(cpu_ctx->cpu);
	dbg_apply_watchpoints(cpu_ctx->cpu);
}

static void
dbg_watchpoint_handler(cpu_ctx_t *cpu_ctx)
{
	// NOTE: this is called from the emulation thread

	cpu_ctx->regs.dr[6] &= ~(DR6_B0_MASK | DR6_B1_MASK | DR6_B2_MASK | DR6_B3_MASK);

	dbg_wait(cpu_ctx);
}

static void
dbg_single_step_handler(cpu_ctx_t *cpu_ctx)
{
	// NOTE: this is called from the emulation thread

	cpu_ctx->regs.dr[6] &= ~DR6_BS_MASK;

	dbg_wait(cpu_ctx);
}

static void
dbg_sw_breakpoint_handler(cpu_ctx_t *cpu_ctx)
{
	// NOTE: this is called from the emulation thread

	addr_t pc = cpu_ctx->regs.cs_hidden.base + cpu_ctx->regs.eip - 1; // if this is our int3, it will always be one byte large
	if (auto it = g_break_list.find(pc); it != g_break_list.end()) {
		// disable all breakpoints so that we can show the original instructions in the disassembler
		dbg_update_sw_breakpoints(cpu_ctx->cpu);
		dbg_remove_sw_breakpoints(cpu_ctx->cpu);
		if (it->second.type == brk_t::step_over) {
			g_break_list.erase(it);
		}
		else {
			std::vector<decltype(g_break_list)::key_type> key_vec;
			for (auto &&elem : g_break_list) {
				if (elem.second.type == brk_t::step_over) {
					key_vec.emplace_back(elem.first);
				}
			}
			for (auto &&key : key_vec) {
				g_break_list.erase(key);
			}
			g_step_out_active = false;
		}

		// wait until the debugger continues execution
		g_break_pc = pc;
		g_mem_editor_update = true;
		g_guest_running.clear();
		g_guest_running.notify_one();
		g_guest_running.wait(false);

		cpu_ctx->regs.eip -= 1;
		dbg_remove_sw_breakpoints(cpu_ctx->cpu, pc);
		dbg_exec_original_instr(cpu_ctx->cpu);
		dbg_apply_sw_breakpoints(cpu_ctx->cpu);
		dbg_apply_watchpoints(cpu_ctx->cpu);
	}
}

void
dbg_exp_handler(cpu_ctx_t *cpu_ctx)
{
	// NOTE: task switches are currently not supported, so we don't check for DR6_BT_MASK

	if (cpu_ctx->regs.dr[6] & (DR6_B0_MASK | DR6_B1_MASK | DR6_B2_MASK | DR6_B3_MASK | DR6_BD_MASK)) {
		// If it is an instruction breakpoint or a general detect condition, clear the corresponding flags in dr6
		uint32_t dr6_mask = DR6_BD_MASK;
		for (int i = 0; i < 4; ++i) {
			int dr7_type = cpu_get_watchpoint_type(cpu_ctx->cpu, i);
			if (dr7_type == DR7_TYPE_INSTR) {
				dr6_mask |= (1 << i);
			}
		}

		cpu_ctx->regs.dr[6] &= ~dr6_mask;
	}

	try {
		if (cpu_ctx->regs.dr[6] & DR6_BS_MASK) {
			dbg_single_step_handler(cpu_ctx);
		}
		else if (cpu_ctx->regs.dr[6] & (DR6_B0_MASK | DR6_B1_MASK | DR6_B2_MASK | DR6_B3_MASK)) {
			dbg_watchpoint_handler(cpu_ctx);
		}
		else {
			dbg_sw_breakpoint_handler(cpu_ctx);
		}
	}
	catch (host_exp_t) {
		// this happens when there is an unhandled exception while attempting to update the breakpoints
		LIB86CPU_ABORT_msg("Failed to update breakpoints");
	}
}
