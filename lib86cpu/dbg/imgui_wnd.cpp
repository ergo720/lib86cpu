/*
 * imgui debugger widgets
 *
 * ergo720                Copyright (c) 2022
 */

#include "imgui.h"
#include "imgui_memory_editor.h"
#include "lib86cpu_priv.h"
#include "imgui_wnd.h"
#include "debugger.h"
#include "internal.h"
#include <charconv>
#include <algorithm>

#define DISAS_INSTR_CACHED_NUM 50
#define DISAS_TXT "Disassembly"
#define BRK_TXT "Breakpoints"
#define BRK_TYPE_TXT "Breakpoint"
#define WATCH_TYPE_TXT "Watchpoint"


enum class dbg_command_t {
	step_into,
	step_out,
	step_over,
	toggle_brk,
	continue_,
};

static std::vector<std::pair<addr_t, std::string>> g_disas_data;
static unsigned g_instr_sel = 0;
static bool g_show_popup = false;
static regs_t g_last_regs;
static uint32_t g_last_eflags;
static uint16_t g_last_fstatus;
static uint16_t g_last_ftags;
static bool g_regs_need_update;
static std::array<char, std::max(std::string(DISAS_TXT).size(), std::string(BRK_TXT).size()) + 1> g_disas_button_text(DISAS_TXT);
static uint32_t g_disas_view_active = 1;

static_assert(std::is_trivially_copyable_v<regs_t>); // make sure we can use std::copy on regs_t

void
dbg_draw_error_popup()
{
	ImGui::SetNextWindowPos(ImVec2(ImGui::GetWindowPos().x + ImGui::GetWindowWidth() * 0.5f,
		ImGui::GetWindowPos().y + ImGui::GetWindowHeight() * 0.5f), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
	ImGui::SetNextWindowSize(ImVec2(235.0f, 75.0f));
	ImGui::OpenPopup("Error");
	if (ImGui::BeginPopupModal("Error", nullptr, ImGuiWindowFlags_NoResize)) {
		ImGui::Text("Failed to insert the breakpoint");
		if (ImGui::Button("OK")) {
			g_show_popup = false;
			ImGui::CloseCurrentPopup();
		}
		ImGui::EndPopup();
	}
}

void
dbg_copy_registers(cpu_t *cpu)
{
	std::copy(&cpu->cpu_ctx.regs, &cpu->cpu_ctx.regs + 1, &g_last_regs);
	g_last_eflags = read_eflags(cpu);
	g_last_fstatus = read_fstatus(cpu);
	g_last_ftags = read_ftags(cpu);
	g_regs_need_update = false;
}

static void
dbg_handle_continue(cpu_t *cpu) // default: F5
{
	if (!g_step_out_active) {
		dbg_copy_registers(cpu);
	}
	cpu->cpu_flags &= ~CPU_SINGLE_STEP;
	g_disas_data.clear();
	g_instr_sel = 0;
	dbg_apply_sw_breakpoints(cpu);
	const char *text = "Not available while debuggee is running";
	ImGui::SetCursorPos(ImVec2(ImGui::GetWindowWidth() / 2 - (ImGui::CalcTextSize(text).x / 2), ImGui::GetWindowHeight() / 2 - (ImGui::CalcTextSize(text).y / 2)));
	ImGui::Text("%s", text);
	g_guest_running.test_and_set();
	g_guest_running.notify_one();
}

static void
dbg_handle_breakpoint_toggle(cpu_t *cpu) // default: F9
{
	if (!g_disas_data.empty()) { // it will happen if the first instr cannot be decoded
		addr_t addr = (g_disas_data.begin() + g_instr_sel)->first;
		if (g_break_list.contains(addr)) {
			dbg_remove_sw_breakpoints(cpu, addr);
			g_break_list.erase(addr);
		}
		else {
			if (const auto &opt = dbg_insert_sw_breakpoint(cpu, addr); opt) {
				g_show_popup = false;
				g_break_list.emplace(addr, brk_info{ *opt, brk_t::breakpoint });
			}
			else {
				g_show_popup = true;
			}
		}
	}
}

static void
dbg_handle_step_into(cpu_t *cpu) // default: F11
{
	// don't reinstall the sw breakpoints because, if we are single-stepping one of them, we will receive a bp exp again, instead of a db exp
	if (!g_step_out_active) {
		dbg_copy_registers(cpu);
	}
	cpu->cpu_flags |= CPU_SINGLE_STEP;
	g_disas_data.clear();
	g_instr_sel = 0;
	const char *text = "Not available while debuggee is running";
	ImGui::SetCursorPos(ImVec2(ImGui::GetWindowWidth() / 2 - (ImGui::CalcTextSize(text).x / 2), ImGui::GetWindowHeight() / 2 - (ImGui::CalcTextSize(text).y / 2)));
	ImGui::Text("%s", text);
	g_guest_running.test_and_set();
	g_guest_running.notify_one();
}

static void
dbg_handle_step_over(cpu_t *cpu) // default: F10
{
	if (g_disas_data.size() >= 2) { // it will happen if the first or second instr cannot be decoded
		std::string_view curr_instr = g_disas_data.begin()->second;
		if (curr_instr.starts_with("call")) {
			addr_t addr = (++g_disas_data.begin())->first;
			if (const auto &opt = dbg_insert_sw_breakpoint(cpu, addr); opt) {
				g_show_popup = false;
				g_break_list.emplace(addr, brk_info{ *opt, brk_t::step_over });
				dbg_handle_continue(cpu);
			}
			else {
				g_show_popup = true;
			}
		}
		else {
			dbg_handle_step_into(cpu);
		}
	}
}

static void
dbg_handle_step_out(cpu_t *cpu) // default: F11 + SHIFT
{
	if (!g_disas_data.empty()) { // it will happen if the first instr cannot be decoded
		std::string_view curr_instr = g_disas_data.begin()->second;
		if (curr_instr.starts_with("ret") || curr_instr.starts_with("iret")) {
			g_step_out_active = false;
			dbg_handle_step_into(cpu);
		}
		else {
			dbg_handle_step_over(cpu);
			g_step_out_active = g_show_popup ? false : true;
		}
	}
}

template<dbg_command_t command>
void exec_dbg_command(cpu_t *cpu)
{
	if constexpr (command != dbg_command_t::toggle_brk) {
		if (g_step_out_active == false) {
			g_regs_need_update = true;
		}
	}

	if constexpr (command == dbg_command_t::step_into) {
		dbg_handle_step_into(cpu);
	}
	else if constexpr (command == dbg_command_t::step_out) {
		dbg_handle_step_out(cpu);
	}
	else if constexpr (command == dbg_command_t::step_over) {
		dbg_handle_step_over(cpu);
	}
	else if constexpr (command == dbg_command_t::toggle_brk) {
		dbg_handle_breakpoint_toggle(cpu);
	}
	else if constexpr (command == dbg_command_t::continue_) {
		dbg_handle_continue(cpu);
	}
	else {
		throw std::logic_error("Unknown debugger command");
	}
}

void
dbg_draw_imgui_wnd(cpu_t *cpu)
{
	// F5: continue execution
	// F9: toggle breakpoint
	// F10: step over
	// F11: step into
	// F11 + SHIFT: step out

	const int wnd_w = g_main_wnd_w;
	const int wnd_h = g_main_wnd_h;
	static const auto &[txt_r, txt_g, txt_b] = g_txt_col;
	static const auto &[brk_r, brk_g, brk_b] = g_brk_col;
	static const auto &[bkg_r, bkg_g, bkg_b] = g_bkg_col;
	static const auto &[reg_r, reg_g, reg_b] = g_reg_col;

	ImGui::SetNextWindowPos(ImVec2(10, 10), ImGuiCond_FirstUseEver);
	ImGui::SetNextWindowSize(ImVec2((wnd_w - 30) / 2, (wnd_h - 30) / 2), ImGuiCond_FirstUseEver);
	ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(txt_r, txt_g, txt_b, 1.0f));
	ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(bkg_r, bkg_g, bkg_b, 1.0f));
	ImGui::PushStyleColor(ImGuiCol_PopupBg, ImVec4(bkg_r, bkg_g, bkg_b, 1.0f));
	if (ImGui::Begin("Disassembler")) {
		static char buff[9];
		ImGui::PushItemWidth(80.0f);
		bool enter_pressed = ImGui::InputText("Address", buff, IM_ARRAYSIZE(buff), ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_EnterReturnsTrue);
		ImGui::SameLine();
		bool change_disas_view = ImGui::Button(g_disas_button_text.data());
		ImGui::PopItemWidth();
		ImGui::ColorEdit3("Text color", g_txt_col);
		ImGui::ColorEdit3("Breakpoint color", g_brk_col);
		ImGui::ColorEdit3("Background color", g_bkg_col);
		ImGui::BeginChild("Disassembler view");
		if (!g_guest_running.test()) {
			if (change_disas_view) {
				constexpr auto disas_txt_size = std::string(DISAS_TXT).size();
				constexpr auto brk_txt_size = std::string(BRK_TXT).size();
				g_disas_view_active ^= 1;
				std::copy_n(g_disas_view_active ? DISAS_TXT : BRK_TXT, g_disas_view_active ? disas_txt_size : brk_txt_size, g_disas_button_text.begin());
				g_disas_button_text[g_disas_view_active ? disas_txt_size : brk_txt_size] = '\0';
			}

			if (g_disas_view_active == 0) {
				// render the breakpoint list window
				constexpr auto brk_type_txt_size = std::string(BRK_TYPE_TXT).size();
				constexpr auto watch_type_txt_size = std::string(WATCH_TYPE_TXT).size();
				static decltype(g_break_list)::iterator sel_it = g_break_list.begin();
				static std::array<char, 9> addr_buff;
				static std::array<char, std::max(brk_type_txt_size, watch_type_txt_size) + 12 + 1> txt_buff; // name type + ": " + 10 chars needed to print its addr
				static uint32_t brk_sel = 0;
				static bool show_brk_popup = false;
				static int brk_type_sel = 0; // 0: brk, 1: watch
				uint32_t num_brk_printed = 0;

				for (auto it = g_break_list.begin(); it != g_break_list.end(); ++it) {
					const auto &elem = *it;
					if (elem.second.type == brk_t::breakpoint) {
						std::snprintf(txt_buff.data(), txt_buff.size(), BRK_TYPE_TXT ": 0x%08X", elem.first);
					}
					else if (elem.second.type == brk_t::watchpoint) {
						assert(0); // not supported yet
					}

					if (ImGui::Selectable(txt_buff.data(), brk_sel == num_brk_printed)) {
						[[maybe_unused]] const auto &ret = std::to_chars(addr_buff.data(), addr_buff.data() + addr_buff.size(), it->first, 16);
						assert(ret.ec == std::errc());
						show_brk_popup = true;
						brk_sel = num_brk_printed;
						sel_it = it;
					}
					++num_brk_printed;
				}

				if ((show_brk_popup == false) && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
					std::fill(addr_buff.begin(), addr_buff.end(), 0); // show an empty address
					show_brk_popup = true;
					sel_it = g_break_list.end();
				}

				if (show_brk_popup) {
					ImGui::SetNextWindowPos(ImVec2(ImGui::GetWindowPos().x + ImGui::GetWindowWidth() * 0.5f,
						ImGui::GetWindowPos().y + ImGui::GetWindowHeight() * 0.5f), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
					ImGui::SetNextWindowSize(ImVec2(250.0f, 100.0f));
					ImGui::OpenPopup("New breakpoint");
					if (ImGui::BeginPopupModal("New breakpoint", nullptr, ImGuiWindowFlags_NoResize)) {
						if (ImGui::BeginCombo("breakpoint type", BRK_TYPE_TXT)) {
							if (ImGui::Selectable(BRK_TYPE_TXT, false)) {
								brk_type_sel = 0;
							}
							if (ImGui::Selectable(WATCH_TYPE_TXT, false)) {
								brk_type_sel = 1;
							}
							ImGui::EndCombo();
						}
						ImGui::InputText("address", addr_buff.data(), addr_buff.size(), ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_EnterReturnsTrue);
						bool close_brk_popup = ImGui::Button("OK");
						ImGui::SameLine();
						bool delete_brk_popup = ImGui::Button("Delete");
						ImGui::SameLine();
						bool cancel_brk_popup = ImGui::Button("Cancel");
						if (g_show_popup) {
							dbg_draw_error_popup();
						}
						else if (close_brk_popup) {
							if (brk_type_sel == 0) { // breakpoint was selected
								uint32_t addr;
								const auto &ret = std::from_chars(addr_buff.data(), addr_buff.data() + addr_buff.size(), addr, 16);
								if (ret.ec != std::errc()) { // the conversion might fail when the popup is open with a right click
									g_show_popup = true;
								}
								else {
									if (const auto &opt = dbg_insert_sw_breakpoint(cpu, addr); opt) {
										if (sel_it != g_break_list.end()) {
											g_break_list.erase(sel_it);
										}
										g_break_list.emplace(addr, brk_info{ *opt, brk_t::breakpoint });
										g_show_popup = show_brk_popup = false;
									}
									else {
										g_show_popup = true;
									}
								}

								ImGui::CloseCurrentPopup();
							}
							else {
								assert(0); // not supported yet
							}
						}
						else if (delete_brk_popup) {
							if (sel_it != g_break_list.end()) {
								g_break_list.erase(sel_it);
							}
							show_brk_popup = false;
						}
						else if (cancel_brk_popup) {
							show_brk_popup = false;
						}
						ImGui::EndPopup();
					}
				}
			}
			else {
				// render the disassembler window
				if (ImGui::IsKeyPressed(ImGuiKey_F5)) {
					exec_dbg_command<dbg_command_t::continue_>(cpu);
				}
				else {
					unsigned instr_to_print = DISAS_INSTR_CACHED_NUM;
					if (enter_pressed) {
						// NOTE: it can't fail because ImGui::InputText only accepts hex digits and g_break_pc is large enough to store every possible 32 bit address
						[[maybe_unused]] auto ret = std::from_chars(buff, buff + sizeof(buff), g_break_pc, 16);
						assert(ret.ec == std::errc());
						g_disas_data.clear();
						g_instr_sel = 0;
					}
					if (g_disas_data.empty()) {
						// this happens the first time the disassembler window is displayed
						g_disas_data = dbg_disas_code_block(cpu, g_break_pc, instr_to_print);
					}
					else if (ImGui::GetScrollY() == ImGui::GetScrollMaxY()) {
						// the user has scrolled up to the end of the instr block we previously cached, so we need to disassemble a new block
						// and append it to the end of the cached data
						const auto &disas_next_block = dbg_disas_code_block(cpu, g_break_pc, instr_to_print);
						g_disas_data.insert(g_disas_data.end(), std::make_move_iterator(disas_next_block.begin()), std::make_move_iterator(disas_next_block.end()));
					}
					assert(std::adjacent_find(g_disas_data.begin(), g_disas_data.end(), [](const auto &lhs, const auto &rhs)
						{
							return lhs.first == rhs.first;
						}) == g_disas_data.end());

					if (!g_step_out_active) {
						unsigned num_instr_printed = 0;
						for (; num_instr_printed < g_disas_data.size(); ++num_instr_printed) {
							// buffer size = buff_size used in log_instr for instr string + 12 chars need to print its addr
							char buffer[256 + 12 + 1];
							addr_t addr = (g_disas_data.begin() + num_instr_printed)->first;
							std::snprintf(buffer, sizeof(buffer), "0x%08X  %s", addr, (g_disas_data.begin() + num_instr_printed)->second.c_str());
							if (g_break_list.contains(addr)) {
								// draw breakpoint with a different text color
								ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(brk_r, brk_g, brk_b, 1.0f));
								if (ImGui::Selectable(buffer, g_instr_sel == num_instr_printed)) {
									g_instr_sel = num_instr_printed;
								}
								ImGui::PopStyleColor();
							}
							else {
								if (ImGui::Selectable(buffer, g_instr_sel == num_instr_printed)) {
									g_instr_sel = num_instr_printed;
								}
							}
						}
						if (num_instr_printed != instr_to_print) {
							for (unsigned instr_left_to_print = num_instr_printed; instr_left_to_print < instr_to_print; ++instr_left_to_print) {
								ImGui::Text("????");
							}
						}
					}

					if (g_show_popup) {
						ImGui::SetNextWindowPos(ImVec2(ImGui::GetWindowPos().x + ImGui::GetWindowWidth() * 0.5f,
							ImGui::GetWindowPos().y + ImGui::GetWindowHeight() * 0.5f), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
						ImGui::SetNextWindowSize(ImVec2(235.0f, 75.0f));
						ImGui::OpenPopup("Error");
						if (ImGui::BeginPopupModal("Error", nullptr, ImGuiWindowFlags_NoResize)) {
							ImGui::Text("Failed to insert the breakpoint");
							if (ImGui::Button("OK")) {
								g_show_popup = false;
								ImGui::CloseCurrentPopup();
							}
							ImGui::EndPopup();
						}
					}
					else {
						if (g_step_out_active || (ImGui::IsKeyPressed(ImGuiKey_F11) && (ImGui::IsKeyPressed(ImGuiKey_LeftShift) || ImGui::IsKeyPressed(ImGuiKey_RightShift)))) {
							exec_dbg_command<dbg_command_t::step_out>(cpu);
						}
						else if (ImGui::IsKeyPressed(ImGuiKey_F11)) {
							exec_dbg_command<dbg_command_t::step_into>(cpu);
						}
						else if (ImGui::IsKeyPressed(ImGuiKey_F10)) {
							exec_dbg_command<dbg_command_t::step_over>(cpu);
						}
						else if (ImGui::IsKeyPressed(ImGuiKey_F9)) {
							exec_dbg_command<dbg_command_t::toggle_brk>(cpu);
						}
					}
				}
			}
		}
		else {
			const char *text = "Not available while debuggee is running";
			ImGui::SetCursorPos(ImVec2(ImGui::GetWindowWidth() / 2 - (ImGui::CalcTextSize(text).x / 2), ImGui::GetWindowHeight() / 2 - (ImGui::CalcTextSize(text).y / 2)));
			ImGui::Text("%s", text);
		}
		ImGui::EndChild();
	}
	ImGui::End();

	ImGui::SetNextWindowPos(ImVec2(wnd_w / 2 + 5, 10), ImGuiCond_FirstUseEver);
	ImGui::SetNextWindowSize(ImVec2((wnd_w - 30) / 2, (wnd_h - 30) / 2), ImGuiCond_FirstUseEver);
	if (ImGui::Begin("Memory editor")) {
		static char buff[9];
		ImGui::PushItemWidth(80.0f);
		bool enter_pressed = ImGui::InputText("Address", buff, IM_ARRAYSIZE(buff), ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_EnterReturnsTrue);
		ImGui::SameLine();
		bool change_mem_view = ImGui::Button(g_mem_button_text.data());
		if (change_mem_view) {
			(++g_mem_active) &= 3;
			g_mem_button_text[g_mem_button_text.size() - 1] = '0' + g_mem_active;
		}
		ImGui::PopItemWidth();
		ImGui::ColorEdit3("Text color", g_txt_col);
		ImGui::ColorEdit3("Background color", g_bkg_col);
		ImGui::BeginChild("Memory view");
		if (!g_guest_running.test()) {
			static uint8_t mem_buff[PAGE_SIZE];
			static MemoryEditor mem_editor;
			mem_editor.WriteFn = &dbg_ram_write;
			if (enter_pressed) {
				// NOTE: it can't fail because ImGui::InputText only accepts hex digits and g_mem_pc is large enough to store every possible 32 bit address
				[[maybe_unused]] auto ret = std::from_chars(buff, buff + sizeof(buff), g_mem_pc[g_mem_active], 16);
				assert(ret.ec == std::errc());
				g_mem_editor_update = true;
			}
			if (g_mem_editor_update || change_mem_view) {
				dbg_ram_read(cpu, mem_buff);
				g_mem_editor_update = false;
			}
			mem_editor.DrawContents(mem_buff, PAGE_SIZE, g_mem_pc[g_mem_active]);
		}
		else {
			const char *text = "Not available while debuggee is running";
			ImGui::SetCursorPos(ImVec2(ImGui::GetWindowWidth() / 2 - (ImGui::CalcTextSize(text).x / 2), ImGui::GetWindowHeight() / 2 - (ImGui::CalcTextSize(text).y / 2)));
			ImGui::Text("%s", text);
		}
		ImGui::EndChild();
	}
	ImGui::End();

	ImGui::SetNextWindowPos(ImVec2(10, wnd_h / 2 + 5), ImGuiCond_FirstUseEver);
	ImGui::SetNextWindowSize(ImVec2(wnd_w - 20, (wnd_h - 30) / 2), ImGuiCond_FirstUseEver);
	if (ImGui::Begin("Registers")) {
		ImGui::ColorEdit3("Text color", g_txt_col);
		ImGui::ColorEdit3("Background color", g_bkg_col);
		ImGui::ColorEdit3("Register change color", g_reg_col);
		ImGui::BeginChild("Registers view");
		if (!g_guest_running.test()) {
			ImVec4 regs_col(reg_r, reg_g, reg_b, 1.0f);
			ImVec4 txt_col(txt_r, txt_g, txt_b, 1.0f);
			ImGui::TextColored(cpu->cpu_ctx.regs.eax != g_last_regs.eax ? regs_col : txt_col, "eax: 0x%08X", cpu->cpu_ctx.regs.eax);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.ecx != g_last_regs.ecx ? regs_col : txt_col, "ecx: 0x%08X", cpu->cpu_ctx.regs.ecx);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.edx != g_last_regs.edx ? regs_col : txt_col, "edx: 0x%08X", cpu->cpu_ctx.regs.edx);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.ebx != g_last_regs.ebx ? regs_col : txt_col, "ebx: 0x%08X", cpu->cpu_ctx.regs.ebx);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.esp != g_last_regs.esp ? regs_col : txt_col, "esp: 0x%08X", cpu->cpu_ctx.regs.esp);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.ebp != g_last_regs.ebp ? regs_col : txt_col, "ebp: 0x%08X", cpu->cpu_ctx.regs.ebp);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.esi != g_last_regs.esi ? regs_col : txt_col, "esi: 0x%08X", cpu->cpu_ctx.regs.esi);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.edi != g_last_regs.edi ? regs_col : txt_col, "edi: 0x%08X", cpu->cpu_ctx.regs.edi);

			ImGui::TextColored(read_eflags(cpu) != g_last_eflags ? regs_col : txt_col, "eflags: 0x%08X", read_eflags(cpu));
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.eip != g_last_regs.eip ? regs_col : txt_col, "eip: 0x%08X", cpu->cpu_ctx.regs.eip);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.cs != g_last_regs.cs ? regs_col : txt_col, "cs: 0x%04hX", cpu->cpu_ctx.regs.cs);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.es != g_last_regs.es ? regs_col : txt_col, "es: 0x%04hX", cpu->cpu_ctx.regs.es);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.ss != g_last_regs.ss ? regs_col : txt_col, "ss: 0x%04hX", cpu->cpu_ctx.regs.ss);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.ds != g_last_regs.ds ? regs_col : txt_col, "ds: 0x%04hX", cpu->cpu_ctx.regs.ds);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.fs != g_last_regs.fs ? regs_col : txt_col, "fs: 0x%04hX", cpu->cpu_ctx.regs.fs);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.gs != g_last_regs.gs ? regs_col : txt_col, "gs: 0x%04hX", cpu->cpu_ctx.regs.gs);

			ImGui::TextColored(cpu->cpu_ctx.regs.cs_hidden.base != g_last_regs.cs_hidden.base ? regs_col : txt_col, "cs.base: 0x%08X", cpu->cpu_ctx.regs.cs_hidden.base);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.cs_hidden.limit != g_last_regs.cs_hidden.limit ? regs_col : txt_col, "cs.limit: 0x%08X", cpu->cpu_ctx.regs.cs_hidden.limit);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.cs_hidden.flags != g_last_regs.cs_hidden.flags ? regs_col : txt_col, "cs.flags: 0x%08X", cpu->cpu_ctx.regs.cs_hidden.flags);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.es_hidden.base != g_last_regs.es_hidden.base ? regs_col : txt_col, "es.base: 0x%08X", cpu->cpu_ctx.regs.es_hidden.base);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.es_hidden.limit != g_last_regs.es_hidden.limit ? regs_col : txt_col, "es.limit: 0x%08X", cpu->cpu_ctx.regs.es_hidden.limit);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.es_hidden.flags != g_last_regs.es_hidden.flags ? regs_col : txt_col, "es.flags: 0x%08X", cpu->cpu_ctx.regs.es_hidden.flags);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.ss_hidden.base != g_last_regs.ss_hidden.base ? regs_col : txt_col, "ss.base: 0x%08X", cpu->cpu_ctx.regs.ss_hidden.base);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.ss_hidden.limit != g_last_regs.ss_hidden.limit ? regs_col : txt_col, "ss.limit: 0x%08X", cpu->cpu_ctx.regs.ss_hidden.limit);

			ImGui::TextColored(cpu->cpu_ctx.regs.ss_hidden.flags != g_last_regs.ss_hidden.flags ? regs_col : txt_col, "ss.flags: 0x%08X", cpu->cpu_ctx.regs.ss_hidden.flags);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.ds_hidden.base != g_last_regs.ds_hidden.base ? regs_col : txt_col, "ds.base: 0x%08X", cpu->cpu_ctx.regs.ds_hidden.base);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.ds_hidden.limit != g_last_regs.ds_hidden.limit ? regs_col : txt_col, "ds.limit: 0x%08X", cpu->cpu_ctx.regs.ds_hidden.limit);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.ds_hidden.flags != g_last_regs.ds_hidden.flags ? regs_col : txt_col, "ds.flags: 0x%08X", cpu->cpu_ctx.regs.ds_hidden.flags);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.fs_hidden.base != g_last_regs.fs_hidden.base ? regs_col : txt_col, "fs.base: 0x%08X", cpu->cpu_ctx.regs.fs_hidden.base);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.fs_hidden.limit != g_last_regs.fs_hidden.limit ? regs_col : txt_col, "fs.limit: 0x%08X", cpu->cpu_ctx.regs.fs_hidden.limit);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.fs_hidden.flags != g_last_regs.fs_hidden.flags ? regs_col : txt_col, "fs.flags: 0x%08X", cpu->cpu_ctx.regs.fs_hidden.flags);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.gs_hidden.base != g_last_regs.gs_hidden.base ? regs_col : txt_col, "gs.base: 0x%08X", cpu->cpu_ctx.regs.gs_hidden.base);

			ImGui::TextColored(cpu->cpu_ctx.regs.gs_hidden.limit != g_last_regs.gs_hidden.limit ? regs_col : txt_col, "gs.limit: 0x%08X", cpu->cpu_ctx.regs.gs_hidden.limit);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.gs_hidden.flags != g_last_regs.gs_hidden.flags ? regs_col : txt_col, "gs.flags: 0x%08X", cpu->cpu_ctx.regs.gs_hidden.flags);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.idtr_hidden.base != g_last_regs.idtr_hidden.base ? regs_col : txt_col, "idtr.base: 0x%08X", cpu->cpu_ctx.regs.idtr_hidden.base);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.idtr_hidden.limit != g_last_regs.idtr_hidden.limit ? regs_col : txt_col, "idtr.limit: 0x%08X", cpu->cpu_ctx.regs.idtr_hidden.limit);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.gdtr_hidden.base != g_last_regs.gdtr_hidden.base ? regs_col : txt_col, "gdtr.base: 0x%08X", cpu->cpu_ctx.regs.gdtr_hidden.base);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.gdtr_hidden.limit != g_last_regs.gdtr_hidden.limit ? regs_col : txt_col, "gdtr.limit: 0x%08X", cpu->cpu_ctx.regs.gdtr_hidden.limit);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.ldtr != g_last_regs.ldtr ? regs_col : txt_col, "ldtr: 0x%04hX", cpu->cpu_ctx.regs.ldtr);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.tr != g_last_regs.tr ? regs_col : txt_col, "tr: 0x%04hX", cpu->cpu_ctx.regs.tr);

			ImGui::TextColored(cpu->cpu_ctx.regs.ldtr_hidden.base != g_last_regs.ldtr_hidden.base ? regs_col : txt_col, "ldtr.base: 0x%08X", cpu->cpu_ctx.regs.ldtr_hidden.base);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.ldtr_hidden.limit != g_last_regs.ldtr_hidden.limit ? regs_col : txt_col, "ldtr.limit: 0x%08X", cpu->cpu_ctx.regs.ldtr_hidden.limit);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.ldtr_hidden.flags != g_last_regs.ldtr_hidden.flags ? regs_col : txt_col, "ldtr.flags: 0x%08X", cpu->cpu_ctx.regs.ldtr_hidden.flags);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.tr_hidden.base != g_last_regs.tr_hidden.base ? regs_col : txt_col, "tr.base: 0x%08X", cpu->cpu_ctx.regs.tr_hidden.base);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.tr_hidden.limit != g_last_regs.tr_hidden.limit ? regs_col : txt_col, "tr.limit: 0x%08X", cpu->cpu_ctx.regs.tr_hidden.limit);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.tr_hidden.flags != g_last_regs.tr_hidden.flags ? regs_col : txt_col, "tr.flags: 0x%08X", cpu->cpu_ctx.regs.tr_hidden.flags);

			ImGui::TextColored(cpu->cpu_ctx.regs.cr0 != g_last_regs.cr0 ? regs_col : txt_col, "cr0: 0x%08X", cpu->cpu_ctx.regs.cr0);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.cr2 != g_last_regs.cr2 ? regs_col : txt_col, "cr2: 0x%08X", cpu->cpu_ctx.regs.cr2);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.cr3 != g_last_regs.cr3 ? regs_col : txt_col, "cr3: 0x%08X", cpu->cpu_ctx.regs.cr3);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.cr4 != g_last_regs.cr4 ? regs_col : txt_col, "cr4: 0x%08X", cpu->cpu_ctx.regs.cr4);

			ImGui::TextColored(cpu->cpu_ctx.regs.dr[0] != g_last_regs.dr[0] ? regs_col : txt_col, "dr0: 0x%08X", cpu->cpu_ctx.regs.dr[0]);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.dr[1] != g_last_regs.dr[1] ? regs_col : txt_col, "dr1: 0x%08X", cpu->cpu_ctx.regs.dr[1]);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.dr[2] != g_last_regs.dr[2] ? regs_col : txt_col, "dr2: 0x%08X", cpu->cpu_ctx.regs.dr[2]);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.dr[3] != g_last_regs.dr[3] ? regs_col : txt_col, "dr3: 0x%08X", cpu->cpu_ctx.regs.dr[3]);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.dr[4] != g_last_regs.dr[4] ? regs_col : txt_col, "dr4: 0x%08X", cpu->cpu_ctx.regs.dr[4]);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.dr[5] != g_last_regs.dr[5] ? regs_col : txt_col, "dr5: 0x%08X", cpu->cpu_ctx.regs.dr[5]);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.dr[6] != g_last_regs.dr[6] ? regs_col : txt_col, "dr6: 0x%08X", cpu->cpu_ctx.regs.dr[6]);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.dr[7] != g_last_regs.dr[7] ? regs_col : txt_col, "dr7: 0x%08X", cpu->cpu_ctx.regs.dr[7]);

			ImGui::TextColored(cpu->cpu_ctx.regs.fr[0].high != g_last_regs.fr[0].high ? regs_col : txt_col, "r0.h: 0x%04hX", cpu->cpu_ctx.regs.fr[0].high);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.fr[0].low != g_last_regs.fr[0].low ? regs_col : txt_col, "r0.l: 0x%016" PRIX64, cpu->cpu_ctx.regs.fr[0].low);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.fr[1].high != g_last_regs.fr[1].high ? regs_col : txt_col, "r1.h: 0x%04hX", cpu->cpu_ctx.regs.fr[1].high);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.fr[1].low != g_last_regs.fr[1].low ? regs_col : txt_col, "r1.l: 0x%016" PRIX64, cpu->cpu_ctx.regs.fr[1].low);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.fr[2].high != g_last_regs.fr[2].high ? regs_col : txt_col, "r2.h: 0x%04hX", cpu->cpu_ctx.regs.fr[2].high);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.fr[3].low != g_last_regs.fr[2].low ? regs_col : txt_col, "r2.l: 0x%016" PRIX64, cpu->cpu_ctx.regs.fr[2].low);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.fr[3].high != g_last_regs.fr[3].high ? regs_col : txt_col, "r3.h: 0x%04hX", cpu->cpu_ctx.regs.fr[3].high);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.fr[3].low != g_last_regs.fr[3].low ? regs_col : txt_col, "r3.l: 0x%016" PRIX64, cpu->cpu_ctx.regs.fr[3].low);

			ImGui::TextColored(cpu->cpu_ctx.regs.fr[4].high != g_last_regs.fr[4].high ? regs_col : txt_col, "r4.h: 0x%04hX", cpu->cpu_ctx.regs.fr[4].high);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.fr[4].low != g_last_regs.fr[4].low ? regs_col : txt_col, "r4.l: 0x%016" PRIX64, cpu->cpu_ctx.regs.fr[4].low);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.fr[5].high != g_last_regs.fr[5].high ? regs_col : txt_col, "r5.h: 0x%04hX", cpu->cpu_ctx.regs.fr[5].high);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.fr[5].low != g_last_regs.fr[5].low ? regs_col : txt_col, "r5.l: 0x%016" PRIX64, cpu->cpu_ctx.regs.fr[5].low);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.fr[6].high != g_last_regs.fr[6].high ? regs_col : txt_col, "r6.h: 0x%04hX", cpu->cpu_ctx.regs.fr[6].high);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.fr[6].low != g_last_regs.fr[6].low ? regs_col : txt_col, "r6.l: 0x%016" PRIX64, cpu->cpu_ctx.regs.fr[6].low);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.fr[7].high != g_last_regs.fr[7].high ? regs_col : txt_col, "r7.h: 0x%04hX", cpu->cpu_ctx.regs.fr[7].high);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.fr[7].low != g_last_regs.fr[7].low ? regs_col : txt_col, "r7.l: 0x%016" PRIX64, cpu->cpu_ctx.regs.fr[7].low);

			ImGui::TextColored(cpu->cpu_ctx.regs.fctrl != g_last_regs.fctrl ? regs_col : txt_col, "fctrl: 0x%04X", cpu->cpu_ctx.regs.fctrl);
			ImGui::SameLine();
			ImGui::TextColored(read_fstatus(cpu) != g_last_fstatus ? regs_col : txt_col, "fstatus: 0x%04hX", read_fstatus(cpu));
			ImGui::SameLine();
			ImGui::TextColored(read_ftags(cpu) != g_last_ftags ? regs_col : txt_col, "ftags: 0x%04hX", read_ftags(cpu));
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.fcs != g_last_regs.fcs ? regs_col : txt_col, "fcs: 0x%04X", cpu->cpu_ctx.regs.fcs);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.fip != g_last_regs.fip ? regs_col : txt_col, "fip: 0x%08X", cpu->cpu_ctx.regs.fip);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.fds != g_last_regs.fds ? regs_col : txt_col, "fds: 0x%04X", cpu->cpu_ctx.regs.fds);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.fdp != g_last_regs.fdp ? regs_col : txt_col, "fdp: 0x%08X", cpu->cpu_ctx.regs.fdp);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.fop != g_last_regs.fop ? regs_col : txt_col, "fop: 0x%04X", cpu->cpu_ctx.regs.fop);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.mxcsr != g_last_regs.mxcsr ? regs_col : txt_col, "mxcsr: 0x%08X", cpu->cpu_ctx.regs.mxcsr);

			ImGui::TextColored(cpu->cpu_ctx.regs.xmm[0].high != g_last_regs.xmm[0].high ? regs_col : txt_col, "xmm0.h: 0x%016" PRIX64, cpu->cpu_ctx.regs.xmm[0].high);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.xmm[0].low != g_last_regs.xmm[0].low ? regs_col : txt_col, "xmm0.l: 0x%016" PRIX64, cpu->cpu_ctx.regs.xmm[0].low);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.xmm[1].high != g_last_regs.xmm[1].high ? regs_col : txt_col, "xmm1.h: 0x%016" PRIX64, cpu->cpu_ctx.regs.xmm[1].high);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.xmm[1].low != g_last_regs.xmm[1].low ? regs_col : txt_col, "xmm1.l: 0x%016" PRIX64, cpu->cpu_ctx.regs.xmm[1].low);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.xmm[2].high != g_last_regs.xmm[2].high ? regs_col : txt_col, "xmm2.h: 0x%016" PRIX64, cpu->cpu_ctx.regs.xmm[2].high);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.xmm[2].low != g_last_regs.xmm[2].low ? regs_col : txt_col, "xmm2.l: 0x%016" PRIX64, cpu->cpu_ctx.regs.xmm[2].low);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.xmm[3].high != g_last_regs.xmm[3].high ? regs_col : txt_col, "xmm3.h: 0x%016" PRIX64, cpu->cpu_ctx.regs.xmm[3].high);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.xmm[3].low != g_last_regs.xmm[3].low ? regs_col : txt_col, "xmm3.l: 0x%016" PRIX64, cpu->cpu_ctx.regs.xmm[3].low);

			ImGui::TextColored(cpu->cpu_ctx.regs.xmm[4].high != g_last_regs.xmm[4].high ? regs_col : txt_col, "xmm4.h: 0x%016" PRIX64, cpu->cpu_ctx.regs.xmm[4].high);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.xmm[4].low != g_last_regs.xmm[4].low ? regs_col : txt_col, "xmm4.l: 0x%016" PRIX64, cpu->cpu_ctx.regs.xmm[4].low);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.xmm[5].high != g_last_regs.xmm[5].high ? regs_col : txt_col, "xmm5.h: 0x%016" PRIX64, cpu->cpu_ctx.regs.xmm[5].high);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.xmm[5].low != g_last_regs.xmm[5].low ? regs_col : txt_col, "xmm5.l: 0x%016" PRIX64, cpu->cpu_ctx.regs.xmm[5].low);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.xmm[6].high != g_last_regs.xmm[6].high ? regs_col : txt_col, "xmm6.h: 0x%016" PRIX64, cpu->cpu_ctx.regs.xmm[6].high);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.xmm[6].low != g_last_regs.xmm[6].low ? regs_col : txt_col, "xmm6.l: 0x%016" PRIX64, cpu->cpu_ctx.regs.xmm[6].low);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.xmm[7].high != g_last_regs.xmm[7].high ? regs_col : txt_col, "xmm7.h: 0x%016" PRIX64, cpu->cpu_ctx.regs.xmm[7].high);
			ImGui::SameLine();
			ImGui::TextColored(cpu->cpu_ctx.regs.xmm[7].low != g_last_regs.xmm[7].low ? regs_col : txt_col, "xmm7.l: 0x%016" PRIX64, cpu->cpu_ctx.regs.xmm[7].low);
		}
		else {
			const char *text = "Not available while debuggee is running";
			ImGui::SetCursorPos(ImVec2(ImGui::GetWindowWidth() / 2 - (ImGui::CalcTextSize(text).x / 2), ImGui::GetWindowHeight() / 2 - (ImGui::CalcTextSize(text).y / 2)));
			ImGui::Text("%s", text);
		}
		ImGui::EndChild();
	}
	ImGui::End();

	ImGui::PopStyleColor(3);
}
