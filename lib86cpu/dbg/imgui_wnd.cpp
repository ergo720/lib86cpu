/*
 * imgui debugger widgets
 *
 * ergo720                Copyright (c) 2022
 */

#include "imgui.h"
#include "lib86cpu_priv.h"
#include "imgui_wnd.h"
#include "debugger.h"
#include "internal.h"
#include <charconv>

#define DISAS_INSTR_NUM_FACTOR 5


void
dbg_draw_disas_wnd(cpu_t *cpu, int wnd_w, int wnd_h)
{
	ImGui::SetNextWindowPos(ImVec2(10, 10), ImGuiCond_FirstUseEver);
	ImGui::SetNextWindowSize(ImVec2(wnd_w - 20, wnd_h - 20), ImGuiCond_FirstUseEver);
	if (ImGui::Begin("Disassembler")) {
		static char buff[9];
		ImGui::PushItemWidth(80.0f);
		bool enter_pressed = ImGui::InputText("Address", buff, IM_ARRAYSIZE(buff), ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_EnterReturnsTrue);
		ImGui::PopItemWidth();
		if (!guest_running.test()) {
			// F5: continue execution, F9: toggle breakpoint
			static std::vector<std::pair<addr_t, std::string>> disas_data;
			static unsigned instr_sel = 0;
			if (!ImGui::IsKeyPressed(ImGuiKey_F5)) {
				static bool show_popup = false;
				unsigned instr_to_print = ImGui::GetWindowHeight() / ImGui::GetTextLineHeightWithSpacing() * DISAS_INSTR_NUM_FACTOR;
				if (enter_pressed) {
					// NOTE: it can't fail because ImGui::InputText only accepts hex digits and break_pc is large enough to store every possible 32 bit address
					[[maybe_unused]] auto ret = std::from_chars(buff, buff + sizeof(buff), break_pc, 16);
					assert(ret.ec == std::errc());
					disas_data.clear();
					instr_sel = 0;
				}
				if (disas_data.empty()) {
					// this happens the first time the disassembler window is displayed
					disas_data = dbg_disas_code_block(cpu, break_pc, instr_to_print);
				}
				else if (ImGui::GetScrollY() == ImGui::GetScrollMaxY()) {
					// the user has scrolled up to the end of the instr block we previously cached, so we need to disassemble a new block
					// and append it to the end of the cached data
					const auto &disas_next_block = dbg_disas_code_block(cpu, break_pc, instr_to_print);
					disas_data.insert(disas_data.end(), std::make_move_iterator(disas_next_block.begin()), std::make_move_iterator(disas_next_block.end()));
				}
				assert(std::adjacent_find(disas_data.begin(), disas_data.end(), [](const auto &lhs, const auto &rhs) {
					return lhs.first == rhs.first;
					}) == disas_data.end()
						);
				if (ImGui::IsKeyPressed(ImGuiKey_F9)) {
					if (!disas_data.empty()) { // it will happen if the first instr cannot be decoded
						addr_t addr = (disas_data.begin() + instr_sel)->first;
						if (break_list.contains(addr)) {
							break_list.erase(addr);
						}
						else {
							if (dbg_insert_sw_breakpoint(cpu, addr)) {
								show_popup = false;
								break_list.insert({ addr, 0 });
							}
							else {
								show_popup = true;
								ImGui::OpenPopup("Error");
							}
						}
					}
				}
				if (show_popup) {
					ImGui::SetNextWindowPos(ImVec2(ImGui::GetWindowPos().x + ImGui::GetWindowWidth() * 0.5f,
						ImGui::GetWindowPos().y + ImGui::GetWindowHeight() * 0.5f), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
					ImGui::SetNextWindowSize(ImVec2(235.0f, 75.0f));
					if (ImGui::BeginPopupModal("Error", nullptr, ImGuiWindowFlags_NoResize)) {
						ImGui::Text("Failed to insert the breakpoint");
						if (ImGui::Button("OK")) {
							show_popup = false;
							ImGui::CloseCurrentPopup();
						}
						ImGui::EndPopup();
					}
				}
				unsigned num_instr_printed = 0;
				for (; num_instr_printed < disas_data.size(); ++num_instr_printed) {
					// buffer size = buff_size used in log_instr for instr string + 12 chars need to print its addr
					char buffer[256 + 12 + 1];
					addr_t addr = (disas_data.begin() + num_instr_printed)->first;
					std::snprintf(buffer, sizeof(buffer), "0x%08X  %s", addr, (disas_data.begin() + num_instr_printed)->second.c_str());
					if (break_list.contains(addr)) {
						// draw breakpoint with a different text color
						ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.0f, 0.0f, 1.0f));
						if (ImGui::Selectable(buffer, instr_sel == num_instr_printed)) {
							instr_sel = num_instr_printed;
						}
						ImGui::PopStyleColor();
					}
					else {
						if (ImGui::Selectable(buffer, instr_sel == num_instr_printed)) {
							instr_sel = num_instr_printed;
						}
					}
				}
				if (num_instr_printed != instr_to_print) {
					for (unsigned instr_left_to_print = num_instr_printed; instr_left_to_print < instr_to_print; ++instr_left_to_print) {
						ImGui::Text("????");
					}
				}
			}
			else {
				disas_data.clear();
				instr_sel = 0;
				dbg_apply_sw_breakpoints(cpu);
				const char *text = "Not available while debuggee is running";
				ImGui::SetCursorPos(ImVec2((wnd_w - 20) / 2 - (ImGui::CalcTextSize(text).x / 2), (wnd_h - 20) / 2 - (ImGui::CalcTextSize(text).y / 2)));
				ImGui::Text(text);
				guest_running.test_and_set();
				guest_running.notify_one();
			}
		}
		else {
			const char *text = "Not available while debuggee is running";
			ImGui::SetCursorPos(ImVec2((wnd_w - 20) / 2 - (ImGui::CalcTextSize(text).x / 2), (wnd_h - 20) / 2 - (ImGui::CalcTextSize(text).y / 2)));
			ImGui::Text(text);
		}
	}
	ImGui::End();
}
