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

#define DISAS_INSTR_NUM_FACTOR 5


void
dbg_draw_disas_wnd(cpu_t *cpu, int wnd_w, int wnd_h)
{
	ImGui::SetNextWindowPos(ImVec2(10, 10), ImGuiCond_FirstUseEver);
	ImGui::SetNextWindowSize(ImVec2(wnd_w - 20, wnd_h - 20), ImGuiCond_FirstUseEver);
	if (ImGui::Begin("Disassembler")) {
		if (!guest_running.test()) {
			if (!ImGui::IsKeyPressed(ImGuiKey_F5)) {
				ImGui::SetCursorPosX(10.0f);
				unsigned instr_to_print = ImGui::GetWindowHeight() / ImGui::GetTextLineHeightWithSpacing() * DISAS_INSTR_NUM_FACTOR;
				static addr_t pc_offset = 0;
				static unsigned instr_sel = 0;
				static std::vector<std::pair<addr_t, std::string>> disas_data;
				if (disas_data.empty()) {
					// this happens the first time the disassembler window is displayed
					disas_data = dbg_disas_code_block(cpu, get_pc(&cpu->cpu_ctx) + pc_offset, instr_to_print);
					pc_offset += instr_to_print;
				}
				else if (ImGui::GetScrollY() == ImGui::GetScrollMaxY()) {
					// the user has scrolled up to the end of the instr block we previously cached, so we need to disassemble a new block
					// and append it to the end of the cached data
					const auto &disas_next_block = dbg_disas_code_block(cpu, get_pc(&cpu->cpu_ctx) + pc_offset, instr_to_print);
					disas_data.insert(disas_data.end(), std::make_move_iterator(disas_next_block.begin()), std::make_move_iterator(disas_next_block.end()));
					pc_offset += instr_to_print;
				}
				assert(std::adjacent_find(disas_data.begin(), disas_data.end(), [](const auto &lhs, const auto &rhs) {
					return lhs.first == rhs.first;
					}) == disas_data.end()
						);
				unsigned num_instr_printed = 0;
				for (; num_instr_printed < disas_data.size(); ++num_instr_printed) {
					// buffer size = buff_size used in log_instr for instr string + 12 chars need to print its addr
					char buffer[256 + 12 + 1];
					std::snprintf(buffer, sizeof(buffer), "0x%08X  %s", (disas_data.begin() + num_instr_printed)->first, (disas_data.begin() + num_instr_printed)->second.c_str());
					if (ImGui::Selectable(buffer, instr_sel == num_instr_printed)) {
						instr_sel = num_instr_printed;
					}
				}
				if (num_instr_printed != instr_to_print) {
					for (unsigned instr_left_to_print = num_instr_printed; instr_left_to_print < instr_to_print; ++instr_left_to_print) {
						ImGui::Text("????");
					}
				}
			}
			else {
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
