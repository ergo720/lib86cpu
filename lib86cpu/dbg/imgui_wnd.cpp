/*
 * imgui debugger widgets
 *
 * ergo720                Copyright (c) 2022
 */

#include "imgui.h"
#include "lib86cpu_priv.h"
#include "imgui_wnd.h"
#include "debugger.h"


void
dbg_draw_disas_wnd(cpu_t *cpu, int fb_w, int fb_h)
{
	ImGui::SetNextWindowPos(ImVec2(10, 10), ImGuiCond_FirstUseEver);
	ImGui::SetNextWindowSize(ImVec2(fb_w - 20, fb_h - 20), ImGuiCond_FirstUseEver);
	if (ImGui::Begin("Disassembler")) {
		unsigned instr_to_print = ImGui::GetWindowHeight() / ImGui::GetTextLineHeightWithSpacing();
		const auto &disas_data = dbg_disas_code_block(cpu, instr_to_print);
		unsigned num_instr_printed = 0;
		for (; num_instr_printed < disas_data.size(); ++num_instr_printed) {
			ImGui::Text("0x%08X  %s", (disas_data.begin() + num_instr_printed)->first, (disas_data.begin() + num_instr_printed)->second.c_str());
		}
		if (num_instr_printed != instr_to_print) {
			for (unsigned instr_left_to_print = num_instr_printed; instr_left_to_print < instr_to_print; ++instr_left_to_print) {
				ImGui::Text("????");
			}
		}
	}
	ImGui::End();
}
