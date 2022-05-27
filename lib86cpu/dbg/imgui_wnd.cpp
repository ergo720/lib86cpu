/*
 * imgui debugger widgets
 *
 * ergo720                Copyright (c) 2022
 */

#include "imgui.h"
#include "imgui_wnd.h"


void
dbg_draw_disas_wnd(int fb_w, int fb_h)
{
	ImGui::SetNextWindowPos(ImVec2(10, 10), ImGuiCond_FirstUseEver);
	ImGui::SetNextWindowSize(ImVec2(fb_w - 20, fb_h - 20), ImGuiCond_FirstUseEver);
	if (ImGui::Begin("Disassembler")) {

	}
	ImGui::End();
}
