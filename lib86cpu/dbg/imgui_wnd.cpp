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

#define DISAS_INSTR_NUM_FACTOR 5


void
dbg_draw_imgui_wnd(cpu_t *cpu)
{
	const int wnd_w = main_wnd_w;
	const int wnd_h = main_wnd_h;
	static const auto &[text_r, text_g, text_b] = text_col;
	static const auto &[break_r, break_g, break_b] = break_col;
	static const auto &[bk_r, bk_g, bk_b] = bk_col;

	ImGui::SetNextWindowPos(ImVec2(10, 10), ImGuiCond_FirstUseEver);
	ImGui::SetNextWindowSize(ImVec2((wnd_w - 30) / 2, (wnd_h - 30) / 2), ImGuiCond_FirstUseEver);
	ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(text_r, text_g, text_b, 1.0f));
	ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(bk_r, bk_g, bk_b, 1.0f));
	ImGui::PushStyleColor(ImGuiCol_PopupBg, ImVec4(bk_r, bk_g, bk_b, 1.0f));
	if (ImGui::Begin("Disassembler")) {
		static char buff[9];
		ImGui::PushItemWidth(80.0f);
		bool enter_pressed = ImGui::InputText("Address", buff, IM_ARRAYSIZE(buff), ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_EnterReturnsTrue);
		ImGui::PopItemWidth();
		ImGui::ColorEdit3("Text color", text_col);
		ImGui::ColorEdit3("Breakpoint color", break_col);
		ImGui::ColorEdit3("Background color", bk_col);
		ImGui::BeginChild("Disassembler view");
		if (!guest_running.test()) {
			// F5: continue execution, F9: toggle breakpoint, F11: step into
			static std::vector<std::pair<addr_t, std::string>> disas_data;
			static unsigned instr_sel = 0;
			static bool show_popup = false;
			if (!show_popup) {
				if (!ImGui::IsKeyPressed(ImGuiKey_F5)) {
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
					if (ImGui::IsKeyPressed(ImGuiKey_F11)) {
						// don't reinstall the sw breakpoints because, if we are single-stepping one of them, we will receive a bp exp again, instead of a db exp
						cpu->cpu_flags |= CPU_SINGLE_STEP;
						disas_data.clear();
						instr_sel = 0;
						const char *text = "Not available while debuggee is running";
						ImGui::SetCursorPos(ImVec2(ImGui::GetWindowWidth() / 2 - (ImGui::CalcTextSize(text).x / 2), ImGui::GetWindowHeight() / 2 - (ImGui::CalcTextSize(text).y / 2)));
						ImGui::Text("%s", text);
						guest_running.test_and_set();
						guest_running.notify_one();
					}
					else {
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

						unsigned num_instr_printed = 0;
						for (; num_instr_printed < disas_data.size(); ++num_instr_printed) {
							// buffer size = buff_size used in log_instr for instr string + 12 chars need to print its addr
							char buffer[256 + 12 + 1];
							addr_t addr = (disas_data.begin() + num_instr_printed)->first;
							std::snprintf(buffer, sizeof(buffer), "0x%08X  %s", addr, (disas_data.begin() + num_instr_printed)->second.c_str());
							if (break_list.contains(addr)) {
								// draw breakpoint with a different text color
								ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(break_r, break_g, break_b, 1.0f));
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
				}
				else {
					cpu->cpu_flags &= ~CPU_SINGLE_STEP;
					disas_data.clear();
					instr_sel = 0;
					dbg_apply_sw_breakpoints(cpu);
					const char *text = "Not available while debuggee is running";
					ImGui::SetCursorPos(ImVec2(ImGui::GetWindowWidth() / 2 - (ImGui::CalcTextSize(text).x / 2), ImGui::GetWindowHeight() / 2 - (ImGui::CalcTextSize(text).y / 2)));
					ImGui::Text("%s", text);
					guest_running.test_and_set();
					guest_running.notify_one();
				}
			}
			else {
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
		ImGui::PopItemWidth();
		ImGui::ColorEdit3("Text color", text_col);
		ImGui::ColorEdit3("Background color", bk_col);
		ImGui::BeginChild("Memory view");
		if (!guest_running.test()) {
			static uint8_t mem_buff[PAGE_SIZE];
			static MemoryEditor mem_editor;
			mem_editor.WriteFn = &dbg_ram_write;
			if (enter_pressed) {
				// NOTE: it can't fail because ImGui::InputText only accepts hex digits and mem_pc is large enough to store every possible 32 bit address
				[[maybe_unused]] auto ret = std::from_chars(buff, buff + sizeof(buff), mem_pc, 16);
				assert(ret.ec == std::errc());
				mem_editor_update = true;
			}
			if (mem_editor_update) {
				dbg_ram_read(cpu, mem_buff);
				mem_editor_update = false;
			}
			mem_editor.DrawContents(mem_buff, PAGE_SIZE, mem_pc);
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
		ImGui::ColorEdit3("Text color", text_col);
		ImGui::ColorEdit3("Background color", bk_col);
		ImGui::BeginChild("Registers view");
		if (!guest_running.test()) {
			ImGui::Text("eax: 0x%08X  ecx: 0x%08X  edx: 0x%08X  ebx: 0x%08X  esp: 0x%08X  ebp: 0x%08X  esi: 0x%08X  edi: 0x%08X",
				cpu->cpu_ctx.regs.eax,
				cpu->cpu_ctx.regs.ecx,
				cpu->cpu_ctx.regs.edx,
				cpu->cpu_ctx.regs.ebx,
				cpu->cpu_ctx.regs.esp,
				cpu->cpu_ctx.regs.ebp,
				cpu->cpu_ctx.regs.esi,
				cpu->cpu_ctx.regs.edi
			);
			ImGui::Text("eflags: 0x%08X  eip: 0x%08X  cs: 0x%04hX  es: 0x%04hX  ss: 0x%04hX  ds: 0x%04hX  fs 0x%04hX  gs: 0x%04hX",
				read_eflags(cpu),
				cpu->cpu_ctx.regs.eip,
				cpu->cpu_ctx.regs.cs,
				cpu->cpu_ctx.regs.es,
				cpu->cpu_ctx.regs.ss,
				cpu->cpu_ctx.regs.ds,
				cpu->cpu_ctx.regs.fs,
				cpu->cpu_ctx.regs.gs
			);
			ImGui::Text("cs.base: 0x%08X  cs.limit: 0x%08X  cs.flags: 0x%08X  es.base: 0x%08X  es.limit: 0x%08X  es.flags: 0x%08X  ss.base: 0x%08X  ss.limit: 0x%08X",
				cpu->cpu_ctx.regs.cs_hidden.base,
				cpu->cpu_ctx.regs.cs_hidden.limit,
				cpu->cpu_ctx.regs.cs_hidden.flags,
				cpu->cpu_ctx.regs.es_hidden.base,
				cpu->cpu_ctx.regs.es_hidden.limit,
				cpu->cpu_ctx.regs.es_hidden.flags,
				cpu->cpu_ctx.regs.ss_hidden.base,
				cpu->cpu_ctx.regs.ss_hidden.limit
			);
			ImGui::Text("ss.limit: 0x%08X  ds.base: 0x%08X  ds.limit: 0x%08X  ds.flags: 0x%08X  fs.base: 0x%08X  fs.limit: 0x%08X  fs.flags: 0x%08X  gs.base: 0x%08X",
				cpu->cpu_ctx.regs.ss_hidden.flags,
				cpu->cpu_ctx.regs.ds_hidden.base,
				cpu->cpu_ctx.regs.ds_hidden.limit,
				cpu->cpu_ctx.regs.ds_hidden.flags,
				cpu->cpu_ctx.regs.fs_hidden.base,
				cpu->cpu_ctx.regs.fs_hidden.limit,
				cpu->cpu_ctx.regs.fs_hidden.flags,
				cpu->cpu_ctx.regs.gs_hidden.base
			);
			ImGui::Text("gs.limit: 0x%08X  gs.flags: 0x%08X  ldtr: 0x%04hX  tr: 0x%04hX  idtr.base: 0x%08X  idtr.limit: 0x%08X  gdtr.base: 0x%08X  gdtr.limit: 0x%08X",
				cpu->cpu_ctx.regs.gs_hidden.limit,
				cpu->cpu_ctx.regs.gs_hidden.flags,
				cpu->cpu_ctx.regs.ldtr,
				cpu->cpu_ctx.regs.tr,
				cpu->cpu_ctx.regs.idtr_hidden.base,
				cpu->cpu_ctx.regs.idtr_hidden.limit,
				cpu->cpu_ctx.regs.gdtr_hidden.base,
				cpu->cpu_ctx.regs.gdtr_hidden.limit
			);
			ImGui::Text("ldtr.base: 0x%08X  ldtr.limit: 0x%08X  ldtr.flags: 0x%08X  tr.base: 0x%08X  tr.limit: 0x%08X  tr.flags: 0x%08X",
				cpu->cpu_ctx.regs.ldtr_hidden.base,
				cpu->cpu_ctx.regs.ldtr_hidden.limit,
				cpu->cpu_ctx.regs.ldtr_hidden.flags,
				cpu->cpu_ctx.regs.tr_hidden.base,
				cpu->cpu_ctx.regs.tr_hidden.limit,
				cpu->cpu_ctx.regs.tr_hidden.flags
			);
			ImGui::Text("cr0: 0x%08X  cr2: 0x%08X  cr3: 0x%08X  cr4: 0x%08X",
				cpu->cpu_ctx.regs.cr0,
				cpu->cpu_ctx.regs.cr2,
				cpu->cpu_ctx.regs.cr3,
				cpu->cpu_ctx.regs.cr4
			);
			ImGui::Text("dr0: 0x%08X  dr1: 0x%08X  dr2: 0x%08X  dr3: 0x%08X  dr4: 0x%08X  dr5: 0x%08X  dr6: 0x%08X  dr7: 0x%08X",
				cpu->cpu_ctx.regs.dr[0],
				cpu->cpu_ctx.regs.dr[1],
				cpu->cpu_ctx.regs.dr[2],
				cpu->cpu_ctx.regs.dr[3],
				cpu->cpu_ctx.regs.dr[4],
				cpu->cpu_ctx.regs.dr[5],
				cpu->cpu_ctx.regs.dr[6],
				cpu->cpu_ctx.regs.dr[7]
			);
			ImGui::Text("r0.h: 0x%04hX  r0.l: 0x%016" PRIX64 "  r1.h: 0x%04hX  r1.l: 0x%016" PRIX64 "  r2.h: 0x%04hX  r2.l: 0x%016" PRIX64 "  r3.h: 0x%04hX  r3.l: 0x%016" PRIX64,
				cpu->cpu_ctx.regs.fr[0].high,
				cpu->cpu_ctx.regs.fr[0].low,
				cpu->cpu_ctx.regs.fr[1].high,
				cpu->cpu_ctx.regs.fr[1].low,
				cpu->cpu_ctx.regs.fr[2].high,
				cpu->cpu_ctx.regs.fr[2].low,
				cpu->cpu_ctx.regs.fr[3].high,
				cpu->cpu_ctx.regs.fr[3].low
			);
			ImGui::Text("r4.h: 0x%04hX  r4.l: 0x%016" PRIX64 "  r5.h: 0x%04hX  r5.l: 0x%016" PRIX64 "  r6.h: 0x%04hX  r6.l: 0x%016" PRIX64 "  r7.h: 0x%04hX  r7.l: 0x%016" PRIX64,
				cpu->cpu_ctx.regs.fr[4].high,
				cpu->cpu_ctx.regs.fr[4].low,
				cpu->cpu_ctx.regs.fr[5].high,
				cpu->cpu_ctx.regs.fr[5].low,
				cpu->cpu_ctx.regs.fr[6].high,
				cpu->cpu_ctx.regs.fr[6].low,
				cpu->cpu_ctx.regs.fr[7].high,
				cpu->cpu_ctx.regs.fr[7].low
			);
			ImGui::Text("fctrl: 0x%04hX  fstatus: 0x%04hX  ftags: 0x%04hX",
				cpu->cpu_ctx.regs.fctrl,
				read_fstatus(cpu),
				read_ftags(cpu)
			);
			ImGui::Text("fcs: 0x%04hX  fip: 0x%08hX  fds: 0x%04hX  fdp: 0x%08hX  fop: 0x%04hX  mxcsr: 0x%08hX",
				cpu->cpu_ctx.regs.fcs,
				cpu->cpu_ctx.regs.fip,
				cpu->cpu_ctx.regs.fds,
				cpu->cpu_ctx.regs.fdp,
				cpu->cpu_ctx.regs.fop,
				cpu->cpu_ctx.regs.mxcsr
			);
			ImGui::Text("xmm0.h: 0x%016" PRIX64 "  xmm0.l: 0x%016" PRIX64 "  xmm1.h: 0x%016" PRIX64 "  xmm1.l: 0x%016" PRIX64 "  xmm2.h: 0x%016" PRIX64 "  xmm2.l: 0x%016" PRIX64 "  xmm3.h: 0x%016" PRIX64 "  xmm3.l: 0x%016" PRIX64,
				cpu->cpu_ctx.regs.xmm[0].high,
				cpu->cpu_ctx.regs.xmm[0].low,
				cpu->cpu_ctx.regs.xmm[1].high,
				cpu->cpu_ctx.regs.xmm[1].low,
				cpu->cpu_ctx.regs.xmm[2].high,
				cpu->cpu_ctx.regs.xmm[2].low,
				cpu->cpu_ctx.regs.xmm[3].high,
				cpu->cpu_ctx.regs.xmm[3].low
			);
			ImGui::Text("xmm4.h: 0x%016" PRIX64 "  xmm4.l: 0x%016" PRIX64 "  xmm5.h: 0x%016" PRIX64 "  xmm5.l: 0x%016" PRIX64 "  xmm6.h: 0x%016" PRIX64 "  xmm6.l: 0x%016" PRIX64 "  xmm7.h: 0x%016" PRIX64 "  xmm7.l: 0x%016" PRIX64,
				cpu->cpu_ctx.regs.xmm[4].high,
				cpu->cpu_ctx.regs.xmm[4].low,
				cpu->cpu_ctx.regs.xmm[5].high,
				cpu->cpu_ctx.regs.xmm[5].low,
				cpu->cpu_ctx.regs.xmm[6].high,
				cpu->cpu_ctx.regs.xmm[6].low,
				cpu->cpu_ctx.regs.xmm[7].high,
				cpu->cpu_ctx.regs.xmm[7].low
			);
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
