/*
 * lib86cpu opengl debugger main window
 *
 * ergo720                Copyright (c) 2022
 */

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"

#include "glad/glad.h"
#include "glfw3.h"

#include "support.h"
#include "internal.h"
#include "main_wnd.h"
#include "imgui_wnd.h"
#include "debugger.h"


static GLFWwindow *main_wnd = nullptr;
static std::atomic_flag has_terminated;
static std::atomic_flag exit_requested;


void
dbg_main_wnd(cpu_t *cpu, std::promise<bool> &has_err)
{
	if (!glfwInit()) {
		last_error = "Failed to initialize glfw";
		has_err.set_value(true);
		return;
	}
	
	main_wnd = glfwCreateWindow(1280, 720, "Lib86dbg", nullptr, nullptr);
	if (!main_wnd) {
		last_error = "Failed to create the debugger window";
		glfwTerminate();
		has_err.set_value(true);
		return;
	}

	glfwMakeContextCurrent(main_wnd);

	if (!gladLoadGLLoader(reinterpret_cast<GLADloadproc>(glfwGetProcAddress))) {
		last_error = "Failed to load opengl functions";
		glfwTerminate();
		has_err.set_value(true);
		return;
	}

	if (!GLAD_GL_VERSION_4_6) {
		last_error = "Failed to meet the minimum required opengl version";
		glfwTerminate();
		has_err.set_value(true);
		return;
	}

	IMGUI_CHECKVERSION();
	ImGui::CreateContext();
	ImGui::StyleColorsDark();
	ImGui_ImplGlfw_InitForOpenGL(main_wnd, true);
	ImGui_ImplOpenGL3_Init();

	read_breakpoints_file(cpu);

	has_terminated.clear();
	has_err.set_value(false); // comment this out to test the debugger for now

	while (!glfwWindowShouldClose(main_wnd)) {
		glfwWaitEvents();

		ImGui_ImplOpenGL3_NewFrame();
		ImGui_ImplGlfw_NewFrame();
		ImGui::NewFrame();

		int fb_w, fb_h;
		glfwGetFramebufferSize(main_wnd, &fb_w, &fb_h);

		dbg_draw_disas_wnd(cpu, fb_w, fb_h);

		ImGui::Render();

		glViewport(0, 0, fb_w, fb_h);
		glClearColor(0.45f, 0.55f, 0.60f, 1.00f);
		glClear(GL_COLOR_BUFFER_BIT);
		ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

		glfwSwapBuffers(main_wnd);
	}

	if (!exit_requested.test()) {
		cpu->int_fn(&cpu->cpu_ctx, CPU_DBG_INT);
		exit_requested.wait(false);
	}

	ImGui_ImplOpenGL3_Shutdown();
	ImGui_ImplGlfw_Shutdown();
	ImGui::DestroyContext();

	glfwTerminate();

	write_breakpoints_file(cpu);

	main_wnd = nullptr;
	exit_requested.clear();
	has_terminated.test_and_set();
	has_terminated.notify_one();
}

void
dbg_should_close()
{
	glfwSetWindowShouldClose(main_wnd, GLFW_TRUE);
	exit_requested.test_and_set();
	exit_requested.notify_one();
	has_terminated.wait(false);
}
