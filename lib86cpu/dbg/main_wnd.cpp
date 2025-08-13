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
dbg_draw_wnd(GLFWwindow *wnd, int fb_w, int fb_h)
{
	ImGui_ImplOpenGL3_NewFrame();
	ImGui_ImplGlfw_NewFrame();
	ImGui::NewFrame();

	glfwGetWindowSize(wnd, &main_wnd_w, &main_wnd_h);
	dbg_draw_imgui_wnd(g_cpu);

	ImGui::Render();

	glViewport(0, 0, fb_w, fb_h);
	glClearColor(0.45f, 0.55f, 0.60f, 1.00f);
	glClear(GL_COLOR_BUFFER_BIT);
	ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

	glfwSwapBuffers(wnd);
}

void
dbg_main_wnd(cpu_t *cpu, std::promise<bool> &has_err)
{
	bool init_has_err = true;

	try {
		read_setting_files(cpu);
		dbg_setup_sw_breakpoints(cpu);

		if (!glfwInit()) {
			last_error = "Failed to initialize glfw";
			has_err.set_value(init_has_err);
			return;
		}

		main_wnd = glfwCreateWindow(main_wnd_w, main_wnd_h, "Lib86dbg", nullptr, nullptr);
		if (!main_wnd) {
			last_error = "Failed to create the debugger window";
			glfwTerminate();
			has_err.set_value(init_has_err);
			return;
		}

		glfwMakeContextCurrent(main_wnd);

		if (!gladLoadGLLoader(reinterpret_cast<GLADloadproc>(glfwGetProcAddress))) {
			last_error = "Failed to load OpenGL functions";
			glfwTerminate();
			has_err.set_value(init_has_err);
			return;
		}

		if (!GLAD_GL_VERSION_4_6) {
			last_error = "Failed to meet the minimum required OpenGL version";
			glfwTerminate();
			has_err.set_value(init_has_err);
			return;
		}

		glfwSetFramebufferSizeCallback(main_wnd, dbg_draw_wnd);

		IMGUI_CHECKVERSION();
		ImGui::CreateContext();
		ImGui::StyleColorsDark();
		ImGui_ImplGlfw_InitForOpenGL(main_wnd, true);
		ImGui_ImplOpenGL3_Init();

		break_pc = get_pc(&cpu->cpu_ctx);
		mem_pc = break_pc;
		g_cpu = cpu;

		init_has_err = false;
		has_terminated.clear();
		exit_requested.clear();
		guest_running.clear();
		has_err.set_value(init_has_err);

		while (!glfwWindowShouldClose(main_wnd)) {
			int fb_w, fb_h;
			glfwGetFramebufferSize(main_wnd, &fb_w, &fb_h);
			dbg_draw_wnd(main_wnd, fb_w, fb_h);

			glfwWaitEventsTimeout(0.5);
		}
	}
	catch (host_exp_t) {
		if (init_has_err) {
			// simply terminate this thread, this happens when the initialization fails in dbg_setup_sw_breakpoints
			has_err.set_value(init_has_err);
			return;
		}
		// fallthrough to the handling code below, this happens when dbg_draw_wnd fails to update the breakpoints
		cpu->raise_int_fn(&cpu->cpu_ctx, CPU_ABORT_INT);
		guest_running.test_and_set();
		guest_running.notify_one();
	}

	// raise an abort interrupt and wait until the guest stops execution
	cpu->raise_int_fn(&cpu->cpu_ctx, CPU_ABORT_INT);
	guest_running.wait(true);

	// set guest_running in the case the guest is waiting in dbg_sw_breakpoint_handler
	guest_running.test_and_set();
	guest_running.notify_one();

	exit_requested.wait(false);

	glfwGetWindowSize(main_wnd, &main_wnd_w, &main_wnd_h);

	ImGui_ImplOpenGL3_Shutdown();
	ImGui_ImplGlfw_Shutdown();
	ImGui::DestroyContext();

	glfwTerminate();

	write_setting_files(cpu);

	main_wnd = nullptr;
	g_cpu = nullptr;
	exit_requested.clear();
	has_terminated.test_and_set();
	has_terminated.notify_one();
}

void
dbg_should_close()
{
	glfwSetWindowShouldClose(main_wnd, GLFW_TRUE);
	glfwPostEmptyEvent();
	guest_running.clear();
	guest_running.notify_one();
	exit_requested.test_and_set();
	exit_requested.notify_one();
	has_terminated.wait(false);
}
