/*
 * lib86cpu opengl debugger main window
 *
 * ergo720                Copyright (c) 2022
 */

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl2.h"
#include "imgui_impl_opengl3.h"

#include "glad/glad.h"
#include "glfw3.h"

#include "support.h"
#include "internal.h"
#include "main_wnd.h"
#include "imgui_wnd.h"
#include "debugger.h"


static GLFWwindow *g_main_wnd = nullptr;
static std::atomic_flag g_has_terminated;
static std::atomic_flag g_exit_requested;


static void
dbg_draw_wnd_gl3(GLFWwindow *wnd, int fb_w, int fb_h)
{
	ImGui_ImplOpenGL3_NewFrame();
	ImGui_ImplGlfw_NewFrame();
	ImGui::NewFrame();

	glfwGetWindowSize(wnd, &g_main_wnd_w, &g_main_wnd_h);
	dbg_draw_imgui_wnd(g_cpu);

	ImGui::Render();

	glViewport(0, 0, fb_w, fb_h);
	glClearColor(0.45f, 0.55f, 0.60f, 1.00f);
	glClear(GL_COLOR_BUFFER_BIT);
	ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

	glfwSwapBuffers(wnd);
}

static void
dbg_draw_wnd_gl2(GLFWwindow *wnd, int fb_w, int fb_h)
{
	ImGui_ImplOpenGL2_NewFrame();
	ImGui_ImplGlfw_NewFrame();
	ImGui::NewFrame();

	glfwGetWindowSize(wnd, &g_main_wnd_w, &g_main_wnd_h);
	dbg_draw_imgui_wnd(g_cpu);

	ImGui::Render();

	glViewport(0, 0, fb_w, fb_h);
	glClearColor(0.45f, 0.55f, 0.60f, 1.00f);
	glClear(GL_COLOR_BUFFER_BIT);
	ImGui_ImplOpenGL2_RenderDrawData(ImGui::GetDrawData());

	glfwSwapBuffers(wnd);
}

void
dbg_main_wnd(cpu_t *cpu, std::promise<bool> &has_err)
{
	bool init_has_err = true;
	bool using_gl3 = true;

	try {
		read_dbg_opt();
		dbg_setup_sw_breakpoints(cpu);
		dbg_copy_registers(cpu);

		if (!glfwInit()) {
			last_error = "Failed to initialize glfw";
			has_err.set_value(init_has_err);
			return;
		}

		g_main_wnd = glfwCreateWindow(g_main_wnd_w, g_main_wnd_h, "Lib86dbg", nullptr, nullptr);
		if (!g_main_wnd) {
			last_error = "Failed to create the debugger window";
			glfwTerminate();
			has_err.set_value(init_has_err);
			return;
		}

		glfwMakeContextCurrent(g_main_wnd);

		if (!gladLoadGLLoader(reinterpret_cast<GLADloadproc>(glfwGetProcAddress))) {
			last_error = "Failed to load OpenGL functions";
			glfwTerminate();
			has_err.set_value(init_has_err);
			return;
		}

		if (!GLAD_GL_VERSION_3_0) {
			if (!GLAD_GL_VERSION_2_0) {
				last_error = "Failed to meet the minimum required OpenGL version";
				glfwTerminate();
				has_err.set_value(init_has_err);
				return;
			}
			using_gl3 = false;
		}
		LOG(log_level::info, "Using OpenGL %s for the debugger", using_gl3 ? "3.0" : "2.0");

		GLFWframebuffersizefun draw_callback = using_gl3 ? dbg_draw_wnd_gl3 : dbg_draw_wnd_gl2;
		glfwSetFramebufferSizeCallback(g_main_wnd, draw_callback);

		IMGUI_CHECKVERSION();
		ImGui::CreateContext();
		ImGui::StyleColorsDark();
		ImGui_ImplGlfw_InitForOpenGL(g_main_wnd, true);
		using_gl3 ? ImGui_ImplOpenGL3_Init() : ImGui_ImplOpenGL2_Init();

		g_break_pc = get_pc(&cpu->cpu_ctx);
		g_cpu = cpu;

		init_has_err = false;
		g_has_terminated.clear();
		g_exit_requested.clear();
		g_guest_running.clear();
		has_err.set_value(init_has_err);

		while (!glfwWindowShouldClose(g_main_wnd)) {
			int fb_w, fb_h;
			glfwGetFramebufferSize(g_main_wnd, &fb_w, &fb_h);
			draw_callback(g_main_wnd, fb_w, fb_h);

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
		g_guest_running.test_and_set();
		g_guest_running.notify_one();
	}

	// raise an abort interrupt and wait until the guest stops execution
	cpu->raise_int_fn(&cpu->cpu_ctx, CPU_ABORT_INT);
	g_guest_running.wait(true);

	// set g_guest_running in the case the guest is waiting in dbg_sw_breakpoint_handler
	g_guest_running.test_and_set();
	g_guest_running.notify_one();

	g_exit_requested.wait(false);

	glfwGetWindowSize(g_main_wnd, &g_main_wnd_w, &g_main_wnd_h);

	using_gl3 ? ImGui_ImplOpenGL3_Shutdown() : ImGui_ImplOpenGL2_Shutdown();
	ImGui_ImplGlfw_Shutdown();
	ImGui::DestroyContext();

	glfwTerminate();

	write_dbg_opt();

	g_main_wnd = nullptr;
	g_cpu = nullptr;
	g_exit_requested.clear();
	g_has_terminated.test_and_set();
	g_has_terminated.notify_one();
}

void
dbg_should_close()
{
	glfwSetWindowShouldClose(g_main_wnd, GLFW_TRUE);
	glfwPostEmptyEvent();
	g_guest_running.clear();
	g_guest_running.notify_one();
	g_exit_requested.test_and_set();
	g_exit_requested.notify_one();
	g_has_terminated.wait(false);
}
