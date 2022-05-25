/*
 * lib86cpu opengl debugger main window
 *
 * ergo720                Copyright (c) 2022
 */

#include "glad/glad.h"
#include "glfw3.h"

#include "support.h"
#include "internal.h"
#include "main_wnd.h"


static GLFWwindow * main_wnd = nullptr;
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
	
	main_wnd = glfwCreateWindow(640, 480, "Debugger", nullptr, nullptr);
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

	has_err.set_value(false);
	has_terminated.clear();

	while (!glfwWindowShouldClose(main_wnd)) {
		glClearColor(0.0f, 0.0f, 0.0f, 1.0f);
		glClear(GL_COLOR_BUFFER_BIT);

		glfwSwapBuffers(main_wnd);

		glfwWaitEvents();
	}

	if (!exit_requested.test()) {
		cpu->int_fn(&cpu->cpu_ctx, CPU_DBG_INT);
		exit_requested.wait(false);
	}

	glfwTerminate();

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
