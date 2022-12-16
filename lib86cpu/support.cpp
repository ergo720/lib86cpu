/*
 * common functions used by the library
 *
 * ergo720                Copyright (c) 2020
 */

#include "support.h"
#include <cstdarg>


void
cpu_runtime_abort(const char *msg)
{
	cpu_abort(static_cast<int32_t>(lc86_status::internal_error), msg);
}

void
cpu_abort(int32_t code, const char *msg, ...)
{
	std::va_list args;
	va_start(args, msg);
	int size = std::vsnprintf(nullptr, 0, msg, args);
	std::string str(size + 1, '\0');
	std::vsnprintf(str.data(), str.length(), msg, args);
	va_end(args);
	throw lc86_exp_abort(str, static_cast<lc86_status>(code));
}

void
discard_log(log_level lv, const unsigned count, const char *msg, ...) {}

std::string
lc86status_to_str(lc86_status status)
{
	switch (status)
	{
	case lc86_status::timeout:
		return "The operation timed out";

	case lc86_status::internal_error:
		return "An unspecified error internal to lib86cpu has occured";

	case lc86_status::no_memory:
		return "The operation failed because of insuffiecient memory";

	case lc86_status::invalid_parameter:
		return "An invalid parameter was specified";

	case lc86_status::not_found:
		return "The specified object could not be found";

	case lc86_status::guest_exp:
		return "A guest exception was raised by lib86cpu while executing the operation";

	case lc86_status::success:
		return "The operation completed successfully";

	default:
		return "Unknown error code";
	}
}

lc86_status
set_last_error(lc86_status status)
{
	last_error = lc86status_to_str(status);
	return status;
}
