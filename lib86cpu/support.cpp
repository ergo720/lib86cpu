/*
 * common functions used by the library
 *
 * ergo720                Copyright (c) 2020
 */

#include "support.h"


void
cpu_abort(int32_t code)
{
	lc86_status code2 = static_cast<lc86_status>(code);
	throw lc86_exp_abort(lc86status_to_str(code2), code2);
}

void
cpu_abort(int32_t code, const char *msg)
{
	throw lc86_exp_abort(msg, static_cast<lc86_status>(code));
}

std::string
lc86status_to_str(lc86_status code)
{
	switch (code)
	{
	case lc86_status::INTERNAL_ERROR:
		return "An unspecified error internal to lib86cpu has occured";

	case lc86_status::NO_MEMORY:
		return "The operation failed because of insuffiecient memory";

	case lc86_status::INVALID_PARAMETER:
		return "An invalid parameter was specified";

	case lc86_status::ALREADY_EXIST:
		return "The specified object already exists";

	case lc86_status::NOT_FOUND:
		return "The specified object could not be found";

	case lc86_status::PAGE_FAULT:
		return "A page fault was raised by lib86cpu while executing the operation";

	case lc86_status::SUCCESS:
		return "The operation completed successfully";

	default:
		return "Unknown error code";
	}
}
