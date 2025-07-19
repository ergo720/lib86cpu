# This cmake file is borrowed from libcpu, Copyright (c) 2009-2010, the libcpu developers

include(CheckIncludeFile)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CheckCXXSourceCompiles)

check_include_file(sys/resource.h HAVE_SYS_RESOURCE_H)
check_symbol_exists(getrusage sys/resource.h HAVE_GETRUSAGE)
check_library_exists(readline readline "" HAVE_LIBREADLINE)
check_library_exists(rt clock_gettime "" HAVE_LIBRT)
check_include_file(netinet/in.h HAVE_NETINET_IN_H)

CHECK_CXX_SOURCE_COMPILES("
template <bool x> struct static_assertion;
template <> struct static_assertion<true> {};
struct s { char c; int i; } __attribute__((packed));
int main() {
	sizeof(static_assertion< sizeof(struct s) == sizeof(char) + sizeof(int) >);
	return 0;
}
"
HAVE_ATTRIBUTE_PACKED)

CHECK_CXX_SOURCE_COMPILES("
template <bool x> struct static_assertion;
template <> struct static_assertion<true> {};
__pragma(pack(push, 1))
struct s { char c; int i; };
__pragma(pack(pop))
int main() {
	sizeof(static_assertion< sizeof(struct s) == sizeof(char) + sizeof(int) >);
	return 0;
}
"
HAVE_PRAGMA_PACK)

CHECK_CXX_SOURCE_COMPILES("
__declspec(dllexport) void foo(void);
int main() {
	return 0;
}
"
HAVE_DECLSPEC_DLLEXPORT)

configure_file(include/config.h.cmake ${PROJECT_SOURCE_DIR}/include/config.h)
