#if defined(_WIN32)
#  define __LITTLE_ENDIAN__        1
#  ifdef _M_IX86
#    define __i386__ 1
#  endif
#  ifdef _M_X64
#    define __x86_64__ 1
#  endif
#endif /* defined(_WIN32) */

#if defined LIB86CPU_BUILD_SHARED_LIB && defined HAVE_DECLSPEC_DLLEXPORT
#  ifdef LIB86CPU_BUILD_CORE
#    define API_FUNC __declspec(dllexport)
#  else
#    define API_FUNC __declspec(dllimport)
#  endif
#else
#  define API_FUNC /* nothing */
#endif

#if HAVE_ATTRIBUTE_PACKED
#  define PACKED(x) x __attribute__((__packed__))
#elif HAVE_PRAGMA_PACK
#  define PACKED(x) __pragma(pack(push, 1)) x __pragma(pack(pop))
#else
#  error "Do not know how to pack structs on this platform"
#endif

#ifndef LIB86CPU_X64_EMITTER
#if defined(_M_X64) || defined(__x86_64__)
#  define LIB86CPU_X64_EMITTER
#endif
#endif

#ifndef LIB86CPU_X64_EMITTER
#error "No emitter was specified"
#endif
