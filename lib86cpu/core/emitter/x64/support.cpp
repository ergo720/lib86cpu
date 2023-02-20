/*
 * common functions used by the x64 jit
 *
 * ergo720                Copyright (c) 2023
 */

#include "internal.h"
#include "clock.h"
#include <immintrin.h>
#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(__GNUG__)
#include "cpuid.h"
#endif

#define FPU_SUPPORTED          (1 << 0)
#define SSE2_SUPPORTED         (1 << 26)
#define CPU_FEATURES_REQUIRED  (FPU_SUPPORTED | SSE2_SUPPORTED)


bool
verify_cpu_features()
{
	// we require x87 fpu and sse2 support at least

#if defined(_MSC_VER)
	int cpu_info[4];
	__cpuid(cpu_info, 1);
	if ((cpu_info[3] & CPU_FEATURES_REQUIRED) == CPU_FEATURES_REQUIRED) {
		return true;
	}
#elif defined(__GNUG__)
	unsigned cpu_info[4];
	if (__get_cpuid(1, &cpu_info[0], &cpu_info[1], &cpu_info[2], &cpu_info[3])) {
		if ((cpu_info[3] & CPU_FEATURES_REQUIRED) == CPU_FEATURES_REQUIRED) {
			return true;
		}
	}
#else
#error "Don't know how to query cpu features on this platform"
#endif

	last_error = "This library requires x87 fpu and sse2 support at least";
	return false;
}

uint128_t
uint128_t::operator>>(int shift)
{
	// NOTE: the shift amount used by the intrinsic is expressed in bytes, not bits

	__m128i val = _mm_set_epi64x(high, low);

	shift /= 8;
	switch (shift)
	{
	case 0:
		val = _mm_srli_si128(val, 0);
		break;

	case 1:
		val = _mm_srli_si128(val, 1);
		break;

	case 2:
		val = _mm_srli_si128(val, 2);
		break;

	case 3:
		val = _mm_srli_si128(val, 3);
		break;

	case 4:
		val = _mm_srli_si128(val, 4);
		break;

	case 5:
		val = _mm_srli_si128(val, 5);
		break;

	case 6:
		val = _mm_srli_si128(val, 6);
		break;

	case 7:
		val = _mm_srli_si128(val, 7);
		break;

	case 8:
		val = _mm_srli_si128(val, 8);
		break;

	case 9:
		val = _mm_srli_si128(val, 9);
		break;

	case 10:
		val = _mm_srli_si128(val, 10);
		break;

	case 11:
		val = _mm_srli_si128(val, 11);
		break;

	case 12:
		val = _mm_srli_si128(val, 12);
		break;

	case 13:
		val = _mm_srli_si128(val, 13);
		break;

	case 14:
		val = _mm_srli_si128(val, 14);
		break;

	case 15:
		val = _mm_srli_si128(val, 15);
		break;

	default:
		LIB86CPU_ABORT_msg("Unsupported 128 bit shift count (count was %d", shift);
	}

	_mm_store_si128(reinterpret_cast<__m128i *>(&low), val);
	return *this;
}

uint128_t
uint128_t::operator<<(int shift)
{
	// NOTE: the shift amount used by the intrinsic is expressed in bytes, not bits

	__m128i val = _mm_set_epi64x(high, low);

	shift /= 8;
	switch (shift)
	{
	case 0:
		val = _mm_slli_si128(val, 0);
		break;

	case 1:
		val = _mm_slli_si128(val, 1);
		break;

	case 2:
		val = _mm_slli_si128(val, 2);
		break;

	case 3:
		val = _mm_slli_si128(val, 3);
		break;

	case 4:
		val = _mm_slli_si128(val, 4);
		break;

	case 5:
		val = _mm_slli_si128(val, 5);
		break;

	case 6:
		val = _mm_slli_si128(val, 6);
		break;

	case 7:
		val = _mm_slli_si128(val, 7);
		break;

	case 8:
		val = _mm_slli_si128(val, 8);
		break;

	case 9:
		val = _mm_slli_si128(val, 9);
		break;

	case 10:
		val = _mm_slli_si128(val, 10);
		break;

	case 11:
		val = _mm_slli_si128(val, 11);
		break;

	case 12:
		val = _mm_slli_si128(val, 12);
		break;

	case 13:
		val = _mm_slli_si128(val, 13);
		break;

	case 14:
		val = _mm_slli_si128(val, 14);
		break;

	case 15:
		val = _mm_slli_si128(val, 15);
		break;

	default:
		LIB86CPU_ABORT_msg("Unsupported 128 bit shift count (count was %d", shift);
	}

	_mm_store_si128(reinterpret_cast<__m128i *>(&low), val);
	return *this;
}

void
halt_loop(cpu_t *cpu)
{
	while (true) {
		uint32_t ret = cpu_timer_helper(&cpu->cpu_ctx);
		_mm_pause();

		if ((ret == CPU_NO_INT) || (ret == CPU_NON_HW_INT)) {
			// either nothing changed or it's not a hw int, keep looping in both cases
			continue;
		}

		if (ret == CPU_HW_INT) {
			// hw int, exit the loop and clear the halted state
			cpu->cpu_ctx.is_halted = 0;
			return;
		}

		// timeout, exit the loop
		return;
	}
}
