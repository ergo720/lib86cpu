/*
 * common functions used by the x64 jit
 *
 * ergo720                Copyright (c) 2023
 */

#include "internal.h"
#include "clock.h"
#include <immintrin.h>


uint128_t::operator uint8_t()
{
	return this->low & 0xFF;
}

uint128_t
uint128_t::operator>>(int shift)
{
	// this requires sse2 at least

	__m128i val;
	val.m128i_u64[0] = this->low;
	val.m128i_u64[1] = this->high;

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


	this->low = val.m128i_u64[0];
	this->high = val.m128i_u64[1];
	return *this;
}

uint80_t::operator uint8_t()
{
	return this->low & 0xFF;
}

uint80_t::operator uint128_t()
{
	uint128_t converted;
	converted.low = this->low;
	converted.high = this->high;
	return converted;
}

uint80_t
uint80_t::operator>>(int shift)
{
	uint128_t val = static_cast<uint128_t>(*this) >> shift;
	this->low = val.low;
	this->high = val.high;
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
