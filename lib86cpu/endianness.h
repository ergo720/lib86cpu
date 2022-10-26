/*
 * endianness support
 *
 * ergo720                Copyright (c) 2022
 */

#pragma once

#include <stdexcept>
#include <bit>


inline uint8_t
byte_swap8(uint8_t val)
{
    return val;
}

inline uint16_t
byte_swap16(uint16_t val) {
#if defined(_MSC_VER) && !defined(_DEBUG)
    return _byteswap_ushort(val);
#else
    uint16_t high = val << 8;
    uint16_t low = val >> 8;
    return high | low;
#endif
}

inline uint32_t
byte_swap32(uint32_t val)
{
#if defined(_MSC_VER) && !defined(_DEBUG)
    return _byteswap_ulong(val);
#else
    uint32_t byte0 = val & 0x000000FF;
    uint32_t byte1 = val & 0x0000FF00;
    uint32_t byte2 = val & 0x00FF0000;
    uint32_t byte3 = val & 0xFF000000;
    return (byte0 << 24) | (byte1 << 8) | (byte2 >> 8) | (byte3 >> 24);
#endif
}

inline uint64_t
byte_swap64(uint64_t val)
{
#if defined(_MSC_VER) && !defined(_DEBUG)
    return _byteswap_uint64(val);
#else
    uint64_t high = byte_swap32(static_cast<uint32_t>(val));
    uint32_t low = byte_swap32(static_cast<uint32_t>(val >> 32));
    return (high << 32) | low;
#endif
}

template<typename T>
void swap_byte_order(T &val)
{
    switch (sizeof(T))
    {
    case 8:
        val = byte_swap64(val);
        break;

    case 4:
        val = byte_swap32(val);
        break;

    case 2:
        val = byte_swap16(val);
        break;

    case 1:
        val = byte_swap8(val);
        break;

    default:
        LIB86CPU_ABORT_msg("Unsupported byte size of %zu", sizeof(T));
    }
}

consteval bool
is_big_endian_()
{
    if constexpr (std::endian::native == std::endian::big) {
        return true;
    }
    else if constexpr (std::endian::native == std::endian::little) {
        return false;
    }
    else {
        throw std::logic_error("Mixed endian systems are not supported");
    }
}

inline constexpr bool is_big_endian = is_big_endian_();
