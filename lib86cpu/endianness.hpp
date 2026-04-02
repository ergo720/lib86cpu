/*
 * endianness support
 *
 * ergo720                Copyright (c) 2022
 */

#pragma once

#include <stdexcept>
#include <bit>


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

static_assert(is_big_endian == false, "lib86cpu only supports little-endian machines right now");
