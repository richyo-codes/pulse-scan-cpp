#pragma once

#include <cstddef>
#include <cstdint>

std::uint16_t compute_checksum(const std::uint8_t *data, std::size_t length);

bool parse_v4_echo_reply(const std::uint8_t *data, std::size_t length, std::uint16_t id,
                         std::uint16_t seq);

bool parse_v6_echo_reply(const std::uint8_t *data, std::size_t length, std::uint16_t id,
                         std::uint16_t seq);
