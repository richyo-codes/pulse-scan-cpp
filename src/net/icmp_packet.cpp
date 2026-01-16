#include "net/icmp_packet.h"

#include <arpa/inet.h>

std::uint16_t compute_checksum(const std::uint8_t *data, std::size_t length) {
    std::uint32_t sum = 0;
    while (length > 1) {
        sum += (static_cast<std::uint16_t>(data[0]) << 8) | data[1];
        data += 2;
        length -= 2;
    }
    if (length > 0) {
        sum += static_cast<std::uint16_t>(data[0]) << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<std::uint16_t>(~sum);
}

bool parse_v4_echo_reply(const std::uint8_t *data, std::size_t length, std::uint16_t id,
                         std::uint16_t seq) {
    std::size_t offset = 0;
    if (length >= 20 && (data[0] >> 4) == 4) {
        const std::uint8_t ihl = static_cast<std::uint8_t>(data[0] & 0x0F);
        const std::size_t ip_header_len = static_cast<std::size_t>(ihl) * 4;
        if (ip_header_len + 8 > length) {
            return false;
        }
        offset = ip_header_len;
    } else if (length < 8) {
        return false;
    }
    const std::uint8_t type = data[offset];
    const std::uint8_t code = data[offset + 1];
    if (type != 0 || code != 0) {
        return false;
    }
    const std::uint16_t resp_id =
        static_cast<std::uint16_t>(data[offset + 4] << 8 | data[offset + 5]);
    const std::uint16_t resp_seq =
        static_cast<std::uint16_t>(data[offset + 6] << 8 | data[offset + 7]);
    return ntohs(resp_id) == id && ntohs(resp_seq) == seq;
}

bool parse_v6_echo_reply(const std::uint8_t *data, std::size_t length, std::uint16_t id,
                         std::uint16_t seq) {
    std::size_t offset = 0;
    if (length >= 40 && (data[0] >> 4) == 6) {
        offset = 40;
        if (offset + 8 > length) {
            return false;
        }
    } else if (length < 8) {
        return false;
    }
    const std::uint8_t type = data[offset];
    const std::uint8_t code = data[offset + 1];
    if (type != 129 || code != 0) {
        return false;
    }
    const std::uint16_t resp_id =
        static_cast<std::uint16_t>(data[offset + 4] << 8 | data[offset + 5]);
    const std::uint16_t resp_seq =
        static_cast<std::uint16_t>(data[offset + 6] << 8 | data[offset + 7]);
    return ntohs(resp_id) == id && ntohs(resp_seq) == seq;
}
