#include "net/udp_probes.h"

#include <array>
#include <cstddef>
#include <cstring>

namespace {

std::vector<std::uint8_t> dns_query_example_com() {
    // Standard DNS query for A record of example.com.
    const std::array<std::uint8_t, 29> payload = {
        0x12, 0x34, // ID
        0x01, 0x00, // flags: recursion desired
        0x00, 0x01, // QDCOUNT
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
        0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',
        0x03, 'c',  'o',  'm',
        0x00,       // end of name
        0x00, 0x01, // QTYPE A
        0x00, 0x01  // QCLASS IN
    };
    return {payload.begin(), payload.end()};
}

std::vector<std::uint8_t> dnssec_query_example_com() {
    // DNSKEY query with EDNS0 + DO bit (DNSSEC OK).
    const std::array<std::uint8_t, 40> payload = {
        0x56, 0x78, // ID
        0x01, 0x00, // flags: recursion desired
        0x00, 0x01, // QDCOUNT
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x01, // ARCOUNT
        0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',
        0x03, 'c',  'o',  'm',
        0x00,       // end of name
        0x00, 0x30, // QTYPE DNSKEY
        0x00, 0x01, // QCLASS IN
        0x00,       // OPT root
        0x00, 0x29, // OPT type
        0x04, 0xD0, // UDP payload size 1232
        0x00,       // extended RCODE
        0x00,       // EDNS version
        0x80, 0x00, // DO bit set
        0x00, 0x00  // RDLEN
    };
    return {payload.begin(), payload.end()};
}

std::vector<std::uint8_t> quic_version_negotiation_probe() {
    // Long header with an unsupported version to elicit a VN response.
    constexpr std::uint8_t dcid_len = 8;
    constexpr std::uint8_t scid_len = 8;
    std::vector<std::uint8_t> packet;
    packet.reserve(1 + 4 + 1 + dcid_len + 1 + scid_len);

    packet.push_back(0xC0); // Long header, fixed bit set.
    packet.push_back(0x0A);
    packet.push_back(0x0A);
    packet.push_back(0x0A);
    packet.push_back(0x0A); // Unsupported version.

    packet.push_back(dcid_len);
    const std::array<std::uint8_t, dcid_len> dcid{{0x50, 0x53, 0x43, 0x50, 0x50, 0x44, 0x31, 0x30}};
    packet.insert(packet.end(), dcid.begin(), dcid.end());

    packet.push_back(scid_len);
    const std::array<std::uint8_t, scid_len> scid{{0x50, 0x53, 0x43, 0x50, 0x50, 0x53, 0x31, 0x30}};
    packet.insert(packet.end(), scid.begin(), scid.end());

    return packet;
}

std::vector<std::uint8_t> ntp_client_probe() {
    // NTP client request (LI=0, VN=4, Mode=3).
    return {0x23};
}

std::vector<std::uint8_t> sip_options_probe() {
    const char *message =
        "OPTIONS sip:example.com SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 0.0.0.0:5060;branch=z9hG4bKpscpp\r\n"
        "Max-Forwards: 70\r\n"
        "To: <sip:example.com>\r\n"
        "From: <sip:scanner@pulsescan-cpp>;tag=pscpp\r\n"
        "Call-ID: pscpp-options\r\n"
        "CSeq: 1 OPTIONS\r\n"
        "Contact: <sip:scanner@0.0.0.0>\r\n"
        "Content-Length: 0\r\n"
        "\r\n";
    return {message, message + std::strlen(message)};
}

std::vector<std::uint8_t> iax2_ping_probe() {
    // IAX2 full frame: src call number (0x8001), dst call number (0x0000),
    // timestamp, oseq, iseq, type=IAX (0x06), subclass=PING (0x06).
    return {
        0x80, 0x01, // src call number
        0x00, 0x00, // dst call number
        0x00, 0x00, 0x00, 0x00, // timestamp
        0x00, // oseq
        0x00, // iseq
        0x06, // type
        0x06  // subclass
    };
}

} // namespace

std::vector<std::uint8_t> udp_probe_payload(std::uint16_t port) {
    switch (port) {
    case 53:
        return dns_query_example_com();
    case 123:
        return ntp_client_probe();
    case 443:
        return quic_version_negotiation_probe();
    case 5060:
        return sip_options_probe();
    case 4569:
        return iax2_ping_probe();
    default:
        return {0x00};
    }
}
