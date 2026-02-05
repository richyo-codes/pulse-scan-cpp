#include <catch2/catch_test_macros.hpp>

#include "net/udp_probes.h"

TEST_CASE("udp probe for DNS includes query", "[udp]") {
    auto payload = udp_probe_payload(53);
    REQUIRE(payload.size() >= 12);
    REQUIRE(payload[2] == 0x01);
    REQUIRE(payload[3] == 0x00);
}

TEST_CASE("udp probe for QUIC uses long header", "[udp]") {
    auto payload = udp_probe_payload(443);
    REQUIRE(payload.size() >= 6);
    REQUIRE((payload[0] & 0xC0) == 0xC0);
}

TEST_CASE("udp probe for NTP uses client mode", "[udp]") {
    auto payload = udp_probe_payload(123);
    REQUIRE(payload.size() >= 1);
    REQUIRE(payload[0] == 0x23);
}

TEST_CASE("udp probe for SIP uses OPTIONS", "[udp]") {
    auto payload = udp_probe_payload(5060);
    REQUIRE(payload.size() >= 8);
    REQUIRE(payload[0] == 'O');
    REQUIRE(payload[1] == 'P');
    REQUIRE(payload[2] == 'T');
}

TEST_CASE("udp probe for IAX2 uses full frame", "[udp]") {
    auto payload = udp_probe_payload(4569);
    REQUIRE(payload.size() == 12);
    REQUIRE(payload[0] == 0x80);
    REQUIRE(payload[1] == 0x01);
    REQUIRE(payload[10] == 0x06);
    REQUIRE(payload[11] == 0x06);
}
