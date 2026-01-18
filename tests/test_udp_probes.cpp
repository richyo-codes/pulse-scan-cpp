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
