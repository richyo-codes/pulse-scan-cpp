#include <catch2/catch_test_macros.hpp>

#include "core/cli.h"
#include "net/icmp_packet.h"
#include "core/output.h"
#include "core/resolve.h"

#include <algorithm>
#include <unordered_map>
#include <vector>

#include <boost/asio/ip/address.hpp>

TEST_CASE("expand_cidr_v4 expands /30", "[resolve]") {
    auto addresses = expand_cidr_v4("192.168.1.0/30");
    REQUIRE(addresses.has_value());
    REQUIRE(addresses->size() == 4);
    REQUIRE(addresses->front().to_string() == "192.168.1.0");
    REQUIRE(addresses->back().to_string() == "192.168.1.3");
}

TEST_CASE("expand_cidr_v4 expands /24", "[resolve]") {
    auto addresses = expand_cidr_v4("192.168.1.0/24");
    REQUIRE(addresses.has_value());
    REQUIRE(addresses->size() == 255);
    REQUIRE(addresses->front().to_string() == "192.168.1.0");
    REQUIRE(addresses->back().to_string() == "192.168.1.255");
}


TEST_CASE("expand_range_v4 expands dash range", "[resolve]") {
    auto addresses = expand_range_v4("192.168.1.50-52");
    REQUIRE(addresses.has_value());
    REQUIRE(addresses->size() == 3);
    REQUIRE(addresses->front().to_string() == "192.168.1.50");
    REQUIRE(addresses->back().to_string() == "192.168.1.52");
}

TEST_CASE("expand_range_v4 expands dotted end", "[resolve]") {
    auto addresses = expand_range_v4("192.168.1.50-192.168.1.52");
    REQUIRE(addresses.has_value());
    REQUIRE(addresses->size() == 3);
    REQUIRE(addresses->front().to_string() == "192.168.1.50");
    REQUIRE(addresses->back().to_string() == "192.168.1.52");
}

TEST_CASE("parse_v4_echo_reply validates id and seq", "[icmp]") {
    std::vector<std::uint8_t> packet(28, 0);
    packet[0] = 0x45; // IPv4 header, IHL=5
    packet[20] = 0;   // type
    packet[21] = 0;   // code
    packet[24] = 0x12;
    packet[25] = 0x34; // id
    packet[26] = 0x00;
    packet[27] = 0x02; // seq

    REQUIRE(parse_v4_echo_reply(packet.data(), packet.size(), 0x1234, 0x0002));
    REQUIRE_FALSE(parse_v4_echo_reply(packet.data(), packet.size(), 0x1234, 0x0003));
}

TEST_CASE("parse_v6_echo_reply validates id and seq", "[icmp]") {
    std::vector<std::uint8_t> packet(8, 0);
    packet[0] = 129; // echo reply
    packet[1] = 0;
    packet[4] = 0x12;
    packet[5] = 0x34; // id
    packet[6] = 0x00;
    packet[7] = 0x05; // seq

    REQUIRE(parse_v6_echo_reply(packet.data(), packet.size(), 0x1234, 0x0005));
    REQUIRE_FALSE(parse_v6_echo_reply(packet.data(), packet.size(), 0x1234, 0x0006));
}

TEST_CASE("cli rejects conflicting ip flags", "[cli]") {
    ScanOptions opts;
    std::vector<std::string> hosts;
    const char *argv[] = {"pulsescan-cpp", "-4", "-6", "example.com"};
    int rc = parse_cli(4, const_cast<char **>(argv), opts, hosts);
    REQUIRE(rc != 0);
}

TEST_CASE("cli rejects icmp with port options", "[cli]") {
    ScanOptions opts;
    std::vector<std::string> hosts;
    const char *argv[] = {"pulsescan-cpp", "--icmp-ping", "example.com", "-p", "80"};
    int rc = parse_cli(5, const_cast<char **>(argv), opts, hosts);
    REQUIRE(rc != 0);
}

TEST_CASE("cli uses default dev ports when none specified", "[cli]") {
    ScanOptions opts;
    std::vector<std::string> hosts;
    const char *argv[] = {"pulsescan-cpp", "example.com"};
    int rc = parse_cli(2, const_cast<char **>(argv), opts, hosts);
    REQUIRE(rc == 0);
    REQUIRE(!opts.ports.empty());
    REQUIRE(std::find(opts.ports.begin(), opts.ports.end(), 22) != opts.ports.end());
    REQUIRE(std::find(opts.ports.begin(), opts.ports.end(), 80) != opts.ports.end());
    REQUIRE(std::find(opts.ports.begin(), opts.ports.end(), 443) != opts.ports.end());
}

TEST_CASE("cli accepts top ports option", "[cli]") {
    ScanOptions opts;
    std::vector<std::string> hosts;
    const char *argv[] = {"pulsescan-cpp", "example.com", "--top-ports", "5"};
    int rc = parse_cli(4, const_cast<char **>(argv), opts, hosts);
    REQUIRE(rc == 0);
    REQUIRE(opts.ports.size() == 5);
}

TEST_CASE("cli accepts json output format", "[cli]") {
    ScanOptions opts;
    std::vector<std::string> hosts;
    const char *argv[] = {"pulsescan-cpp", "example.com", "--output", "json"};
    int rc = parse_cli(4, const_cast<char **>(argv), opts, hosts);
    REQUIRE(rc == 0);
    REQUIRE(opts.output_format == OutputFormat::Json);
}

TEST_CASE("format_address_with_reverse uses map when present", "[output]") {
    std::unordered_map<std::string, std::string> reverse_map;
    reverse_map["127.0.0.1"] = "localhost";
    auto addr = boost::asio::ip::make_address("127.0.0.1");
    REQUIRE(format_address_with_reverse(addr, reverse_map) == "127.0.0.1 (localhost)");
}
