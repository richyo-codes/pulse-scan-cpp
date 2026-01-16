#include <catch2/catch_test_macros.hpp>
#include <boost/asio.hpp>

#include <cstdlib>

#include "core/scan_utils.h"

namespace {

bool env_enabled(const char *name) {
    if (const char *value = std::getenv(name)) {
        return value[0] != '\0' && value[0] != '0';
    }
    return false;
}

} // namespace

TEST_CASE("resolve IPv4 loopback", "[dns]") {
    boost::asio::io_context io;
    boost::asio::ip::tcp::resolver resolver(io);
    boost::system::error_code ec;
    auto results = resolver.resolve("127.0.0.1", "", ec);

    REQUIRE_FALSE(ec);
    bool found_v4 = false;
    for (const auto &entry : results) {
        if (entry.endpoint().address().is_v4()) {
            found_v4 = true;
            break;
        }
    }
    REQUIRE(found_v4);
}

TEST_CASE("resolve IPv6 loopback when available", "[dns]") {
    boost::asio::io_context io;
    boost::asio::ip::tcp::resolver resolver(io);
    boost::system::error_code ec;
    auto results = resolver.resolve("::1", "", ec);

    if (ec) {
        SKIP("IPv6 loopback resolution failed on this system");
    }

    bool found_v6 = false;
    for (const auto &entry : results) {
        if (entry.endpoint().address().is_v6()) {
            found_v6 = true;
            break;
        }
    }

    if (!found_v6) {
        SKIP("IPv6 loopback not available on this system");
    }
}

TEST_CASE("resolve localhost", "[dns]") {
    boost::asio::io_context io;
    boost::asio::ip::tcp::resolver resolver(io);
    boost::system::error_code ec;
    auto results = resolver.resolve("localhost", "", ec);

    REQUIRE_FALSE(ec);
    REQUIRE(results.begin() != results.end());
}

TEST_CASE("resolve external hostname when enabled", "[dns][integration]") {
    if (!env_enabled("RUN_INTEGRATION_TESTS")) {
        SKIP("set RUN_INTEGRATION_TESTS=1 to enable external DNS lookup");
    }

    boost::asio::io_context io;
    boost::asio::ip::tcp::resolver resolver(io);
    boost::system::error_code ec;
    auto results = resolver.resolve("example.com", "", ec);

    REQUIRE_FALSE(ec);
    REQUIRE(results.begin() != results.end());
}

TEST_CASE("format_address handles resolved addresses when enabled", "[dns][integration]") {
    if (!env_enabled("RUN_INTEGRATION_TESTS")) {
        SKIP("set RUN_INTEGRATION_TESTS=1 to enable external DNS lookup");
    }

    boost::asio::io_context io;
    boost::asio::ip::tcp::resolver resolver(io);
    boost::system::error_code ec;
    auto results = resolver.resolve("example.com", "", ec);

    REQUIRE_FALSE(ec);
    REQUIRE(results.begin() != results.end());

    for (const auto &entry : results) {
        const auto addr = entry.endpoint().address();
        REQUIRE_NOTHROW(format_address(addr));
        REQUIRE_FALSE(format_address(addr).empty());
    }
}
