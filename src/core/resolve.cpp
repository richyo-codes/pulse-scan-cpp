#include "core/resolve.h"

#include "core/logging.h"

#include <boost/asio/ip/address.hpp>

#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

namespace asio = boost::asio;

std::optional<std::vector<asio::ip::address>> expand_cidr_v4(const std::string &input) {
    const auto slash = input.find('/');
    if (slash == std::string::npos) {
        return std::nullopt;
    }
    const std::string ip_part = input.substr(0, slash);
    const std::string prefix_part = input.substr(slash + 1);
    if (ip_part.empty() || prefix_part.empty()) {
        return std::nullopt;
    }

    char *endptr = nullptr;
    long prefix = std::strtol(prefix_part.c_str(), &endptr, 10);
    if (endptr == prefix_part.c_str() || *endptr != '\0') {
        return std::nullopt;
    }
    if (prefix < 0 || prefix > 32) {
        return std::nullopt;
    }

    boost::system::error_code ec;
    auto addr = asio::ip::make_address_v4(ip_part, ec);
    if (ec) {
        return std::nullopt;
    }

    const std::uint32_t host = addr.to_uint();
    const std::uint32_t mask = prefix == 0 ? 0u : (0xFFFFFFFFu << (32 - prefix));
    const std::uint32_t network = host & mask;
    const std::uint32_t broadcast = network | ~mask;

    std::vector<asio::ip::address> addresses;
    addresses.reserve(static_cast<std::size_t>(broadcast - network + 1));
    for (std::uint32_t ip = network; ip <= broadcast; ++ip) {
        addresses.emplace_back(asio::ip::address_v4(ip));
        if (ip == 0xFFFFFFFFu) {
            break;
        }
    }
    return addresses;
}

std::optional<std::vector<asio::ip::address>> expand_range_v4(const std::string &input) {
    const auto dash = input.find('-');
    if (dash == std::string::npos) {
        return std::nullopt;
    }

    const std::string left = input.substr(0, dash);
    const std::string right = input.substr(dash + 1);
    if (left.empty() || right.empty()) {
        return std::nullopt;
    }

    boost::system::error_code ec;
    auto start_addr = asio::ip::make_address_v4(left, ec);
    if (ec) {
        return std::nullopt;
    }

    std::uint32_t start = start_addr.to_uint();
    std::uint32_t end = start;

    if (right.find('.') != std::string::npos) {
        auto end_addr = asio::ip::make_address_v4(right, ec);
        if (ec) {
            return std::nullopt;
        }
        end = end_addr.to_uint();
    } else {
        const auto last_dot = left.rfind('.');
        if (last_dot == std::string::npos) {
            return std::nullopt;
        }
        const std::string prefix = left.substr(0, last_dot + 1);
        auto end_addr = asio::ip::make_address_v4(prefix + right, ec);
        if (ec) {
            return std::nullopt;
        }
        end = end_addr.to_uint();
    }

    if (start > end) {
        std::swap(start, end);
    }

    std::vector<asio::ip::address> addresses;
    addresses.reserve(static_cast<std::size_t>(end - start + 1));
    for (std::uint32_t ip = start; ip <= end; ++ip) {
        addresses.emplace_back(asio::ip::address_v4(ip));
        if (ip == 0xFFFFFFFFu) {
            break;
        }
    }
    return addresses;
}

std::vector<asio::ip::address> resolve_or_expand(const std::string &host,
                                                 asio::ip::tcp::resolver &resolver,
                                                 const ScanOptions &opts,
                                                 bool &used_range) {
    used_range = false;
    auto cidr = expand_cidr_v4(host);
    if (cidr.has_value()) {
        used_range = true;
        if (opts.ipv6_only) {
            return {};
        }
        return *cidr;
    }
    auto range = expand_range_v4(host);
    if (range.has_value()) {
        used_range = true;
        if (opts.ipv6_only) {
            return {};
        }
        return *range;
    }

    boost::system::error_code ec;
    log_trace("resolve host=" + host, opts.verbose);
    auto resolved = resolver.resolve(host, "", ec);
    log_dns_results(host, resolved, ec, opts.debug_dns);
    if (ec || resolved.empty()) {
        std::cerr << "Failed to resolve host " << host << ": "
                  << (ec ? ec.message() : "no results") << "\n";
        return {};
    }

    std::vector<asio::ip::address> addresses;
    for (const auto &entry : resolved) {
        const auto addr = entry.endpoint().address();
        if (opts.ipv4_only && !addr.is_v4()) {
            continue;
        }
        if (opts.ipv6_only && !addr.is_v6()) {
            continue;
        }
        addresses.push_back(addr);
    }
    return addresses;
}
