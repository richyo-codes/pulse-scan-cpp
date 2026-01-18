#pragma once

#include "core/options.h"

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

std::optional<std::vector<boost::asio::ip::address>> expand_cidr_v4(const std::string &input);
std::optional<std::vector<boost::asio::ip::address>> expand_range_v4(const std::string &input);

std::vector<boost::asio::ip::address> resolve_or_expand(const std::string &host,
                                                        boost::asio::ip::tcp::resolver &resolver,
                                                        const ScanOptions &opts,
                                                        bool &used_range);

std::unordered_map<std::string, std::string> reverse_dns_map(
    boost::asio::ip::tcp::resolver &resolver,
    const std::vector<boost::asio::ip::address> &addresses,
    const ScanOptions &opts);
