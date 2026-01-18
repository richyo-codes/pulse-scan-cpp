#pragma once

#include "net/scan_result.h"

#include <boost/asio/ip/address.hpp>

#include <string>
#include <unordered_map>

bool should_report(const ScanResult &result, bool open_only);
std::string format_address_with_reverse(
    const boost::asio::ip::address &addr,
    const std::unordered_map<std::string, std::string> &reverse_map);
