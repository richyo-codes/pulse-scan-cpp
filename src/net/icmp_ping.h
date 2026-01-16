#pragma once

#include "core/options.h"

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/address.hpp>

#include <string>

struct IcmpResult {
    std::string state;
    std::string detail;
};

boost::asio::awaitable<IcmpResult> icmp_ping_once(const boost::asio::ip::address &addr,
                                                  const ScanOptions &opts);
