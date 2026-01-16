#pragma once

#include "core/options.h"
#include "net/scan_result.h"

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/address.hpp>

#include <functional>
#include <string>

struct ScanRecord {
    std::string host;
    boost::asio::ip::address addr;
    ScanResult result;
};

using ScanCallback = std::function<void(const ScanRecord &)>;

boost::asio::awaitable<void> run_scans(const std::string &host,
                                       const std::vector<boost::asio::ip::address> &addresses,
                                       ScanOptions opts,
                                       const ScanCallback &on_result);
