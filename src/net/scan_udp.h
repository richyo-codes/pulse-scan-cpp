#pragma once

#include "core/options.h"
#include "net/scan_result.h"

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/udp.hpp>

boost::asio::awaitable<ScanResult> scan_udp(
    boost::asio::ip::udp::endpoint endpoint, const ScanOptions &opts);
