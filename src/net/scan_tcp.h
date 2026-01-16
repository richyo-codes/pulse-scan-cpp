#pragma once

#include "core/options.h"
#include "net/scan_result.h"

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>

boost::asio::awaitable<ScanResult> scan_tcp_connect(
    boost::asio::ip::tcp::endpoint endpoint, const ScanOptions &opts);

boost::asio::awaitable<ScanResult> scan_tcp_banner(
    boost::asio::ip::tcp::endpoint endpoint, const ScanOptions &opts);
