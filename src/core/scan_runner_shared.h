#pragma once

#include "core/scan_runner.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/steady_timer.hpp>

#include <queue>
#include <string>
#include <utility>

// Bundle shared references to keep lambda captures explicit but compact.
struct ScanShared {
    boost::asio::any_io_executor &executor;
    ScanOptions &opts;
    std::queue<std::pair<boost::asio::ip::address, int>> &remaining_targets;
    std::size_t &inflight;
    const ScanCallback &on_result;
    const std::string &host;
    boost::asio::steady_timer &done_timer;
};
