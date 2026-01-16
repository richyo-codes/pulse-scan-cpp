#pragma once

#include "core/options.h"

#include <boost/asio/awaitable.hpp>

#include <string>
#include <vector>

boost::asio::awaitable<void> ping_loop(const std::vector<std::string> &hosts, ScanOptions opts);
