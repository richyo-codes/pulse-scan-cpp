#pragma once

#include "core/options.h"

#include <boost/asio/awaitable.hpp>

#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using IcmpStateMap = std::unordered_map<std::string, std::pair<std::string, std::string>>;

boost::asio::awaitable<void> icmp_scan_hosts(const std::vector<std::string> &hosts,
                                             ScanOptions opts,
                                             IcmpStateMap *last_state,
                                             bool changes_only);

boost::asio::awaitable<void> icmp_ping_loop(const std::vector<std::string> &hosts,
                                            ScanOptions opts);
