#include "net/icmp_ping.h"

#include <string>

namespace asio = boost::asio;

asio::awaitable<IcmpResult> icmp_ping_once(const asio::ip::address &, const ScanOptions &) {
    co_return IcmpResult{"error", "ICMP ping not supported on this platform"};
}
