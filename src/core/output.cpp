#include "core/output.h"
#include "core/scan_utils.h"

bool should_report(const ScanResult &result, bool open_only) {
    if (!open_only) {
        return true;
    }
    return result.state == "open";
}

std::string format_address_with_reverse(
    const boost::asio::ip::address &addr,
    const std::unordered_map<std::string, std::string> &reverse_map) {
    const auto base = format_address(addr);
    auto it = reverse_map.find(base);
    if (it == reverse_map.end() || it->second.empty()) {
        return base;
    }
    return base + " (" + it->second + ")";
}
