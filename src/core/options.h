#pragma once

#include <chrono>
#include <cstddef>
#include <string>
#include <vector>

enum class ScanMode {
    TcpConnect,
    TcpBanner,
    Udp
};

struct ScanOptions {
    std::vector<int> ports;
    std::chrono::milliseconds timeout{1000};
    std::size_t max_inflight{200};
    ScanMode mode{ScanMode::TcpConnect};
    std::chrono::milliseconds banner_timeout{500};
    std::size_t banner_bytes{128};
    std::chrono::milliseconds ping_interval{1000};
    bool ping_mode{false};
    bool open_only{false};
    bool debug_dns{false};
    bool verbose{false};
    bool ipv4_only{false};
    bool ipv6_only{false};
    bool icmp_ping{false};
    bool sandbox{false};
    int icmp_count{1};
};
