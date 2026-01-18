#pragma once

#include <atomic>
#include <cstdint>
#include <string>

struct ScanStatus {
    std::atomic<std::uint64_t> total_targets{0};
    std::atomic<std::uint64_t> completed_targets{0};
    std::atomic<std::uint64_t> total_hosts{0};
    std::atomic<std::uint64_t> completed_hosts{0};
    std::atomic<std::uint64_t> cycles{0};
};

std::string format_status(const ScanStatus &status);
