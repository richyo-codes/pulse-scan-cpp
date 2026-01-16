#pragma once

#include <string>

struct ScanResult {
    int port{};
    std::string state;
    std::string detail;
};
