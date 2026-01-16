#pragma once

#include "core/options.h"

#include <string>
#include <vector>

enum class SandboxStatus {
    Applied,
    Skipped,
    Failed
};

SandboxStatus apply_sandbox(const ScanOptions &opts,
                            const std::vector<std::string> &hosts,
                            std::string &message);
