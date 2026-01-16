#include "platform/sandbox.h"

SandboxStatus apply_sandbox(const ScanOptions &, const std::vector<std::string> &,
                            std::string &message) {
    message = "Sandboxing not supported on this platform";
    return SandboxStatus::Skipped;
}
