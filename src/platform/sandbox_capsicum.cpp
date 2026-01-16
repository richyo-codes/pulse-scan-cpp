#include "platform/sandbox.h"

#if defined(__FreeBSD__)

#include <sys/capsicum.h>
#include <arpa/inet.h>

#include <cerrno>
#include <cstring>
#include <string>

namespace {

bool is_ip_literal(const std::string &host) {
    in_addr addr4{};
    in6_addr addr6{};
    return inet_pton(AF_INET, host.c_str(), &addr4) == 1 ||
           inet_pton(AF_INET6, host.c_str(), &addr6) == 1;
}

} // namespace

SandboxStatus apply_sandbox(const ScanOptions &, const std::vector<std::string> &hosts,
                            std::string &message) {
    for (const auto &host : hosts) {
        if (!is_ip_literal(host)) {
            message = "Capsicum sandbox requires IP literals (DNS not available)";
            return SandboxStatus::Skipped;
        }
    }

    if (cap_getmode() == 1) {
        message = "Capsicum already enabled";
        return SandboxStatus::Applied;
    }

    if (cap_enter() != 0) {
        message = "Capsicum cap_enter failed: " + std::string(strerror(errno));
        return SandboxStatus::Failed;
    }

    message = "Capsicum sandbox enabled";
    return SandboxStatus::Applied;
}

#else

SandboxStatus apply_sandbox(const ScanOptions &, const std::vector<std::string> &,
                            std::string &message) {
    message = "Capsicum sandbox not available on this platform";
    return SandboxStatus::Skipped;
}

#endif
