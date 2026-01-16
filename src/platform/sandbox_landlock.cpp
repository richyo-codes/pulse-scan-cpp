#include "platform/sandbox.h"

#if defined(__linux__)

#include <linux/landlock.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>

namespace {

int ll_create_ruleset(const struct landlock_ruleset_attr *attr, std::size_t size,
                      std::uint32_t flags) {
    return static_cast<int>(syscall(__NR_landlock_create_ruleset, attr, size, flags));
}

int ll_add_rule(int ruleset_fd, enum landlock_rule_type rule_type,
                const void *rule_attr, std::uint32_t flags) {
    return static_cast<int>(syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr,
                                    flags));
}

int ll_restrict_self(int ruleset_fd, std::uint32_t flags) {
    return static_cast<int>(syscall(__NR_landlock_restrict_self, ruleset_fd, flags));
}

void add_path_rule(int ruleset_fd, const char *path, std::uint64_t access) {
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) {
        return;
    }

    landlock_path_beneath_attr path_beneath{};
    path_beneath.allowed_access = access;
    path_beneath.parent_fd = fd;

    ll_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0);
    close(fd);
}

} // namespace

SandboxStatus apply_sandbox(const ScanOptions &, const std::vector<std::string> &,
                            std::string &message) {
    landlock_ruleset_attr ruleset{};
    ruleset.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;

    int ruleset_fd = ll_create_ruleset(&ruleset, sizeof(ruleset), 0);
    if (ruleset_fd < 0) {
        if (errno == ENOSYS) {
            message = "Landlock not supported by kernel";
            return SandboxStatus::Skipped;
        }
        message = "Landlock create_ruleset failed: " + std::string(strerror(errno));
        return SandboxStatus::Failed;
    }

    // Allow DNS-related config files and their parent directories.
    add_path_rule(ruleset_fd, "/etc", LANDLOCK_ACCESS_FS_READ_DIR);
    add_path_rule(ruleset_fd, "/etc/resolv.conf", LANDLOCK_ACCESS_FS_READ_FILE);
    add_path_rule(ruleset_fd, "/etc/hosts", LANDLOCK_ACCESS_FS_READ_FILE);
    add_path_rule(ruleset_fd, "/etc/nsswitch.conf", LANDLOCK_ACCESS_FS_READ_FILE);

    add_path_rule(ruleset_fd, "/run", LANDLOCK_ACCESS_FS_READ_DIR);
    add_path_rule(ruleset_fd, "/run/systemd", LANDLOCK_ACCESS_FS_READ_DIR);
    add_path_rule(ruleset_fd, "/run/systemd/resolve", LANDLOCK_ACCESS_FS_READ_DIR);
    add_path_rule(ruleset_fd, "/run/systemd/resolve/stub-resolv.conf",
                  LANDLOCK_ACCESS_FS_READ_FILE);
    add_path_rule(ruleset_fd, "/run/systemd/resolve/resolv.conf",
                  LANDLOCK_ACCESS_FS_READ_FILE);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        message = "Landlock failed to set no_new_privs: " + std::string(strerror(errno));
        close(ruleset_fd);
        return SandboxStatus::Failed;
    }

    if (ll_restrict_self(ruleset_fd, 0) != 0) {
        message = "Landlock restrict_self failed: " + std::string(strerror(errno));
        close(ruleset_fd);
        return SandboxStatus::Failed;
    }

    close(ruleset_fd);
    message = "Landlock sandbox enabled";
    return SandboxStatus::Applied;
}

#else

SandboxStatus apply_sandbox(const ScanOptions &, const std::vector<std::string> &,
                            std::string &message) {
    message = "Landlock sandbox not available on this platform";
    return SandboxStatus::Skipped;
}

#endif
