#include "core/status.h"

#include <iomanip>
#include <sstream>

std::string format_status(const ScanStatus &status) {
    const auto total = status.total_targets.load();
    const auto done = status.completed_targets.load();
    const auto hosts_total = status.total_hosts.load();
    const auto hosts_done = status.completed_hosts.load();
    const auto cycles = status.cycles.load();

    std::ostringstream out;
    out << "progress: targets " << done << "/" << total;
    if (total > 0) {
        const double pct = (static_cast<double>(done) / static_cast<double>(total)) * 100.0;
        out << " (" << std::fixed << std::setprecision(1) << pct << "%)";
    }
    if (hosts_total > 0) {
        out << ", hosts " << hosts_done << "/" << hosts_total;
    }
    if (cycles > 0) {
        out << ", cycles " << cycles;
    }
    return out.str();
}
