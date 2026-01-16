#include "core/output.h"

bool should_report(const ScanResult &result, bool open_only) {
    if (!open_only) {
        return true;
    }
    return result.state == "open";
}
