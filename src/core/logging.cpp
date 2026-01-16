#include "core/logging.h"

#include <iostream>

#ifdef ENABLE_STACKTRACE
#include <boost/stacktrace.hpp>
#endif

#include "core/scan_utils.h"

void log_exception(const char *context, const std::exception &e) {
    std::cerr << context << ": " << e.what() << "\n";
#if defined(ENABLE_STACKTRACE) && !defined(NDEBUG)
    std::cerr << boost::stacktrace::stacktrace();
#endif
}

void log_trace(const std::string &message, bool enabled) {
    if (!enabled) {
        return;
    }
    std::cerr << "[trace] " << message << "\n";
}

void log_dns_results(const std::string &host,
                     const boost::asio::ip::tcp::resolver::results_type &results,
                     const boost::system::error_code &ec,
                     bool enabled) {
    if (!enabled) {
        return;
    }
    if (ec) {
        std::cerr << "[dns] " << host << " -> error: " << ec.message() << "\n";
        return;
    }
    std::size_t count = 0;
    for (const auto &entry : results) {
        std::cerr << "[dns] " << host << " -> "
                  << format_address(entry.endpoint().address()) << "\n";
        ++count;
    }
    if (count == 0) {
        std::cerr << "[dns] " << host << " -> no results\n";
    }
}
