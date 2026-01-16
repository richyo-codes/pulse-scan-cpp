#include "core/app.h"

#include "core/cli.h"
#include "core/logging.h"
#include "core/output.h"
#include "core/ping_loop.h"
#include "core/resolve.h"
#include "core/scan_runner.h"
#include "core/scan_utils.h"
#include "net/icmp_scan.h"
#include "platform/sandbox.h"

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include <iostream>
#include <vector>

namespace asio = boost::asio;

using asio::awaitable;
using asio::co_spawn;
using asio::redirect_error;
using asio::use_awaitable;

namespace {

awaitable<void> run_port_scans(const std::vector<std::string> &hosts, ScanOptions opts) {
    auto executor = co_await asio::this_coro::executor;
    asio::io_context &io = static_cast<asio::io_context &>(executor.context());
    asio::ip::tcp::resolver resolver(io);

    for (const auto &host : hosts) {
        bool used_range = false;
        auto addresses = resolve_or_expand(host, resolver, opts, used_range);
        if (addresses.empty()) {
            if (used_range) {
                std::cerr << "No addresses after IP filter for host " << host << "\n";
            }
            continue;
        }

        co_await run_scans(
            host, addresses, opts,
            [&](const ScanRecord &record) {
                if (!should_report(record.result, opts.open_only)) {
                    return;
                }
                std::cout << record.host << " "
                          << format_address(record.addr) << ":"
                          << record.result.port << " -> "
                          << record.result.state << " ("
                          << record.result.detail << ")\n";
            });
    }
    co_return;
}

} // namespace

int run_app(int argc, char **argv) {
    ScanOptions opts;
    std::vector<std::string> hosts;
    int exit_code = parse_cli(argc, argv, opts, hosts);
    if (exit_code != 0) {
        return exit_code;
    }

    if (opts.sandbox) {
        std::string message;
        SandboxStatus status = apply_sandbox(opts, hosts, message);
        if (!message.empty()) {
            std::cerr << message << "\n";
        }
        if (status == SandboxStatus::Failed) {
            return 1;
        }
    }

    asio::io_context io;
    if (opts.icmp_ping && opts.ping_mode) {
        co_spawn(
            io, icmp_ping_loop(hosts, opts),
            [](std::exception_ptr eptr) {
                if (!eptr) {
                    return;
                }
                try {
                    std::rethrow_exception(eptr);
                } catch (const std::exception &e) {
                    log_exception("ICMP ping loop error", e);
                }
            });
    } else if (opts.icmp_ping) {
        co_spawn(
            io, icmp_scan_hosts(hosts, opts, nullptr, false),
            [](std::exception_ptr eptr) {
                if (!eptr) {
                    return;
                }
                try {
                    std::rethrow_exception(eptr);
                } catch (const std::exception &e) {
                    log_exception("ICMP ping error", e);
                }
            });
    } else if (opts.ping_mode) {
        co_spawn(
            io, ping_loop(hosts, opts),
            [](std::exception_ptr eptr) {
                if (!eptr) {
                    return;
                }
                try {
                    std::rethrow_exception(eptr);
                } catch (const std::exception &e) {
                    log_exception("Ping loop error", e);
                }
            });
    } else {
        co_spawn(
            io, run_port_scans(hosts, opts),
            [](std::exception_ptr eptr) {
                if (!eptr) {
                    return;
                }
                try {
                    std::rethrow_exception(eptr);
                } catch (const std::exception &e) {
                    log_exception("Scan runner error", e);
                }
            });
    }

    io.run();
    return 0;
}
