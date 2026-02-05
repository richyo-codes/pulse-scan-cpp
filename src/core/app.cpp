#include "core/app.h"

#include "core/cli.h"
#include "core/logging.h"
#include "core/output.h"
#include "core/ping_loop.h"
#include "core/resolve.h"
#include "core/scan_runner.h"
#include "core/scan_utils.h"
#include "core/status.h"
#include "net/icmp_scan.h"
#include "platform/sandbox.h"

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/streambuf.hpp>
#if !defined(_WIN32)
#include <boost/asio/posix/stream_descriptor.hpp>
#include <unistd.h>
#endif

#include <csignal>
#include <iostream>
#include <memory>
#include <unordered_map>
#include <vector>

namespace asio = boost::asio;

using asio::awaitable;
using asio::co_spawn;

namespace {

awaitable<void> run_port_scans(const std::vector<std::string> &hosts, ScanOptions opts,
                               ScanStatus *status) {
    auto executor = co_await asio::this_coro::executor;
    asio::io_context &io = static_cast<asio::io_context &>(executor.context());
    asio::ip::tcp::resolver resolver(io);

    if (status) {
        status->total_hosts.store(hosts.size());
        status->completed_targets.store(0);
        status->completed_hosts.store(0);
    }

    std::vector<std::pair<std::string, std::vector<asio::ip::address>>> targets;
    targets.reserve(hosts.size());
    std::uint64_t total = 0;
    for (const auto &host : hosts) {
        bool used_range = false;
        auto addresses = resolve_or_expand(host, resolver, opts, used_range);
        if (addresses.empty()) {
            if (used_range) {
                std::cerr << "No addresses after IP filter for host " << host << "\n";
            }
            continue;
        }
        total += static_cast<std::uint64_t>(addresses.size()) * opts.ports.size();
        targets.emplace_back(host, std::move(addresses));
    }
    if (status) {
        status->total_targets.store(total);
    }

    for (auto &target : targets) {
        const auto &host = target.first;
        const auto &addresses = target.second;
        auto reverse_map = reverse_dns_map(resolver, addresses, opts);

        std::unordered_map<std::string, std::vector<ScanResult>> results_by_addr;
        co_await run_scans(
            host, addresses, opts,
            [&](const ScanRecord &record) {
                if (status) {
                    status->completed_targets.fetch_add(1);
                }
                if (opts.output_format == OutputFormat::Json) {
                    if (!should_report(record.result, opts.open_only)) {
                        return;
                    }
                    emit_port_result(record, reverse_map, false, opts.mode, opts.output_format);
                    return;
                }
                const auto key = format_address(record.addr);
                results_by_addr[key].push_back(record.result);
            });
        if (opts.output_format == OutputFormat::Text) {
            for (const auto &addr : addresses) {
                const auto key = format_address(addr);
                auto it = results_by_addr.find(key);
                if (it == results_by_addr.end()) {
                    continue;
                }
                emit_scan_report(host, addr, it->second, reverse_map, opts.mode,
                                 opts.open_only);
            }
        }
        if (status) {
            status->completed_hosts.fetch_add(1);
        }
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
        
        if (opts.verbose && !message.empty()) {
            std::cerr << message << "\n";
        }

        if (status == SandboxStatus::Failed) {
            if (!message.empty()) {
                std::cerr << message << "\n";
            }

            return 1;
        }
    }

    asio::io_context io;
    ScanStatus status;
    const bool continuous = opts.ping_mode;

    asio::signal_set signals(io, SIGINT, SIGTERM
#ifdef SIGINFO
                             , SIGINFO
#endif
    );
    std::function<void()> arm_signals;
    arm_signals = [&]() {
        signals.async_wait([&](const boost::system::error_code &ec, int signo) {
            if (ec) {
                return;
            }
            if (signo == SIGINT || signo == SIGTERM) {
                std::cerr << "Stopping... " << format_status(status) << "\n";
                io.stop();
                return;
            }
#ifdef SIGINFO
            if (signo == SIGINFO) {
                std::cerr << format_status(status) << "\n";
            }
#endif
            arm_signals();
        });
    };
    arm_signals();

#if !defined(_WIN32)
    std::shared_ptr<asio::posix::stream_descriptor> input;
    input = std::make_shared<asio::posix::stream_descriptor>(io, ::dup(STDIN_FILENO));
    auto input_buf = std::make_shared<boost::asio::streambuf>();
    std::function<void()> arm_input;
    arm_input = [&, input, input_buf]() {
        asio::async_read_until(*input, *input_buf, '\n',
                               [&, input, input_buf](const boost::system::error_code &ec, std::size_t) {
                                   if (ec) {
                                       return;
                                   }
                                   input_buf->consume(input_buf->size());
                                   std::cerr << format_status(status) << "\n";
                                   arm_input();
                               });
    };
    arm_input();
#endif

#if !defined(_WIN32)
    auto stop_all = [&]() {
        signals.cancel();
        if (input) {
            boost::system::error_code ec;
            input->cancel(ec);
            input->close(ec);
        }
        io.stop();
    };
#else
    auto stop_all = [&]() {
        signals.cancel();
        io.stop();
    };
#endif

    if (opts.icmp_ping && opts.ping_mode) {
        co_spawn(
            io, icmp_ping_loop(hosts, opts, &status),
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
            io, icmp_scan_hosts(hosts, opts, nullptr, false, &status),
            [&, continuous](std::exception_ptr eptr) {
                if (eptr) {
                    try {
                        std::rethrow_exception(eptr);
                    } catch (const std::exception &e) {
                        log_exception("ICMP ping error", e);
                    }
                }
                if (!continuous) {
                    stop_all();
                }
            });
    } else if (opts.ping_mode) {
        co_spawn(
            io, ping_loop(hosts, opts, &status),
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
            io, run_port_scans(hosts, opts, &status),
            [&, continuous](std::exception_ptr eptr) {
                if (eptr) {
                    try {
                        std::rethrow_exception(eptr);
                    } catch (const std::exception &e) {
                        log_exception("Scan runner error", e);
                    }
                }
                if (!continuous) {
                    stop_all();
                }
            });
    }

    io.run();
    return 0;
}
