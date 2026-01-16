#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include "core/cli.h"
#include "net/icmp_ping.h"
#include "core/logging.h"
#include "core/resolve.h"
#include "core/scan_runner.h"
#include "core/scan_utils.h"
#include "platform/sandbox.h"

#include <algorithm>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace asio = boost::asio;

using asio::awaitable;
using asio::co_spawn;
using asio::detached;
using asio::ip::tcp;
using asio::ip::udp;
using asio::redirect_error;
using asio::steady_timer;
using asio::use_awaitable;

using IcmpStateMap = std::unordered_map<std::string, std::pair<std::string, std::string>>;

bool should_report(const ScanResult &result, bool open_only) {
    if (!open_only) {
        return true;
    }
    return result.state == "open";
}

awaitable<void> ping_loop(const std::vector<std::string> &hosts, ScanOptions opts) {
    auto executor = co_await asio::this_coro::executor;
    asio::io_context &io = static_cast<asio::io_context &>(executor.context());
    tcp::resolver resolver(io);

    std::unordered_map<std::string, std::pair<std::string, std::string>> last_state;
    bool first_pass = true;

    steady_timer timer(executor);

    for (;;) {
        log_trace("ping cycle start", opts.verbose);
        std::unordered_set<std::string> current_keys;
        for (const auto &host : hosts) {
            boost::system::error_code ec;
            log_trace("resolve host=" + host, opts.verbose);
            auto resolved = resolver.resolve(host, "", ec);
            log_dns_results(host, resolved, ec, opts.debug_dns);
            if (ec || resolved.empty()) {
                std::cerr << "Failed to resolve host " << host << ": "
                          << (ec ? ec.message() : "no results") << "\n";
                continue;
            }

            std::vector<asio::ip::address> addresses;
            for (const auto &entry : resolved) {
                const auto addr = entry.endpoint().address();
                if (opts.ipv4_only && !addr.is_v4()) {
                    continue;
                }
                if (opts.ipv6_only && !addr.is_v6()) {
                    continue;
                }
                addresses.push_back(addr);
            }
            if (addresses.empty()) {
                std::cerr << "No addresses after IP filter for host " << host << "\n";
                continue;
            }

            co_await run_scans(
                host, addresses, opts, [&](const ScanRecord &record) {
                    const auto key = record.host + "|" + format_address(record.addr) + ":" +
                                     std::to_string(record.result.port);
                    current_keys.insert(key);
                    const auto current = std::make_pair(record.result.state, record.result.detail);
                    auto it = last_state.find(key);
                    if (first_pass || it == last_state.end() || it->second != current) {
                        if (should_report(record.result, opts.open_only)) {
                            const char *prefix = first_pass ? "" : "CHANGE ";
                            std::cout << prefix << record.host << " "
                                      << format_address(record.addr) << ":"
                                      << record.result.port << " -> " << record.result.state
                                      << " (" << record.result.detail << ")\n";
                        }
                        last_state[key] = current;
                    }
                });
        }

        if (!first_pass) {
            for (auto it = last_state.begin(); it != last_state.end();) {
                if (current_keys.find(it->first) == current_keys.end()) {
                    if (!opts.open_only) {
                        std::cout << "CHANGE " << it->first
                                  << " -> unavailable (no longer resolved)\n";
                    }
                    it = last_state.erase(it);
                } else {
                    ++it;
                }
            }
        }
        first_pass = false;

        log_trace("ping cycle end", opts.verbose);
        timer.expires_after(opts.ping_interval);
        co_await timer.async_wait(use_awaitable);
    }
}

awaitable<void> icmp_scan_hosts(const std::vector<std::string> &hosts, ScanOptions opts,
                                IcmpStateMap *last_state, bool changes_only) {
    auto executor = co_await asio::this_coro::executor;
    asio::io_context &io = static_cast<asio::io_context &>(executor.context());
    tcp::resolver resolver(io);

    std::unordered_set<std::string> current_keys;
    const bool first_pass = !last_state || last_state->empty();

        for (const auto &host : hosts) {
            bool used_cidr = false;
            auto addresses = resolve_or_expand(host, resolver, opts, used_cidr);
            if (addresses.empty()) {
                if (used_cidr) {
                    std::cerr << "No addresses after IP filter for host " << host << "\n";
                }
                continue;
            }

            for (const auto &addr : addresses) {
                IcmpResult final_result{"down", "timeout"};
                bool permission_error = false;
                for (int i = 0; i < opts.icmp_count; ++i) {
                    auto result = co_await icmp_ping_once(addr, opts);
                    if (result.state == "up") {
                        final_result = result;
                        break;
                    }
                    if (result.state == "error") {
                        if (result.detail.find("ICMP requires") != std::string::npos) {
                            std::cerr << result.detail << "\n";
                            permission_error = true;
                            break;
                        }
                        final_result = result;
                    } else {
                        final_result = result;
                    }
                }
                if (permission_error) {
                    co_return;
                }

                auto result = final_result;
                if (opts.icmp_count > 1 && result.state == "down") {
                    result.detail = "timeout (" + std::to_string(opts.icmp_count) + "x)";
                }
                const auto key = host + "|" + format_address(addr);
                current_keys.insert(key);
                const auto current = std::make_pair(result.state, result.detail);

            if (last_state) {
                auto it = last_state->find(key);
                if (first_pass || it == last_state->end() || it->second != current) {
                    if (!opts.open_only || result.state == "up") {
                        const char *prefix = (changes_only && !first_pass) ? "CHANGE " : "";
                        std::cout << prefix << host << " " << format_address(addr)
                                  << " -> " << result.state << " (" << result.detail << ")\n";
                    }
                    (*last_state)[key] = current;
                }
            } else {
                if (!opts.open_only || result.state == "up") {
                    std::cout << host << " " << format_address(addr) << " -> "
                              << result.state << " (" << result.detail << ")\n";
                }
            }
        }
    }

    if (last_state && !first_pass) {
        for (auto it = last_state->begin(); it != last_state->end();) {
            if (current_keys.find(it->first) == current_keys.end()) {
                if (!opts.open_only) {
                    std::cout << "CHANGE " << it->first
                              << " -> unavailable (no longer resolved)\n";
                }
                it = last_state->erase(it);
            } else {
                ++it;
            }
        }
    }

    co_return;
}

awaitable<void> icmp_ping_loop(const std::vector<std::string> &hosts, ScanOptions opts) {
    steady_timer timer(co_await asio::this_coro::executor);
    IcmpStateMap last_state;

    for (;;) {
        log_trace("icmp ping cycle start", opts.verbose);
        co_await icmp_scan_hosts(hosts, opts, &last_state, true);
        log_trace("icmp ping cycle end", opts.verbose);
        timer.expires_after(opts.ping_interval);
        co_await timer.async_wait(use_awaitable);
    }
}

int main(int argc, char **argv) {
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
        tcp::resolver resolver(io);
        co_spawn(io,
                 [&]() -> awaitable<void> {
                     for (const auto &host : hosts) {
            bool used_cidr = false;
            auto addresses = resolve_or_expand(host, resolver, opts, used_cidr);
            if (addresses.empty()) {
                if (used_cidr) {
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
                 }(),
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
