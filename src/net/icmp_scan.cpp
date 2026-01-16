#include "net/icmp_scan.h"

#include "core/logging.h"
#include "core/resolve.h"
#include "core/scan_utils.h"
#include "net/icmp_ping.h"

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <iostream>
#include <string>
#include <unordered_set>

namespace asio = boost::asio;

using asio::steady_timer;
using asio::use_awaitable;

boost::asio::awaitable<void> icmp_scan_hosts(const std::vector<std::string> &hosts,
                                             ScanOptions opts,
                                             IcmpStateMap *last_state,
                                             bool changes_only) {
    auto executor = co_await asio::this_coro::executor;
    asio::io_context &io = static_cast<asio::io_context &>(executor.context());
    asio::ip::tcp::resolver resolver(io);

    std::unordered_set<std::string> current_keys;
    const bool first_pass = !last_state || last_state->empty();

    for (const auto &host : hosts) {
        bool used_range = false;
        auto addresses = resolve_or_expand(host, resolver, opts, used_range);
        if (addresses.empty()) {
            if (used_range) {
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

boost::asio::awaitable<void> icmp_ping_loop(const std::vector<std::string> &hosts,
                                            ScanOptions opts) {
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
