#include "core/ping_loop.h"

#include "core/logging.h"
#include "core/output.h"
#include "core/resolve.h"
#include "core/scan_runner.h"
#include "core/scan_utils.h"

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <iostream>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace asio = boost::asio;

using asio::steady_timer;
using asio::use_awaitable;

boost::asio::awaitable<void> ping_loop(const std::vector<std::string> &hosts, ScanOptions opts) {
    auto executor = co_await asio::this_coro::executor;
    asio::io_context &io = static_cast<asio::io_context &>(executor.context());
    asio::ip::tcp::resolver resolver(io);

    std::unordered_map<std::string, std::pair<std::string, std::string>> last_state;
    bool first_pass = true;

    steady_timer timer(executor);

    for (;;) {
        log_trace("ping cycle start", opts.verbose);
        std::unordered_set<std::string> current_keys;
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
