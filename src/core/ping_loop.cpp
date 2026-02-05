#include "core/ping_loop.h"

#include "core/logging.h"
#include "core/output.h"
#include "core/status.h"
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

boost::asio::awaitable<void> ping_loop(const std::vector<std::string> &hosts, ScanOptions opts,
                                       ScanStatus *status) {
    auto executor = co_await asio::this_coro::executor;
    asio::io_context &io = static_cast<asio::io_context &>(executor.context());
    asio::ip::tcp::resolver resolver(io);

    std::unordered_map<std::string, std::pair<std::string, std::string>> last_state;
    bool first_pass = true;

    steady_timer timer(executor);

    if (status) {
        status->total_hosts.store(hosts.size());
    }

    for (;;) {
        log_trace("ping cycle start", opts.verbose);
        if (status) {
            status->cycles.fetch_add(1);
            status->completed_targets.store(0);
            status->completed_hosts.store(0);
        }
        std::unordered_set<std::string> current_keys;
        std::vector<std::pair<std::string, std::vector<asio::ip::address>>> targets;
        targets.reserve(hosts.size());
        std::uint64_t cycle_total = 0;
        for (const auto &host : hosts) {
            bool used_range = false;
            auto addresses = resolve_or_expand(host, resolver, opts, used_range);
            if (addresses.empty()) {
                if (used_range) {
                    std::cerr << "No addresses after IP filter for host " << host << "\n";
                }
                continue;
            }
            cycle_total += static_cast<std::uint64_t>(addresses.size()) * opts.ports.size();
            targets.emplace_back(host, std::move(addresses));
        }
        if (status) {
            status->total_targets.store(cycle_total);
        }

        for (auto &target : targets) {
            const auto &host = target.first;
            const auto &addresses = target.second;
            auto reverse_map = reverse_dns_map(resolver, addresses, opts);

            co_await run_scans(
                host, addresses, opts, [&](const ScanRecord &record) {
                    if (status) {
                        status->completed_targets.fetch_add(1);
                    }
                    const auto key = record.host + "|" + format_address(record.addr) + ":" +
                                     std::to_string(record.result.port);
                    current_keys.insert(key);
                    const auto current = std::make_pair(record.result.state, record.result.detail);
                    auto it = last_state.find(key);
                    if (first_pass || it == last_state.end() || it->second != current) {
                        if (should_report(record.result, opts.open_only)) {
                            emit_port_result(record, reverse_map, !first_pass, opts.mode,
                                             opts.output_format);
                        }
                        last_state[key] = current;
                    }
                });
            if (status) {
                status->completed_hosts.fetch_add(1);
            }
        }

        if (!first_pass) {
            for (auto it = last_state.begin(); it != last_state.end();) {
                if (current_keys.find(it->first) == current_keys.end()) {
                    if (!opts.open_only) {
                        emit_unavailable(it->first, true, opts.mode, opts.output_format);
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
