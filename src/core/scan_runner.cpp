#include "core/scan_runner.h"

#include "core/logging.h"
#include "net/scan_tcp.h"
#include "net/scan_udp.h"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <queue>

namespace asio = boost::asio;

using asio::awaitable;
using asio::co_spawn;
using asio::detached;
using asio::ip::tcp;
using asio::ip::udp;
using asio::redirect_error;
using asio::steady_timer;
using asio::use_awaitable;

namespace {

bool should_report(const ScanResult &result, bool open_only) {
    if (!open_only) {
        return true;
    }
    return result.state == "open";
}

void safe_on_result(const ScanCallback &on_result, const ScanRecord &record) {
    try {
        on_result(record);
    } catch (const std::exception &e) {
        log_exception("Result handler error", e);
    }
}

awaitable<ScanResult> scan_one(int port, asio::ip::address addr, const ScanOptions &opts) {
    if (!addr.is_v4() && !addr.is_v6()) {
        ScanResult result;
        result.port = port;
        result.state = "error";
        result.detail = "invalid address type";
        co_return result;
    }

    switch (opts.mode) {
    case ScanMode::TcpConnect:
        co_return co_await scan_tcp_connect(tcp::endpoint(addr, static_cast<unsigned short>(port)),
                                            opts);
    case ScanMode::TcpBanner:
        co_return co_await scan_tcp_banner(tcp::endpoint(addr, static_cast<unsigned short>(port)),
                                           opts);
    case ScanMode::Udp:
        co_return co_await scan_udp(udp::endpoint(addr, static_cast<unsigned short>(port)), opts);
    }
    co_return ScanResult{port, "error", "unsupported mode"};
}

} // namespace

awaitable<void> run_scans(const std::string &host,
                          const std::vector<asio::ip::address> &addresses,
                          ScanOptions opts,
                          const ScanCallback &on_result) {
    if (addresses.empty()) {
        co_return;
    }
    log_trace("scan start host=" + host + " ports=" + std::to_string(opts.ports.size()),
              opts.verbose);
    auto executor = co_await asio::this_coro::executor;
    std::queue<std::pair<asio::ip::address, int>> remaining_targets;
    for (const auto &addr : addresses) {
        for (int p : opts.ports) {
            remaining_targets.emplace(addr, p);
        }
    }

    steady_timer done_timer(executor);
    done_timer.expires_at(steady_timer::time_point::max());

    std::size_t inflight = 0;

    std::function<void()> launch_next = [&]() {
        while (inflight < opts.max_inflight && !remaining_targets.empty()) {
            auto target = remaining_targets.front();
            remaining_targets.pop();
            ++inflight;
            const auto addr = target.first;
            const int port = target.second;

            co_spawn(
                executor,
                [&, addr, port]() -> awaitable<void> {
                    try {
                        auto res = co_await scan_one(port, addr, opts);
                        safe_on_result(on_result, {host, addr, res});
                    } catch (const std::exception &e) {
                        ScanResult res;
                        res.port = port;
                        res.state = "error";
                        res.detail = e.what();
                        log_exception("Scan error", e);
                        safe_on_result(on_result, {host, addr, res});
                    }
                    --inflight;
                    launch_next();
                    if (remaining_targets.empty() && inflight == 0) {
                        done_timer.cancel();
                    }
                },
                [=](std::exception_ptr eptr) {
                    if (!eptr) {
                        return;
                    }
                    try {
                        std::rethrow_exception(eptr);
                    } catch (const std::exception &e) {
                        log_exception("Scan coroutine error", e);
                    }
                });
        }
    };

    launch_next();

    boost::system::error_code ec;
    co_await done_timer.async_wait(redirect_error(use_awaitable, ec));
    log_trace("scan done host=" + host, opts.verbose);
    co_return;
}
