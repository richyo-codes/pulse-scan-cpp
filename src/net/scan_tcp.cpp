#include "net/scan_tcp.h"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <algorithm>

namespace asio = boost::asio;

using asio::awaitable;
using asio::co_spawn;
using asio::detached;
using asio::ip::tcp;
using asio::redirect_error;
using asio::steady_timer;
using asio::use_awaitable;

awaitable<ScanResult> scan_tcp_connect(const tcp::endpoint endpoint, const ScanOptions &opts) {
    auto executor = co_await asio::this_coro::executor;
    tcp::socket socket(executor);
    steady_timer timer(executor);
    timer.expires_after(opts.timeout);

    bool timed_out = false;
    boost::system::error_code connect_ec;

    // Cancel the socket if we hit the timeout.
    co_spawn(executor,
             [&socket, &timer, &timed_out]() -> awaitable<void> {
                 boost::system::error_code ec;
                 co_await timer.async_wait(redirect_error(use_awaitable, ec));
                 if (!ec) {
                     timed_out = true;
                     socket.cancel();
                 }
             },
             detached);

    co_await socket.async_connect(endpoint, redirect_error(use_awaitable, connect_ec));
    timer.cancel();

    ScanResult result;
    result.port = endpoint.port();
    if (!connect_ec && !timed_out) {
        result.state = "open";
        result.detail = "connect succeeded";
    } else if (timed_out || connect_ec == asio::error::operation_aborted) {
        result.state = "filtered/timeout";
        result.detail = "no response before deadline";
    } else if (connect_ec == asio::error::connection_refused) {
        result.state = "closed";
        result.detail = connect_ec.message();
    } else {
        result.state = "error";
        result.detail = connect_ec.message();
    }
    co_return result;
}

awaitable<ScanResult> scan_tcp_banner(const tcp::endpoint endpoint, const ScanOptions &opts) {
    auto executor = co_await asio::this_coro::executor;
    tcp::socket socket(executor);
    steady_timer timer(executor);
    timer.expires_after(opts.timeout);

    bool timed_out = false;
    boost::system::error_code connect_ec;

    co_spawn(executor,
             [&socket, &timer, &timed_out]() -> awaitable<void> {
                 boost::system::error_code ec;
                 co_await timer.async_wait(redirect_error(use_awaitable, ec));
                 if (!ec) {
                     timed_out = true;
                     socket.cancel();
                 }
             },
             detached);

    co_await socket.async_connect(endpoint, redirect_error(use_awaitable, connect_ec));
    timer.cancel();

    ScanResult result;
    result.port = endpoint.port();
    if (connect_ec || timed_out) {
        if (timed_out || connect_ec == asio::error::operation_aborted) {
            result.state = "filtered/timeout";
            result.detail = "no response before deadline";
        } else if (connect_ec == asio::error::connection_refused) {
            result.state = "closed";
            result.detail = connect_ec.message();
        } else {
            result.state = "error";
            result.detail = connect_ec.message();
        }
        co_return result;
    }

    // Connected: try to read a small banner with a shorter timer.
    steady_timer banner_timer(executor);
    banner_timer.expires_after(opts.banner_timeout);
    bool banner_timeout = false;
    co_spawn(executor,
             [&socket, &banner_timer, &banner_timeout]() -> awaitable<void> {
                 boost::system::error_code ec;
                 co_await banner_timer.async_wait(redirect_error(use_awaitable, ec));
                 if (!ec) {
                     banner_timeout = true;
                     socket.cancel();
                 }
             },
             detached);

    std::array<char, 512> buf{};
    boost::system::error_code read_ec;
    auto n = co_await socket.async_read_some(
        asio::buffer(buf.data(), std::min(buf.size(), opts.banner_bytes)),
        redirect_error(use_awaitable, read_ec));
    banner_timer.cancel();

    result.state = "open";
    if (!read_ec && n > 0) {
        std::string banner(buf.data(), buf.data() + n);
        result.detail = "banner: " + banner;
    } else if (banner_timeout || read_ec == asio::error::operation_aborted) {
        result.detail = "no banner before deadline";
    } else if (read_ec) {
        result.detail = "read error: " + read_ec.message();
    } else {
        result.detail = "no banner data";
    }
    co_return result;
}
