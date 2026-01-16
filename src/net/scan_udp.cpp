#include "net/scan_udp.h"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>

namespace asio = boost::asio;

using asio::awaitable;
using asio::co_spawn;
using asio::detached;
using asio::ip::udp;
using asio::redirect_error;
using asio::steady_timer;
using asio::use_awaitable;

awaitable<ScanResult> scan_udp(const udp::endpoint endpoint, const ScanOptions &opts) {
    auto executor = co_await asio::this_coro::executor;
    udp::socket socket(executor);
    steady_timer timer(executor);
    timer.expires_after(opts.timeout);

    boost::system::error_code open_ec;
    socket.open(endpoint.protocol(), open_ec);
    ScanResult result;
    result.port = endpoint.port();
    if (open_ec) {
        result.state = "error";
        result.detail = "open failed: " + open_ec.message();
        co_return result;
    }

    bool timed_out = false;
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

    // Fire an empty datagram; some services respond with a banner or echo.
    boost::system::error_code send_ec;
    std::array<char, 1> payload{{0}};
    co_await socket.async_send_to(asio::buffer(payload), endpoint,
                                  redirect_error(use_awaitable, send_ec));
    if (send_ec) {
        timer.cancel();
        result.state = "error";
        result.detail = "send failed: " + send_ec.message();
        co_return result;
    }

    std::array<char, 512> buf{};
    udp::endpoint sender;
    boost::system::error_code recv_ec;
    auto n = co_await socket.async_receive_from(asio::buffer(buf), sender,
                                                redirect_error(use_awaitable, recv_ec));
    timer.cancel();

    if (!recv_ec && n > 0) {
        result.state = "open";
        result.detail = "received " + std::to_string(n) + " bytes";
    } else if (timed_out || recv_ec == asio::error::operation_aborted) {
        result.state = "open|filtered";
        result.detail = "no response before deadline";
    } else if (recv_ec == asio::error::connection_refused ||
               recv_ec == asio::error::connection_reset) {
        result.state = "closed";
        result.detail = recv_ec.message();
    } else {
        result.state = "error";
        result.detail = recv_ec.message();
    }
    co_return result;
}
