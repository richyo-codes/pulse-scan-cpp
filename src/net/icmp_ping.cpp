#include "net/icmp_ping.h"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ip/icmp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "net/icmp_packet.h"

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>
#include <unistd.h>
#include <vector>

namespace asio = boost::asio;

using asio::awaitable;
using asio::co_spawn;
using asio::detached;
using asio::ip::icmp;
using asio::redirect_error;
using asio::steady_timer;
using asio::use_awaitable;

namespace {

std::string permission_hint() {
    return "ICMP requires root or CAP_NET_RAW (try: sudo setcap cap_net_raw+ep ./pulsescan-cpp)";
}

void write_u16(std::vector<std::uint8_t> &buf, std::size_t offset, std::uint16_t value) {
    buf[offset] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
    buf[offset + 1] = static_cast<std::uint8_t>(value & 0xFF);
}

std::uint16_t checksum_v6(const asio::ip::address_v6 &src, const asio::ip::address_v6 &dst,
                          const std::uint8_t *payload, std::size_t length) {
    std::vector<std::uint8_t> pseudo;
    pseudo.reserve(40 + length);

    auto src_bytes = src.to_bytes();
    auto dst_bytes = dst.to_bytes();
    pseudo.insert(pseudo.end(), src_bytes.begin(), src_bytes.end());
    pseudo.insert(pseudo.end(), dst_bytes.begin(), dst_bytes.end());

    std::uint32_t len = htonl(static_cast<std::uint32_t>(length));
    pseudo.push_back(static_cast<std::uint8_t>((len >> 24) & 0xFF));
    pseudo.push_back(static_cast<std::uint8_t>((len >> 16) & 0xFF));
    pseudo.push_back(static_cast<std::uint8_t>((len >> 8) & 0xFF));
    pseudo.push_back(static_cast<std::uint8_t>(len & 0xFF));

    pseudo.push_back(0);
    pseudo.push_back(0);
    pseudo.push_back(0);
    pseudo.push_back(58); // Next header: ICMPv6

    pseudo.insert(pseudo.end(), payload, payload + length);
    return compute_checksum(pseudo.data(), pseudo.size());
}

} // namespace

awaitable<IcmpResult> icmp_ping_once(const asio::ip::address &addr, const ScanOptions &opts) {
    auto executor = co_await asio::this_coro::executor;
    icmp::socket socket(executor);

    boost::system::error_code open_ec;
    if (addr.is_v4()) {
        socket.open(icmp::v4(), open_ec);
    } else if (addr.is_v6()) {
        socket.open(icmp::v6(), open_ec);
    } else {
        co_return IcmpResult{"error", "invalid address type"};
    }

    if (open_ec) {
        if (open_ec.value() == EPERM || open_ec.value() == EACCES) {
            co_return IcmpResult{"error", permission_hint()};
        }
        co_return IcmpResult{"error", "socket open failed: " + open_ec.message()};
    }

    const std::string body = "pulsescan-cpp";
    std::vector<std::uint8_t> packet(8 + body.size());
    packet[0] = addr.is_v6() ? 128 : 8;
    packet[1] = 0;
    write_u16(packet, 2, 0);
    const std::uint16_t identifier = static_cast<std::uint16_t>(::getpid() & 0xFFFF);
    static std::uint16_t sequence = 0;
    const std::uint16_t seq = ++sequence;
    write_u16(packet, 4, htons(identifier));
    write_u16(packet, 6, htons(seq));
    std::memcpy(packet.data() + 8, body.data(), body.size());

    if (addr.is_v4()) {
        const std::uint16_t checksum = compute_checksum(packet.data(), packet.size());
        write_u16(packet, 2, checksum);
    } else {
        boost::system::error_code connect_ec;
        socket.connect(icmp::endpoint(addr, 0), connect_ec);
        if (connect_ec) {
            co_return IcmpResult{"error", "connect failed: " + connect_ec.message()};
        }
        const auto local = socket.local_endpoint();
        const auto checksum = checksum_v6(local.address().to_v6(), addr.to_v6(),
                                          packet.data(), packet.size());
        write_u16(packet, 2, checksum);
    }

    icmp::endpoint destination(addr, 0);
    boost::system::error_code send_ec;
    co_await socket.async_send_to(asio::buffer(packet), destination,
                                  redirect_error(use_awaitable, send_ec));
    if (send_ec) {
        co_return IcmpResult{"error", "send failed: " + send_ec.message()};
    }

    steady_timer timer(executor);
    timer.expires_after(opts.timeout);
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

    std::array<std::uint8_t, 1024> reply{};
    icmp::endpoint sender;
    for (;;) {
        boost::system::error_code recv_ec;
        const auto n = co_await socket.async_receive_from(
            asio::buffer(reply), sender, redirect_error(use_awaitable, recv_ec));

        if (timed_out || recv_ec == asio::error::operation_aborted) {
            co_return IcmpResult{"down", "timeout"};
        }
        if (recv_ec) {
            co_return IcmpResult{"error", "receive failed: " + recv_ec.message()};
        }

        bool ok = false;
        if (addr.is_v4()) {
            ok = parse_v4_echo_reply(reply.data(), n, identifier, seq);
        } else {
            ok = parse_v6_echo_reply(reply.data(), n, identifier, seq);
        }

        if (ok) {
            timer.cancel();
            co_return IcmpResult{"up", "echo reply"};
        }
        // Ignore unrelated ICMP and keep waiting until timeout.
    }
}
