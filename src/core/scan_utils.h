#pragma once

#include <boost/asio/ip/address.hpp>

#include <string>

inline std::string format_address(const boost::asio::ip::address &addr) {
    try {
        return addr.to_string();
    } catch (const std::exception &) {
        return "<invalid>";
    }
}
