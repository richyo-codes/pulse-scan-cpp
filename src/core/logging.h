#pragma once

#include <boost/asio/ip/tcp.hpp>
#include <boost/system/error_code.hpp>

#include <string>

void log_exception(const char *context, const std::exception &e);
void log_trace(const std::string &message, bool enabled);
void log_dns_results(const std::string &host,
                     const boost::asio::ip::tcp::resolver::results_type &results,
                     const boost::system::error_code &ec,
                     bool enabled);
