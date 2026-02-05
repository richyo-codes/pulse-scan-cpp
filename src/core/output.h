#pragma once

#include "core/options.h"

#include <boost/asio/ip/address.hpp>

#include <string>
#include <unordered_map>
#include <vector>

struct ScanRecord;
struct ScanResult;
struct IcmpResult;

bool should_report(const ScanResult &result, bool open_only);
std::string format_address_with_reverse(
    const boost::asio::ip::address &addr,
    const std::unordered_map<std::string, std::string> &reverse_map);
std::string service_name_for_port(int port, ScanMode mode);
std::string reverse_dns_for(
    const boost::asio::ip::address &addr,
    const std::unordered_map<std::string, std::string> &reverse_map);

void emit_scan_report(const std::string &host,
                      const boost::asio::ip::address &addr,
                      const std::vector<ScanResult> &results,
                      const std::unordered_map<std::string, std::string> &reverse_map,
                      ScanMode mode,
                      bool open_only);

void emit_port_result(const ScanRecord &record,
                      const std::unordered_map<std::string, std::string> &reverse_map,
                      bool is_change,
                      ScanMode mode,
                      OutputFormat format);
void emit_icmp_result(const std::string &host,
                      const boost::asio::ip::address &addr,
                      const IcmpResult &result,
                      const std::unordered_map<std::string, std::string> &reverse_map,
                      bool is_change,
                      OutputFormat format);
void emit_unavailable(const std::string &key,
                      bool is_change,
                      const std::string &mode,
                      OutputFormat format);
void emit_unavailable(const std::string &key,
                      bool is_change,
                      ScanMode mode,
                      OutputFormat format);
