#include "core/output.h"
#include "core/scan_utils.h"
#include "core/scan_runner.h"
#include "net/icmp_ping.h"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <unordered_map>

bool should_report(const ScanResult &result, bool open_only) {
    if (!open_only) {
        return true;
    }
    return result.state == "open";
}

std::string reverse_dns_for(
    const boost::asio::ip::address &addr,
    const std::unordered_map<std::string, std::string> &reverse_map) {
    const auto base = format_address(addr);
    auto it = reverse_map.find(base);
    if (it == reverse_map.end()) {
        return "";
    }
    return it->second;
}

std::string format_address_with_reverse(
    const boost::asio::ip::address &addr,
    const std::unordered_map<std::string, std::string> &reverse_map) {
    const auto base = format_address(addr);
    const auto reverse = reverse_dns_for(addr, reverse_map);
    if (reverse.empty()) {
        return base;
    }
    return base + " (" + reverse + ")";
}

namespace {

std::string mode_label(ScanMode mode) {
    switch (mode) {
        case ScanMode::TcpConnect:
            return "connect";
        case ScanMode::TcpBanner:
            return "banner";
        case ScanMode::Udp:
            return "udp";
    }
    return "unknown";
}

std::string json_escape(const std::string &value) {
    std::ostringstream out;
    for (unsigned char c : value) {
        switch (c) {
            case '\"':
                out << "\\\"";
                break;
            case '\\':
                out << "\\\\";
                break;
            case '\b':
                out << "\\b";
                break;
            case '\f':
                out << "\\f";
                break;
            case '\n':
                out << "\\n";
                break;
            case '\r':
                out << "\\r";
                break;
            case '\t':
                out << "\\t";
                break;
            default:
                if (c < 0x20) {
                    out << "\\u"
                        << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<int>(c)
                        << std::dec;
                } else {
                    out << c;
                }
        }
    }
    return out.str();
}

struct ParsedKey {
    std::string host;
    std::string address;
    int port = 0;
};

std::optional<ParsedKey> parse_key(const std::string &key) {
    auto pipe = key.find('|');
    if (pipe == std::string::npos) {
        return std::nullopt;
    }
    auto rest = key.substr(pipe + 1);
    auto colon = rest.rfind(':');
    if (colon == std::string::npos) {
        return std::nullopt;
    }
    ParsedKey parsed;
    parsed.host = key.substr(0, pipe);
    parsed.address = rest.substr(0, colon);
    try {
        parsed.port = std::stoi(rest.substr(colon + 1));
    } catch (...) {
        return std::nullopt;
    }
    return parsed;
}

} // namespace

std::string service_name_for_port(int port, ScanMode mode) {
    static const std::unordered_map<int, std::string> kTcpServices = {
        {20, "ftp-data"},
        {21, "ftp"},
        {22, "ssh"},
        {23, "telnet"},
        {25, "smtp"},
        {53, "domain"},
        {80, "http"},
        {81, "http-alt"},
        {88, "kerberos"},
        {110, "pop3"},
        {111, "rpcbind"},
        {135, "msrpc"},
        {139, "netbios-ssn"},
        {143, "imap"},
        {389, "ldap"},
        {443, "https"},
        {445, "microsoft-ds"},
        {465, "smtps"},
        {587, "submission"},
        {631, "ipp"},
        {873, "rsync"},
        {993, "imaps"},
        {995, "pop3s"},
        {1433, "ms-sql"},
        {2049, "nfs"},
        {3306, "mysql"},
        {3389, "ms-wbt-server"},
        {5432, "postgresql"},
        {5672, "amqp"},
        {5900, "vnc"},
        {6379, "redis"},
        {8080, "http-alt"},
        {8443, "https-alt"},
        {9092, "kafka"},
        {9200, "elasticsearch"},
        {9300, "elasticsearch"},
        {11211, "memcache"},
        {27017, "mongodb"}
    };
    static const std::unordered_map<int, std::string> kUdpServices = {
        {53, "domain"},
        {67, "dhcp"},
        {68, "dhcp"},
        {69, "tftp"},
        {123, "ntp"},
        {161, "snmp"},
        {500, "isakmp"},
        {1900, "ssdp"},
        {5353, "mdns"}
    };
    const auto &table = (mode == ScanMode::Udp) ? kUdpServices : kTcpServices;
    auto it = table.find(port);
    if (it != table.end()) {
        return it->second;
    }
    return "unknown";
}

void emit_scan_report(const std::string &host,
                      const boost::asio::ip::address &addr,
                      const std::vector<ScanResult> &results,
                      const std::unordered_map<std::string, std::string> &reverse_map,
                      ScanMode mode,
                      bool open_only) {
    const auto address = format_address(addr);
    std::string report_header = "Scan report for " + host;
    if (host != address) {
        report_header += " (" + address + ")";
    } else {
        const auto reverse = reverse_dns_for(addr, reverse_map);
        if (!reverse.empty()) {
            report_header += " (" + reverse + ")";
        }
    }
    std::cout << report_header << "\n";
    std::cout << "Host is up.\n";


    std::vector<ScanResult> sorted = results;
    std::sort(sorted.begin(), sorted.end(),
              [](const ScanResult &a, const ScanResult &b) { return a.port < b.port; });

    std::size_t closed = 0;
    std::size_t filtered = 0;
    std::size_t errors = 0;
    std::size_t open = 0;
    for (const auto &result : sorted) {
        if (result.state == "open") {
            open++;
        } else if (result.state == "closed") {
            closed++;
        } else if (result.state == "filtered/timeout" || result.state == "open|filtered") {
            filtered++;
        } else {
            errors++;
        }
    }

    if (!open_only) {
        if (closed > 0) {
            std::cout << "Not shown: " << closed
                      << " closed " << (mode == ScanMode::Udp ? "udp" : "tcp")
                      << " ports (conn-refused)\n";
        }
        if (filtered > 0) {
            std::cout << "Not shown: " << filtered
                      << " filtered " << (mode == ScanMode::Udp ? "udp" : "tcp")
                      << " ports (no-response)\n";
        }
        if (errors > 0) {
            std::cout << "Not shown: " << errors
                      << " error " << (mode == ScanMode::Udp ? "udp" : "tcp")
                      << " ports (io-error)\n";
        }
    }

    std::vector<ScanResult> display;
    display.reserve(sorted.size());
    for (const auto &result : sorted) {
        if (!open_only || result.state == "open") {
            display.push_back(result);
        }
    }

    if (display.empty()) {
        if (!open_only && !sorted.empty()) {
            std::cout << "All " << sorted.size()
                      << " scanned " << (mode == ScanMode::Udp ? "udp" : "tcp")
                      << " ports on " << address << " are "
                      << (closed == sorted.size() ? "closed" : "filtered") << ".\n";
        }
        std::cout << "\n";
        return;
    }

    const bool show_detail = (mode == ScanMode::TcpBanner);
    const int port_width = 9;
    const int state_width = 14;
    const int service_width = 12;
    std::ostringstream header_line;
    header_line << std::left << std::setw(port_width) << "PORT"
                << std::left << std::setw(state_width) << "STATE"
                << std::left << std::setw(service_width) << "SERVICE";
    if (show_detail) {
        header_line << "DETAIL";
    }
    std::cout << header_line.str() << "\n";
    for (const auto &result : display) {
        std::ostringstream port_label;
        port_label << result.port << "/" << (mode == ScanMode::Udp ? "udp" : "tcp");
        std::ostringstream line;
        line << std::left << std::setw(port_width) << port_label.str()
             << std::left << std::setw(state_width) << result.state
             << std::left << std::setw(service_width)
             << service_name_for_port(result.port, mode);
        if (show_detail) {
            std::string detail = result.detail;
            std::replace(detail.begin(), detail.end(), '\n', ' ');
            std::replace(detail.begin(), detail.end(), '\r', ' ');
            std::replace(detail.begin(), detail.end(), '\t', ' ');
            if (detail.size() > 100) {
                detail = detail.substr(0, 97) + "...";
            }
            line << detail;
        }
        std::cout << line.str() << "\n";
    }
    std::cout << "\n";
}

void emit_port_result(const ScanRecord &record,
                      const std::unordered_map<std::string, std::string> &reverse_map,
                      bool is_change,
                      ScanMode mode,
                      OutputFormat format) {
    if (format == OutputFormat::Text) {
        const char *prefix = is_change ? "CHANGE " : "";
        std::cout << prefix << record.host << " "
                  << format_address_with_reverse(record.addr, reverse_map) << ":"
                  << record.result.port << " -> " << record.result.state << " ("
                  << record.result.detail << ")\n";
        return;
    }

    const auto address = format_address(record.addr);
    const auto reverse = reverse_dns_for(record.addr, reverse_map);
    std::ostringstream out;
    out << "{"
        << "\"event\":\"result\""
        << ",\"change\":" << (is_change ? "true" : "false")
        << ",\"mode\":\"" << json_escape(mode_label(mode)) << "\""
        << ",\"host\":\"" << json_escape(record.host) << "\""
        << ",\"address\":\"" << json_escape(address) << "\""
        << ",\"reverse_dns\":\"" << json_escape(reverse) << "\""
        << ",\"port\":" << record.result.port
        << ",\"state\":\"" << json_escape(record.result.state) << "\""
        << ",\"detail\":\"" << json_escape(record.result.detail) << "\""
        << "}\n";
    std::cout << out.str();
}

void emit_icmp_result(const std::string &host,
                      const boost::asio::ip::address &addr,
                      const IcmpResult &result,
                      const std::unordered_map<std::string, std::string> &reverse_map,
                      bool is_change,
                      OutputFormat format) {
    if (format == OutputFormat::Text) {
        const char *prefix = is_change ? "CHANGE " : "";
        std::cout << prefix << host << " " << format_address_with_reverse(addr, reverse_map)
                  << " -> " << result.state << " (" << result.detail << ")\n";
        return;
    }

    const auto address = format_address(addr);
    const auto reverse = reverse_dns_for(addr, reverse_map);
    std::ostringstream out;
    out << "{"
        << "\"event\":\"result\""
        << ",\"change\":" << (is_change ? "true" : "false")
        << ",\"mode\":\"icmp\""
        << ",\"host\":\"" << json_escape(host) << "\""
        << ",\"address\":\"" << json_escape(address) << "\""
        << ",\"reverse_dns\":\"" << json_escape(reverse) << "\""
        << ",\"port\":null"
        << ",\"state\":\"" << json_escape(result.state) << "\""
        << ",\"detail\":\"" << json_escape(result.detail) << "\""
        << "}\n";
    std::cout << out.str();
}

void emit_unavailable(const std::string &key,
                      bool is_change,
                      const std::string &mode,
                      OutputFormat format) {
    if (format == OutputFormat::Text) {
        const char *prefix = is_change ? "CHANGE " : "";
        std::cout << prefix << key << " -> unavailable (no longer resolved)\n";
        return;
    }

    auto parsed = parse_key(key);
    std::ostringstream out;
    out << "{"
        << "\"event\":\"unavailable\""
        << ",\"change\":" << (is_change ? "true" : "false")
        << ",\"mode\":\"" << json_escape(mode) << "\"";
    if (parsed) {
        out << ",\"host\":\"" << json_escape(parsed->host) << "\""
            << ",\"address\":\"" << json_escape(parsed->address) << "\""
            << ",\"port\":" << parsed->port;
    } else {
        out << ",\"key\":\"" << json_escape(key) << "\"";
    }
    out << ",\"state\":\"unavailable\""
        << ",\"detail\":\"no longer resolved\""
        << "}\n";
    std::cout << out.str();
}

void emit_unavailable(const std::string &key,
                      bool is_change,
                      ScanMode mode,
                      OutputFormat format) {
    emit_unavailable(key, is_change, mode_label(mode), format);
}
