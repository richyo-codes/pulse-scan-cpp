#include "core/cli.h"

#include <CLI/CLI.hpp>

#include <algorithm>
#include <cctype>
#include <string>

namespace chrono = std::chrono;

namespace {

std::vector<int> parse_ports(const std::string &input) {
    // Accept comma-separated list with optional ranges: "80,443,8000-8005"
    std::vector<int> ports;
    std::size_t pos = 0;
    while (pos < input.size()) {
        auto next_delim = input.find(',', pos);
        auto token = input.substr(pos, next_delim == std::string::npos ? input.size() - pos
                                                                       : next_delim - pos);
        if (!token.empty()) {
            auto dash = token.find('-');
            if (dash == std::string::npos) {
                ports.push_back(std::stoi(token));
            } else {
                auto start = std::stoi(token.substr(0, dash));
                auto end = std::stoi(token.substr(dash + 1));
                if (start > end) {
                    std::swap(start, end);
                }
                for (int p = start; p <= end; ++p) {
                    ports.push_back(p);
                }
            }
        }
        if (next_delim == std::string::npos) {
            break;
        }
        pos = next_delim + 1;
    }
    return ports;
}

} // namespace

int parse_cli(int argc, char **argv, ScanOptions &opts, std::vector<std::string> &hosts) {
    CLI::App app{"Coroutine-based async port scanner (no raw sockets)"};

    std::string port_list = "80,443,8080";
    double timeout_seconds = 1.0;
    double banner_timeout_seconds = 0.5;
    double ping_interval_seconds = 1.0;
    std::string mode_name = "connect";
    bool ping_mode = false;
    bool open_only = false;
    bool debug_dns = false;
    bool verbose = false;
    bool ipv4_only = false;
    bool ipv6_only = false;
    bool icmp_ping = false;
    bool sandbox = false;
    int icmp_count = 1;

    app.add_option("host", hosts, "Target host(s) (ip or DNS)")
        ->required()
        ->expected(-1);
    auto *ports_opt = app.add_option("-p,--ports", port_list,
                   "Ports to scan (comma list and ranges, e.g. 22,80,8000-8010)")
        ->capture_default_str();
    app.add_option("-t,--timeout", timeout_seconds, "Per-connection timeout in seconds")
        ->capture_default_str();
    app.add_option("--max-inflight", opts.max_inflight,
                   "Max concurrent connection attempts (default: 200)")
        ->capture_default_str();
    auto *mode_opt = app.add_option("-m,--mode", mode_name, "Scan mode: connect, banner, udp")
        ->check(CLI::IsMember({"connect", "banner", "udp"}, CLI::ignore_case))
        ->capture_default_str();
    auto *banner_timeout_opt = app.add_option("--banner-timeout", banner_timeout_seconds,
                   "Banner wait timeout in seconds (banner mode)")
        ->capture_default_str();
    auto *banner_bytes_opt = app.add_option("--banner-bytes", opts.banner_bytes,
                   "Max bytes to read for banner (banner mode)")
        ->capture_default_str();
    app.add_flag("--ping", ping_mode,
                 "Repeat scans at an interval and only report changes");
    app.add_flag("--open", open_only, "Only print open ports");
    app.add_flag("--debug-dns", debug_dns, "Log DNS resolution results");
    app.add_flag("-v,--verbose", verbose, "Enable verbose tracing");
    app.add_flag("-4", ipv4_only, "Use IPv4 only");
    app.add_flag("-6", ipv6_only, "Use IPv6 only");
    app.add_flag("--icmp-ping", icmp_ping, "ICMP echo ping (requires privileges)");
    app.add_option("-c,--icmp-count", icmp_count,
                   "ICMP echo count per host (icmp mode)")
        ->capture_default_str();
    app.add_flag("--sandbox", sandbox, "Enable OS sandboxing (Landlock/Capsicum)");
    app.add_option("--interval", ping_interval_seconds,
                   "Ping interval in seconds (ping mode)")
        ->capture_default_str();

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError &e) {
        return app.exit(e);
    }

    if (ipv4_only && ipv6_only) {
        std::cerr << "Cannot use -4 and -6 together\n";
        return 1;
    }
    if (icmp_ping) {
        if (ports_opt->count() > 0 || mode_opt->count() > 0 ||
            banner_timeout_opt->count() > 0 || banner_bytes_opt->count() > 0) {
            std::cerr << "--icmp-ping cannot be used with port scan options\n";
            return 1;
        }
    }
    if (icmp_count < 1) {
        std::cerr << "--icmp-count must be >= 1\n";
        return 1;
    }

    opts.ports = parse_ports(port_list);
    opts.timeout = chrono::milliseconds(static_cast<int>(timeout_seconds * 1000));
    opts.banner_timeout =
        chrono::milliseconds(static_cast<int>(banner_timeout_seconds * 1000));
    opts.ping_interval =
        chrono::milliseconds(static_cast<int>(ping_interval_seconds * 1000));
    opts.open_only = open_only;
    opts.debug_dns = debug_dns;
    opts.verbose = verbose;
    opts.ipv4_only = ipv4_only;
    opts.ipv6_only = ipv6_only;
    opts.ping_mode = ping_mode;
    opts.icmp_ping = icmp_ping;
    opts.sandbox = sandbox;
    opts.icmp_count = icmp_count;

    auto lower_mode = mode_name;
    std::transform(lower_mode.begin(), lower_mode.end(), lower_mode.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (lower_mode == "connect") {
        opts.mode = ScanMode::TcpConnect;
    } else if (lower_mode == "banner") {
        opts.mode = ScanMode::TcpBanner;
    } else {
        opts.mode = ScanMode::Udp;
    }

    return 0;
}
