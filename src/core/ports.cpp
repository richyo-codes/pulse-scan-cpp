#include "core/ports.h"

#include <algorithm>
#include <sstream>

namespace {

const std::vector<int> kDevPorts = {
    22,    80,   443,  3000, 3001, 3002, 4000, 4200,
    5000,  5001, 5173, 5432, 5672, 6379, 8000, 8080,
    8081,  8082, 8443, 9000, 9090, 9092, 9200, 9300,
    11211, 15672, 2181, 27017, 3306, 6006, 9222, 9229
};

const std::vector<int> kPopularPorts = {
    20,  21,  22,  23,  25,  53,  80,  81,  88,  110,
    111, 113, 119, 135, 139, 143, 161, 389, 443, 445,
    465, 512, 513, 514, 515, 543, 544, 548, 554, 587,
    631, 636, 873, 902, 993, 995, 1025, 1080, 1433, 1723,
    2049, 2082, 2083, 3306, 3389, 5432, 5900, 6379, 8080, 8443
};

} // namespace

std::vector<int> default_dev_ports() {
    return kDevPorts;
}

std::vector<int> top_ports(std::size_t count) {
    if (count == 0) {
        return {};
    }
    auto limit = std::min(count, kPopularPorts.size());
    return std::vector<int>(kPopularPorts.begin(), kPopularPorts.begin() + limit);
}

std::size_t top_ports_limit() {
    return kPopularPorts.size();
}

std::string port_list_to_string(const std::vector<int> &ports) {
    std::ostringstream out;
    for (std::size_t i = 0; i < ports.size(); ++i) {
        if (i > 0) {
            out << ",";
        }
        out << ports[i];
    }
    return out.str();
}
