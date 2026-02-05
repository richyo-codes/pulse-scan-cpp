#pragma once

#include <cstddef>
#include <string>
#include <vector>

std::vector<int> default_dev_ports();
std::vector<int> top_ports(std::size_t count);
std::size_t top_ports_limit();
std::string port_list_to_string(const std::vector<int> &ports);
