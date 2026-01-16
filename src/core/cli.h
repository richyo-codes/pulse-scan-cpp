#pragma once

#include "core/options.h"

#include <vector>

int parse_cli(int argc, char **argv, ScanOptions &opts, std::vector<std::string> &hosts);
