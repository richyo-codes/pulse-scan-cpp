cmake_minimum_required(VERSION 3.20)

# set(VCPKG_LIBRARY_LINKAGE static)
# set(VCPKG_TARGET_TRIPET x64-windows-static)
# set(VCPKG_INSTALL_OPTIONS --allow-unsupported)

message("VCPKG_ROOT: $ENV{VCPKG_ROOT}")
message("CMAKE_TOOLCHAIN_FILE: $ENV{CMAKE_TOOLCHAIN_FILE}")

list(APPEND CMAKE_PROJECT_TOP_LEVEL_INCLUDES "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")
list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES CMAKE_PROJECT_TOP_LEVEL_INCLUDES)

if(POLICY CMP0167)
  cmake_policy(SET CMP0167 NEW)
endif()

project(pulsescan_cpp LANGUAGES CXX)

option(ENABLE_STACKTRACE "Enable Boost stacktrace logging" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(CLI11 CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS asio)
if(ENABLE_STACKTRACE)
  find_package(Boost REQUIRED COMPONENTS stacktrace_basic)
endif()


add_executable(pulsescan_cpp
    src/core/app.cpp
    src/core/cli.cpp
    src/main.cpp
    src/core/logging.cpp
    src/core/output.cpp
    src/core/ping_loop.cpp
    src/net/icmp_packet.cpp
    src/core/resolve.cpp
    src/core/scan_runner.cpp
    src/net/icmp_scan.cpp
    src/net/scan_tcp.cpp
    src/net/scan_udp.cpp
)
set_target_properties(pulsescan_cpp PROPERTIES OUTPUT_NAME "pulsescan-cpp")

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_sources(pulsescan_cpp PRIVATE src/net/icmp_ping.cpp)
  target_sources(pulsescan_cpp PRIVATE src/platform/sandbox_landlock.cpp)
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  target_sources(pulsescan_cpp PRIVATE src/net/icmp_ping.cpp)
  target_sources(pulsescan_cpp PRIVATE src/platform/sandbox_capsicum.cpp)
else()
  target_sources(pulsescan_cpp PRIVATE src/net/icmp_ping_stub.cpp)
  target_sources(pulsescan_cpp PRIVATE src/platform/sandbox_none.cpp)
endif()
target_include_directories(pulsescan_cpp PRIVATE src)

find_package(CURL REQUIRED)
target_link_libraries(pulsescan_cpp PRIVATE CURL::libcurl)

# this is heuristically generated, and may not be correct
find_package(cpr CONFIG REQUIRED)
target_link_libraries(pulsescan_cpp PRIVATE cpr::cpr)

target_link_libraries(pulsescan_cpp PRIVATE Boost::asio CLI11::CLI11)
if(ENABLE_STACKTRACE)
  target_link_libraries(pulsescan_cpp PRIVATE Boost::stacktrace_basic)
  target_compile_definitions(pulsescan_cpp PRIVATE ENABLE_STACKTRACE)
endif()

include(CTest)
if(BUILD_TESTING)
  find_package(Catch2 CONFIG REQUIRED)
  include(Catch)

  add_executable(pulsescan_cpp_tests
      tests/test_network.cpp
      tests/test_parsing.cpp
      src/core/cli.cpp
      src/core/logging.cpp
      src/core/resolve.cpp
      src/net/icmp_packet.cpp
  )
  target_include_directories(pulsescan_cpp_tests PRIVATE src)
  target_link_libraries(pulsescan_cpp_tests PRIVATE Boost::asio CLI11::CLI11 Catch2::Catch2WithMain)
  if(ENABLE_STACKTRACE)
    target_link_libraries(pulsescan_cpp_tests PRIVATE Boost::stacktrace_basic)
    target_compile_definitions(pulsescan_cpp_tests PRIVATE ENABLE_STACKTRACE)
  endif()
  catch_discover_tests(pulsescan_cpp_tests)
endif()
