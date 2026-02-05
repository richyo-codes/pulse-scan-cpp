cmake_minimum_required(VERSION 3.20)

option(PULSECAN_USE_VCPKG "Use vcpkg toolchain when available" ON)

if(PULSECAN_USE_VCPKG)
  message("VCPKG_ROOT: $ENV{VCPKG_ROOT}")
  message("CMAKE_TOOLCHAIN_FILE: $ENV{CMAKE_TOOLCHAIN_FILE}")
  if(DEFINED ENV{VCPKG_ROOT} AND EXISTS "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")
    list(APPEND CMAKE_PROJECT_TOP_LEVEL_INCLUDES "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")
    list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES CMAKE_PROJECT_TOP_LEVEL_INCLUDES)
  endif()
endif()

if(POLICY CMP0167)
  cmake_policy(SET CMP0167 NEW)
endif()

project(pulsescan_cpp VERSION 1.0.0 LANGUAGES CXX)

option(ENABLE_STACKTRACE "Enable Boost stacktrace logging" OFF)
option(ENABLE_ASIO_SSL "Enable Boost.Asio SSL support" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(CLI11 CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS asio system)
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
    src/core/ports.cpp
    src/core/status.cpp
    src/net/icmp_packet.cpp
    src/core/resolve.cpp
    src/core/scan_runner.cpp
    src/net/icmp_scan.cpp
    src/net/scan_tcp.cpp
    src/net/scan_udp.cpp
    src/net/udp_probes.cpp
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

target_link_libraries(pulsescan_cpp PRIVATE Boost::asio Boost::system CLI11::CLI11)
if(ENABLE_STACKTRACE)
  target_link_libraries(pulsescan_cpp PRIVATE Boost::stacktrace_basic)
  target_compile_definitions(pulsescan_cpp PRIVATE ENABLE_STACKTRACE)
endif()
if(NOT ENABLE_ASIO_SSL)
  target_compile_definitions(pulsescan_cpp PRIVATE BOOST_ASIO_DISABLE_SSL)
endif()

include(CTest)
if(BUILD_TESTING)
  find_package(Catch2 CONFIG REQUIRED)
  include(Catch)

  add_executable(pulsescan_cpp_tests
      tests/test_network.cpp
      tests/test_parsing.cpp
      tests/test_udp_probes.cpp
      src/core/cli.cpp
      src/core/logging.cpp
      src/core/output.cpp
      src/core/ports.cpp
      src/core/resolve.cpp
      src/core/status.cpp
      src/net/icmp_packet.cpp
      src/net/udp_probes.cpp
  )
  target_include_directories(pulsescan_cpp_tests PRIVATE src)
  target_link_libraries(pulsescan_cpp_tests PRIVATE Boost::asio Boost::system CLI11::CLI11 Catch2::Catch2WithMain)
  if(ENABLE_STACKTRACE)
    target_link_libraries(pulsescan_cpp_tests PRIVATE Boost::stacktrace_basic)
    target_compile_definitions(pulsescan_cpp_tests PRIVATE ENABLE_STACKTRACE)
  endif()
  if(NOT ENABLE_ASIO_SSL)
    target_compile_definitions(pulsescan_cpp_tests PRIVATE BOOST_ASIO_DISABLE_SSL)
  endif()
  catch_discover_tests(pulsescan_cpp_tests)
endif()

include(GNUInstallDirs)
install(TARGETS pulsescan_cpp RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES README.md LICENSE
        DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(DIRECTORY docs/
        DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(FILES scripts/completions/pulsescan-cpp.bash
        DESTINATION ${CMAKE_INSTALL_DATADIR}/bash-completion/completions
        RENAME pulsescan-cpp)

set(CPACK_PACKAGE_NAME "pulsescan-cpp")
set(CPACK_PACKAGE_VENDOR "ryoung")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "PulseScan C++ async port and host scanner")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_RPM_PACKAGE_AUTOREQPROV ON)
set(CPACK_GENERATOR "DEB;RPM")
include(CPack)
