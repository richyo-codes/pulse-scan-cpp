cmake_minimum_required(VERSION 3.20)

option(PULSECAN_USE_VCPKG "Use vcpkg toolchain when available" ON)

if(PULSECAN_USE_VCPKG)
  message("VCPKG_ROOT: $ENV{VCPKG_ROOT}")
  message("CMAKE_TOOLCHAIN_FILE: $ENV{CMAKE_TOOLCHAIN_FILE}")
  if(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    message(STATUS "FreeBSD native builds can use system packages with -DPULSECAN_USE_VCPKG=OFF (cli11, boost-all).")
  endif()
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
option(ENABLE_INTEGRATION_TESTS "Enable environment-dependent integration tests" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(CLI11 CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS system)
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
target_compile_definitions(pulsescan_cpp PRIVATE PROJECT_VERSION="${PROJECT_VERSION}")

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

if(TARGET Boost::headers)
  set(PULSECAN_BOOST_HEADERS_TARGET Boost::headers)
elseif(TARGET Boost::boost)
  set(PULSECAN_BOOST_HEADERS_TARGET Boost::boost)
else()
  message(FATAL_ERROR "No Boost headers target found (expected Boost::headers or Boost::boost)")
endif()

set(PULSECAN_FORCE_CLI11_HEADER_ONLY OFF)
if(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" AND PULSECAN_USE_VCPKG)
  # FreeBSD cross builds can mix libc++ and libstdc++ ABI for prebuilt CLI11.
  # In that case, force header-only mode to avoid linking libCLI11.a.
  set(PULSECAN_FORCE_CLI11_HEADER_ONLY ON)
endif()

if(TARGET CLI11::CLI11HeaderOnly)
  set(PULSECAN_CLI11_TARGET CLI11::CLI11HeaderOnly)
else()
  if(NOT TARGET CLI11::CLI11)
    message(FATAL_ERROR "No CLI11 target found (expected CLI11::CLI11HeaderOnly or CLI11::CLI11)")
  endif()
  if(PULSECAN_FORCE_CLI11_HEADER_ONLY)
    get_target_property(PULSECAN_CLI11_INCLUDE_DIRS CLI11::CLI11 INTERFACE_INCLUDE_DIRECTORIES)
    if(NOT PULSECAN_CLI11_INCLUDE_DIRS)
      message(FATAL_ERROR "Could not read CLI11 include directories from CLI11::CLI11")
    endif()
    target_include_directories(pulsescan_cpp PRIVATE ${PULSECAN_CLI11_INCLUDE_DIRS})
    target_compile_definitions(pulsescan_cpp PRIVATE CLI11_HEADER_ONLY)
    set(PULSECAN_CLI11_TARGET "")
  else()
    set(PULSECAN_CLI11_TARGET CLI11::CLI11)
  endif()
endif()

target_link_libraries(pulsescan_cpp PRIVATE ${PULSECAN_BOOST_HEADERS_TARGET} Boost::system ${PULSECAN_CLI11_TARGET})
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

  add_executable(pulsescan_cpp_unit_tests
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
  target_include_directories(pulsescan_cpp_unit_tests PRIVATE src)
  if(TARGET CLI11::CLI11HeaderOnly OR NOT PULSECAN_FORCE_CLI11_HEADER_ONLY)
    target_link_libraries(pulsescan_cpp_unit_tests PRIVATE ${PULSECAN_BOOST_HEADERS_TARGET} Boost::system ${PULSECAN_CLI11_TARGET} Catch2::Catch2WithMain)
  else()
    target_include_directories(pulsescan_cpp_unit_tests PRIVATE ${PULSECAN_CLI11_INCLUDE_DIRS})
    target_compile_definitions(pulsescan_cpp_unit_tests PRIVATE CLI11_HEADER_ONLY)
    target_link_libraries(pulsescan_cpp_unit_tests PRIVATE ${PULSECAN_BOOST_HEADERS_TARGET} Boost::system Catch2::Catch2WithMain)
  endif()
  if(ENABLE_STACKTRACE)
    target_link_libraries(pulsescan_cpp_unit_tests PRIVATE Boost::stacktrace_basic)
    target_compile_definitions(pulsescan_cpp_unit_tests PRIVATE ENABLE_STACKTRACE)
  endif()
  if(NOT ENABLE_ASIO_SSL)
    target_compile_definitions(pulsescan_cpp_unit_tests PRIVATE BOOST_ASIO_DISABLE_SSL)
  endif()
  target_compile_definitions(pulsescan_cpp_unit_tests PRIVATE PROJECT_VERSION="${PROJECT_VERSION}")
  catch_discover_tests(pulsescan_cpp_unit_tests)

  if(ENABLE_INTEGRATION_TESTS)
    add_executable(pulsescan_cpp_integration_tests
        tests/test_network.cpp
    )
    target_include_directories(pulsescan_cpp_integration_tests PRIVATE src)
    target_link_libraries(pulsescan_cpp_integration_tests PRIVATE ${PULSECAN_BOOST_HEADERS_TARGET} Boost::system Catch2::Catch2WithMain)
    catch_discover_tests(pulsescan_cpp_integration_tests)
  endif()
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
set(CPACK_PACKAGE_CONTACT "ryoung")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "PulseScan C++ network scanner and host monitor")
set(CPACK_PACKAGE_DESCRIPTION "PulseScan C++ is an asynchronous network scanner supporting TCP connect, banner, UDP probing, and ICMP host checks with optional JSON output.")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "ryoung")
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION "${CPACK_PACKAGE_DESCRIPTION}")
set(CPACK_DEBIAN_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://github.com/richnetdesign/port-scanner-cpp")
set(CPACK_RPM_PACKAGE_AUTOREQPROV ON)
set(CPACK_RPM_PACKAGE_LICENSE "GPL-3.0-only")
set(CPACK_RPM_PACKAGE_GROUP "Applications/Internet")
set(CPACK_RPM_PACKAGE_DESCRIPTION "${CPACK_PACKAGE_DESCRIPTION}")
set(CPACK_GENERATOR "DEB;RPM")
include(CPack)
