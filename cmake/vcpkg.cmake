#
# CMake helper for vcpkg
# automatically clones vcpkg to local directory so it doesnt need to be installed globally

set(VCPKG_LIBRARY_LINKAGE static)

include(FetchContent)
FetchContent_Populate(
  vcpkg
  GIT_REPOSITORY https://github.com/microsoft/vcpkg.git
  GIT_TAG        84bab45d415d22042bd0b9081aea57f362da3f35
  SOURCE_DIR     "${CMAKE_SOURCE_DIR}/vcpkg"
  QUIET
)

list(APPEND CMAKE_PROJECT_TOP_LEVEL_INCLUDES "${vcpkg_SOURCE_DIR}/scripts/buildsystems/vcpkg.cmake")
list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES CMAKE_PROJECT_TOP_LEVEL_INCLUDES)
                                                                                  