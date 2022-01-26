# CMake version
cmake_minimum_required(VERSION 3.5.1)

# Project
project(rats-tls)
set(RTLS_LIB rats_tls)
set(RTLS_SRC_PATH ${CMAKE_CURRENT_LIST_DIR})

# Software version
file(STRINGS "VERSION" RATS_TLS_VERSION)
set(VERSION ${RATS_TLS_VERSION})
string(REPLACE "." ";" VERSION_LIST ${RATS_TLS_VERSION})
list(GET VERSION_LIST 0 VERSION_MAJOR)
list(GET VERSION_LIST 1 VERSION_MINOR)
list(GET VERSION_LIST 2 VERSION_PATCH)

# Build options
option(BUILD_SAMPLES "Compile sample code along with libraries" ON)
option(SGX_HW "Run SGX on hardware, OFF for simulation" ON)
option(SGX_LVI_MITIGATION "Mitigation flag, default on" ON)

# Define build mode
set(RATS_TLS_BUILD_MODE "host"
    CACHE STRING "Select build mode for rats-tls(normal|occlum|sgx)")

# Print build mode
message(STATUS "Build Mode: ${RATS_TLS_BUILD_MODE}")

# CMake modules path
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# Bulid mode macro
#  normal: NORMAL
#  occlum: OCCLUM
#  sgx: SGX
if(RATS_TLS_BUILD_MODE STREQUAL "host")
    set(HOST 1)
    add_definitions(-DHOST)
elseif(RATS_TLS_BUILD_MODE STREQUAL "occlum")
    set(OCCLUM 1)
    add_definitions(-DOCCLUM)
elseif(RATS_TLS_BUILD_MODE STREQUAL "sgx")
    include(FindSGX)
    if(NOT SGX_FOUND)
        message(FATAL_ERROR "Not found intel sgx sdk !")
    else()
        message(STATUS "Found intel sgx sdk.")
    endif()

    set(SGX 1)
    add_definitions(-DSGX)
elseif(RATS_TLS_BUILD_MODE STREQUAL "tdx")
    set(TDX 1)
    add_definitions(-DTDX)
else()
    message(FATAL_ERROR "Invalid build mode!")
endif()

# Default build type
set(RATS_TLS_BUILD_TYPE "debug"
    CACHE STRING "Select build type for rats-tls(debug|prerelease|release)"
    )

# Print build type
message(STATUS "Build Type: ${RATS_TLS_BUILD_TYPE}")

# Build type macro
#  debug: DEBUG
#  prerelease: PRERELEASE
#  release: RELEASE
if(RATS_TLS_BUILD_TYPE STREQUAL "debug")
    set(DEBUG 1)
    set(SGX_DEBUG 1)
elseif(RATS_TLS_BUILD_TYPE STREQUAL "prerelease")
    set(PRERELEASE 1)
    set(SGX_PRERELEASE 1)
elseif(RATS_TLS_BUILD_TYPE STREQUAL "release")
    set(RELEASE 1)
    set(SGX_RELEASE 1)
else()
    message(FATAL_ERROR "Invalid build type!")
endif()

# Include custom modules
include(CustomInstallDirs)
include(CompilerOptions)
if(SGX)
    include(SGXCommon)
    include(SGXSSL)
endif()

# Subdirectory
add_subdirectory(src)

if(BUILD_SAMPLES)
    message(STATUS "Build Samples: on")
    add_subdirectory(samples)
endif()

# Uninstall target
if(NOT TARGET uninstall)
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/CMakeUninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

  add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()
