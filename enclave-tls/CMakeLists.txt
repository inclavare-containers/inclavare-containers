# CMake version
cmake_minimum_required(VERSION 3.5.1)

# Project
project(enclave_tls)

# Software version
set(VERSION "0.1.0")
set(VERSION_MAJOR 0)
set(VERSION_MINOR 1)
set(VERSION_PATCH 0)

# Build options
option(BUILD_SAMPLES "Compile sample code along with libraries" OFF)

# Define build mode
set(ENCLAVE_TLS_BUILD_MODE "normal"
    CACHE STRING "Select build mode for enclave-tls(normal|occlum|sgx)")

# Print build mode
message(STATUS "Build Mode: ${ENCLAVE_TLS_BUILD_MODE}")

# Bulid mode macro
#  normal: NORMAL
#  occlum: OCCLUM
#  sgx: SGX
if(ENCLAVE_TLS_BUILD_MODE STREQUAL "normal")
    set(NORMAL 1)
elseif(ENCLAVE_TLS_BUILD_MODE STREQUAL "occlum")
    set(OCCLUM 1)
    add_definitions(-DWITH_OCCLUM)
elseif(ENCLAVE_TLS_BUILD_MODE STREQUAL "sgx")
    set(SGX 1)
    add_definitions(-DWITH_SGX)
else()
    message(FATAL_ERROR "Invalid build mode!")
endif()

# Default build type
set(ENCLAVE_TLS_BUILD_TYPE "debug"
    CACHE STRING "Select build type for enclave-tls(debug|prerelease|release)")

# Print build type
message(STATUS "Build Type: ${ENCLAVE_TLS_BUILD_TYPE}")

# Build type macro
#  debug: DEBUB
#  prerelease: PRERELEASE
#  release: RELEASE
if(ENCLAVE_TLS_BUILD_TYPE STREQUAL "debug")
    set(DEBUG 1)
    set(SGX_DEBUG 1)
elseif(ENCLAVE_TLS_BUILD_TYPE STREQUAL "prerelease")
    set(PRERELEASE 1)
    set(SGX_PRERELEASE 1)
elseif(ENCLAVE_TLS_BUILD_TYPE STREQUAL "release")
    set(RELEASE 1)
    set(SGX_RELEASE 1)
else()
    message(FATAL_ERROR "Invalid build type!")
endif()

# CMake modules path
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Include custom modules
include(CustomInstallDirs)
include(CompilerOptions)

# Subdirectory
add_subdirectory(src)

if(BUILD_SAMPLES)
    message(STATUS "Build Samples: on")
    add_subdirectory(samples)
endif()
