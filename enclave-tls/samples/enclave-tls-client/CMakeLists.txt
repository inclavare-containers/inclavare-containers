# Project name
project(enclave-tls-client)

set(CMAKE_C_FLAGS "-fpie -fPIE ${CMAKE_C_FLAGS}")

if(BUILD_SAMPLES)
    set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include
                     ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include/enclave-tls
                     ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include/internal
                     )
    set(LIBRARY_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../src)
else()
    list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
    include(CustomInstallDirs)
    include(FindEnclaveTlsSdk)
    if(NOT ENCLAVE_TLS_FOUND)
        message(FATAL_ERROR "Failed to find enclave_tls!")
    endif()
    set(INCLUDE_DIRS ${ENCLAVE_TLS_INSTALL_INCLUDE_PATH}
                     ${ENCLAVE_TLS_INCLUDE_DIRS}
                     )
    set(LIBRARY_DIRS ${ENCLAVE_TLS_LIBRARIES})
endif()

include_directories(${INCLUDE_DIRS})
link_directories(${LIBRARY_DIRS})

# Set source file
set(SOURCES client.c)

# Generate bin file
add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} enclave_tls)

install(TARGETS ${PROJECT_NAME}
	DESTINATION ${ENCLAVE_TLS_INSTALL_BIN_PATH})
