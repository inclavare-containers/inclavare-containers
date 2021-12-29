# Project name
project(rats_tls_u)

# Set include directory
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../include
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../include/rats-tls
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../include/internal
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../include/edl
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../verifiers/sgx-ecdsa
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../verifiers/sgx-ecdsa-qve
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../verifiers/sgx-la
                 )
include_directories(${INCLUDE_DIRS})

# Set source file
set(SOURCES rtls_syscalls_ocall.c
            rtls_socket_ocall.c
            sgx_ecdsa_ocall.c
            sgx_la_ocall.c
            )

# Generate library
set(EDL_SEARCH_PATHS ${CMAKE_CURRENT_SOURCE_DIR}/../../include/edl)
set(RTLS_EDL ${CMAKE_CURRENT_SOURCE_DIR}/../../include/edl/rtls.edl)

add_untrusted_library(${PROJECT_NAME} STATIC
                      SRCS ${SOURCES}
                      EDL ${RTLS_EDL}
                      EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS}
                      )

# Install library
install(TARGETS ${PROJECT_NAME}
	DESTINATION ${RATS_TLS_INSTALL_LIB_PATH})
