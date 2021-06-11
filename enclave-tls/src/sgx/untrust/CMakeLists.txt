# Project name
project(enclave_tls_u)

# Set include directory
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../include
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../include/enclave-tls
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../include/internal
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../include/edl
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../enclave_quotes/sgx-ecdsa
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../enclave_quotes/sgx-la
                 )
include_directories(${INCLUDE_DIRS})

# Set source file
set(SOURCES etls_syscalls_ocall.c
            sgx_ecdsa_ocall.c
            sgx_la_ocall.c
            ${CMAKE_CURRENT_SOURCE_DIR}/../../util/sgxutils.c
            )

# Generate library
set(EDL_SEARCH_PATHS ${CMAKE_CURRENT_SOURCE_DIR}/../../include/edl)
set(ETLS_EDL ${CMAKE_CURRENT_SOURCE_DIR}/../../include/edl/etls.edl)
add_untrusted_library(${PROJECT_NAME} STATIC
                      SRCS ${SOURCES}
                      EDL ${ETLS_EDL}
                      EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS}
                      HEADER_ONLY)

# Install library
install(TARGETS ${PROJECT_NAME}
	DESTINATION ${ENCLAVE_TLS_INSTALL_LIB_PATH})
