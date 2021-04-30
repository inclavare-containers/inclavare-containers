# Add third party directory
add_subdirectory(external)

# Set include directory
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include
                 ${CMAKE_CURRENT_SOURCE_DIR}/include/enclave-tls
                 ${CMAKE_CURRENT_SOURCE_DIR}/include/internal
                 )
include_directories(${INCLUDE_DIRS})

# Set source file
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/core/etls_core_generate_certificate.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/enclave_tls_cleanup.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/enclave_tls_init.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/enclave_tls_negotiate.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/enclave_tls_receive.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/enclave_tls_transmit.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto_wrappers/internal/crypto_wrapper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto_wrappers/internal/etls_crypto_wrapper_load_all.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto_wrappers/internal/etls_crypto_wrapper_load_single.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto_wrappers/internal/etls_crypto_wrapper_select.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto_wrappers/api/crypto_wrapper_register.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/internal/etls_tls_wrapper_load_all.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/internal/etls_tls_wrapper_load_single.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/internal/etls_tls_wrapper_select.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/internal/tls_wrapper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/api/tls_wrapper_register.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/api/tls_wrapper_verify_certificate_extension.c
    ${CMAKE_CURRENT_SOURCE_DIR}/enclave_quotes/internal/enclave_quote.c
    ${CMAKE_CURRENT_SOURCE_DIR}/enclave_quotes/internal/etls_enclave_quote_load_all.c
    ${CMAKE_CURRENT_SOURCE_DIR}/enclave_quotes/internal/etls_enclave_quote_load_single.c
    ${CMAKE_CURRENT_SOURCE_DIR}/enclave_quotes/internal/etls_enclave_quote_select.c
    ${CMAKE_CURRENT_SOURCE_DIR}/enclave_quotes/api/enclave_quote_register.c
    )

# Generate library
add_library(${PROJECT_NAME} SHARED ${SOURCES})
target_link_libraries(${PROJECT_NAME} ${ENCLAVE_TLS_LDFLAGS})
set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${VERSION} SOVERSION ${VERSION_MAJOR})

# Install
install(TARGETS ${PROJECT_NAME}
	DESTINATION ${ENCLAVE_TLS_INSTALL_LIB_PATH})

# Add instance directory
add_subdirectory(crypto_wrappers)
add_subdirectory(enclave_quotes)
add_subdirectory(tls_wrappers)
if(SGX)
    add_subdirectory(sgx)
endif()
