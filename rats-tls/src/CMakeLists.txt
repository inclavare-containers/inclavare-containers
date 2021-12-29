# Set include directory
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include
                 ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls
                 ${CMAKE_CURRENT_SOURCE_DIR}/include/internal
		 /usr/include
                 )
if(SGX)
    list(APPEND INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include/edl
                             ${CMAKE_BINARY_DIR}/src/sgx/trust
                             ${CMAKE_BINARY_DIR}/../src/external/sgx-ssl/intel-sgx-ssl/src/intel-sgx-ssl/Linux/package/include
                             )
endif()
include_directories(${INCLUDE_DIRS})

# Add third party and instance directory
add_subdirectory(external)
add_subdirectory(crypto_wrappers)
add_subdirectory(attesters)
add_subdirectory(verifiers)
add_subdirectory(tls_wrappers)
if(SGX)
    add_subdirectory(sgx)
endif()

# Set source file
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/core/rtls_common.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/rtls_core_generate_certificate.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/cpu.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/rats_tls_cleanup.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/rats_tls_init.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/rats_tls_negotiate.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/rats_tls_receive.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/rats_tls_transmit.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/rats_tls_callback.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto_wrappers/api/crypto_wrapper_register.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto_wrappers/internal/crypto_wrapper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto_wrappers/internal/rtls_crypto_wrapper_load_all.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto_wrappers/internal/rtls_crypto_wrapper_load_single.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto_wrappers/internal/rtls_crypto_wrapper_select.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/api/tls_wrapper_register.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/internal/rtls_tls_wrapper_load_all.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/internal/rtls_tls_wrapper_load_single.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/internal/rtls_tls_wrapper_select.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/internal/tls_wrapper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/api/tls_wrapper_verify_certificate_extension.c
    ${CMAKE_CURRENT_SOURCE_DIR}/attesters/api/enclave_attester_register.c
    ${CMAKE_CURRENT_SOURCE_DIR}/attesters/internal/enclave_attester.c
    ${CMAKE_CURRENT_SOURCE_DIR}/attesters/internal/rtls_enclave_attester_load_all.c
    ${CMAKE_CURRENT_SOURCE_DIR}/attesters/internal/rtls_enclave_attester_load_single.c
    ${CMAKE_CURRENT_SOURCE_DIR}/attesters/internal/rtls_enclave_attester_select.c
    ${CMAKE_CURRENT_SOURCE_DIR}/verifiers/api/enclave_verifier_register.c
    ${CMAKE_CURRENT_SOURCE_DIR}/verifiers/internal/enclave_verifier.c
    ${CMAKE_CURRENT_SOURCE_DIR}/verifiers/internal/rtls_enclave_verifier_load_all.c
    ${CMAKE_CURRENT_SOURCE_DIR}/verifiers/internal/rtls_enclave_verifier_load_single.c
    ${CMAKE_CURRENT_SOURCE_DIR}/verifiers/internal/rtls_enclave_verifier_select.c
    )
if(SGX)
    list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/sgx/trust/rtls_syscalls.c
                        ${CMAKE_CURRENT_SOURCE_DIR}/sgx/trust/sgx_ecdsa_ecalls.c
                        ${CMAKE_CURRENT_SOURCE_DIR}/sgx/trust/sgx_dummy.c
                        )
endif()

# Static library dependencies
if(SGX)
    set(DEPEND_TRUSTED_LIBS rtls_edl_t
                            intel-sgx-ssl
                            crypto_wrapper_nullcrypto
                            crypto_wrapper_openssl
                            tls_wrapper_nulltls
                            tls_wrapper_openssl
                            attester_nullattester
                            attester_sgx_ecdsa
                            attester_sgx_la
                            verifier_nullverifier
                            verifier_sgx_ecdsa
                            verifier_sgx_ecdsa_qve
                            verifier_sgx_la
                            )
endif()

# Generate library
if(SGX)
    add_trusted_library(${RTLS_LIB} SRCS ${SOURCES} TRUSTED_LIBS ${DEPEND_TRUSTED_LIBS})
    add_dependencies(${RTLS_LIB} ${DEPEND_TRUSTED_LIBS})
else()
    add_library(${RTLS_LIB} SHARED ${SOURCES})
    target_link_libraries(${RTLS_LIB} ${RATS_TLS_LDFLAGS})
    set_target_properties(${RTLS_LIB} PROPERTIES VERSION ${VERSION} SOVERSION ${VERSION_MAJOR})
endif()

# Install lib
install(TARGETS ${RTLS_LIB}
    DESTINATION ${RATS_TLS_INSTALL_LIB_PATH})

# Install header
set(RTLS_INCLUDE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/api.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/cert.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/crypto_wrapper.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/attester.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/verifier.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/err.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/log.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/sgx.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/tls_wrapper.h
                       )
install(DIRECTORY DESTINATION ${RATS_TLS_INSTALL_INCLUDE_PATH}/rats-tls)
install(FILES ${RTLS_INCLUDE_FILES}
DESTINATION ${RATS_TLS_INSTALL_INCLUDE_PATH}/rats-tls)
