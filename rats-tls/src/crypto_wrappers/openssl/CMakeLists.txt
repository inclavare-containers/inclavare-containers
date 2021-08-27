# Project name
project(crypto_wrapper_openssl)

# Set include directory
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../include
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../include/enclave-tls
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../include/internal
                 )
if(SGX)
    list(APPEND INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../include/edl
                             ${CMAKE_BINARY_DIR}/src/sgx/trust
                             ${CMAKE_BINARY_DIR}/../src/external/sgx-ssl/intel-sgx-ssl/src/intel-sgx-ssl/Linux/package/include
                             )
endif()
include_directories(${INCLUDE_DIRS})

# Set dependency library directory
set(LIBRARY_DIRS ${CMAKE_BINARY_DIR}/src
                 ${CMAKE_BINARY_DIR}/src/external/intel-sgx-ssl/lib
                 ${ENCLAVE_TLS_INSTALL_LIB_PATH}
                 )
link_directories(${LIBRARY_DIRS})

# Set source file
set(SOURCES cleanup.c
            gen_cert.c
            gen_privkey.c
            gen_pubkey_hash.c
            init.c
            main.c
            pre_init.c
            )

# Generate library
if(SGX)
    set(DEPEND_TRUSTED_LIBS sgx_tsgxssl_cryptod)
    add_trusted_library(${PROJECT_NAME} SRCS ${SOURCES} TRUSTED_LIBS ${DEPEND_TRUSTED_LIBS})
else()
    add_library(${PROJECT_NAME} SHARED ${SOURCES})
    target_link_libraries(${PROJECT_NAME} ${ENCLAVE_TLS_LDFLAGS} ${ETLS_LIB} crypto.so)
    set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${VERSION} SOVERSION ${VERSION_MAJOR})
    # Install library
    install(TARGETS ${PROJECT_NAME}
	   DESTINATION ${ENCLAVE_TLS_INSTALL_LIBCW_PATH})
endif()
