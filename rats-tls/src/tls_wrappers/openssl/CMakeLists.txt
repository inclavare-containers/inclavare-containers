# Project name
project(tls_wrapper_openssl)

# Set include directory
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../include
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../include/enclave-tls
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../include/internal
                 )
if(SGX)
    list(APPEND INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../include/edl
                             ${CMAKE_BINARY_DIR}/src/sgx/trust
                             /opt/intel/sgxsdk/include/tlibc
                             ${CMAKE_BINARY_DIR}/../src/external/sgx-ssl/intel-sgx-ssl/src/intel-sgx-ssl/Linux/package/include
                             )
endif()
include_directories(${INCLUDE_DIRS})

# Set dependency library directory
set(LIBRARY_DIRS ${CMAKE_BINARY_DIR}/src
                 ${CMAKE_BINARY_DIR}/../src/external/sgx-ssl/intel-sgx-ssl/src/intel-sgx-ssl/Linux/package/lib64
                 /opt/intel/sgxsdk/lib64
                 ${ENCLAVE_TLS_INSTALL_LIB_PATH}
                 )
link_directories(${LIBRARY_DIRS})

# Set source file
set(SOURCES cleanup.c
            init.c
            main.c
            negotiate.c
            un_negotiate.c
            pre_init.c
            receive.c
            transmit.c
            use_cert.c
            use_privkey.c
            per_thread.c
            )

# Generate library
if(SGX)
    set(DEPEND_TRUSTED_LIBS sgx_tsgxssl sgx_tsgxssl_ssl)
    add_trusted_library(${PROJECT_NAME} SRCS ${SOURCES} TRUSTED_LIBS ${DEPEND_TRUSTED_LIBS})
else()
    add_library(${PROJECT_NAME} SHARED ${SOURCES})
    target_link_libraries(${PROJECT_NAME} ${ENCLAVE_TLS_LDFLAGS} ${ETLS_LIB} ssl)
    # Install library
    install(TARGETS ${PROJECT_NAME}
	DESTINATION ${ENCLAVE_TLS_INSTALL_LIBTW_PATH})
endif()
