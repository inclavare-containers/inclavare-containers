# Project name
project(tls_wrapper_openssl)

# Set include directory
if(SGX)
    list(APPEND INCLUDE_DIRS /opt/intel/sgxsdk/include/tlibc)
endif()
include_directories(${INCLUDE_DIRS})

# Set dependency library directory
set(LIBRARY_DIRS ${CMAKE_BINARY_DIR}/src
                 ${CMAKE_BINARY_DIR}/../src/external/sgx-ssl/intel-sgx-ssl/src/intel-sgx-ssl/Linux/package/lib64
                 /opt/intel/sgxsdk/lib64
                 ${RATS_TLS_INSTALL_LIB_PATH}
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
            x509_openssl10x.c
            )

# Generate library
if(SGX)
    set(DEPEND_TRUSTED_LIBS sgx_tsgxssl sgx_tsgxssl_ssl)
    add_trusted_library(${PROJECT_NAME} SRCS ${SOURCES} TRUSTED_LIBS ${DEPEND_TRUSTED_LIBS})
else()
    add_library(${PROJECT_NAME} SHARED ${SOURCES})
    target_link_libraries(${PROJECT_NAME} ${RATS_TLS_LDFLAGS} ${RTLS_LIB} ssl)
    set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${VERSION} SOVERSION ${VERSION_MAJOR})
    # Install library
    install(TARGETS ${PROJECT_NAME}
	DESTINATION ${RATS_TLS_INSTALL_LIBTW_PATH})
endif()
