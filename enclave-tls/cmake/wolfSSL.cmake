# Project name
project(wolfssl-v4.6.0-stable)

include(ExternalProject)

set(WOLFSSL_ROOT ${CMAKE_CURRENT_SOURCE_DIR})

# Set wolfssl configure flags
set(WOLFSSL_CONFIGURE_FLAGS "--prefix=${WOLFSSL_ROOT} \
                            --enable-writedup --enable-shared --enable-static \
                            --enable-keygen --enable-certgen --enable-certext \
                            --with-pic --disable-examples --disable-crypttests \
                            --enable-aesni --enable-tlsv10"
                            )
#if(DEBUG)
    set(WOLFSSL_CONFIGURE_FLAGS "${WOLFSSL_CONFIGURE_FLAGS} --enable-debug")
#endif()

# Set wolfssl compile flags
set(WOLFSSL_CFLAGS "-DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_ALWAYS_VERIFY_CB -DKEEP_PEER_CERT \
                   -Wno-stringop-truncation -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_KEY_GEN \
                   -DWOLFSSL_CERT_GEN -DWOLFSSL_CERT_EXT -DKEEP_PEER_CERT \
                   -DWOLFSSL_TEST_CERT -DWOLFSSL_SMALL_CERT_VERIFY"
                   )

# Set wolfssl link flags
#set(WOLFSSL_LDFLAGS)

set(_configure_script "${CMAKE_CURRENT_SOURCE_DIR}/wolfssl_configure.sh")
file(WRITE "${_configure_script}"
"#!/bin/sh
cd ${WOLFSSL_ROOT}/src/${PROJECT_NAME}
patch -p1 < ${CMAKE_CURRENT_SOURCE_DIR}/patch/wolfssl.patch
./autogen.sh
CFLAGS=\"${WOLFSSL_CFLAGS}\" ./configure ${WOLFSSL_CONFIGURE_FLAGS}
cd -
")

set(_configure_cmake "${CMAKE_CURRENT_SOURCE_DIR}/configure.cmake")
file(WRITE "${_configure_cmake}"
"execute_process(COMMAND sh ${_configure_script} WORKING_DIRECTORY ${WOLFSSL_ROOT}/src/${PROJECT_NAME})"
)

set(_install_script "${CMAKE_CURRENT_SOURCE_DIR}/wolfssl_install.sh")
file(WRITE "${_install_script}"
"#!/bin/sh
cd ${WOLFSSL_ROOT}/src/${PROJECT_NAME} && make install
install -d -m 0755 ${ENCLAVE_TLS_INSTALL_INCLUDE_PATH}/wolfssl
install -m 0755 ${WOLFSSL_ROOT}/include/wolfssl/*.h ${ENCLAVE_TLS_INSTALL_INCLUDE_PATH}/wolfssl
install -d -m 0755 ${ENCLAVE_TLS_INSTALL_INCLUDE_PATH}/wolfssl/wolfcrypt
install -m 0755 ${WOLFSSL_ROOT}/include/wolfssl/wolfcrypt/*.h ${ENCLAVE_TLS_INSTALL_INCLUDE_PATH}/wolfssl/wolfcrypt
install -d -m 0755 ${ENCLAVE_TLS_INSTALL_LIB_PATH}
install -m 0755 ${WOLFSSL_ROOT}/lib/libwolfssl*.a* ${ENCLAVE_TLS_INSTALL_LIB_PATH}
install -m 0755 ${WOLFSSL_ROOT}/lib/libwolfssl*.so* ${ENCLAVE_TLS_INSTALL_LIB_PATH}
cd -
")

set(_install_cmake "${CMAKE_CURRENT_SOURCE_DIR}/install.cmake")
file(WRITE "${_install_cmake}"
"execute_process(COMMAND sh ${_install_script} WORKING_DIRECTORY ${WOLFSSL_ROOT}/src/${PROJECT_NAME})"
)

# Set wolfssl git and comiple parameters
set(WOLFSSL_URL           https://github.com/wolfSSL/wolfssl/archive/refs/tags/v4.6.0-stable.zip)
set(WOLFSSL_DOWNLOAD_NAME wolfssl-v4.6.0-stable.zip)
set(WOLFSSL_MAKE          cd ${WOLFSSL_ROOT}/src/${PROJECT_NAME} && make)

ExternalProject_Add(${PROJECT_NAME}
    PREFIX            ${WOLFSSL_ROOT}
    URL               ${WOLFSSL_URL}
    DOWNLOAD_NAME     ${WOLFSSL_DOWNLOAD_NAME}
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -P ${_configure_cmake}
    BUILD_COMMAND     ${WOLFSSL_MAKE}
    INSTALL_COMMAND   ${CMAKE_COMMAND} -P ${_install_cmake}
    )
