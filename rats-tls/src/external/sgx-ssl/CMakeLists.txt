set(SGXSSL_SRC_PATH ${CMAKE_BINARY_DIR}/src/external/sgx-ssl/intel-sgx-ssl/src)
set(SGXSSL_LIB_PATH ${SGXSSL_SRC_PATH}/intel-sgx-ssl/Linux/package/lib64)
set(SGXSSL_INC_PATH ${SGXSSL_SRC_PATH}/intel-sgx-ssl/Linux/package/include)
set(SGXSSL_LIB_FILES ${SGXSSL_LIB_PATH}/libsgx_usgxssl.a
		     ${SGXSSL_LIB_PATH}/libsgx_tsgxssl.a
                     ${SGXSSL_LIB_PATH}/libsgx_tsgxssl_ssl.a
		     ${SGXSSL_LIB_PATH}/libsgx_tsgxssl_crypto.a
                     )
