add_subdirectory(nullcrypto)
add_subdirectory(wolfcrypt)

if (SGX)
    add_subdirectory(wolfcrypt-sgx)
endif()
