add_subdirectory(nullverifier)
add_subdirectory(sgx-ecdsa)
if(OCCLUM OR SGX)
    add_subdirectory(sgx-ecdsa-qve)
endif()

if(SGX)
    add_subdirectory(sgx-la)
endif()
