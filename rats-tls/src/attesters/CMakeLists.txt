add_subdirectory(nullattester)

if(TDX)
    add_subdirectory(tdx-ecdsa)
endif()

if(OCCLUM OR SGX)
    add_subdirectory(sgx-ecdsa)
endif()

if(SGX)
    add_subdirectory(sgx-la)
endif()
