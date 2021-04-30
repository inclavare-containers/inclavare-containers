# Project name
project(enclave_quote_sgx_ecdsa)

# Set include directory
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../include
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../include/enclave-tls
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../include/internal
                 ${CMAKE_CURRENT_SOURCE_DIR}
                 )

if(OCCLUM)
    set(INCLUDE_DIRS ${INCLUDE_DIRS}
                     ${SGXSDK_INSTALL_INCLUDE_PATH})
endif()

include_directories(${INCLUDE_DIRS})

# Set dependency library directory
set(LIBRARY_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../)

if(OCCLUM)
    set(LIBRARY_DIRS ${LIBRARY_DIRS}
                     ${SGXSDK_INSTALL_LIB_PATH}
                     )
endif()

link_directories(${LIBRARY_DIRS})

# Set extra link library
if(OCCLUM)
    set(EXTRA_LINK_LIBRARY sgx_dcap_quoteverify)
endif()

# Set source file
set(SOURCES cleanup.c
            collect_evidence.c
            init.c
            main.c
            pre_init.c
            verify_evidence.c
            )

# Generate library
add_library(${PROJECT_NAME} SHARED ${SOURCES})
target_link_libraries(${PROJECT_NAME} ${EXTRA_LINK_LIBRARY} ${ENCLAVE_TLS_LDFLAGS})

# Install library
install(TARGETS ${PROJECT_NAME}
	DESTINATION ${ENCLAVE_TLS_INSTALL_LIBEQ_PATH})
