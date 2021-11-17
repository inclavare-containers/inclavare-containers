# Project name
project(verifier_sgx_ecdsa_qve)

# Set include directory
list(APPEND INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR})
if(OCCLUM)
    list(APPEND INCLUDE_DIRS ${SGXSDK_INSTALL_INCLUDE_PATH})
endif()
include_directories(${INCLUDE_DIRS})

# Set dependency library directory
set(LIBRARY_DIRS ${CMAKE_BINARY_DIR}/src
                 ${RATS_TLS_INSTALL_LIB_PATH}
                 )
if(OCCLUM)
    list(APPEND LIBRARY_DIRS ${SGXSDK_INSTALL_LIB_PATH})
endif()
link_directories(${LIBRARY_DIRS})

# Set extra link library
if(OCCLUM)
    set(EXTRA_LINK_LIBRARY sgx_dcap_quoteverify)
endif()

# Set source file
if(SGX)
    set(SOURCES init.c
                main.c
                )
else()
    set(SOURCES cleanup.c
                init.c
                main.c
                pre_init.c
                verify_evidence.c
                )
endif()

# Generate library
if(SGX)
    add_trusted_library(${PROJECT_NAME} SRCS ${SOURCES})
else()
    add_library(${PROJECT_NAME} SHARED ${SOURCES})
    target_link_libraries(${PROJECT_NAME} ${EXTRA_LINK_LIBRARY} ${RATS_TLS_LDFLAGS} ${RTLS_LIB})
    set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${VERSION} SOVERSION ${VERSION_MAJOR})
    # Install library
    install(TARGETS ${PROJECT_NAME}
	    DESTINATION ${RATS_TLS_INSTALL_LIBV_PATH})
endif()
