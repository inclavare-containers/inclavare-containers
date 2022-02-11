# Project name
project(verifier_sgx_la)

if(SGX)
# Set include directory
list(APPEND INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${INCLUDE_DIRS})

set(LIBRARY_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../
                 ${SGXSDK_INSTALL_LIB_PATH}
                 )
link_directories(${LIBRARY_DIRS})

# Set source file
set(SOURCES cleanup.c
            init.c
            main.c
            pre_init.c
            verify_evidence.c
            )

# Generate library
add_trusted_library(${PROJECT_NAME} SRCS ${SOURCES})

# Install library
install(TARGETS ${PROJECT_NAME}
	DESTINATION ${RATS_TLS_INSTALL_LIBV_PATH})
endif()
