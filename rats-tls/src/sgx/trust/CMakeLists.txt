# Project name
project(rtls_edl_t)

# Set include directory
include_directories(${INCLUDE_DIRS})

# Set source file
set(SOURCES sgx_dummy.c
            rtls_syscalls.c
            sgx_ecdsa_ecalls.c
            )

# Generate library
set(EDL_SEARCH_PATHS ${CMAKE_CURRENT_SOURCE_DIR}/../../include/edl)
set(RTLS_EDL ${CMAKE_CURRENT_SOURCE_DIR}/../../include/edl/rtls.edl)
add_trusted_library(${PROJECT_NAME}
                    SRCS ${SOURCES}
                    EDL ${RTLS_EDL}
                    EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS}
		    )

# Install library
install(TARGETS ${PROJECT_NAME}
	DESTINATION ${RATS_TLS_INSTALL_LIB_PATH})
