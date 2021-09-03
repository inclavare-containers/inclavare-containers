# Project name
project(crypto_wrapper_nullcrypto)

# Set include directory
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../include
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../include/rats-tls
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../include/internal
                 )
if(SGX)
    list(APPEND INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../include/edl
                             ${CMAKE_BINARY_DIR}/src/sgx/trust)
endif()
include_directories(${INCLUDE_DIRS})

# Set dependency library directory
set(LIBRARY_DIRS ${CMAKE_BINARY_DIR}/src
                 ${RATS_TLS_INSTALL_LIB_PATH}
                 )
link_directories(${LIBRARY_DIRS})

# Set source file
set(SOURCES cleanup.c
            gen_cert.c
            gen_privkey.c
            gen_pubkey_hash.c
            init.c
            main.c
            pre_init.c
            )

# Generate library
if(SGX)
    add_trusted_library(${PROJECT_NAME} SRCS ${SOURCES})
else()
    add_library(${PROJECT_NAME} SHARED ${SOURCES})
    target_link_libraries(${PROJECT_NAME} ${RATS_TLS_LDFLAGS} ${RTLS_LIB})
    set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${VERSION} SOVERSION ${VERSION_MAJOR})
    # Install library
    install(TARGETS ${PROJECT_NAME}
	    DESTINATION ${RATS_TLS_INSTALL_LIBCW_PATH})
endif()
