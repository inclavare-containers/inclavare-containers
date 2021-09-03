# Project name
project(utils)

# Set include directory
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../include/enclave-tls)
include_directories(${INCLUDE_DIRS})

# Set source file
set(SOURCES toml.c parse.c)

# Generate library
if(SGX)
        add_untrusted_library(${PROJECT_NAME} STATIC
                                SRCS ${SOURCES}
                                )
else()
       add_library(${PROJECT_NAME} SHARED ${SOURCES})
       target_link_libraries(${PROJECT_NAME} ${EXTRA_LINK_LIBRARY} ${ENCLAVE_TLS_LDFLAGS} ${ETLS_LIB})
       # Install library
       install(TARGETS ${PROJECT_NAME}
               DESTINATION ${ENCLAVE_TLS_INSTALL_LIBA_PATH})
endif()
