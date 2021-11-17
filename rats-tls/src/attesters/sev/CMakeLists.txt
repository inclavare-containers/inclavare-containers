# Project name
project(attester_sev)

# Set include directory
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../include
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../include/enclave-tls
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../include/internal
                 )
include_directories(${INCLUDE_DIRS})

# Set dependency library directory
set(LIBRARY_DIRS ${CMAKE_BINARY_DIR}/src
                 ${RATS_TLS_INSTALL_LIB_PATH}
                 )
link_directories(${LIBRARY_DIRS})

# Set rpc interface library
set(TTRPC_LIB libttrpc.so)

# Set source file
set(SOURCES cleanup.c
            collect_evidence.c
            init.c
            main.c
            pre_init.c
            )

add_custom_target(ttrpc_lib ALL
	COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR}/ttrpc && cargo build --release && cp -f target/release/${TTRPC_LIB} ${CMAKE_BINARY_DIR}/src)

add_library(${PROJECT_NAME} SHARED ${SOURCES})
add_dependencies(${PROJECT_NAME} ttrpc_lib)
target_link_libraries(${PROJECT_NAME} ${RATS_TLS_LDFLAGS} ${RTLS_LIB} ${TTRPC_LIB} crypto)
set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${VERSION} SOVERSION ${VERSION_MAJOR})
# Install library
install(TARGETS ${PROJECT_NAME}
    DESTINATION ${RATS_TLS_INSTALL_LIBA_PATH})
install(FILES ${CMAKE_BINARY_DIR}/src/${TTRPC_LIB}
	DESTINATION ${RATS_TLS_INSTALL_LIB_PATH})
