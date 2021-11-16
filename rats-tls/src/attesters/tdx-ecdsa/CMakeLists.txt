# Project name
project(attester_tdx_ecdsa)

# Set include directory
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../include
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../include/rats-tls
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../include/internal
                 ${CMAKE_CURRENT_SOURCE_DIR}
                 ${SGXSDK_INSTALL_INCLUDE_PATH}
                 /usr/include
                 )
include_directories(${INCLUDE_DIRS})

# Set dependency library directory
set(LIBRARY_DIRS ${CMAKE_BINARY_DIR}/src
                 ${RATS_TLS_INSTALL_LIB_PATH}
                 )

link_directories(${LIBRARY_DIRS})

# Set extra link library
set(EXTRA_LINK_LIBRARY tdx_attest)

# Set source file
set(SOURCES cleanup.c
            collect_evidence.c
            init.c
            main.c
            pre_init.c
            )

# Generate library
    add_library(${PROJECT_NAME} SHARED ${SOURCES})
    target_link_libraries(${PROJECT_NAME} ${EXTRA_LINK_LIBRARY} ${RATS_TLS_LDFLAGS} ${RTLS_LIB})
    set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${VERSION} SOVERSION ${VERSION_MAJOR})
    # Install library
    install(TARGETS ${PROJECT_NAME}
        DESTINATION ${RATS_TLS_INSTALL_LIBA_PATH})
