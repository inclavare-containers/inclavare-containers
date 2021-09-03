include(CustomInstallDirs)
include(FindPackageHandleStandardArgs)

set(RATS_TLS_INCLUDE_DIR ${RTLS_SRC_PATH}/src/include)

# Handle the QUIETLY and REQUIRED arguments and set RATS_TLS_FOUND to TRUE if all listed variables are TRUE.
find_package_handle_standard_args(RATS_TLS
    DEFAULT_MSG
    RATS_TLS_INCLUDE_DIR)

if(RATS_TLS_FOUND)
    set(RATS_TLS_INCLUDES ${RATS_TLS_INCLUDE_DIR})
else()
    set(RATS_TLS_LIBRARIES)
    set(RATS_TLS_INCLUDES)
endif()
