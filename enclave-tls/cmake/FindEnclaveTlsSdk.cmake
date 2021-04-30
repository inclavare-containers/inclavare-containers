include(CustomInstallDirs)
include(FindPackageHandleStandardArgs)

# Look for the header file
find_path(ENCLAVE_TLS_INCLUDE_DIR NAMES api.h ${ENCLAVE_TLS_INSTALL_FULL_INCLUDEDIR})

# Look for the library
find_library(ENCLAVE_TLS_LIBRARY NAMES enclave_tls ${ENCLAVE_TLS_INSTALL_FULL_LIBDIR})

# Handle the QUIETLY and REQUIRED arguments and set ENCLAVE_TLS_FOUND to TRUE if all listed variables are TRUE.
find_package_handle_standard_args(ENCLAVE_TLS
    DEFAULT_MSG
    REQUIRED_VARS ENCLAVE_TLS_INCLUDE_DIR ENCLAVE_TLS_LIBRARY)

if(ENCLAVE_TLS_FOUND)
    set(ENCLAVE_TLS_LIBRARIES ${ENCLAVE_TLS_LIBRARY})
    set(ENCLAVE_TLS_INCLUDE_DIRS ${ENCLAVE_TLS_INCLUDE_DIR})
else()
    set(ENCLAVE_TLS_LIBRARIES)
    set(ENCLAVE_TLS_INCLUDE_DIRS)
endif()
