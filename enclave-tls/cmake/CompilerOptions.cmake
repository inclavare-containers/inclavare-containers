set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11 -fPIC")
set(ENCLAVE_TLS_LDFLAGS "-fPIC -Bsymbolic -ldl")

if(OCCLUM)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DOCCLUM")
endif()

if(DEBUG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb -O0")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
endif()
