# init-runelet
Essentially, it is init process inside container. In runc, init process eventually executes the entrypoint of container defined in config.json. In rune, init process never call execve() syscall. Instead, it serves for the communications between Enclave Runtime PAL and the host side through Enclave Runtime PAL API.

# runelet
init-runelet is created by `rune create`, and runelet process on behalf of enclave application is created by `rune exec`.

# Enclave Runtime PAL API
This API defines the function calls beutween Enclave Runtime PAL and init-runelet.

# Enclave Runtime PAL
The implementer of Enclave Runtime PAL API, on behalf of Enclave Runtime.

# Enclave Runtime
The implementer of enclave. Occlum and Graphene-SGX are all the so-called Enclave Runtime.

# Enclave Application
The actual running entity inside Enclave Runtime.

# Enclave Container
A new class of container managed by OCI Runtime `rune`.
