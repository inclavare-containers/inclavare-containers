# Enclave Runtime Programming Guide v2

# 1. Background
The enclave runtime currently supported by runE are occlum and WAMR (WebAssembly Micro Runtime). In order to facilitate other libos programs to run in runE, a set of enclave runtime API interfaces is defined. Libos only needs to support this set of API interfaces to run as an enclave runtime in runE.

# 2. enclave runtime in runE
runE enclave runtime is bounded by the enclave runtime pal API layer, below the API layer is runE, above the API layer is the enclave runtime, and the operating mode is libos.

## 2.1 enclave runtime pal API definition
```c
struct pal_attr_t {
    const char*     args;
    const char*     log_level;
};

struct stdio_fds {
    int stdin, stdout, stderr;
};

struct pal_create_process_args {
    char *path;
    char *argv[];
    char *env[];
    struct stdio_fds *stdio;
    int *pid;
}__attribute__((packed));

struct pal_exec_args {
    int pid;
    int *exit_value;
}__attribute__((packed));

struct pal_kill_args {
    int pid;
    int sig;
}__attribute__((packed));

struct pal_opt {
    int pal_version();
    int pal_init(struct pal_attr_t *attr);
    int pal_create_process(struct pal_create_process_args *args);
    int pal_exec(struct pal_exec_args *args);
    int pal_kill(struct pal_kill_args *args);
    int pal_destroy();
};
```

## 2.2 enclave runtime Library file naming and function naming rules
The enclave runtime is generated as a so dynamic library, which is dynamically loaded by rune using dlopen; the enclave runtime needs to export symbols according to the function named in the previous chapter.<br />

# 3. pal interface

## 3.1 pal_version
The value of this global variable is the version of pal_api, refer to the implementation:
```c
int pal_version()
{
    return 2;
}
```

## 3.2 pal_init
The main task of this interface should be to create an enclave space and complete the memory layout of the enclave space; libos also needs to complete the initialization of components such as VM, FS, and NET. Reference implementation:
```c
int pal_init(const struct pal_attr_t *attr)
{
    ...
    sgx_launch_token_t token;
    get_token(&token);
    sgx_create_enclave(..., token, ...);
    ...
}
```

## 3.3 pal_create_process
The main job of this interface is to create a new process, reference implementation:
```c
int pal_create_process(struct pal_create_process_args *args)
{
    ...
    args->pid = libos_create_process(...);
    ...
}
```

## 3.4 pal_exec
The main job of this interface is to run a program created by pal_create_process, refer to the implementation:
```c
int pal_exec(struct pal_exec_args *args)
{
    ...
    libos_exec(...);
    ...
}
```

## 3.5 pal_kill
The main job of this interface is to send a signal to the specified pid, refer to the implementation:
```c
int pal_kill(int pid, int sig)
{
    ...
    libos_kill(...)
    ...
}
```

## 3.6 pal_destroy
The main job of this interface is to destroy the entire enclave space. If it is libos, you need to do component de-initialization before destroying the enclave. Reference implementation:
```c
int pal_destroy(void) {
    ...
    libos_uninitialize();
    sgx_destroy_enclave(global_eid);
    ...
}
```
