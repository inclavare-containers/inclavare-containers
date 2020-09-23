# Enclave Runtime PAL API Specification v1

## 1.pal_init()

### Description
Initialize enclave runtime with specific attributes.

### Prototype 
```c
struct pal_attr_t {
	const char *args;
	const char *log_level;
};

int pal_init(const struct pal_attr_t *attr);
```

### Parameters
```
@args: the enclave runtime specific argument string.
@log_level: the output log level of enclave runtime.
```

### Return value
```
0: Success
-ENOENT: Invalid instance path of enclave runtime
Others: Enclave runtime specific error codes
```

## 2.pal_exec()

### Description 
Pass the path of the application to be executed, and synchronously wait for the end of the application to run and return the result.

### Prototype
```c
struct pal_stdio_fds {
	int stdin, stdout, stderr;
};

int pal_exec(char *path, char *argv[], struct pal_stdio_fds *stdio, int *exit_code);
```

### Parameters 
```
@path: The path of the application to be run.
@argv: The array of argument strings passed to the application, terminated by a NULL pointer.
@stdio: The stdio fds consumed by the application.
@exit_code: Return the exit code of an application.
```

### Return value
```
0: success
-ENOENT: The path does not exist
-EACCES: Permission denied
-ENOEXEC: The path is not an executable file
-ENOMEM: No Memory
-EINVAL: Invalid argument
```

## 3.pal_destroy()

### Description
Destroy the enclave runtime instance

### Prototype
```c
int pal_destroy(); 
```

### Parameters
```
N/A
```

### Return value 
```
0: Success
-ENOSYS: The function is not supported
```
