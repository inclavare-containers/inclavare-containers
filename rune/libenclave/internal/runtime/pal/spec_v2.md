# Enclave Runtime PAL API Specification v2

## 1.pal_get_version()

### Description
Indicate PAL API version number implemented by runelet and enclave runtime; runelet is compatible with any enclave runtimes equal to or less than the indicated value. If this symbol is undefined in enclave runtime, version 1 is assuemd by runelet.

### Prototype
```c
int pal_get_version();
```

### Parameters
```
N/A
```

### Return value
```
@int: the PAL API version of the current enclave runtime.
```

## 2.pal_init()

### Description
Do libos initialization according to the incoming attr parameters.

### Prototype
```c
struct pal_attr_t {
	const char *args;
	const char *log_level;
};

int pal_init(struct pal_attr_t *attr);
```

### Parameters
```
@args: Pass the required parameters of libos (can be instance path etc.).
@log_level: Log level.
```
### Return value
```
0: Success
-EINVAL: Invalid argument
-ENOSYS: The function is not supported
```

## 3.pal_create_process()

### Description
Create a new process, but do not run it; the real run is triggered by pal_exec().

### Prototype
```c
struct pal_stdio_fds {
	int stdin, stdout, stderr;
};

struct pal_create_process_args {
	char *path;
	char *argv[];
	char *env[];
	struct pal_stdio_fds *stdio;
	int *pid;
}__attribute__((packed));

int pal_create_process(struct pal_create_process_args *args);
```

### Parameters
```
@path: The path of the binary file to be run (relative path in the libos file system).
@argv: Binary parameters, ending with a null element.
@env: Binary environment variables, ending with a null element.
@stdio: The fd of stdio.
@pid: If the function return value is 0, pid stores the pid of the new process in libos.
```

### Return value
```
0: Success
-EINVAL: Invalid argument
-ENOSYS: The function is not supported
```

## 4.pal_exec()

### Description
Execute the program corresponding to pid.

### Prototype
```c
struct pal_exec_args {
	int pid;
	int *exit_value;
}__attribute__((packed));

int pal_exec(struct pal_exec_args *attr);
```

### Parameters
```
@pid: The pid of the generation process.
@exit_value: The exit value of the process.
```

### Return value
```
0: Success
-EINVAL: Invalid argument
-ENOSYS: The function is not supported
```

## 5.pal_kill()

### Description
Send signals to processes running in enclave runtime.

### Prototype
```c
int pal_kill(int pid, int sig);
```

### Parameters
```
@pid: Send to all processes if equal to -1, or send to current process if equal to 0, or send to the process that owns the pid if others.  
@sig: Signal number to be sent.
```

### Return value
```
0: Success
-EINVAL: Invalid argument
-ENOSYS: The function is not supported
```

## 6.pal_destroy()

### Description
Destroy libos instance.

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
