# Enclave Runtime PAL API Specification v2
Enclave Runtime PAL API defines a common interface to interact between `rune` and enclave runtime.

## 1. pal_version
| **Description** | Indicate PAL API version number implemented by runelet and enclave runtime; runelet is compatible with any enclave runtimes equal to or less than the indicated value. If this symbol is undefined in enclave runtime, version 1 is assuemd by runelet. |
| :---: | :--- |
| **Prototype** | `int pal_version();` |
| **Parameters** | N/A |
| **Return value** | N/A |

## 2.pal_init()
| **Description** | Do libos initialization according to the incoming attr parameters. |
| :---: | :--- |
| **Prototype** | struct pal_attr_t {<br />    const char *args;<br />    const char *log_level;<br />};<br />int pal_init(struct palattrt *attr); |
| **Parameters** | @args: Pass the required parameters of libos (can be instance path etc.)<br />@log_level: Log level. |
| **Return value** | 0: Success<br />-EINVAL: Invalid argument<br />-ENOSYS: The function is not supported |

## 3. pal_create_process
| **Description** | Create a new process, but do not run it; the real run is triggered by pal_exec(). |
| :---: | :--- |
| **Prototype** | struct stdio_fds {<br />    int stdin, stdout, stderr;<br />};<br />struct pal_create_process_args {<br />    char *path;<br />    char *argv[];<br />    char *env[];<br />    struct stdio_fds *stdio;<br />    int *pid;<br />}__attribute__((packed));<br />int pal_create_process(struct pal_create_process_args *args); |
| **Parameters** | @path: The path of the binary file to be run (relative path in the libos file system).<br />@argv: Binary parameters, ending with a null element.<br />@env: Binary environment variables, ending with a null element.<br />@stdio: The fd of stdio.<br />@pid: If the function return value is 0, pid stores the pid of the new process in libos. |
| **Return value** | 0: Success<br />-EINVAL: Invalid argument<br />-ENOSYS: The function is not supported |

## 4. pal_exec
| **Description** | Execute the program corresponding to pid. |
| :---: | :--- |
| **Prototype** | struct pal_exec_args {<br />    int pid;<br />    int *exit_value;};<br />}__attribute__((packed));<br />int pal_exec(struct pal_exec_args *attr); |
| **Parameters** | @pid: The pid of the generation process.<br />@exit_value: The exit value of the process. |

## 5.pal_kill()
| **Description** | Send signals to processes running in enclave runtime. |
| :---: | :--- |
| **Prototype** | int pal_kill(int pid, int sig); |
| **Parameters** | @pid: Send to all processes if equal to -1, or send to current process if equal to 0, or send to the process that owns the pid if others. <br />@sig: Signal number to be sent |
| **Return value** | 0: Success<br />-EINVAL: Invalid argument<br />-ENOSYS: The function is not supported |

## 6.pal_destroy()
| **Description** | Destroy libos instance. |
| :---: | :--- |
| **Prototype** | int pal_destroy(); |
| **Parameters** | NA. |
| **Return value** | 0: Success<br />-ENOSYS: The function is not supported |
