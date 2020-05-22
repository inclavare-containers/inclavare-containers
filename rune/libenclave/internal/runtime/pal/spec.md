# Enclave Runtime PAL API Specification
Enclave Runtime PAL API defines a common interface to interact between `rune` and enclave runtime.

## pal_init()
| **Description** | Initialize enclave runtime with specific attributes. |
| :-: | :- |
| **Prototype** | struct pal_attr_t {<br/>      const char \*args;<br/>      const char \*log_level;<br/>};<br/>int pal_init(const struct pal_attr_t *attr); |
| **Parameters** | @args: the enclave runtime specific argument string.<br/>@log_level: the output log level of enclave runtime. |
| **Return value** | 0: Success<br/>-ENOENT: Invalid instance path of enclave runtime<br/>Others: Enclave runtime specific error codes |
| **Availability **| >=v1 |

## pal_exec()
| **Description** | Pass the path of the application to be executed, and synchronously wait for the end of the application to run and return the result. |
| :-: | :- |
| **Prototype** | struct pal_stdio_fds {<br/>      int stdin, stdout, stderr;<br />};<br/>int pal_exec(char \*path, char \*argv[],<br/>             struct pal_stdio_fds \*stdio,<br/>             int \*exit_code); |
| **Parameters** | @path: The path of the application to be run<br/>@argv: The array of argument strings passed to the application, terminated by a NULL pointer<br/>@stdio: The stdio fds consumed by the application<br/>@exit_code: Return the exit code of an application |
| **Return value** | 0: success<br/>-ENOENT: The path does not exist<br/>-EACCES: Permission denied<br />-ENOEXEC: The path is not an executable file<br =/>-ENOMEM: <br />-EINVAL: Invalid argument |
| **Availability **| >=v1 |

## pal_destroy()
| **Description** | Destroy the enclave runtime instance |
| :-: | :- |
| **Prototype** | int pal_destroy(); |
| **Parameters** | N/A |
| **Return value** | 0: Success<br/>-ENOSYS: The function is not supported |
| **Availability **| >=v1 |
