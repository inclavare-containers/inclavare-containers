int pal_skeleton_init(char *instance_path);
int pal_skeleton_exec(char *path, char *argv[], int *exit_value,
			int stdin_fd, int stdout_fd, int stderr_fd);
int pal_skeleton_kill(int sig, int pid);
int pal_skeleton_destroy();
