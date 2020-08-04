#include "liberpal-skeleton.h"

int pal_get_version(void)
{
	return 1;
}

int pal_init(pal_attr_t *attr)
{
	return __pal_init(attr);
}

int pal_exec(char *path, char *argv[], pal_stdio_fds *stdio, int *exit_code)
{
	return __pal_exec(path, argv, stdio, exit_code);
}

int pal_destroy(void)
{
	return __pal_destory();
}
