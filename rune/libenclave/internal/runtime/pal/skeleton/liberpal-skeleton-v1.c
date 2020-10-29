#include "liberpal-skeleton.h"

int pal_get_version(void)
{
	return 1;
}

/* *INDENT-OFF* */
int pal_init(pal_attr_v1_t *attr)
{
	return __pal_init_v1(attr);
}

int pal_exec(char *path, char *argv[], pal_stdio_fds *stdio, int *exit_code)
{
	return __pal_exec(path, argv, stdio, exit_code);
}
/* *INDENT-ON* */

int pal_destroy(void)
{
	return __pal_destroy();
}
