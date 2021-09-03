#include <enclave-tls/toml.h>

extern int parse_config_file(char *path, char *s_toml_table, char *s_toml_sub_table,
			     toml_datum_t *toml_data);
extern int parse_hex(const char *hex, void *buffer, size_t buffer_size);
