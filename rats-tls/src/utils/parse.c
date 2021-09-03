#include <string.h>
#include <ctype.h>
#include <enclave-tls/toml.h>

int parse_hex(const char *hex, void *buffer, size_t buffer_size)
{
	if (!hex || !buffer || buffer_size == 0)
		return -1;

	if (strlen(hex) != buffer_size * 2) {
		printf("Invalid hex string (%s) length\n", hex);
		return -1;
	}

	for (size_t i = 0; i < buffer_size; i++) {
		if (!isxdigit(hex[i * 2]) || !isxdigit(hex[i * 2 + 1])) {
			printf("Invalid hex string '%s'\n", hex);
			return -1;
		}

		sscanf(hex + i * 2, "%02hhx", &((uint8_t *)buffer)[i]);
	}

	return 0;
}

int parse_config_file(char *path, char *s_toml_table, char *s_toml_sub_table,
		      toml_datum_t *toml_data)
{
	FILE *fp;
	char errbuf[200];

	fp = fopen(path, "r");
	if (!fp) {
		printf("failed to open /opt/enclave-tls/config.toml\n");
		goto err;
	}

	toml_table_t *conf = toml_parse_file(fp, errbuf, sizeof(errbuf));
	fclose(fp);

	if (!conf) {
		printf("failed to parse %s\n", errbuf);
		goto err;
	}

	toml_table_t *toml_table = toml_table_in(conf, s_toml_table);
	if (!toml_table) {
		printf("there is no %s data\n", s_toml_table);
		return 0;
	}

	*toml_data = toml_string_in(toml_table, s_toml_sub_table);
	if (toml_data->ok) {
		return 0;
	} else
		printf("there is no %s\n", s_toml_sub_table);

	toml_free(conf);

	return 0;

err:
	return -1;
}
