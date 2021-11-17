/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/attester.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sevcert.h"

bool reverse_bytes(uint8_t *bytes, size_t size)
{
	uint8_t *start = bytes;
	uint8_t *end = bytes + size - 1;

	if (!bytes)
		return false;

	while (start < end) {
		uint8_t byte = *start;
		*start = *end;
		*end = byte;
		start++;
		end--;
	}

	return true;
}

int read_file(const char *filename, void *buffer, size_t len)
{
	FILE *fp = NULL;
	size_t count = 0;

	if ((fp = fopen(filename, "r")) == NULL) {
		RTLS_ERR("open %s error!\n", filename);
		return 0;
	}

	if ((count = fread(buffer, 1, len, fp)) != len) {
		fclose(fp);
		RTLS_ERR("read %s error with count %d\n", filename, count);
		return 0;
	}

	fclose(fp);
	return count;
}

int execute_system_command(const char *cmdline_str)
{
	FILE *pipe = popen((const char *)cmdline_str, "r");
	char output[4096];

	if (!pipe)
		return -1;

	while (!feof(pipe))
		fread(output, 1, sizeof(output), pipe);

	pclose(pipe);
	return 0;
}

int get_file_size(char *name)
{
	struct stat statbuf;
	if (stat(name, &statbuf) == 0)
		return statbuf.st_size;

	return 0;
}

int sev_load_ask_cert(amd_cert *ask_cert, amd_cert *ark_cert)
{
	SEV_ERROR_CODE cmd_ret = STATUS_SUCCESS;

	char cmdline_str[200] = {
		0,
	};
	int count = snprintf(cmdline_str, sizeof(cmdline_str), "wget --no-proxy -O %s %s",
			     ASK_ARK_FILENAME, ASK_ARK_MILAN_SITE);
	cmdline_str[count] = '\0';

	/* Don't re-download the ASK/ARK from the KDS server if you already have it */
	if (get_file_size(ASK_ARK_FILENAME) == 0) {
		if (execute_system_command(cmdline_str)) {
			RTLS_ERR("download %s fail\n", ASK_ARK_FILENAME);
			return -1;
		}
	}

	/* Read in the ask_ark so we can split it into 2 separate cert files */
	uint8_t ask_ark_buf[sizeof(amd_cert) * 2] = { 0 };
	size_t file_size = read_file(ASK_ARK_FILENAME, ask_ark_buf, sizeof(ask_ark_buf));
	if (file_size != sizeof(ask_ark_buf)) {
		RTLS_ERR("read %s fail\n", ASK_ARK_FILENAME);
		return -1;
	}

	/* Initialize the ASK */
	cmd_ret = amd_cert_init(ask_cert, ask_ark_buf);
	if (cmd_ret != STATUS_SUCCESS) {
		RTLS_ERR("Error: Failed to initialize ASK certificate\n");
		return cmd_ret;
	}

	/* Initialize the ARK */
	size_t ask_size = amd_cert_get_size(ask_cert);
	cmd_ret = amd_cert_init(ark_cert, (uint8_t *)(ask_ark_buf + ask_size));
	if (cmd_ret != STATUS_SUCCESS) {
		RTLS_ERR("Error: Failed to initialize ASK certificate\n");
		return cmd_ret;
	}

	/* Check the usage of the ASK and ARK */
	if (ask_cert->key_usage != AMD_USAGE_ASK || ark_cert->key_usage != AMD_USAGE_ARK) {
		RTLS_ERR("Error: Certificate Usage %d did not match expected value %d\n",
			 ask_cert->key_usage, AMD_USAGE_ASK);
		return cmd_ret;
	}

	return cmd_ret;
}
