/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <string.h>
#include "amdcert.h"

/**
 * Bytes, NOT bits
 */
size_t amd_cert_get_size(const amd_cert *cert)
{
	size_t size = 0;
	uint32_t fixed_offset = offsetof(amd_cert, pub_exp); // 64 bytes

	if (cert)
		size = fixed_offset + (cert->pub_exp_size + 2 * cert->modulus_size) / 8;

	return size;
}

/* Obtain information on device type from provided Root certificate */
// clang-format off
enum ePSP_DEVICE_TYPE get_device_type(const amd_cert *ark)
{
	if (!ark)
		return PSP_DEVICE_TYPE_INVALID;

	if (memcmp(&ark->key_id_0, amd_root_key_id_rome, sizeof(ark->key_id_0 + ark->key_id_1)) == 0) {
		return PSP_DEVICE_TYPE_ROME;
	}

	if (memcmp(&ark->key_id_0, amd_root_key_id_naples, sizeof(ark->key_id_0 + ark->key_id_1)) == 0) {
		return PSP_DEVICE_TYPE_NAPLES;
	}

	if (memcmp(&ark->key_id_0, amd_root_key_id_milan, sizeof(ark->key_id_0 + ark->key_id_1)) == 0) {
		return PSP_DEVICE_TYPE_MILAN;
	}

	return PSP_DEVICE_TYPE_INVALID;
}
// clang-format on

/**
 * This function takes Bits, NOT Bytes
 */
bool key_size_is_valid(size_t size)
{
	return (size == AMD_CERT_KEY_BITS_2K) || (size == AMD_CERT_KEY_BITS_4K);
}

SEV_ERROR_CODE amd_cert_init(amd_cert *cert, const uint8_t *buffer)
{
	if (!cert || !buffer)
		return ERROR_INVALID_PARAM;

	memset(cert, 0, sizeof(*cert));

	uint32_t pub_exp_offset = offsetof(amd_cert, pub_exp); // 64 bytes
	memcpy(cert, buffer, pub_exp_offset);

	uint32_t modulus_offset = pub_exp_offset + (cert->pub_exp_size / 8); // 2k or 4k bits
	uint32_t sig_offset =
		modulus_offset + (cert->modulus_size / 8); // 2k or 4k bits, Mod size as def in spec

	// Initialize the remainder of the certificate
	memcpy(&cert->pub_exp, (void *)(buffer + pub_exp_offset), cert->pub_exp_size / 8);
	memcpy(&cert->modulus, (void *)(buffer + modulus_offset), cert->modulus_size / 8);
	memcpy(&cert->sig, (void *)(buffer + sig_offset), cert->modulus_size / 8);

	return STATUS_SUCCESS;
}

SEV_ERROR_CODE amd_cert_validate_sig(const amd_cert *cert, const amd_cert *parent,
				     enum ePSP_DEVICE_TYPE device_type)
{
	SEV_ERROR_CODE cmd_ret = ERROR_INVALID_CERTIFICATE;
	hmac_sha_256 sha_digest_256;
	hmac_sha_512 sha_digest_384;
	SHA_TYPE algo = SHA_TYPE_256;
	uint8_t *sha_digest = NULL;
	size_t sha_length = 0;

	RSA *rsa_pub_key = NULL;
	BIGNUM *modulus = NULL;
	BIGNUM *pub_exp = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	uint32_t sig_len = cert->modulus_size / 8;

	uint32_t digest_len = 0;
	uint8_t decrypted[AMD_CERT_KEY_BYTES_4K] = { 0 }; // TODO wrong length
	uint8_t signature[AMD_CERT_KEY_BYTES_4K] = { 0 };
	uint32_t fixed_offset = offsetof(amd_cert, pub_exp); // 64 bytes

	if (!cert || !parent) {
		cmd_ret = ERROR_INVALID_PARAM;
		goto err;
	}

	// Set SHA_TYPE to 256 bit or 384 bit depending on device_type
	if (device_type == PSP_DEVICE_TYPE_NAPLES) {
		algo = SHA_TYPE_256;
		sha_digest = sha_digest_256;
		sha_length = sizeof(hmac_sha_256);
	} else /*if (ROME/MILAN)*/ {
		algo = SHA_TYPE_384;
		sha_digest = sha_digest_384;
		sha_length = sizeof(hmac_sha_512);
	}

	// Memzero all the buffers
	memset(sha_digest, 0, sha_length);
	memset(decrypted, 0, sizeof(decrypted));
	memset(signature, 0, sizeof(signature));

	// New up the RSA key
	rsa_pub_key = RSA_new();

	// Convert the parent to an RSA key to pass into RSA_verify
	modulus = BN_lebin2bn((uint8_t *)&parent->modulus, parent->modulus_size / 8,
			      NULL); // n    // New's up BigNum
	pub_exp = BN_lebin2bn((uint8_t *)&parent->pub_exp, parent->pub_exp_size / 8,
			      NULL); // e
	if (RSA_set0_key(rsa_pub_key, modulus, pub_exp, NULL) != 1)
		goto err;

	md_ctx = EVP_MD_CTX_create();
	if (EVP_DigestInit(md_ctx, (algo == SHA_TYPE_256) ? EVP_sha256() : EVP_sha384()) <= 0)
		goto err;
	if (EVP_DigestUpdate(md_ctx, cert, fixed_offset) <= 0) // Calls SHA256_UPDATE
		goto err;
	if (EVP_DigestUpdate(md_ctx, &cert->pub_exp, cert->pub_exp_size / 8) <= 0)
		goto err;
	if (EVP_DigestUpdate(md_ctx, &cert->modulus, cert->modulus_size / 8) <= 0)
		goto err;
	EVP_DigestFinal(md_ctx, sha_digest, &digest_len);

	// Swap the bytes of the signature
	memcpy(signature, &cert->sig, parent->modulus_size / 8);
	if (!reverse_bytes(signature, parent->modulus_size / 8))
		goto err;

	// Now we will verify the signature. Start by a RAW decrypt of the signature
	if (RSA_public_decrypt(sig_len, signature, decrypted, rsa_pub_key, RSA_NO_PADDING) == -1)
		goto err;

	// Verify the data
	// SLen of -2 means salt length is recovered from the signature
	if (RSA_verify_PKCS1_PSS(rsa_pub_key, sha_digest,
				 (algo == SHA_TYPE_256) ? EVP_sha256() : EVP_sha384(), decrypted,
				 -2) != 1) {
		goto err;
	}

	cmd_ret = STATUS_SUCCESS;

err:
	// Free the keys and contexts
	if (rsa_pub_key)
		RSA_free(rsa_pub_key);

	if (md_ctx)
		EVP_MD_CTX_free(md_ctx);

	return cmd_ret;
}

SEV_ERROR_CODE amd_cert_validate_common(const amd_cert *cert)
{
	SEV_ERROR_CODE cmd_ret = STATUS_SUCCESS;

	if (!cert)
		return ERROR_INVALID_PARAM;

	if (cert->version != AMD_CERT_VERSION || !key_size_is_valid(cert->modulus_size) ||
	    !key_size_is_valid(cert->pub_exp_size))
		cmd_ret = ERROR_INVALID_CERTIFICATE;

	return cmd_ret;
}

SEV_ERROR_CODE amd_cert_validate(const amd_cert *cert, const amd_cert *parent,
				 AMD_SIG_USAGE expected_usage, enum ePSP_DEVICE_TYPE device_type)
{
	SEV_ERROR_CODE cmd_ret = STATUS_SUCCESS;

	if (!cert || !parent || cert->key_usage != expected_usage)
		return ERROR_INVALID_PARAM;

	// Validate the signature before using any certificate fields
	cmd_ret = amd_cert_validate_sig(cert, parent, device_type);
	if (cmd_ret != STATUS_SUCCESS)
		return cmd_ret;

	// Validate the fixed data
	cmd_ret = amd_cert_validate_common(cert);
	if (cmd_ret != STATUS_SUCCESS)
		return cmd_ret;

	return cmd_ret;
}

SEV_ERROR_CODE amd_cert_validate_ask(const amd_cert *ask, const amd_cert *ark)
{
	enum ePSP_DEVICE_TYPE device_type = get_device_type(ark);

	return amd_cert_validate(ask, ark, AMD_USAGE_ASK, device_type);
}

SEV_ERROR_CODE amd_cert_validate_ark(const amd_cert *ark)
{
	SEV_ERROR_CODE cmd_ret = STATUS_SUCCESS;
	hmac_sha_256 hash;
	hmac_sha_256 fused_hash;
	const uint8_t *amd_root_key_id = NULL;
	enum ePSP_DEVICE_TYPE device_type = get_device_type(ark);

	if (!ark) {
		cmd_ret = ERROR_INVALID_PARAM;
		return cmd_ret;
	}

	memset(&hash, 0, sizeof(hash));
	memset(&fused_hash, 0, sizeof(fused_hash));

	// Validate the certificate. Check for self-signed ARK
	cmd_ret = amd_cert_validate(ark, ark, AMD_USAGE_ARK, device_type); // Rome
	if (cmd_ret != STATUS_SUCCESS) {
		// Not a self-signed ARK. Check the ARK without a signature
		cmd_ret = amd_cert_validate(ark, NULL, AMD_USAGE_ARK, device_type); // Naples
		if (cmd_ret != STATUS_SUCCESS)
			return cmd_ret;
	}

	if (device_type == PSP_DEVICE_TYPE_NAPLES)
		amd_root_key_id = amd_root_key_id_naples;
	else if (device_type == PSP_DEVICE_TYPE_ROME)
		amd_root_key_id = amd_root_key_id_rome;
	else //if (device_type == PSP_DEVICE_TYPE_MILAN)
		amd_root_key_id = amd_root_key_id_milan;

	if (memcmp(&ark->key_id_0, amd_root_key_id, sizeof(ark->key_id_0 + ark->key_id_1)) != 0)
		return ERROR_INVALID_CERTIFICATE;

	if (memcmp(&ark->key_id_0, amd_root_key_id, sizeof(ark->key_id_0 + ark->key_id_1)) != 0)
		cmd_ret = ERROR_INVALID_CERTIFICATE;

	// We have to trust the ARK from the website, as there is no way to
	// validate it further, here. It is trustable due to being transmitted
	// over https

	return cmd_ret;
}

/**
 * The verify_sev_cert function takes in a parent of an sev_cert not
 *   an amd_cert, so need to pull the pubkey out of the amd_cert and
 *   place it into a tmp sev_cert to help validate the cek
 */
SEV_ERROR_CODE amd_cert_export_pub_key(const amd_cert *cert, sev_cert *pub_key_cert)
{
	if (!cert || !pub_key_cert) {
		return ERROR_INVALID_PARAM;
	}

	memset(pub_key_cert, 0, sizeof(*pub_key_cert));

	if (cert->modulus_size == AMD_CERT_KEY_BITS_2K) { // Naples
		pub_key_cert->pub_key_algo = SEV_SIG_ALGO_RSA_SHA256;
	} else if (cert->modulus_size == AMD_CERT_KEY_BITS_4K) { // Rome
		pub_key_cert->pub_key_algo = SEV_SIG_ALGO_RSA_SHA384;
	}

	pub_key_cert->pub_key_usage = cert->key_usage;
	pub_key_cert->pub_key.rsa.modulus_size = cert->modulus_size;
	memcpy(pub_key_cert->pub_key.rsa.pub_exp, &cert->pub_exp, cert->pub_exp_size / 8);
	memcpy(pub_key_cert->pub_key.rsa.modulus, &cert->modulus, cert->modulus_size / 8);

	return STATUS_SUCCESS;
}
