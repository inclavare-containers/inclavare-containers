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
#include <sys/types.h>
#include <openssl/evp.h>
#include <openssl/ts.h>
#include <openssl/ecdh.h>
#include "utils.h"

/**
 * Description: Validates the usage parameter of an sev_cert
 * Notes:       sev_cert.c  -> usage_is_valid()
 * Parameters:  [usage] is the input value to be validated
 */
SEV_ERROR_CODE validate_usage(uint32_t usage)
{
	SEV_ERROR_CODE cmd_ret = ERROR_INVALID_CERTIFICATE;

	switch (usage) {
	case SEV_USAGE_ARK:
	case SEV_USAGE_ASK:
	case SEV_USAGE_OCA:
	case SEV_USAGE_PEK:
	case SEV_USAGE_PDH:
	case SEV_USAGE_CEK:
		cmd_ret = STATUS_SUCCESS;
		break;
	default:
		cmd_ret = ERROR_INVALID_CERTIFICATE;
	}

	return cmd_ret;
}

/**
 * Description: Validates the body (version through and including reserved1) of
 *              an sev_cert. Separate functions are used to validate the pubkey
 *              and the sigs
 * Notes:       sev_cert.c -> sev_cert_validate_body()
 * Parameters:  [cert] the sev_cert which to validate the body of
 */
SEV_ERROR_CODE validate_body(const sev_cert *cert)
{
	if (!cert)
		return ERROR_INVALID_CERTIFICATE;

	if ((cert->version == 0) || (cert->version > SEV_CERT_MAX_VERSION))
		return ERROR_INVALID_CERTIFICATE;

	return STATUS_SUCCESS;
}

/**
 * Description: When a .cert file is imported, the PubKey is in sev_cert
 *              format. This function converts that format into a EVP_PKEY
 *              format where it can be used by other openssl functions.
 * Note:        This function NEWs/allocates memory for a EC_KEY that must be
 *              freed in the calling function using EC_KEY_free()
 * Parameters:  [cert] is the source sev_cert containing the public key we want
 *               to extract
 *              [evp_pubkey] is the destination EVP_PKEY where the extracted
 *               public key will go into
 */
SEV_ERROR_CODE compile_public_key_from_certificate(const sev_cert *cert, EVP_PKEY *evp_pub_key)
{
	if (!cert)
		return ERROR_INVALID_CERTIFICATE;

	SEV_ERROR_CODE cmd_ret = ERROR_INVALID_CERTIFICATE;
	RSA *rsa_pub_key = NULL;
	EC_KEY *ec_pub_key = NULL;
	BIGNUM *x_big_num = NULL;
	BIGNUM *y_big_num = NULL;
	BIGNUM *modulus = NULL;
	BIGNUM *pub_exp = NULL;

	if ((cert->pub_key_algo == SEV_SIG_ALGO_RSA_SHA256) ||
	    (cert->pub_key_algo == SEV_SIG_ALGO_RSA_SHA384)) {
		// New up the RSA key
		rsa_pub_key = RSA_new();

		// Convert the parent to an RSA key to pass into RSA_verify
		modulus = BN_lebin2bn((uint8_t *)&cert->pub_key.rsa.modulus,
				      cert->pub_key.rsa.modulus_size / 8,
				      NULL); // n    // New's up BigNum
		pub_exp = BN_lebin2bn((uint8_t *)&cert->pub_key.rsa.pub_exp,
				      cert->pub_key.rsa.modulus_size / 8, NULL); // e
		if (RSA_set0_key(rsa_pub_key, modulus, pub_exp, NULL) != 1)
			goto err;

		/*
         * Create a public EVP_PKEY from the public RSA_KEY
         * This function links evp_pub_key to rsa_pub_key, so when evp_pub_key
         *  is freed, rsa_pub_key is freed. We don't want the user to have to
         *  manage 2 keys, so just return EVP_PKEY and make sure user free's it
         */
		if (EVP_PKEY_assign_RSA(evp_pub_key, rsa_pub_key) != 1)
			goto err;

	} else if ((cert->pub_key_algo == SEV_SIG_ALGO_ECDSA_SHA256) ||
		   (cert->pub_key_algo == SEV_SIG_ALGO_ECDSA_SHA384) ||
		   (cert->pub_key_algo == SEV_SIG_ALGO_ECDH_SHA256) ||
		   (cert->pub_key_algo == SEV_SIG_ALGO_ECDH_SHA384)) { // ecdsa.c -> sign_verify_msg

		// Store the x and y components as separate BIGNUM objects. The values in the
		// SEV certificate are little-endian, must reverse bytes before storing in BIGNUM
		if ((cert->pub_key_algo == SEV_SIG_ALGO_ECDSA_SHA256) ||
		    (cert->pub_key_algo == SEV_SIG_ALGO_ECDSA_SHA384)) {
			x_big_num = BN_lebin2bn(cert->pub_key.ecdsa.qx,
						sizeof(cert->pub_key.ecdsa.qx),
						NULL); // New's up BigNum
			y_big_num = BN_lebin2bn(cert->pub_key.ecdsa.qy,
						sizeof(cert->pub_key.ecdsa.qy), NULL);
		} else if ((cert->pub_key_algo == SEV_SIG_ALGO_ECDH_SHA256) ||
			   (cert->pub_key_algo == SEV_SIG_ALGO_ECDH_SHA384)) {
			x_big_num = BN_lebin2bn(cert->pub_key.ecdh.qx,
						sizeof(cert->pub_key.ecdh.qx),
						NULL); // New's up BigNum
			y_big_num = BN_lebin2bn(cert->pub_key.ecdh.qy,
						sizeof(cert->pub_key.ecdh.qy), NULL);
		}

		int nid = EC_curve_nist2nid("P-384"); // NID_secp384r1

		// Create/allocate memory for an EC_KEY object using the NID above
		if (!(ec_pub_key = EC_KEY_new_by_curve_name(nid)))
			goto err;
		// Store the x and y coordinates of the public key
		if (EC_KEY_set_public_key_affine_coordinates(ec_pub_key, x_big_num, y_big_num) != 1)
			goto err;
		// Make sure the key is good
		if (EC_KEY_check_key(ec_pub_key) != 1)
			goto err;

		/*
             * Create a public EVP_PKEY from the public EC_KEY
             * This function links evp_pub_key to ec_pub_key, so when evp_pub_key
             *  is freed, ec_pub_key is freed. We don't want the user to have to
             *  manage 2 keys, so just return EVP_PKEY and make sure user free's it
             */
		if (EVP_PKEY_assign_EC_KEY(evp_pub_key, ec_pub_key) != 1)
			goto err;
	}

	if (!evp_pub_key)
		goto err;

	cmd_ret = STATUS_SUCCESS;

err:
	// Free memory if it was allocated
	BN_free(y_big_num); // If NULL, does nothing
	BN_free(x_big_num);
	// BN_free(modulus);   // Don't free here. RSA key is associated with these
	// BN_free(pub_exp);

	return cmd_ret;
}

/**
 * Calculate the complete SHA256/SHA384 digest of the input message.
 * Use for RSA and ECDSA, not ECDH
 * Formerly called CalcHashDigest
 *
 * params:
 *   msg       : message buffer to hash.
 *   msg_len   : length of the input message.
 *               - For SEV_CERTs, use PubKeyOffset (number of bytes to be hashed,
 *                 from the top of the sev_cert until the first signature.
 *                 Version through and including pub_key)
 *   digest    : output buffer for the final digest.
 *   digest_len: length of the output buffer.
 */
bool digest_sha(const void *msg, size_t msg_len, uint8_t *digest, size_t digest_len,
		SHA_TYPE sha_type)
{
	//TODO 384 vs 512 is all a mess
	if ((sha_type == SHA_TYPE_256 && digest_len != SHA256_DIGEST_LENGTH) /* ||
            (sha_type == SHA_TYPE_384 && digest_len != SHA384_DIGEST_LENGTH)*/)
		return false;

	if (sha_type == SHA_TYPE_256) {
		SHA256_CTX context;

		if (SHA256_Init(&context) != 1)
			return false;
		if (SHA256_Update(&context, (void *)msg, msg_len) != 1)
			return false;
		if (SHA256_Final(digest, &context) != 1)
			return false;
	} else if (sha_type == SHA_TYPE_384) {
		SHA512_CTX context;

		if (SHA384_Init(&context) != 1)
			return false;
		if (SHA384_Update(&context, (void *)msg, msg_len) != 1)
			return false;
		if (SHA384_Final(digest, &context) != 1)
			return false;
	}

	return true;
}

/**
 * Description:
 * Notes:       sev_cert.c -> sev_cert_validate_sig()
 *              This function gets called from a loop, and this function has
 *              to see which of the signatures this currentSig matches to
 * Parameters:  [child_cert] the cert which we want to validate the signature of.
 *               This is the cert that gets hashed and validated
 *              [parent_cert] tells us the algo used to sign the child cert
 *              [parent_signing_key] used to validate the hash of the child cert
 *              Ex) child_cert = PEK. parent_cert = OCA. parent_signing_key = OCA PubKey
 */
SEV_ERROR_CODE validate_signature(const sev_cert *child_cert, const sev_cert *parent_cert,
				  EVP_PKEY *parent_signing_key) // Probably PubKey
{
	if (!child_cert || !parent_cert || !parent_signing_key)
		return ERROR_INVALID_CERTIFICATE;

	SEV_ERROR_CODE cmd_ret = ERROR_INVALID_CERTIFICATE;
	sev_sig cert_sig[SEV_CERT_MAX_SIGNATURES] = { child_cert->sig_1, child_cert->sig_2 };
	hmac_sha_256 sha_digest_256; // Hash on the cert from Version to PubKey
	hmac_sha_512 sha_digest_384; // Hash on the cert from Version to PubKey
	SHA_TYPE sha_type;
	uint8_t *sha_digest = NULL;
	size_t sha_length = 0;

	// TODO should this be child cert? should prob combine this function anyway
	// Determine if SHA_TYPE is 256 bit or 384 bit
	if (parent_cert->pub_key_algo == SEV_SIG_ALGO_RSA_SHA256 ||
	    parent_cert->pub_key_algo == SEV_SIG_ALGO_ECDSA_SHA256 ||
	    parent_cert->pub_key_algo == SEV_SIG_ALGO_ECDH_SHA256) {
		sha_type = SHA_TYPE_256;
		sha_digest = sha_digest_256;
		sha_length = sizeof(hmac_sha_256);
	} else if (parent_cert->pub_key_algo ==
			   SEV_SIG_ALGO_RSA_SHA384 || // SEV_SIG_ALGO_RSA_SHA384
		   parent_cert->pub_key_algo == SEV_SIG_ALGO_ECDSA_SHA384 ||
		   parent_cert->pub_key_algo == SEV_SIG_ALGO_ECDH_SHA384) {
		sha_type = SHA_TYPE_384;
		sha_digest = sha_digest_384;
		sha_length = sizeof(hmac_sha_512);
	} else {
		return cmd_ret;
	}

	// 1. SHA256 hash the cert from Version through pub_key parameters
	// Calculate the digest of the input message   rsa.c -> rsa_pss_verify_msg()
	// SHA256/SHA384 hash the cert from the [Version:pub_key] params
	uint32_t pub_key_offset = offsetof(sev_cert, sig_1_usage); // 16 + sizeof(SEV_PUBKEY)
	if (!digest_sha((uint8_t *)child_cert, pub_key_offset, sha_digest, sha_length, sha_type)) {
		return cmd_ret;
	}

	// 2. Use the pub_key in sig[i] arg to decrypt the sig in child_cert arg
	// Try both sigs in child_cert, to see if either of them match. In PEK, CEK and OCA can be in any order
	bool found_match = false;
	for (int i = 0; i < SEV_CERT_MAX_SIGNATURES; i++) {
		if ((parent_cert->pub_key_algo == SEV_SIG_ALGO_RSA_SHA256) ||
		    (parent_cert->pub_key_algo == SEV_SIG_ALGO_RSA_SHA384)) {
			uint32_t sig_len = parent_cert->pub_key.rsa.modulus_size / 8;
			// // Should be child_cert but SEV_RSA_SIG doesn't have a size param
			uint8_t decrypted[4096] = { 0 }; // TODO wrong length
			uint8_t signature[4096] = { 0 };

			RSA *rsa_pub_key = EVP_PKEY_get1_RSA(
				parent_signing_key); // Signer's (parent's) public key
			if (!rsa_pub_key) {
				RTLS_ERR("Error parent signing key is bad\n");
				break;
			}

			// Swap the bytes of the signature
			memcpy(signature, &cert_sig[i].rsa,
			       parent_cert->pub_key.rsa.modulus_size / 8);
			if (!reverse_bytes(signature, parent_cert->pub_key.rsa.modulus_size / 8))
				break;

			// Now we will verify the signature. Start by a RAW decrypt of the signature
			if (RSA_public_decrypt(sig_len, signature, decrypted, rsa_pub_key,
					       RSA_NO_PADDING) == -1)
				break;

			// Verify the data
			// SLen of -2 means salt length is recovered from the signature
			if (RSA_verify_PKCS1_PSS(rsa_pub_key, sha_digest,
						 (parent_cert->pub_key_algo ==
						  SEV_SIG_ALGO_RSA_SHA256) ?
							       EVP_sha256() :
							       EVP_sha384(),
						 decrypted, -2) != 1) {
				RSA_free(rsa_pub_key);
				continue;
			}

			found_match = true;
			RSA_free(rsa_pub_key);
			break;
		} else if ((parent_cert->pub_key_algo == SEV_SIG_ALGO_ECDSA_SHA256) ||
			   (parent_cert->pub_key_algo == SEV_SIG_ALGO_ECDSA_SHA384) ||
			   (parent_cert->pub_key_algo == SEV_SIG_ALGO_ECDH_SHA256) ||
			   (parent_cert->pub_key_algo == SEV_SIG_ALGO_ECDH_SHA384)) {
			ECDSA_SIG *tmp_ecdsa_sig = ECDSA_SIG_new();
			BIGNUM *r_big_num = BN_new();
			BIGNUM *s_big_num = BN_new();

			// Store the x and y components as separate BIGNUM objects. The values in the
			// SEV certificate are little-endian, must reverse bytes before storing in BIGNUM
			r_big_num = BN_lebin2bn(cert_sig[i].ecdsa.r, 72,
						r_big_num); // LE to BE
			s_big_num = BN_lebin2bn(cert_sig[i].ecdsa.s, 72, s_big_num);

			// Calling ECDSA_SIG_set0() transfers the memory management of the values to
			// the ECDSA_SIG object, and therefore the values that have been passed
			// in should not be freed directly after this function has been called
			if (ECDSA_SIG_set0(tmp_ecdsa_sig, r_big_num, s_big_num) != 1) {
				BN_free(s_big_num); // Frees BIGNUMs manually here
				BN_free(r_big_num);
				ECDSA_SIG_free(tmp_ecdsa_sig);
				continue;
			}
			EC_KEY *tmp_ec_key = EVP_PKEY_get1_EC_KEY(
				parent_signing_key); // Make a local key so you can free it later
			if (ECDSA_do_verify(sha_digest, (uint32_t)sha_length, tmp_ecdsa_sig,
					    tmp_ec_key) != 1) {
				EC_KEY_free(tmp_ec_key);
				ECDSA_SIG_free(tmp_ecdsa_sig); // Frees BIGNUMs too
				continue;
			}

			found_match = true;
			EC_KEY_free(tmp_ec_key);
			ECDSA_SIG_free(tmp_ecdsa_sig); // Frees BIGNUMs too
			break;
		} else { // Bad/unsupported signing key algorithm
			RTLS_ERR("Unexpected algorithm! %x\n", parent_cert->pub_key_algo);
			break;
		}
	}

	if (!found_match)
		return cmd_ret;

	// 3. Compare

	cmd_ret = STATUS_SUCCESS;

	return cmd_ret;
}

/**
 * Description: Gets called from ValidatePublicKey as a subfunction to do the
 *              work of actually validating an RSA public key
 * Notes:       rsa.c -> rsa_pubkey_is_valid()
 * Parameters:  [cert] the input sev_cert to validate the public key of
 *              [public_key] currently unused
 *
 * This function is untested because we don't have any RSA SEV_CERTs to test
 */
SEV_ERROR_CODE validate_rsa_pub_key(const sev_cert *cert, const EVP_PKEY *PublicKey)
{
	if (!cert || !PublicKey)
		return ERROR_INVALID_CERTIFICATE;

	SEV_ERROR_CODE cmd_ret = ERROR_INVALID_CERTIFICATE;

	if (cert->pub_key.rsa.modulus_size <= SEV_RSA_PUB_KEY_MAX_BITS) // bits
		cmd_ret = STATUS_SUCCESS;

	return cmd_ret;
}

/**
 * Description: The generic function to validate the public key of an sev_cert.
 *              Calls ValidateRSAPubkey to actually do the work for an RSA pubkey
 * Notes:       rsa.c -> pubkey_is_valid()
 * Parameters:  [cert] is the child cert
 *              [PublicKey] is the parent's public key
 */
SEV_ERROR_CODE validate_public_key(const sev_cert *cert, const EVP_PKEY *PublicKey)
{
	if (!cert || !PublicKey)
		return ERROR_INVALID_CERTIFICATE;

	SEV_ERROR_CODE cmd_ret = ERROR_INVALID_CERTIFICATE;

	if (validate_usage(cert->pub_key_usage) != STATUS_SUCCESS)
		return ERROR_INVALID_CERTIFICATE;

	if ((cert->pub_key_algo == SEV_SIG_ALGO_RSA_SHA256) ||
	    (cert->pub_key_algo == SEV_SIG_ALGO_RSA_SHA384)) {
		if (validate_rsa_pub_key(cert, PublicKey) != STATUS_SUCCESS)
			return ERROR_INVALID_CERTIFICATE;
	} else if ((cert->pub_key_algo == SEV_SIG_ALGO_ECDSA_SHA256) ||
		   (cert->pub_key_algo == SEV_SIG_ALGO_ECDSA_SHA384) ||
		   (cert->pub_key_algo == SEV_SIG_ALGO_ECDH_SHA256) ||
		   (cert->pub_key_algo == SEV_SIG_ALGO_ECDH_SHA384))
		; // Are no invalid values for these cert types
	else
		return ERROR_INVALID_CERTIFICATE;

	return STATUS_SUCCESS;
}

/**
 * Description: Takes in a signed certificate and validates the signature(s)
 *              against the public keys in other certificates
 * Notes:       This test assumes parent_cert1 is always valid, and parent_cert2
 *              may be valid
 *              sev_cert.c -> sev_cert_validate()
 * Parameters:  [parent_cert1][parent_cert2] these are used to validate the 1 or 2
 *              signatures in the child cert (passed into the class constructor)
 */
SEV_ERROR_CODE verify_sev_cert(const sev_cert *child_cert, const sev_cert *parent_cert1,
			       const sev_cert *parent_cert2)
{
	RTLS_DEBUG("child_cert %p, parent_cert1 %p, parent_cert2 %p\n", child_cert, parent_cert1,
		   parent_cert2);
	if (!parent_cert1)
		return ERROR_INVALID_CERTIFICATE;

	SEV_ERROR_CODE cmd_ret = ERROR_INVALID_CERTIFICATE;
	EVP_PKEY *parent_pub_key[SEV_CERT_MAX_SIGNATURES] = { NULL };
	const sev_cert *parent_cert[SEV_CERT_MAX_SIGNATURES] = {
		parent_cert1, parent_cert2
	}; // A cert has max of x parents/sigs

	// Get the public key from parent certs
	int numSigs = (parent_cert1 && parent_cert2) ? 2 : 1; // Run the loop for 1 or 2 signatures
	int i = 0;
	for (i = 0; i < numSigs; i++) {
		// New up the EVP_PKEY
		if (!(parent_pub_key[i] = EVP_PKEY_new()))
			goto err;

		// This function allocates memory and attaches an EC_Key
		// to your EVP_PKEY so, to prevent mem leaks, make sure
		// the EVP_PKEY is freed at the end of this function
		if (compile_public_key_from_certificate(parent_cert[i], parent_pub_key[i]) !=
		    STATUS_SUCCESS)
			goto err;

		// Now, we have Parent's PublicKey(s), validate them
		if (validate_public_key(child_cert, parent_pub_key[i]) != STATUS_SUCCESS)
			goto err;

		// Validate the signature before we do any other checking
		// Sub-function will need a separate loop to find which of the 2 signatures this one matches to
		if (validate_signature(child_cert, parent_cert[i], parent_pub_key[i]) !=
		    STATUS_SUCCESS)
			goto err;
	}

	if (i != numSigs)
		goto err;

	// Validate the certificate body
	if (validate_body(child_cert) != STATUS_SUCCESS)
		goto err;

	// Although the signature was valid, ensure that the certificate
	// was signed with the proper key(s) in the correct order
	if (child_cert->pub_key_usage == SEV_USAGE_PDH) {
		// The PDH certificate must be signed by the PEK
		if (parent_cert1->pub_key_usage != SEV_USAGE_PEK) {
			goto err;
		}
	} else if (child_cert->pub_key_usage == SEV_USAGE_PEK) {
		// The PEK certificate must be signed by the CEK and the OCA
		if (((parent_cert1->pub_key_usage != SEV_USAGE_OCA) &&
		     (parent_cert2->pub_key_usage != SEV_USAGE_CEK)) &&
		    ((parent_cert2->pub_key_usage != SEV_USAGE_OCA) &&
		     (parent_cert1->pub_key_usage != SEV_USAGE_CEK))) {
			goto err;
		}
	} else if (child_cert->pub_key_usage == SEV_USAGE_OCA) {
		// The OCA certificate must be self-signed
		if (parent_cert1->pub_key_usage != SEV_USAGE_OCA) {
			goto err;
		}
	} else if (child_cert->pub_key_usage == SEV_USAGE_CEK) {
		// The CEK must be signed by the ASK
		if (parent_cert1->pub_key_usage != SEV_USAGE_ASK) {
			goto err;
		}
	} else
		goto err;

	cmd_ret = STATUS_SUCCESS;

err:
	// Free memory
	for (int i = 0; i < SEV_CERT_MAX_SIGNATURES; i++) {
		EVP_PKEY_free(parent_pub_key[i]);
	}

	return cmd_ret;
}

/*
 * It would be easier if we could just pass in the populated ECDSA_SIG from
 *  ecdsa_sign instead of using sev_sig to BigNums as the intermediary, but we
 *  do need to ecdsa_verify to verify something signed by firmware, so we
 *  wouldn't have the ECDSA_SIG
 */
bool ecdsa_verify(sev_sig *sig, EVP_PKEY **pub_evp_key, uint8_t *digest, size_t length)
{
	bool is_valid = false;
	EC_KEY *pub_ec_key = NULL;
	BIGNUM *r = NULL;
	BIGNUM *s = NULL;
	ECDSA_SIG *ecdsa_sig = NULL;

	pub_ec_key = EVP_PKEY_get1_EC_KEY(*pub_evp_key);
	if (!pub_ec_key) {
		EC_KEY_free(pub_ec_key);
		return is_valid;
	}

	// Store the x and y components as separate BIGNUM objects. The values in the
	// SEV certificate are little-endian, must reverse bytes before storing in BIGNUM
	r = BN_lebin2bn(sig->ecdsa.r, sizeof(sig->ecdsa.r), NULL); // New's up BigNum
	s = BN_lebin2bn(sig->ecdsa.s, sizeof(sig->ecdsa.s), NULL);

	// Create a ecdsa_sig from the bignums and store in sig
	ecdsa_sig = ECDSA_SIG_new();
	ECDSA_SIG_set0(ecdsa_sig, r, s);

	// Validation will also be done by the FW
	if (ECDSA_do_verify(digest, (uint32_t)length, ecdsa_sig, pub_ec_key) != 1)
		goto err;

	is_valid = true;

err:
	ECDSA_SIG_free(ecdsa_sig);
	EC_KEY_free(pub_ec_key);
	return is_valid;
}

/**
 * rsa_pss_verify
 */
#define BITS_PER_BYTE 8
static bool rsa_verify(sev_sig *sig, EVP_PKEY **evp_pub_key, const uint8_t *sha_digest,
		       size_t sha_length, SHA_TYPE sha_type, bool pss)
{
	bool is_valid = false;
	RSA *rsa_pub_key = NULL;
	uint32_t sig_len = 0;

	// Pull the RSA key from the EVP_PKEY
	rsa_pub_key = EVP_PKEY_get1_RSA(*evp_pub_key);
	if (!rsa_pub_key)
		return is_valid;

	sig_len = RSA_size(rsa_pub_key);

	if (pss) {
		uint8_t decrypted[4096 / BITS_PER_BYTE] = { 0 }; // TODO wrong length
		uint8_t signature[4096 / BITS_PER_BYTE] = { 0 };

		// Memzero all the buffers
		memset(decrypted, 0, sizeof(decrypted));
		memset(signature, 0, sizeof(signature));

		// Swap the bytes of the signature
		memcpy(signature, sig->rsa.s, 4096 / BITS_PER_BYTE);
		if (!reverse_bytes(signature, 4096 / BITS_PER_BYTE))
			return is_valid;

		// Now we will verify the signature. Start by a RAW decrypt of the signature
		if (RSA_public_decrypt(sig_len, signature, decrypted, rsa_pub_key,
				       RSA_NO_PADDING) == -1)
			return is_valid;

		// Verify the data
		// SLen of -2 means salt length is recovered from the signature
		if (RSA_verify_PKCS1_PSS(rsa_pub_key, sha_digest,
					 (sha_type == SHA_TYPE_256) ? EVP_sha256() : EVP_sha384(),
					 decrypted, -2) != 1) {
			printf("Error: rsa_verify with pss Failed\n");
			return is_valid;
		}
	} else {
		// Verify the data
		if (RSA_verify((sha_type == SHA_TYPE_256) ? NID_sha256 : NID_sha384, sha_digest,
			       (uint32_t)sha_length, sig->rsa.s, sig_len, rsa_pub_key) != 1) {
			RTLS_ERR("Error: rsa_verify without pss Failed\n");
			return is_valid;
		}
	}

	is_valid = true;

	// Free the keys and contexts
	// if (rsa_pub_key)
	//     RSA_free(rsa_pub_key);

	// if (md_ctx)
	//     EVP_MD_CTX_free(md_ctx);

	return is_valid;
}

static bool verify_message(sev_sig *sig, EVP_PKEY **evp_key_pair, const uint8_t *msg, size_t length,
			   const SEV_SIG_ALGO algo)
{
	hmac_sha_256 sha_digest_256; // Hash on the cert from Version to PubKey
	hmac_sha_512 sha_digest_384; // Hash on the cert from Version to PubKey
	SHA_TYPE sha_type;
	uint8_t *sha_digest = NULL;
	size_t sha_length;
	const bool pss = true;

	// Determine if SHA_TYPE is 256 bit or 384 bit
	if (algo == SEV_SIG_ALGO_RSA_SHA256 || algo == SEV_SIG_ALGO_ECDSA_SHA256 ||
	    algo == SEV_SIG_ALGO_ECDH_SHA256) {
		sha_type = SHA_TYPE_256;
		sha_digest = sha_digest_256;
		sha_length = sizeof(hmac_sha_256);
	} else if (algo == SEV_SIG_ALGO_RSA_SHA384 || algo == SEV_SIG_ALGO_ECDSA_SHA384 ||
		   algo == SEV_SIG_ALGO_ECDH_SHA384) {
		sha_type = SHA_TYPE_384;
		sha_digest = sha_digest_384;
		sha_length = sizeof(hmac_sha_512);
	} else {
		return false;
	}

	memset(sha_digest, 0, sha_length);

	// Calculate the hash digest
	if (!digest_sha(msg, length, sha_digest, sha_length, sha_type))
		return false;

	if ((algo == SEV_SIG_ALGO_RSA_SHA256) || (algo == SEV_SIG_ALGO_RSA_SHA384)) {
		if (!rsa_verify(sig, evp_key_pair, sha_digest, sha_length, sha_type, pss))
			return false;
	} else if ((algo == SEV_SIG_ALGO_ECDSA_SHA256) || (algo == SEV_SIG_ALGO_ECDSA_SHA384)) {
		if (!ecdsa_verify(sig, evp_key_pair, sha_digest, sha_length))
			return false;
	} else if ((algo == SEV_SIG_ALGO_ECDH_SHA256) || (algo == SEV_SIG_ALGO_ECDH_SHA384)) {
		RTLS_ERR("Error: ECDH signing unsupported");
		return false; // Error unsupported
	} else {
		RTLS_ERR("Error: invalid signing algo. Can't sign");
		return false; // Invalid params
	}

	return true;
}

int validate_attestation(sev_cert *pek, sev_attestation_report *report)
{
	int cmd_ret = -1;

	EVP_PKEY *pek_pub_key = NULL;
	if (!(pek_pub_key = EVP_PKEY_new()))
		return cmd_ret;

	// Get the friend's Public EVP_PKEY from the certificate
	// This function allocates memory and attaches an EC_Key
	//  to your EVP_PKEY so, to prevent mem leaks, make sure
	//  the EVP_PKEY is freed at the end of this function
	if (compile_public_key_from_certificate(pek, pek_pub_key) != STATUS_SUCCESS)
		goto err;

	// Validate the report
	if (!verify_message((sev_sig *)&report->sig1, &pek_pub_key, (const uint8_t *)report,
			    offsetof(sev_attestation_report, sig_usage), SEV_SIG_ALGO_ECDSA_SHA256))
		goto err;

	cmd_ret = 0;

err:
	// Free memory
	EVP_PKEY_free(pek_pub_key);
	return cmd_ret;
}
