/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _SEV_API_H
#define _SEV_API_H

#include <linux/types.h>

typedef struct __attribute__((__packed__)) sev_attestation_report_t {
	uint8_t mnonce[16];
	uint8_t launch_digest[32];
	uint32_t policy;
	uint32_t sig_usage;
	uint32_t sig_algo;
	uint32_t reserved;
	uint8_t sig1[144];
} sev_attestation_report;

// Appendix C.3: SEV Certificates
#define SEV_RSA_PUB_KEY_MAX_BITS   4096
#define SEV_ECDSA_PUB_KEY_MAX_BITS 576
#define SEV_ECDH_PUB_KEY_MAX_BITS  576
#define SEV_PUB_KEY_SIZE	   (SEV_RSA_PUB_KEY_MAX_BITS / 8)

// Appendix C.3.1 Public Key Formats - RSA Public Key
/**
 * SEV RSA Public key information.
 *
 * @modulus_size - Size of modulus in bits.
 * @pub_exp      - The public exponent of the public key.
 * @modulus      - The modulus of the public key.
 */
typedef struct __attribute__((__packed__)) sev_rsa_pub_key_t {
	uint32_t modulus_size;
	uint8_t pub_exp[SEV_RSA_PUB_KEY_MAX_BITS / 8];
	uint8_t modulus[SEV_RSA_PUB_KEY_MAX_BITS / 8];
} sev_rsa_pub_key;

/**
 * SEV Elliptical Curve algorithm details.
 *
 * @SEV_EC_INVALID - Invalid cipher size selected.
 * @SEV_EC_P256    - 256 bit elliptical curve cipher.
 * @SEV_EC_P384    - 384 bit elliptical curve cipher.
 */
typedef enum __attribute__((mode(QI)))
SEV_EC { SEV_EC_INVALID = 0,
	 SEV_EC_P256 = 1,
	 SEV_EC_P384 = 2,
} SEV_EC;

// Appendix C.3.2: Public Key Formats - ECDSA Public Key
/**
 * SEV Elliptical Curve DSA algorithm details.
 *
 * @curve - The SEV Elliptical curve ID.
 * @qx    - x component of the public point Q.
 * @qy    - y component of the public point Q.
 * @rmbz  - RESERVED. Must be zero!
 */
typedef struct __attribute__((__packed__)) sev_ecdsa_pub_key_t {
	uint32_t curve; // SEV_EC as a uint32_t
	uint8_t qx[SEV_ECDSA_PUB_KEY_MAX_BITS / 8];
	uint8_t qy[SEV_ECDSA_PUB_KEY_MAX_BITS / 8];
	uint8_t rmbz[SEV_PUB_KEY_SIZE - 2 * SEV_ECDSA_PUB_KEY_MAX_BITS / 8 - sizeof(uint32_t)];
} sev_ecdsa_pub_key;

// Appendix C.3.3: Public Key Formats - ECDH Public Key
/**
 * SEV Elliptical Curve Diffie Hellman Public Key details.
 *
 * @curve - The SEV Elliptical curve ID.
 * @qx    - x component of the public point Q.
 * @qy    - y component of the public point Q.
 * @rmbz  - RESERVED. Must be zero!
 */
typedef struct __attribute__((__packed__)) sev_ecdh_pub_key_t {
	uint32_t curve; // SEV_EC as a uint32_t
	uint8_t qx[SEV_ECDH_PUB_KEY_MAX_BITS / 8];
	uint8_t qy[SEV_ECDH_PUB_KEY_MAX_BITS / 8];
	uint8_t rmbz[SEV_PUB_KEY_SIZE - 2 * SEV_ECDH_PUB_KEY_MAX_BITS / 8 - sizeof(uint32_t)];
} sev_ecdh_pub_key;

// Appendix C.4: Public Key Formats
/**
 * The SEV Public Key memory slot may hold RSA, ECDSA, or ECDH.
 */
typedef union {
	sev_rsa_pub_key rsa;
	sev_ecdsa_pub_key ecdsa;
	sev_ecdh_pub_key ecdh;
} sev_pubkey;

// Appendix C.4: Signature Formats
/**
 * SEV Signature may be RSA or ECDSA.
 */
#define SEV_RSA_SIG_MAX_BITS	    4096
#define SEV_ECDSA_SIG_COMP_MAX_BITS 576
#define SEV_SIG_SIZE		    (SEV_RSA_SIG_MAX_BITS / 8)

// Appendix C.4.1: RSA Signature
/**
 * SEV RSA Signature data.
 *
 * @S - Signature bits.
 */
typedef struct __attribute__((__packed__)) sev_rsa_sig_t {
	uint8_t s[SEV_RSA_SIG_MAX_BITS / 8];
} sev_rsa_sig;

// Appendix C.4.2: ECDSA Signature
/**
 * SEV Elliptical Curve Signature data.
 *
 * @r    - R component of the signature.
 * @s    - S component of the signature.
 * @rmbz - RESERVED. Must be zero!
 */
typedef struct __attribute__((__packed__)) sev_ecdsa_sig_t {
	uint8_t r[SEV_ECDSA_SIG_COMP_MAX_BITS / 8];
	uint8_t s[SEV_ECDSA_SIG_COMP_MAX_BITS / 8];
	uint8_t rmbz[SEV_SIG_SIZE - 2 * SEV_ECDSA_SIG_COMP_MAX_BITS / 8];
} sev_ecdsa_sig;

/**
 * SEV Signature may be RSA or ECDSA.
 */
typedef union {
	sev_rsa_sig rsa;
	sev_ecdsa_sig ecdsa;
} sev_sig;

// Appendix C.1: USAGE Enumeration
/**
 * SEV Usage codes.
 */
typedef enum __attribute__((mode(HI))) SEV_USAGE {
	SEV_USAGE_ARK = 0x0,
	SEV_USAGE_ASK = 0x13,
	SEV_USAGE_INVALID = 0x1000,
	SEV_USAGE_OCA = 0x1001,
	SEV_USAGE_PEK = 0x1002,
	SEV_USAGE_PDH = 0x1003,
	SEV_USAGE_CEK = 0x1004,
} SEV_USAGE;

// Appendix C.1: ALGO Enumeration
/**
 * SEV Algorithm cipher codes.
 */
typedef enum __attribute__((mode(HI))) SEV_SIG_ALGO {
	SEV_SIG_ALGO_INVALID = 0x0,
	SEV_SIG_ALGO_RSA_SHA256 = 0x1,
	SEV_SIG_ALGO_ECDSA_SHA256 = 0x2,
	SEV_SIG_ALGO_ECDH_SHA256 = 0x3,
	SEV_SIG_ALGO_RSA_SHA384 = 0x101,
	SEV_SIG_ALGO_ECDSA_SHA384 = 0x102,
	SEV_SIG_ALGO_ECDH_SHA384 = 0x103,
} SEV_SIG_ALGO;

#define SEV_CERT_MAX_VERSION	1 // Max supported version
#define SEV_CERT_MAX_SIGNATURES 2 // Max number of sig's

// Appendix C.1: SEV Certificate Format
/**
 * SEV Certificate format.
 *
 * @version       - Certificate version, set to 01h.
 * @api_major     - If PEK, set to API major version, otherwise zero.
 * @api_minor     - If PEK, set to API minor version, otherwise zero.
 * @reserved_0    - RESERVED, Must be zero!
 * @reserved_1    - RESERVED, Must be zero!
 * @pub_key_usage - Public key usage              (SEV_SIG_USAGE).
 * @pub_key_algo  - Public key algorithm          (SEV_SIG_ALGO).
 * @pub_key       - Public Key.
 * @sig_1_usage   - Key usage of SIG1 signing key (SEV_SIG_USAGE).
 * @sig_1_algo    - First signature algorithm     (SEV_SIG_ALGO).
 * @sig_1         - First signature.
 * @sig_2_usage   - Key usage of SIG2 signing key (SEV_SIG_USAGE).
 * @sig_2_algo    - Second signature algorithm    (SEV_SIG_ALGO).
 * @sig_2         - Second signature
 */
typedef struct __attribute__((__packed__)) sev_cert_t {
	uint32_t version; // Certificate Version. Should be 1.
	uint8_t api_major; // Version of API generating the
	uint8_t api_minor; // certificate. Unused during validation.
	uint8_t reserved_0;
	uint8_t reserved_1;
	uint32_t pub_key_usage; // SEV_USAGE
	uint32_t pub_key_algo; // SEV_SIG_ALGO
	sev_pubkey pub_key;
	uint32_t sig_1_usage; // SEV_USAGE
	uint32_t sig_1_algo; // SEV_SIG_ALGO
	sev_sig sig_1;
	uint32_t sig_2_usage; // SEV_USAGE
	uint32_t sig_2_algo; // SEV_SIG_ALGO
	sev_sig sig_2;
} sev_cert;

typedef struct __attribute__((__packed__)) sev_evidence_t {
	sev_attestation_report attestation_report;
	sev_cert cek_cert;
	sev_cert pek_cert;
	sev_cert oca_cert;
} sev_evidence_t;

// Chapter 4.4 - Status Codes
/**
 * SEV Error Codes (each entry stored in a byte).
 */
typedef enum __attribute__((mode(HI))) SEV_ERROR_CODE {
	STATUS_SUCCESS = 0x00,
	ERROR_INVALID_PLATFORM_STATE = 0x01,
	ERROR_INVALID_GUEST_STATE = 0x02,
	ERROR_INVALID_CONFIG = 0x03,
	ERROR_INVALID_LENGTH = 0x04,
	ERROR_ALREADY_OWNED = 0x05,
	ERROR_INVALID_CERTIFICATE = 0x06,
	ERROR_POLICY_FAILURE = 0x07,
	ERROR_INACTIVE = 0x08,
	ERROR_INVALID_ADDRESS = 0x09,
	ERROR_BAD_SIGNATURE = 0x0A,
	ERROR_BAD_MEASUREMENT = 0x0B,
	ERROR_ASID_OWNED = 0x0C,
	ERROR_INVALID_ASID = 0x0D,
	ERROR_WBINVD_REQUIRED = 0x0E,
	ERROR_DF_FLUSH_REQUIRED = 0x0F,
	ERROR_INVALID_GUEST = 0x10,
	ERROR_INVALID_COMMAND = 0x11,
	ERROR_ACTIVE = 0x12,
	ERROR_HWERROR_PLATFORM = 0x13,
	ERROR_HWERROR_UNSAFE = 0x14,
	ERROR_UNSUPPORTED = 0x15,
	ERROR_INVALID_PARAM = 0x16,
	ERROR_RESOURCE_LIMIT = 0x17,
	ERROR_SECURE_DATA_INVALID = 0x18,

	// SNP
	ERROR_INVALID_PAGE_SIZE = 0x19,
	ERROR_INVALID_PAGE_STATE = 0x1A,
	ERROR_INVALID_MDATA_ENTRY = 0x1B,
	ERROR_INVALID_PAGE_OWNER = 0x1C,
	ERROR_AEAD_OFLOW = 0x1D,

	ERROR_RING_BUFFER_EXIT = 0x1F,
	ERROR_LIMIT,
} SEV_ERROR_CODE;

// ------------------------------------------------------------ //
// --- Definition of API-defined Encryption and HMAC values --- //
// ------------------------------------------------------------ //

// Chapter 2 - Summary of Keys
typedef uint8_t aes_128_key[128 / 8];
typedef uint8_t hmac_key_128[128 / 8];
typedef uint8_t hmac_sha_256[256 / 8]; // 256
typedef uint8_t hmac_sha_512[512 / 8]; // 384, 512

// Appendix B.1: Certificate Format
typedef union {
	uint8_t short_len[2048 / 8];
	uint8_t long_len[4096 / 8];
} amd_cert_pub_exp;

typedef union {
	uint8_t short_len[2048 / 8];
	uint8_t long_len[4096 / 8];
} amd_cert_mod;

typedef union {
	uint8_t short_len[2048 / 8];
	uint8_t long_len[4096 / 8];
} amd_cert_sig;

typedef enum __attribute__((mode(QI))) AMD_SIG_USAGE {
	AMD_USAGE_ARK = 0x00,
	AMD_USAGE_ASK = 0x13,
} AMD_SIG_USAGE;

// Appendix B.1: AMD Signing Key Certificate Format
typedef struct __attribute__((__packed__)) amd_cert_t {
	uint32_t version; // Certificate Version. Should be 1.
	uint64_t key_id_0; // The unique ID for this key
	uint64_t key_id_1;
	uint64_t certifying_id_0; // The unique ID for the key that signed this cert.
	uint64_t certifying_id_1; // If this cert is self-signed, then equals KEY_ID field.
	uint32_t key_usage; // AMD_SIG_USAGE
	uint64_t reserved_0;
	uint64_t reserved_1;
	uint32_t pub_exp_size; // Size of public exponent in bits. Must be 2048/4096.
	uint32_t modulus_size; // Size of modulus in bits. Must be 2048/4096.
	amd_cert_pub_exp pub_exp; // Public exponent of this key. Size is pub_exp_size.
	amd_cert_mod modulus; // Public modulus of this key. Size is modulus_size.
	amd_cert_sig sig; // Public signature of this key. Size is modulus_size.
} amd_cert;

#define AMD_SEV_DEVELOPER_SITE "https://developer.amd.com/sev/"
#define ASK_ARK_PATH_SITE      "https://developer.amd.com/wp-content/resources/"

#define ASK_ARK_FILENAME    "ask_ark.cert"
#define ASK_ARK_NAPLES_FILE "ask_ark_naples.cert"
#define ASK_ARK_ROME_FILE   "ask_ark_rome.cert"
#define ASK_ARK_MILAN_FILE  "ask_ark_milan.cert"

#define ASK_ARK_NAPLES_SITE ASK_ARK_PATH_SITE ASK_ARK_NAPLES_FILE
#define ASK_ARK_ROME_SITE   ASK_ARK_PATH_SITE ASK_ARK_ROME_FILE
#define ASK_ARK_MILAN_SITE  ASK_ARK_PATH_SITE ASK_ARK_MILAN_FILE

enum __attribute__((mode(QI))) ePSP_DEVICE_TYPE {
	PSP_DEVICE_TYPE_INVALID = 0,
	PSP_DEVICE_TYPE_NAPLES = 1,
	PSP_DEVICE_TYPE_ROME = 2,
	PSP_DEVICE_TYPE_MILAN = 3,
};

typedef enum __attribute__((mode(QI))) SHA_TYPE {
	SHA_TYPE_256 = 0,
	SHA_TYPE_384 = 1,
} SHA_TYPE;

#endif
