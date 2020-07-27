#include <wolfssl/wolfcrypt/sha256.h>

void sha256_rsa_pubkey
(
    unsigned char hash[SHA256_DIGEST_SIZE],
    RsaKey* key
);
