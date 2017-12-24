#include <openssl/sha.h>
#include <openssl/ripemd.h>

static void _hash256(uint8_t *digest, const uint8_t *message, size_t len) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, message, len);
    SHA256_Final(digest, &ctx);
}

static void _rmd160(uint8_t *digest, const uint8_t *message, size_t len) {
    RIPEMD160_CTX ctx;
    RIPEMD160_Init(&ctx);
    RIPEMD160_Update(&ctx, message, len);
    RIPEMD160_Final(digest, &ctx);
}

static void sha2_hash160(uint8_t *digest, const uint8_t *message, size_t len) {
    uint8_t tmp[SHA256_DIGEST_LENGTH];
    bbp_sha256(tmp, message, len);
    bbp_rmd160(digest, tmp, SHA256_DIGEST_LENGTH);
}

int main(int argc, char** argv)
{
    uint8_t _digest[32];
    char _msg[] = "This is protected message"; 

    // get digest
    sha2_hash160(_digest, (uint8_t)_msg, sizeof(_msg) - 1);

    // sign with private key


    // verify with public key 
 
}
