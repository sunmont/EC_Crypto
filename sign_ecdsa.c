#include <openssl/ec.h> 
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

static int _sign(uint8_t* hash)
{
    int r;

    EC_KEY *eckey=EC_KEY_new();
    if (!eckey) return -1;

    EC_GROUP *ecgroup= EC_GROUP_new_by_curve_name(NID_secp192k1);
    if (!ecgroup) return -1;

    r = EC_KEY_set_group(eckey, ecgroup);
    if (r != 1) return -2;

    r = EC_KEY_generate_key(eckey);
    if (r != 1) return -3;

    ECDSA_SIG *sig = ECDSA_do_sign(hash, strlen(hash), eckey);
    if (!sig) return -1;

    printf("r: %s\n", BN_bn2hex(sig->r));
    printf("s: %s\n", BN_bn2hex(sig->s));

    // i2d_ECDSA_SIG(sign, &der);

    ECDSA_SIG_free(sig);
    EC_KEY_free(ckey);
    EC_GROUP_free(ecgroup);

    return 0;
}    

static int _verify(uint8_t* hash, size_t hash_len, ECDSA_SIG* sig, EC_KEY *_pub_key)
{
    int r;

    r = ECDSA_do_verify(hash, hash_len, sig, _pub_key);
    if (r != 1)
    {
        return -1;
    }

    return 0;
}


