#include "dh.h"

#include <stdio.h>
#include <stdlib.h>
#include <openssl/bn.h>
#include <openssl/sha.h>


/*
 * RFC 3526, 2048-bit MODP Group 14
 */
static const char *GROUP14_PRIME =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF";

#define GROUP14_GENERATOR 2


int dh_generate_keypair(DHKeyPair *keypair)
{
    BIGNUM *p = NULL;
    BIGNUM *g = NULL;
    BN_CTX *ctx = NULL;

    if (keypair == NULL) {
        return 0;
    }

    keypair->private_key = NULL;
    keypair->public_key = NULL;

    /*
     * Create the group parameters.
     */
    p = BN_new();
    g = BN_new();
    ctx = BN_CTX_new();

    if (p == NULL || g == NULL || ctx == NULL) {
        goto error;
    }

    /*
     * Convert the RFC 3526 prime from hexadecimal to BIGNUM.
     */
    if (!BN_hex2bn(&p, GROUP14_PRIME)) {
        goto error;
    }

    /*
     * Generator g = 2.
     */
    if (!BN_set_word(g, GROUP14_GENERATOR)) {
        goto error;
    }

    /*
     * Generate private exponent.
     *
     * The private value is randomly selected in [2, p-1).
     */
    keypair->private_key = BN_new();

    if (keypair->private_key == NULL) {
        goto error;
    }

    if (!BN_rand_range(keypair->private_key, p)) {
        goto error;
    }

    /*
     * Calculate:
     *
     * public_key = g^private_key mod p
     *
     * BN_mod_exp is only doing the generic modular
     * exponentiation. The DH protocol itself is implemented here.
     */
    keypair->public_key = BN_new();

    if (keypair->public_key == NULL) {
        goto error;
    }

    if (!BN_mod_exp(
            keypair->public_key,
            g,
            keypair->private_key,
            p,
            ctx)) {
        goto error;
    }

    BN_free(p);
    BN_free(g);
    BN_CTX_free(ctx);

    return 1;

error:

    BN_free(p);
    BN_free(g);
    BN_CTX_free(ctx);

    dh_free_keypair(keypair);

    return 0;
}


BIGNUM *dh_compute_shared_secret(
    const BIGNUM *private_key,
    const BIGNUM *peer_public_key
)
{
    BIGNUM *p = NULL;
    BIGNUM *shared_secret = NULL;
    BN_CTX *ctx = NULL;

    if (private_key == NULL || peer_public_key == NULL) {
        return NULL;
    }

    p = BN_new();
    shared_secret = BN_new();
    ctx = BN_CTX_new();

    if (p == NULL || shared_secret == NULL || ctx == NULL) {
        goto error;
    }

    /*
     * Load the same RFC 3526 Group 14 prime.
     */
    if (!BN_hex2bn(&p, GROUP14_PRIME)) {
        goto error;
    }

    /*
     * Calculate:
     *
     * shared_secret = peer_public_key^private_key mod p
     */
    if (!BN_mod_exp(
            shared_secret,
            peer_public_key,
            private_key,
            p,
            ctx)) {
        goto error;
    }

    BN_free(p);
    BN_CTX_free(ctx);

    return shared_secret;

error:

    BN_free(p);
    BN_free(shared_secret);
    BN_CTX_free(ctx);

    return NULL;
}

void dh_print_fingerprint(const BIGNUM *shared_secret)
{
    unsigned char secret_bytes[256];
    unsigned char hash[SHA256_DIGEST_LENGTH];

    int secret_length = BN_num_bytes(shared_secret);

    BN_bn2bin(shared_secret, secret_bytes);

    SHA256(secret_bytes,
           secret_length,
           hash);

    printf("Fingerprint: ");

    for (int i = 0; i < 8; i++) {
        printf("%02x", hash[i]);
    }

    printf("\n");
}

void dh_free_keypair(DHKeyPair *keypair)
{
    if (keypair == NULL) {
        return;
    }

    BN_free(keypair->private_key);
    BN_free(keypair->public_key);

    keypair->private_key = NULL;
    keypair->public_key = NULL;
}