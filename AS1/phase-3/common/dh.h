#ifndef DH_H
#define DH_H

#include <openssl/bn.h>

typedef struct {
    BIGNUM *private_key;
    BIGNUM *public_key;
} DHKeyPair;

int dh_generate_keypair(DHKeyPair *keypair);

BIGNUM *dh_compute_shared_secret(
    const BIGNUM *private_key,
    const BIGNUM *peer_public_key
);

void dh_print_fingerprint(const BIGNUM *shared_secret);

int dh_derive_key(
    const BIGNUM *shared_secret,
    unsigned char *key
);

void dh_free_keypair(DHKeyPair *keypair);

#endif