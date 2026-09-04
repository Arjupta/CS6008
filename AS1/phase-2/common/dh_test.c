#include <stdio.h>
#include <openssl/bn.h>
#include "dh.h"

int main()
{
    DHKeyPair alice;
    DHKeyPair bob;

    BIGNUM *alice_secret;
    BIGNUM *bob_secret;

    alice.private_key = NULL;
    alice.public_key = NULL;

    bob.private_key = NULL;
    bob.public_key = NULL;

    /*
     * Generate Alice's DH key pair.
     */
    if (!dh_generate_keypair(&alice)) {
        printf("Alice key generation failed.\n");
        return 1;
    }

    /*
     * Generate Bob's DH key pair.
     */
    if (!dh_generate_keypair(&bob)) {
        printf("Bob key generation failed.\n");
        dh_free_keypair(&alice);
        return 1;
    }

    /*
     * Alice uses Bob's public key.
     */
    alice_secret = dh_compute_shared_secret(
        alice.private_key,
        bob.public_key
    );

    /*
     * Bob uses Alice's public key.
     */
    bob_secret = dh_compute_shared_secret(
        bob.private_key,
        alice.public_key
    );

    if (alice_secret == NULL || bob_secret == NULL) {
        printf("Shared secret computation failed.\n");

        BN_free(alice_secret);
        BN_free(bob_secret);

        dh_free_keypair(&alice);
        dh_free_keypair(&bob);

        return 1;
    }

    /*
     * Compare the two shared secrets.
     */
    if (BN_cmp(alice_secret, bob_secret) == 0) {
        printf("[SUCCESS] Alice and Bob calculated the same shared secret.\n");
    } else {
        printf("[FAILURE] Shared secrets do not match.\n");
    }

    /*
     * We deliberately DO NOT print the shared secret.
     */

    BN_free(alice_secret);
    BN_free(bob_secret);

    dh_free_keypair(&alice);
    dh_free_keypair(&bob);

    return 0;
}
