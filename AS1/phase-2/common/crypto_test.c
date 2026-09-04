#include <stdio.h>
#include <string.h>

#include "crypto.h"

int main(void)
{
    unsigned char key[AES_KEY_SIZE];
    unsigned char nonce[GCM_NONCE_SIZE];
    unsigned char tag[GCM_TAG_SIZE];

    unsigned char ciphertext[1024];
    unsigned char decrypted[1024];

    const char *message = "Hello Bob";

    /* Test key — only for this test program. */
    for (int i = 0; i < AES_KEY_SIZE; i++)
        key[i] = i;

    printf("Original: %s\n", message);

    int ciphertext_len = aes_gcm_encrypt(
        key,
        (const unsigned char *)message,
        strlen(message),
        nonce,
        ciphertext,
        tag
    );

    if (ciphertext_len <= 0) {
        printf("Encryption failed.\n");
        return 1;
    }

    printf("Encryption successful.\n");

    int plaintext_len = aes_gcm_decrypt(
        key,
        nonce,
        ciphertext,
        ciphertext_len,
        tag,
        decrypted
    );

    if (plaintext_len <= 0) {
        printf("Decryption failed.\n");
        return 1;
    }

    decrypted[plaintext_len] = '\0';

    printf("Decrypted: %s\n", decrypted);

    /*
     * Now modify one byte of the ciphertext.
     */
    ciphertext[0] ^= 1;

    plaintext_len = aes_gcm_decrypt(
        key,
        nonce,
        ciphertext,
        ciphertext_len,
        tag,
        decrypted
    );

    if (plaintext_len <= 0)
        printf("Tampering detected!\n");
    else
        printf("ERROR: Tampering was not detected.\n");

    return 0;
}
