#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

int aes_gcm_encrypt(
    const unsigned char *key,
    const unsigned char *plaintext,
    int plaintext_len,
    unsigned char *nonce,
    unsigned char *ciphertext,
    unsigned char *tag
)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len;
    int ciphertext_len;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return 0;

    if (!RAND_bytes(nonce, GCM_NONCE_SIZE))
        goto error;

    if (!EVP_EncryptInit_ex(
            ctx,
            EVP_aes_256_gcm(),
            NULL,
            NULL,
            NULL))
        goto error;

    if (!EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_IVLEN,
            GCM_NONCE_SIZE,
            NULL))
        goto error;

    if (!EVP_EncryptInit_ex(
            ctx,
            NULL,
            NULL,
            key,
            nonce))
        goto error;

    if (!EVP_EncryptUpdate(
            ctx,
            ciphertext,
            &len,
            plaintext,
            plaintext_len))
        goto error;

    ciphertext_len = len;

    if (!EVP_EncryptFinal_ex(
            ctx,
            ciphertext + len,
            &len))
        goto error;

    ciphertext_len += len;

    if (!EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_GET_TAG,
            GCM_TAG_SIZE,
            tag))
        goto error;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;

error:
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}


int aes_gcm_decrypt(
    const unsigned char *key,
    const unsigned char *nonce,
    const unsigned char *ciphertext,
    int ciphertext_len,
    const unsigned char *tag,
    unsigned char *plaintext
)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len;
    int plaintext_len;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return 0;

    if (!EVP_DecryptInit_ex(
            ctx,
            EVP_aes_256_gcm(),
            NULL,
            NULL,
            NULL))
        goto error;

    if (!EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_IVLEN,
            GCM_NONCE_SIZE,
            NULL))
        goto error;

    if (!EVP_DecryptInit_ex(
            ctx,
            NULL,
            NULL,
            key,
            nonce))
        goto error;

    if (!EVP_DecryptUpdate(
            ctx,
            plaintext,
            &len,
            ciphertext,
            ciphertext_len))
        goto error;

    plaintext_len = len;

    /*
     * Give OpenSSL the authentication tag.
     */
    if (!EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_TAG,
            GCM_TAG_SIZE,
            (void *)tag))
        goto error;

    /*
     * This is where authentication is checked.
     */
    if (EVP_DecryptFinal_ex(
            ctx,
            plaintext + len,
            &len) <= 0)
        goto error;

    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;

error:
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}