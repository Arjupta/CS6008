#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <time.h>
#include "../common/dh.h"
#include "../common/crypto.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// Use this server for MITM attack 
// #define SERVER_IP "10.129.27.78"
// #define PORT 5001
#define SERVER_IP "10.129.27.74"
#define PORT 5000
#define BUFFER_SIZE 1024
#define USERNAME_SIZE 32

static time_t monotonic_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
}

int send_message(int sockfd, const char *message)
{
    char buffer[BUFFER_SIZE];

    snprintf(buffer,
             BUFFER_SIZE,
             "%s%s",
             message,
             (message[strlen(message) - 1] == '\n') ? "" : "\n");

    return send(sockfd,
                buffer,
                strlen(buffer),
                0);
}

int send_encrypted_message(
    int sockfd,
    const unsigned char *key,
    const char *message
)
{
    unsigned char nonce[GCM_NONCE_SIZE];
    unsigned char ciphertext[BUFFER_SIZE];
    unsigned char tag[GCM_TAG_SIZE];

    int plaintext_len = strlen(message);

    int ciphertext_len = aes_gcm_encrypt(
        key,
        (const unsigned char *)message,
        plaintext_len,
        nonce,
        ciphertext,
        tag
    );

    // Uncomment this to fail 
    // ciphertext[0] ^= 0x01;

    if (ciphertext_len <= 0) {
        printf("[CRYPTO] Encryption failed.\n");
        return -1;
    }

    /*
     * Convert binary data to hexadecimal so that
     * our existing newline-delimited protocol can
     * continue to use strings.
     */
    char nonce_hex[GCM_NONCE_SIZE * 2 + 1];
    char ciphertext_hex[BUFFER_SIZE * 2 + 1];
    char tag_hex[GCM_TAG_SIZE * 2 + 1];

    for (int i = 0; i < GCM_NONCE_SIZE; i++)
        sprintf(&nonce_hex[i * 2], "%02x", nonce[i]);

    for (int i = 0; i < ciphertext_len; i++)
        sprintf(&ciphertext_hex[i * 2], "%02x", ciphertext[i]);

    for (int i = 0; i < GCM_TAG_SIZE; i++)
        sprintf(&tag_hex[i * 2], "%02x", tag[i]);

    nonce_hex[GCM_NONCE_SIZE * 2] = '\0';
    ciphertext_hex[ciphertext_len * 2] = '\0';
    tag_hex[GCM_TAG_SIZE * 2] = '\0';

    char packet[BUFFER_SIZE * 3];

    snprintf(
        packet,
        sizeof(packet),
        "ENC %s %s %s\n",
        nonce_hex,
        ciphertext_hex,
        tag_hex
    );

    return send(
        sockfd,
        packet,
        strlen(packet),
        0
    );
}

int decrypt_message(
    const unsigned char *key,
    char *packet,
    unsigned char *plaintext
)
{
    char *type;
    char *nonce_hex;
    char *ciphertext_hex;
    char *tag_hex;

    unsigned char nonce[GCM_NONCE_SIZE];
    unsigned char ciphertext[BUFFER_SIZE];
    unsigned char tag[GCM_TAG_SIZE];

    /*
     * Packet format:
     *
     * ENC <nonce> <ciphertext> <tag>
     */

    type = strtok(packet, " ");
    nonce_hex = strtok(NULL, " ");
    ciphertext_hex = strtok(NULL, " ");
    tag_hex = strtok(NULL, " \n");

    if (type == NULL ||
        nonce_hex == NULL ||
        ciphertext_hex == NULL ||
        tag_hex == NULL ||
        strcmp(type, "ENC") != 0) {

        printf("[CRYPTO] Invalid encrypted packet.\n");
        return 0;
    }

    /*
     * Convert nonce from hexadecimal to bytes.
     */
    for (int i = 0; i < GCM_NONCE_SIZE; i++) {
        sscanf(
            &nonce_hex[i * 2],
            "%2hhx",
            &nonce[i]
        );
    }

    /*
     * Convert ciphertext from hexadecimal to bytes.
     */
    int ciphertext_len = strlen(ciphertext_hex) / 2;

    for (int i = 0; i < ciphertext_len; i++) {
        sscanf(
            &ciphertext_hex[i * 2],
            "%2hhx",
            &ciphertext[i]
        );
    }

    /*
     * Convert authentication tag from hexadecimal to bytes.
     */
    for (int i = 0; i < GCM_TAG_SIZE; i++) {
        sscanf(
            &tag_hex[i * 2],
            "%2hhx",
            &tag[i]
        );
    }

    /*
     * Decrypt and authenticate.
     */
    int plaintext_len = aes_gcm_decrypt(
        key,
        nonce,
        ciphertext,
        ciphertext_len,
        tag,
        plaintext
    );

    if (plaintext_len <= 0) {
        printf("[CRYPTO] Authentication failed.\n");
        return 0;
    }

    plaintext[plaintext_len] = '\0';

    return plaintext_len;
}

int perform_dh_handshake(
    int sock,
    DHKeyPair *dh_keypair,
    BIGNUM **shared_secret
)
{
    char buffer[BUFFER_SIZE];

    /*
     * Step 1: Receive server's public key
     */
    int bytes_received = recv(
        sock,
        buffer,
        BUFFER_SIZE - 1,
        0
    );

    if (bytes_received <= 0) {
        perror("recv");
        return 0;
    }

    buffer[bytes_received] = '\0';

    if (strncmp(buffer, "DH_PUBLIC ", 10) != 0) {
        printf("[DH] Invalid server DH message.\n");
        return 0;
    }

    char *server_public_hex = buffer + 10;

    server_public_hex[strcspn(server_public_hex, "\n")] = '\0';

    BIGNUM *server_public_key = NULL;

    if (!BN_hex2bn(&server_public_key, server_public_hex)) {
        printf("[DH] Failed to parse server public key.\n");
        return 0;
    }

    printf("[DH] Received server public key.\n");


    /*
     * Step 2: Generate client's DH key pair
     */
    if (!dh_generate_keypair(dh_keypair)) {
        printf("[DH] Failed to generate client key pair.\n");

        BN_free(server_public_key);
        return 0;
    }


    /*
     * Step 3: Send client's public key
     */
    char public_key_hex[BUFFER_SIZE];

    char *temp_hex = BN_bn2hex(dh_keypair->public_key);

    snprintf(
        public_key_hex,
        BUFFER_SIZE,
        "DH_PUBLIC %s\n",
        temp_hex
    );

    OPENSSL_free(temp_hex);

    if (send(
            sock,
            public_key_hex,
            strlen(public_key_hex),
            0
        ) < 0) {

        perror("send");

        BN_free(server_public_key);
        dh_free_keypair(dh_keypair);

        return 0;
    }


    /*
     * Step 4: Compute shared secret
     */
    *shared_secret =
        dh_compute_shared_secret(
            dh_keypair->private_key,
            server_public_key
        );

    BN_free(server_public_key);

    if (*shared_secret == NULL) {
        printf("[DH] Failed to compute shared secret.\n");

        dh_free_keypair(dh_keypair);
        return 0;
    }

    printf("[DH] Shared secret established.\n");
    // dh_print_fingerprint(*shared_secret);


    /*
     * Step 5: Wait for server confirmation
     */
    bytes_received = recv(
        sock,
        buffer,
        BUFFER_SIZE - 1,
        0
    );

    if (bytes_received <= 0) {
        perror("recv");
        BN_free(*shared_secret);
        *shared_secret = NULL;
        dh_free_keypair(dh_keypair);
        return 0;
    }

    buffer[bytes_received] = '\0';

    if (strcmp(buffer, "DH_OK\n") != 0) {
        printf("[DH] Server did not confirm DH handshake.\n");

        BN_free(*shared_secret);
        *shared_secret = NULL;
        dh_free_keypair(dh_keypair);

        return 0;
    }

    printf("[DH] Handshake complete.\n");

    return 1;
}

int send_all(int sockfd, const unsigned char *buf, int len)
{
    int total = 0;

    while (total < len) {
        int n = send(sockfd, buf + total, len - total, 0);

        if (n <= 0)
            return 0;

        total += n;
    }

    return 1;
}

int recv_all(int sockfd, unsigned char *buf, int len)
{
    int total = 0;

    while (total < len) {
        int n = recv(sockfd, buf + total, len - total, 0);

        if (n <= 0)
            return 0;

        total += n;
    }

    return 1;
}

int verify_server_certificate(int sockfd)
{
    uint32_t cert_len_net;
    uint32_t cert_len;

    /* Receive certificate length */
    if (!recv_all(sockfd, (unsigned char *)&cert_len_net, sizeof(cert_len_net)))
        return 0;

    cert_len = ntohl(cert_len_net);

    if (cert_len <= 0 || cert_len > 100000)
        return 0;

    /* Receive DER certificate */
    unsigned char *cert_data = malloc(cert_len);

    if (!cert_data)
        return 0;

    if (!recv_all(sockfd, cert_data, cert_len)) {
        free(cert_data);
        return 0;
    }

    /* Convert DER data to X509 certificate */
    const unsigned char *p = cert_data;
    X509 *cert = d2i_X509(NULL, &p, cert_len);

    free(cert_data);

    if (!cert) {
        printf("[CERT] Could not parse certificate.\n");
        return 0;
    }

    /* Load trusted CA */
    FILE *ca_file = fopen("../ca/ca.crt", "r");

    if (!ca_file) {
        printf("[CERT] Could not open CA certificate.\n");
        X509_free(cert);
        return 0;
    }

    X509 *ca_cert = PEM_read_X509(ca_file, NULL, NULL, NULL);
    fclose(ca_file);

    if (!ca_cert) {
        X509_free(cert);
        return 0;
    }

    /* Verify that server certificate was signed by our CA */
    EVP_PKEY *ca_key = X509_get_pubkey(ca_cert);

    if (!ca_key) {
        X509_free(cert);
        X509_free(ca_cert);
        return 0;
    }

    if (X509_verify(cert, ca_key) != 1) {
        printf("[CERT] Certificate signature verification failed.\n");

        EVP_PKEY_free(ca_key);
        X509_free(cert);
        X509_free(ca_cert);
        return 0;
    }

    EVP_PKEY_free(ca_key);

    /* Check certificate validity period */
    if (X509_cmp_current_time(X509_get0_notBefore(cert)) > 0 ||
        X509_cmp_current_time(X509_get0_notAfter(cert)) < 0) {

        printf("[CERT] Certificate is expired or not yet valid.\n");

        X509_free(cert);
        X509_free(ca_cert);
        return 0;
    }

    /* Check expected server identity */
    if (X509_check_ip_asc(cert, "10.129.27.74", 0) != 1) {

        printf("[CERT] Certificate identity does not match server.\n");

        X509_free(cert);
        X509_free(ca_cert);
        return 0;
    }

    printf("[CERT] Certificate verified successfully.\n");

    /*
     * Proof-of-possession will be done here next.
     */

    /* Generate a random challenge */
    unsigned char challenge[32];

    if (RAND_bytes(challenge, sizeof(challenge)) != 1) {
        printf("[CERT] Failed to generate challenge.\n");

        X509_free(cert);
        X509_free(ca_cert);
        return 0;
    }

    /* Send challenge length */
    uint32_t challenge_len_net = htonl(sizeof(challenge));

    if (!send_all(sockfd,
                (unsigned char *)&challenge_len_net,
                sizeof(challenge_len_net))) {

        X509_free(cert);
        X509_free(ca_cert);
        return 0;
    }

    /* Send challenge */
    if (!send_all(sockfd, challenge, sizeof(challenge))) {

        X509_free(cert);
        X509_free(ca_cert);
        return 0;
    }

    printf("[CERT] Challenge sent to server.\n");

    /* Receive signature length */
    uint32_t signature_len_net;

    if (!recv_all(sockfd,
                (unsigned char *)&signature_len_net,
                sizeof(signature_len_net))) {

        X509_free(cert);
        X509_free(ca_cert);
        return 0;
    }

    uint32_t signature_len = ntohl(signature_len_net);

    if (signature_len <= 0 || signature_len > 10000) {
        X509_free(cert);
        X509_free(ca_cert);
        return 0;
    }

    /* Receive signature */
    unsigned char *signature = malloc(signature_len);

    if (!signature) {
        X509_free(cert);
        X509_free(ca_cert);
        return 0;
    }

    if (!recv_all(sockfd, signature, signature_len)) {
        free(signature);
        X509_free(cert);
        X509_free(ca_cert);
        return 0;
    }

    /* Get server public key from certificate */
    EVP_PKEY *server_public_key = X509_get_pubkey(cert);

    if (!server_public_key) {
        free(signature);
        X509_free(cert);
        X509_free(ca_cert);
        return 0;
    }

    /* Verify server's signature */
    EVP_MD_CTX *verify_ctx = EVP_MD_CTX_new();

    if (!verify_ctx) {
        EVP_PKEY_free(server_public_key);
        free(signature);
        X509_free(cert);
        X509_free(ca_cert);
        return 0;
    }

    if (EVP_DigestVerifyInit(
            verify_ctx,
            NULL,
            EVP_sha256(),
            NULL,
            server_public_key) != 1 ||
        EVP_DigestVerify(
            verify_ctx,
            signature,
            signature_len,
            challenge,
            sizeof(challenge)) != 1) {

        printf("[CERT] Server proof-of-possession FAILED.\n");

        EVP_MD_CTX_free(verify_ctx);
        EVP_PKEY_free(server_public_key);
        free(signature);
        X509_free(cert);
        X509_free(ca_cert);

        return 0;
    }

    printf("[CERT] Server proof-of-possession verified.\n");

    EVP_MD_CTX_free(verify_ctx);
    EVP_PKEY_free(server_public_key);
    free(signature);

    X509_free(cert);
    X509_free(ca_cert);

    return 1;
}

void initiate_e2e(
    int sockfd,
    const unsigned char *aes_key,
    const char *username,
    const char *target,
    DHKeyPair *e2e_keypair,
    int *e2e_established,
    char *e2e_peer
)
{
    // Commenting sanity check to allow rotation
    // if (*e2e_established) {
    //     printf("[E2E] E2E session already established with %s.\n",
    //            e2e_peer);
    //     return;
    // }

    /* Generate E2E DH key pair */
    if (!dh_generate_keypair(e2e_keypair)) {
        printf("[E2E] Failed to generate key pair.\n");
        return;
    }

    /* Remember who we are establishing E2E with */
    strncpy(e2e_peer, target, USERNAME_SIZE - 1);
    e2e_peer[USERNAME_SIZE - 1] = '\0';

    /* Convert public key to hexadecimal */
    char *public_hex = BN_bn2hex(e2e_keypair->public_key);

    if (public_hex == NULL) {
        printf("[E2E] Failed to convert public key.\n");
        return;
    }

    /*
     * Format:
     *
     * @target __E2E_INIT__ username public_key
     */
    char message[BUFFER_SIZE];

    snprintf(
        message,
        sizeof(message),
        "@%s __E2E_INIT__ %s %s",
        target,
        username,
        public_hex
    );

    OPENSSL_free(public_hex);

    /* Send using existing client-server AES key */
    if (send_encrypted_message(sockfd, aes_key, message) < 0) {
        perror("[E2E] send");
        return;
    }

    printf("[E2E] Sent key exchange request to %s.\n", target);
}

void handle_e2e_init(
    int sockfd,
    const unsigned char *aes_key,
    const char *username,
    char *message,
    DHKeyPair *e2e_keypair,
    BIGNUM **e2e_shared_secret,
    unsigned char *e2e_key,
    unsigned char *old_e2e_key,
    int *old_key_valid,
    int *e2e_established,
    char *e2e_peer,
    time_t *last_rotation,
    int *rotation_in_progress
)
{
    char peer_username[USERNAME_SIZE];
    char public_key_hex[BUFFER_SIZE];

    /*
     * Expected:
     *
     * __E2E_INIT__ peer_username public_key
     */
    if (sscanf(
            message,
            "__E2E_INIT__ %31s %1023s",
            peer_username,
            public_key_hex
        ) != 2) {

        printf("[E2E] Invalid E2E_INIT message.\n");
        return;
    }

    /* Remember the peer */
    strncpy(e2e_peer, peer_username, USERNAME_SIZE - 1);
    e2e_peer[USERNAME_SIZE - 1] = '\0';

    /* Convert peer public key from hexadecimal */
    BIGNUM *peer_public_key = NULL;

    if (!BN_hex2bn(&peer_public_key, public_key_hex)) {
        printf("[E2E] Failed to parse peer public key.\n");
        return;
    }

    /* Generate our E2E DH key pair */
    if (!dh_generate_keypair(e2e_keypair)) {
        printf("[E2E] Failed to generate key pair.\n");
        BN_free(peer_public_key);
        return;
    }

    /* Compute E2E shared secret */
    *e2e_shared_secret =
        dh_compute_shared_secret(
            e2e_keypair->private_key,
            peer_public_key
        );

    BN_free(peer_public_key);

    if (*e2e_shared_secret == NULL) {
        printf("[E2E] Failed to compute shared secret.\n");
        dh_free_keypair(e2e_keypair);
        return;
    }

    /*
    * Preserve the current key 
    before installing the new one.
    */
    if (*e2e_established) {
        memcpy(old_e2e_key, e2e_key, 32);
        *old_key_valid = 1;
    }

    /* Derive AES-256 E2E key */
    if (!dh_derive_key(*e2e_shared_secret, e2e_key)) {
        printf("[E2E] Failed to derive E2E key.\n");
        return;
    }

    printf("[E2E] Shared secret established with %s.\n",
           e2e_peer);

    // printf("[E2E] Fingerprint: ");
    // dh_print_fingerprint(*e2e_shared_secret);

    /* Convert our public key to hexadecimal */
    char *public_hex = BN_bn2hex(e2e_keypair->public_key);

    if (public_hex == NULL) {
        printf("[E2E] Failed to convert public key.\n");
        return;
    }

    /*
     * Send:
     *
     * @peer __E2E_ACK__ username public_key
     */
    char ack[BUFFER_SIZE];

    snprintf(
        ack,
        sizeof(ack),
        "@%s __E2E_ACK__ %s %s",
        e2e_peer,
        username,
        public_hex
    );

    OPENSSL_free(public_hex);

    /* Send ACK through existing encrypted connection */
    if (send_encrypted_message(sockfd, aes_key, ack) < 0) {
        perror("[E2E] ACK send");
        return;
    }

    *e2e_established = 1;

    *last_rotation = monotonic_seconds();
    *rotation_in_progress = 0;
    
    printf("[E2E] Key exchange complete with %s.\n",
           e2e_peer);
}

void handle_e2e_ack(
    char *message,
    DHKeyPair *e2e_keypair,
    BIGNUM **e2e_shared_secret,
    unsigned char *e2e_key,
    unsigned char *old_e2e_key,
    int *old_key_valid,
    int *e2e_established,
    time_t *last_rotation,
    int *rotation_in_progress
)
{
    char peer_username[USERNAME_SIZE];
    char public_key_hex[BUFFER_SIZE];

    /*
     * Expected:
     *
     * __E2E_ACK__ peer_username public_key
     */
    if (sscanf(
            message,
            "__E2E_ACK__ %31s %1023s",
            peer_username,
            public_key_hex
        ) != 2) {

        printf("[E2E] Invalid E2E_ACK message.\n");
        return;
    }

    /* Convert peer public key from hexadecimal */
    BIGNUM *peer_public_key = NULL;

    if (!BN_hex2bn(&peer_public_key, public_key_hex)) {
        printf("[E2E] Failed to parse peer public key.\n");
        return;
    }

    /* Compute shared secret */
    *e2e_shared_secret =
        dh_compute_shared_secret(
            e2e_keypair->private_key,
            peer_public_key
        );

    BN_free(peer_public_key);

    if (*e2e_shared_secret == NULL) {
        printf("[E2E] Failed to compute shared secret.\n");
        return;
    }

    if (*e2e_established) {
        memcpy(old_e2e_key, e2e_key, 32);
        *old_key_valid = 1;
    }

    /* Derive E2E AES-256 key */
    if (!dh_derive_key(*e2e_shared_secret, e2e_key)) {
        printf("[E2E] Failed to derive E2E key.\n");
        return;
    }

    printf("[E2E] Shared secret established with %s.\n",
           peer_username);

    // printf("[E2E] Fingerprint: ");
    // dh_print_fingerprint(*e2e_shared_secret);

    *e2e_established = 1;
    *last_rotation = monotonic_seconds();
    *rotation_in_progress = 0;

    printf("[E2E] Key exchange complete with %s.\n",
        peer_username);
}

int send_e2e_message(
    int sockfd,
    const unsigned char *aes_key,
    const unsigned char *e2e_key,
    const char *target,
    const char *message
)
{
    unsigned char nonce[GCM_NONCE_SIZE];
    unsigned char ciphertext[BUFFER_SIZE];
    unsigned char tag[GCM_TAG_SIZE];

    int plaintext_len = strlen(message);

    /*
     * Encrypt the actual chat message using the E2E key.
     */
    int ciphertext_len = aes_gcm_encrypt(
        e2e_key,
        (const unsigned char *)message,
        plaintext_len,
        nonce,
        ciphertext,
        tag
    );

    if (ciphertext_len <= 0) {
        printf("[E2E] Encryption failed.\n");
        return -1;
    }

    /*
     * Convert nonce, ciphertext and tag to hexadecimal.
     */
    char nonce_hex[GCM_NONCE_SIZE * 2 + 1];
    char ciphertext_hex[BUFFER_SIZE * 2 + 1];
    char tag_hex[GCM_TAG_SIZE * 2 + 1];

    for (int i = 0; i < GCM_NONCE_SIZE; i++)
        sprintf(&nonce_hex[i * 2], "%02x", nonce[i]);

    for (int i = 0; i < ciphertext_len; i++)
        sprintf(&ciphertext_hex[i * 2], "%02x", ciphertext[i]);

    for (int i = 0; i < GCM_TAG_SIZE; i++)
        sprintf(&tag_hex[i * 2], "%02x", tag[i]);

    nonce_hex[GCM_NONCE_SIZE * 2] = '\0';
    ciphertext_hex[ciphertext_len * 2] = '\0';
    tag_hex[GCM_TAG_SIZE * 2] = '\0';

    // Uncomment this to check gcm verification for e2e
    // ciphertext_hex[0] =(ciphertext_hex[0] == '0') ? '1' : '0';

    /*
     * Inner E2E packet.
     *
     * The server will see this after decrypting
     * the outer client-server encryption.
     */
    char e2e_packet[BUFFER_SIZE * 3];

    snprintf(
        e2e_packet,
        sizeof(e2e_packet),
        "@%s __E2E_MSG__ %s %s %s",
        target,
        nonce_hex,
        ciphertext_hex,
        tag_hex
    );

    /*
     * Now encrypt the E2E packet with the existing
     * client-server AES key.
     */
    return send_encrypted_message(
        sockfd,
        aes_key,
        e2e_packet
    );
}

void handle_e2e_message(
    const unsigned char *e2e_key,
    const unsigned char *old_e2e_key,
    int old_key_valid,
    char *message
)
{
    char *type;
    char *nonce_hex;
    char *ciphertext_hex;
    char *tag_hex;

    unsigned char nonce[GCM_NONCE_SIZE];
    unsigned char ciphertext[BUFFER_SIZE];
    unsigned char tag[GCM_TAG_SIZE];
    unsigned char plaintext[BUFFER_SIZE];

    /*
     * Expected format:
     *
     * __E2E_MSG__ nonce ciphertext tag
     */

    type = strtok(message, " ");
    nonce_hex = strtok(NULL, " ");
    ciphertext_hex = strtok(NULL, " ");
    tag_hex = strtok(NULL, " \n");

    if (type == NULL ||
        nonce_hex == NULL ||
        ciphertext_hex == NULL ||
        tag_hex == NULL ||
        strcmp(type, "__E2E_MSG__") != 0) {

        printf("[E2E] Invalid E2E message.\n");
        return;
    }

    /* Convert nonce */
    for (int i = 0; i < GCM_NONCE_SIZE; i++) {
        sscanf(
            &nonce_hex[i * 2],
            "%2hhx",
            &nonce[i]
        );
    }

    /* Convert ciphertext */
    int ciphertext_len = strlen(ciphertext_hex) / 2;

    for (int i = 0; i < ciphertext_len; i++) {
        sscanf(
            &ciphertext_hex[i * 2],
            "%2hhx",
            &ciphertext[i]
        );
    }

    /* Convert authentication tag */
    for (int i = 0; i < GCM_TAG_SIZE; i++) {
        sscanf(
            &tag_hex[i * 2],
            "%2hhx",
            &tag[i]
        );
    }

    /*
     * Decrypt and authenticate using the E2E key.
     */
    int plaintext_len = aes_gcm_decrypt(
        e2e_key,
        nonce,
        ciphertext,
        ciphertext_len,
        tag,
        plaintext
    );

    /*
    * If the new/current key fails authentication,
    * try the previous key.
    */
    if (plaintext_len <= 0 && old_key_valid) {

        printf("[E2E] Current key authentication failed. "
            "Trying previous key...\n");

        plaintext_len = aes_gcm_decrypt(
            old_e2e_key,
            nonce,
            ciphertext,
            ciphertext_len,
            tag,
            plaintext
        );
    }

    if (plaintext_len <= 0) {
        printf("[E2E] Authentication failed.\n");
        return;
    }

    plaintext[plaintext_len] = '\0';

    printf("[E2E MESSAGE] %s\n", plaintext);
    fflush(stdout);
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    char username[USERNAME_SIZE];
    char current_chat[USERNAME_SIZE] = "";

    DHKeyPair dh_keypair;
    BIGNUM *shared_secret = NULL;

    dh_keypair.private_key = NULL;
    dh_keypair.public_key = NULL;

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sockfd);
        return 1;
    }

    // Connect to server
    if (connect(sockfd,
                (struct sockaddr *)&server_addr,
                sizeof(server_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return 1;
    }

    if (!verify_server_certificate(sockfd)) {
        printf("[CERT] Server authentication failed.\n");
        close(sockfd);
        return 1;
    }

    if (!perform_dh_handshake(
            sockfd,
            &dh_keypair,
            &shared_secret
        )) {

        printf("[DH] Handshake failed.\n");

        close(sockfd);
        return 1;
    }

    unsigned char aes_key[32];

    if (!dh_derive_key(shared_secret, aes_key)) {
        printf("[DH] Failed to derive AES key.\n");

        BN_free(shared_secret);
        dh_free_keypair(&dh_keypair);
        close(sockfd);
        return 1;
    }

    printf("[DH] AES-256 key derived.\n");

    // Now proceed with username registration

    printf("[CONNECTED] Connected to server.\n");   

    // Credential for e2e 
    DHKeyPair e2e_keypair;
    BIGNUM *e2e_shared_secret = NULL;
    unsigned char e2e_key[32];
    unsigned char old_e2e_key[32];

    int old_key_valid = 0;
    int rotation_in_progress = 0;
    int e2e_established = 0;
    char e2e_peer[USERNAME_SIZE];

    time_t last_rotation = monotonic_seconds();

    while (1) {
        printf("Enter username: ");

        if (fgets(username, USERNAME_SIZE, stdin) == NULL) {
            close(sockfd);
            return 1;
        }

        username[strcspn(username, "\n")] = '\0';

        if (send_encrypted_message(sockfd, aes_key, username) < 0) {
            perror("send");
            close(sockfd);
            return 1;
        }

        char response[BUFFER_SIZE];

        int bytes_received = recv(sockfd,
                                response,
                                BUFFER_SIZE - 1,
                                0);

        if (bytes_received <= 0) {
            printf("[DISCONNECTED] Server disconnected.\n");
            close(sockfd);
            return 1;
        }

        unsigned char plaintext[BUFFER_SIZE];

        int plaintext_len = decrypt_message(
            aes_key,
            response,
            plaintext
        );

        if (plaintext_len <= 0) {
            printf("[CRYPTO] Failed to decrypt server response.\n");
            close(sockfd);
            return 1;
        }

        plaintext[plaintext_len] = '\0';

        if (strcmp((char *)plaintext, "USERNAME_OK") == 0) {
            printf("[REGISTER] Username registered: %s\n", username);
            break;
        }

        if (strcmp((char *)plaintext, "USERNAME_TAKEN") == 0) {
            printf("[REGISTER] Username '%s' is already in use. Try another.\n",
                username);
            continue;
        }

        printf("[ERROR] Unexpected server response.\n");
        close(sockfd);
        return 1;
    }

    // Continuously monitor keyboard and socket
    while (1) {

        fd_set readfds;

        FD_ZERO(&readfds);

        // Monitor keyboard input
        FD_SET(STDIN_FILENO, &readfds);

        // Monitor server socket
        FD_SET(sockfd, &readfds);

        int max_fd = sockfd;

        if (STDIN_FILENO > max_fd) {
            max_fd = STDIN_FILENO;
        }

        struct timeval timeout;

        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        // Wait until keyboard or socket has data
        int activity = select(
            max_fd + 1,
            &readfds,
            NULL,
            NULL,
            &timeout
        );

        if (activity < 0) {
            perror("select");
            break;
        }

        /*
        * Automatic E2E key rotation every 60 seconds.
        *
        * Only the lexicographically smaller username initiates
        * the rotation. This prevents both clients from starting
        * a new DH exchange at the same time.
        */
        if (e2e_established &&
            !rotation_in_progress &&
            strcmp(username, e2e_peer) < 0 &&
            monotonic_seconds() - last_rotation >= 60) {

            printf("[E2E] 60 seconds elapsed. Starting key rotation...\n");

            rotation_in_progress = 1;

            initiate_e2e(
                sockfd,
                aes_key,
                username,
                e2e_peer,
                &e2e_keypair,
                &e2e_established,
                e2e_peer
            );
        }

        if (old_key_valid &&
            !rotation_in_progress &&
            monotonic_seconds() - last_rotation >= 5) {

            OPENSSL_cleanse(old_e2e_key, 32);
            old_key_valid = 0;

            printf("[E2E] Previous key discarded.\n");
        }
        
        // Check keyboard
        if (FD_ISSET(STDIN_FILENO, &readfds)) {

            char message[BUFFER_SIZE];

            if (fgets(message, BUFFER_SIZE, stdin) == NULL) {
                break;
            }

            // Remove newline
            message[strcspn(message, "\n")] = '\0';


            // -------------------------
            // /quit
            // -------------------------
            if (strcmp(message, "/quit") == 0) {

                if (send_encrypted_message(sockfd, aes_key, "/quit\n") < 0) {
                    perror("send");
                }

                printf("[DISCONNECTED] Closing connection.\n");
                break;
            }


            // -------------------------
            // /who
            // -------------------------
            if (strcmp(message, "/who") == 0) {

                if (send_encrypted_message(sockfd, aes_key, "/who\n") < 0) {
                    perror("send");
                    break;
                }

                continue;
            }


            // -------------------------
            // /chat username
            // -------------------------
            if (strncmp(message, "/chat ", 6) == 0) {

                char *target = message + 6;

                if (strlen(target) == 0) {
                    printf("[ERROR] Usage: /chat username\n");
                    continue;
                }

                strncpy(current_chat,
                        target,
                        USERNAME_SIZE - 1);

                current_chat[USERNAME_SIZE - 1] = '\0';

                printf("[CHAT] Now chatting with %s\n", current_chat);
                continue;
            }

            // -------------------------
            // /e2e username
            // -------------------------
            if (strncmp(message, "/e2e ", 5) == 0) {

                char target[USERNAME_SIZE];

                if (sscanf(message + 5, "%31s", target) == 1) {

                    initiate_e2e(
                        sockfd,
                        aes_key,
                        username,
                        target,
                        &e2e_keypair,
                        &e2e_established,
                        e2e_peer
                    );

                } else {
                    printf("[ERROR] Usage: /e2e username\n");
                }

                continue;
            }

            // -------------------------
            // @username message
            // -------------------------

            if (message[0] == '@') {

                char routed_message[BUFFER_SIZE+1];

                snprintf(routed_message,
                        BUFFER_SIZE+1,
                        "%s\n",
                        message);

                char target[USERNAME_SIZE];

                if (sscanf(message, "@%31s", target) == 1) {

                    /*
                    * If this target has an established E2E session,
                    * encrypt the actual message using e2e_key.
                    */
                    if (e2e_established &&
                        strcmp(target, e2e_peer) == 0) {

                        char *actual_message = strchr(message, ' ');

                        if (actual_message != NULL) {
                            actual_message++;

                            if (send_e2e_message(
                                    sockfd,
                                    aes_key,
                                    e2e_key,
                                    target,
                                    actual_message
                                ) < 0) {

                                perror("[E2E] send");
                                break;
                            }
                        }

                    } else {

                        /*
                        * Existing client-server encrypted message.
                        */
                        if (send_encrypted_message(
                                sockfd,
                                aes_key,
                                routed_message
                            ) < 0) {

                            perror("send");
                            break;
                        }
                    }
                }

                continue;
            }

            // -------------------------
            // Normal message
            // -------------------------
            if (strlen(current_chat) == 0) {

                printf("[ERROR] No chat selected. Use /chat username first.\n");

                continue;
            }

            char routed_message[BUFFER_SIZE];

            snprintf(routed_message,
                    BUFFER_SIZE,
                    "@%s %.*s\n",
                    current_chat,
                    BUFFER_SIZE - USERNAME_SIZE - 3,
                    message);

            if (e2e_established &&
                strcmp(current_chat, e2e_peer) == 0) {

                if (send_e2e_message(
                        sockfd,
                        aes_key,
                        e2e_key,
                        current_chat,
                        message
                    ) < 0) {

                    perror("[E2E] send");
                    break;
                }

            } else {

                if (send_encrypted_message(
                        sockfd,
                        aes_key,
                        routed_message
                    ) < 0) {

                    perror("send");
                    break;
                }
            }
        }

        // Check server socket
        if (FD_ISSET(sockfd, &readfds)) {

            char buffer[BUFFER_SIZE];

            int bytes_received = recv(sockfd,
                                      buffer,
                                      BUFFER_SIZE - 1,
                                      0);

            if (bytes_received <= 0) {
                printf("[DISCONNECTED] Server disconnected.\n");
                break;
            }

            buffer[bytes_received] = '\0';

            unsigned char plaintext[BUFFER_SIZE];

            int plaintext_len = decrypt_message(
                aes_key,
                buffer,
                plaintext
            );

            if (plaintext_len <= 0) {
                printf("[CRYPTO] Failed to decrypt server message.\n");
                continue;
            }

            plaintext[plaintext_len] = '\0';

            if (strncmp((char *)plaintext,
                        "__E2E_INIT__",
                        strlen("__E2E_INIT__")) == 0) {

                handle_e2e_init(
                    sockfd,
                    aes_key,
                    username,
                    (char *)plaintext,
                    &e2e_keypair,
                    &e2e_shared_secret,
                    e2e_key,
                    old_e2e_key,
                    &old_key_valid,
                    &e2e_established,
                    e2e_peer,
                    &last_rotation,
                    &rotation_in_progress
                );

                continue;
            }

            if (strncmp((char *)plaintext,
                        "__E2E_ACK__",
                        strlen("__E2E_ACK__")) == 0) {

                handle_e2e_ack(
                    (char *)plaintext,
                    &e2e_keypair,
                    &e2e_shared_secret,
                    e2e_key,
                    old_e2e_key,
                    &old_key_valid,
                    &e2e_established,
                    &last_rotation,
                    &rotation_in_progress
                );

                continue;
            }

            /*
            * E2E encrypted message
            */
            if (strncmp(
                    (char *)plaintext,
                    "__E2E_MSG__",
                    strlen("__E2E_MSG__")
                ) == 0) {

                if (!e2e_established) {
                    printf("[E2E] Received E2E message but no E2E session exists.\n");
                    continue;
                }

                handle_e2e_message(
                    e2e_key,
                    old_e2e_key,
                    old_key_valid,
                    (char *)plaintext
                );

                continue;
            }

            printf("[MESSAGE] %s\n", plaintext);
            fflush(stdout);
        }
    }

    close(sockfd);

    return 0;
}