#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include "../common/dh.h"
#include "../common/crypto.h"

#define PORT 5000
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 2
#define USERNAME_SIZE 32

typedef struct {
    int socket;
    int registered;
    int dh_complete;
    char username[USERNAME_SIZE];

    DHKeyPair dh_keypair;
    BIGNUM *shared_secret;

    unsigned char aes_key[32];
} Client;

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

void format_forwarded_message(
    const char *sender,
    const char *message,
    char *formatted_message
)
{
    char *message_text = strchr(message, ' ');

    if (message_text != NULL) {
        message_text++;
    } else {
        message_text = (char *)message;
    }

    snprintf(
        formatted_message,
        BUFFER_SIZE,
        "%s: %s",
        sender,
        message_text
    );
}

int main() {
    int server_fd;
    struct sockaddr_in server_addr;

    Client clients[MAX_CLIENTS];

    // Initialize client slots
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].socket = -1;
        clients[i].registered = 0;
        clients[i].dh_complete = 0;
        clients[i].username[0] = '\0';

        clients[i].dh_keypair.private_key = NULL;
        clients[i].dh_keypair.public_key = NULL;
        clients[i].shared_secret = NULL;
    }

    // Create TCP socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    // Allow quick reuse of the port
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind
    if (bind(server_fd,
             (struct sockaddr *)&server_addr,
             sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    // Listen
    if (listen(server_fd, MAX_CLIENTS) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    printf("Server listening on port %d...\n", PORT);

    while (1) {
        fd_set readfds;

        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);

        int max_fd = server_fd;

        // Add connected clients to the set
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].socket != -1) {
                FD_SET(clients[i].socket, &readfds);

                if (clients[i].socket > max_fd) {
                    max_fd = clients[i].socket;
                }
            }
        }

        // Wait until something happens
        int activity = select(max_fd + 1,
                            &readfds,
                            NULL,
                            NULL,
                            NULL);

        if (activity < 0) {
            perror("select");
            continue;
        }

        // New client connection
        if (FD_ISSET(server_fd, &readfds)) {

            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);

            int client_fd = accept(server_fd,
                                (struct sockaddr *)&client_addr,
                                &client_len);

            if (client_fd < 0) {
                perror("accept");
                continue;
            }

            int slot = -1;

            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i].socket == -1) {
                    slot = i;
                    break;
                }
            }

            if (slot == -1) {
                printf("Maximum number of clients reached.\n");
                close(client_fd);
            } else {
                clients[slot].socket = client_fd;
                clients[slot].registered = 0;
                clients[slot].dh_complete = 0;
                clients[slot].username[0] = '\0';

                clients[slot].dh_keypair.private_key = NULL;
                clients[slot].dh_keypair.public_key = NULL;
                clients[slot].shared_secret = NULL;

                if (!dh_generate_keypair(&clients[slot].dh_keypair)) {
                    printf("[DH] Failed to generate server key pair.\n");

                    close(client_fd);

                    clients[slot].socket = -1;
                    continue;
                }

                printf("[CONNECT] New client connected.\n");

                printf("[DH] Server generated key pair for client slot %d.\n",
                    slot);
                
                char public_key_hex[BUFFER_SIZE];

                char *temp_hex =
                    BN_bn2hex(clients[slot].dh_keypair.public_key);

                snprintf(public_key_hex,
                        BUFFER_SIZE,
                        "DH_PUBLIC %s\n",
                        temp_hex);

                OPENSSL_free(temp_hex);

                if (send(client_fd,
                        public_key_hex,
                        strlen(public_key_hex),
                        0) < 0) {

                    perror("send");

                    dh_free_keypair(&clients[slot].dh_keypair);

                    close(client_fd);

                    clients[slot].socket = -1;
                    continue;
                }
            }
        }

        // Check connected clients for messages
        for (int i = 0; i < MAX_CLIENTS; i++) {

            if (clients[i].socket == -1) {
                continue;
            }

            if (!FD_ISSET(clients[i].socket, &readfds)) {
                continue;
            }

            char buffer[BUFFER_SIZE];

            int bytes_received = recv(
                clients[i].socket,
                buffer,
                BUFFER_SIZE - 1,
                0
            );

            if (bytes_received <= 0) {
                if (clients[i].registered) {
                    printf("[DISCONNECT] %s disconnected.\n",
                        clients[i].username);
                } else {
                    printf("[DISCONNECT] Unregistered client disconnected.\n");
                }

                close(clients[i].socket);

                clients[i].socket = -1;
                clients[i].registered = 0;
                clients[i].username[0] = '\0';

                continue;
            }

            buffer[bytes_received] = '\0';

            if (!clients[i].dh_complete) {

                if (strncmp(buffer, "DH_PUBLIC ", 10) != 0) {
                    printf("[DH] Invalid client DH message.\n");

                    close(clients[i].socket);
                    clients[i].socket = -1;

                    continue;
                }

                char *client_public_hex = buffer + 10;

                client_public_hex[strcspn(client_public_hex, "\n")] = '\0';

                BIGNUM *client_public_key = NULL;

                if (!BN_hex2bn(&client_public_key, client_public_hex)) {
                    printf("[DH] Failed to parse client public key.\n");

                    close(clients[i].socket);
                    clients[i].socket = -1;

                    continue;
                }

                clients[i].shared_secret =
                    dh_compute_shared_secret(
                        clients[i].dh_keypair.private_key,
                        client_public_key
                    );

                BN_free(client_public_key);

                if (clients[i].shared_secret == NULL) {
                    printf("[DH] Failed to compute shared secret.\n");

                    close(clients[i].socket);
                    clients[i].socket = -1;

                    continue;
                }

                printf("[DH] Shared secret established.\n");
                // dh_print_fingerprint(clients[i].shared_secret);
                if (!dh_derive_key(
                        clients[i].shared_secret,
                        clients[i].aes_key
                    )) {
                    printf("[DH] Failed to derive AES key.\n");

                    close(clients[i].socket);
                    clients[i].socket = -1;

                    continue;
                }

                printf("[DH] AES-256 key derived.\n");

                clients[i].dh_complete = 1;

                send(clients[i].socket,
                    "DH_OK\n",
                    6,
                    0);

                continue;
            }

            unsigned char plaintext[BUFFER_SIZE];

            int plaintext_len = decrypt_message(
                clients[i].aes_key,
                buffer,
                plaintext
            );

            if (plaintext_len <= 0) {
                printf("[CRYPTO] Failed to decrypt message from %s.\n", buffer);

                close(clients[i].socket);
                clients[i].socket = -1;
                continue;
            }

            if (!clients[i].registered) {

                plaintext[plaintext_len] = '\0';
                int duplicate = 0;

                for (int j = 0; j < MAX_CLIENTS; j++) {

                    if (j == i) {
                        continue;
                    }

                    if (clients[j].socket != -1 &&
                        clients[j].registered &&
                        strcmp(clients[j].username, (char *)plaintext) == 0) {

                        duplicate = 1;
                        break;
                    }
                }

                if (duplicate) {

                    printf("[REGISTER] Username already in use: %s\n",
                        plaintext);

                    send_encrypted_message(
                        clients[i].socket,
                        clients[i].aes_key,
                        "USERNAME_TAKEN"
                    );

                    continue;
                }

                strncpy(clients[i].username,
                        (char *)plaintext,
                        USERNAME_SIZE - 1);

                clients[i].username[USERNAME_SIZE - 1] = '\0';

                clients[i].registered = 1;

                send_encrypted_message(
                    clients[i].socket,
                    clients[i].aes_key,
                    "USERNAME_OK"
                );

                printf("[REGISTER] Username registered: %s\n",
                    clients[i].username);

                continue;
            }

            printf("[MESSAGE] %s: %s",
                clients[i].username,
                plaintext);

            if (strcmp((char *)plaintext, "/quit\n") == 0) {

                printf("%s requested to quit.\n",
                    clients[i].username);

                close(clients[i].socket);

                clients[i].socket = -1;
                clients[i].registered = 0;
                clients[i].username[0] = '\0';

                continue;
            }

            if (plaintext[0] == '@') {
                char target[USERNAME_SIZE];

                if (sscanf((char *)plaintext, "@%31s", target) == 1) {

                    for (int j = 0; j < MAX_CLIENTS; j++) {

                        if (clients[j].socket != -1 &&
                            clients[j].registered &&
                            strcmp(clients[j].username, target) == 0) {
                            
                            char forwarded_message[BUFFER_SIZE];

                            format_forwarded_message(
                                clients[i].username,
                                (char *)plaintext,
                                forwarded_message
                            );
                            
                            if (send_encrypted_message(
                                    clients[j].socket,
                                    clients[j].aes_key,
                                    forwarded_message) < 0) {
                                perror("send");
                            }

                            printf("[MESSAGE] %s -> %s: %s",
                                clients[i].username,
                                target,
                                plaintext);

                            break;
                        }
                    }
                }

                continue;
            }

            if (strcmp((char *)plaintext, "/who\n") == 0) {

                char response[BUFFER_SIZE] = "Online users:\n";

                for (int j = 0; j < MAX_CLIENTS; j++) {
                    if (clients[j].socket != -1 &&
                        clients[j].registered) {
                        strcat(response, clients[j].username);
                        strcat(response, "\n");
                    }
                }

                printf("[COMMAND] %s requested /who\n",
                    clients[i].username);
                if (send_encrypted_message(
                    clients[i].socket,
                    clients[i].aes_key,
                    response
                ) < 0) {
                    perror("send");
                }

                continue;
            }

            // Relay message to all other connected clients
            for (int j = 0; j < MAX_CLIENTS; j++) {

                // Don't send the message back to the sender
                if (j == i) {
                    continue;
                }

                // Only send to connected clients
                if (clients[j].socket != -1 &&
                    clients[j].registered) {

                    if (send_encrypted_message(
                        clients[j].socket,
                        clients[j].aes_key,
                        (char *)plaintext
                    ) < 0) {
                        perror("send");
                    }
                }
            }
        }
    }
    close(server_fd);
    return 0;
}
