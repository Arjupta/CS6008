#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include "../common/dh.h"

#define SERVER_IP "10.129.27.74"
#define PORT 5000
#define BUFFER_SIZE 1024
#define USERNAME_SIZE 32

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

    while (1) {
        printf("Enter username: ");

        if (fgets(username, USERNAME_SIZE, stdin) == NULL) {
            close(sockfd);
            return 1;
        }

        username[strcspn(username, "\n")] = '\0';

        if (send_message(sockfd, username) < 0) {
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

        response[bytes_received] = '\0';

        if (strcmp(response, "USERNAME_OK\n") == 0) {
            printf("[REGISTER] Username registered: %s\n", username);
            break;
        }

        if (strcmp(response, "USERNAME_TAKEN\n") == 0) {
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

        // Wait until keyboard or socket has data
        int activity = select(max_fd + 1,
                              &readfds,
                              NULL,
                              NULL,
                              NULL);

        if (activity < 0) {
            perror("select");
            break;
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

                if (send_message(sockfd, "/quit") < 0) {
                    perror("send");
                }

                printf("[DISCONNECTED] Closing connection.\n");
                break;
            }


            // -------------------------
            // /who
            // -------------------------
            if (strcmp(message, "/who") == 0) {

                if (send_message(sockfd, "/who") < 0) {
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
            // @username message
            // -------------------------
            if (message[0] == '@') {

                if (send_message(sockfd, message) < 0) {
                    perror("send");
                    break;
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

            if (send_message(sockfd, routed_message) < 0) {
                perror("send");
                break;
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

            printf("[MESSAGE] %s", buffer);
            fflush(stdout);
        }
    }

    close(sockfd);

    return 0;
}