#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>

#define SERVER_IP "192.168.56.10"
#define PORT 5000
#define BUFFER_SIZE 1024
#define USERNAME_SIZE 32

int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    char username[USERNAME_SIZE];
    char current_chat[USERNAME_SIZE] = "";

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

    printf("Connected to server.\n");

    printf("Enter username: ");

    if (fgets(username, USERNAME_SIZE, stdin) == NULL) {
        close(sockfd);
        return 1;
    }

    // Remove newline
    username[strcspn(username, "\n")] = '\0';

    if (send(sockfd,
            username,
            strlen(username),
            0) < 0) {
        perror("send");
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

                send(sockfd, "/quit\n", 6, 0);
                break;
            }


            // -------------------------
            // /who
            // -------------------------
            if (strcmp(message, "/who") == 0) {

                if (send(sockfd,
                        "/who\n",
                        5,
                        0) < 0) {

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
                    printf("Usage: /chat username\n");
                    continue;
                }

                strncpy(current_chat,
                        target,
                        USERNAME_SIZE - 1);

                current_chat[USERNAME_SIZE - 1] = '\0';

                printf("Now chatting with %s\n", current_chat);

                continue;
            }


            // -------------------------
            // @username message
            // -------------------------
            if (message[0] == '@') {

                if (send(sockfd,
                        message,
                        strlen(message),
                        0) < 0) {

                    perror("send");
                    break;
                }

                continue;
            }


            // -------------------------
            // Normal message
            // -------------------------
            if (strlen(current_chat) == 0) {

                printf("No chat selected. Use /chat username first.\n");

                continue;
            }

            char routed_message[BUFFER_SIZE];

            snprintf(routed_message,
                    BUFFER_SIZE,
                    "@%s %.*s\n",
                    current_chat,
                    BUFFER_SIZE - USERNAME_SIZE - 3,
                    message);

            if (send(sockfd,
                    routed_message,
                    strlen(routed_message),
                    0) < 0) {

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
                printf("Server disconnected.\n");
                break;
            }

            buffer[bytes_received] = '\0';

            printf("Received: %s", buffer);
            fflush(stdout);
        }
    }

    close(sockfd);

    return 0;
}