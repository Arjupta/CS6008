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

int main() {
    int sockfd;
    struct sockaddr_in server_addr;

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

    char username[BUFFER_SIZE];

    printf("Enter username: ");

    if (fgets(username, BUFFER_SIZE, stdin) == NULL) {
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

            if (send(sockfd,
                     message,
                     strlen(message),
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