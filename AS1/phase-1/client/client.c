#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define SERVER_IP "192.168.56.10"
#define PORT 5000
#define BUFFER_SIZE 1024

int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    char message[BUFFER_SIZE];

    // 1. Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    // 2. Configure server address
    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sockfd);
        return 1;
    }

    // 3. Connect to server
    if (connect(sockfd,
                (struct sockaddr *)&server_addr,
                sizeof(server_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return 1;
    }

    printf("Connected to server.\n");

    // 4. Read a message from the user
    printf("Enter message: ");

    if (fgets(message, BUFFER_SIZE, stdin) == NULL) {
        close(sockfd);
        return 1;
    }

    // 5. Send message
    if (send(sockfd,
             message,
             strlen(message),
             0) < 0) {
        perror("send");
        close(sockfd);
        return 1;
    }

    printf("Message sent.\n");

    // 6. Close socket
    close(sockfd);

    return 0;
}