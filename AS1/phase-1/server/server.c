#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 5000
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 2
#define USERNAME_SIZE 32

typedef struct {
    int socket;
    char username[USERNAME_SIZE];
} Client;

int main() {
    int server_fd;
    struct sockaddr_in server_addr;

    Client clients[MAX_CLIENTS];

    // Initialize client slots
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].socket = -1;
        clients[i].username[0] = '\0';
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

        // Accept clients
    while (1) {
        int client_fd;
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        client_fd = accept(server_fd,
                           (struct sockaddr *)&client_addr,
                           &client_len);

        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        // Find an empty client slot
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
            continue;
        }

        clients[slot].socket = client_fd;

        // Temporary username
        snprintf(clients[slot].username,
                 USERNAME_SIZE,
                 "client%d",
                 slot + 1);

        printf("Client connected: %s\n",
               clients[slot].username);
    }

    close(server_fd);
    return 0;
}
