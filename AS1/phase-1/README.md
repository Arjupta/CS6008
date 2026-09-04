# Message Framing and Routing.
The chat application uses TCP sockets with a simple newline-delimited message format. Each message sent by the client is terminated with \n, which acts as the message delimiter. The receiver therefore treats the newline character as the indication that a message is complete. Commands such as /who and /quit are also transmitted with this delimiter (e.g., /who\n).

The server maintains a client table containing the socket, registration status, and username of each connected client. Although Phase 1 limits the server to two simultaneous clients, the routing logic can theoretically support additional clients by increasing MAX_CLIENTS. Messages beginning with @username are routed only to the client with the specified username. Other normal messages are forwarded to all other registered clients. The /who command is handled by the server and returns the usernames of all currently registered clients.

# Output
- phase1.pcap
- client/client.c
- server/server.c
- alice_tcp_stream.png
- bob_tcp_strem.png
