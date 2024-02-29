#include "../include/http_util.h"

#define PORT_LEN 6

void usage(const char *program) {
  fprintf(stderr, "usage: %s <port (1024|65535)\n", program);
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "[ERROR] not enough arguments supplied\n");
    usage(argv[0]);
    exit(EXIT_FAILURE);
  } else if (!validate_port(argv[1])) {
    fprintf(stderr, "[ERROR] invalid port specified\n");
    usage(argv[0]);
    exit(EXIT_FAILURE);
  }

  struct addrinfo *srv_entries, *srv_entry;
  struct sockaddr_in cliaddr;
  socklen_t cliaddr_len;
  int listenfd, connfd;
  char port[PORT_LEN], ipstr[INET6_ADDRSTRLEN];

  strcpy(port, argv[1]);
  listenfd = fill_socket_info(&srv_entries, &srv_entry, port);

  if (listen(listenfd, BACKLOG) < 0) {
    perror("listen");
    exit(EXIT_FAILURE);
  }

  get_ipstr(ipstr, srv_entry);

  fprintf(stderr, "[INFO] listening on %s:%s\n", ipstr, port);

  freeaddrinfo(srv_entries);

  cliaddr_len = sizeof(cliaddr);
  while (1) {
    if ((connfd = accept(listenfd, (struct sockaddr *)&cliaddr, &cliaddr_len)) <
        0) {
      perror("accept");
      exit(EXIT_FAILURE);
    }

    http_recv(connfd);

    http_send(connfd);

    close(connfd);
  }

  return EXIT_SUCCESS;
}
