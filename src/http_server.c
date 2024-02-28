#include "../include/http_server.h"

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
  char *recv_buf, *send_buf;

  HTTPCommand command;
  HTTPHeader hdrs[HTTP_MAX_HDRS];
  size_t n_hdrs, skip;

  strcpy(port, argv[1]);
  listenfd = fill_socket_info(&srv_entries, &srv_entry, port);

  if (listen(listenfd, BACKLOG) < 0) {
    perror("listen");
    exit(EXIT_FAILURE);
  }

  get_ipstr(ipstr, srv_entry);

  fprintf(stderr, "[INFO] listening on %s:%s\n", ipstr, port);

  freeaddrinfo(srv_entries);

  recv_buf = (char *)malloc(HTTP_MAX_RECV + 1);
  chk_alloc_err(recv_buf, "malloc", __func__, __LINE__ - 1);

  send_buf = (char *)malloc(HTTP_MAX_SEND + 1);
  chk_alloc_err(send_buf, "malloc", __func__, __LINE__ - 1);

  alloc_hdr(hdrs, HTTP_MAX_HDR_SZ, HTTP_MAX_HDRS);

  cliaddr_len = sizeof(cliaddr);
  while (1) {
    if ((connfd = accept(listenfd, (struct sockaddr *)&cliaddr, &cliaddr_len)) <
        0) {
      perror("accept");
      exit(EXIT_FAILURE);
    }

    https_recv(connfd, recv_buf);

    memset(&command, 0, sizeof(command));
    skip = parse_command(recv_buf, &command);
    print_command(command);

    recv_buf += skip;
    skip = parse_headers(recv_buf, hdrs, &n_hdrs);
    print_headers(hdrs, n_hdrs);

    https_send(connfd, send_buf);

    close(connfd);
  }

  free_hdr(hdrs, HTTP_MAX_HDRS);
  free(recv_buf);
  free(send_buf);

  return EXIT_SUCCESS;
}
