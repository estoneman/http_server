#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BACKLOG 10
#define MAX_DURATION 10

#define HTTP_CRLF "\r\n"
#define HTTP_MAXLINE 1024
#define HTTP_MAX_HDRS 1024
#define HTTP_MAX_HDR_SZ 1024
#define HTTP_MAX_RECV (1024 * 1024)
#define HTTP_MAX_METHOD_LENGTH 32
#define HTTP_MAX_URI_LENGTH 1024
#define HTTP_MAX_VERSION_LENGTH 32

#define MIN_PORT 1024
#define MAX_PORT 65535

typedef struct {
  int major;
  int minor;
} HTTPVersionInfo;

typedef struct {
  char method[HTTP_MAX_METHOD_LENGTH];
  char uri[HTTP_MAX_URI_LENGTH];
  char version[HTTP_MAX_VERSION_LENGTH];
} HTTPCommand;

typedef struct {
  char *key;
  char *value;
} HTTPHeader;

inline void alloc_hdr(HTTPHeader *, size_t, size_t);
inline void chk_alloc_err(void *, const char *, const char *, int);
inline int fill_socket_info(struct addrinfo **, struct addrinfo **,
                            const char *);
inline size_t find_crlf(char *buf);
inline void free_hdr(HTTPHeader *, size_t);
inline void *get_inetaddr(struct sockaddr *);
inline void get_ipstr(char *, struct addrinfo *);
inline size_t http_readline(char *recv_buf, char *line_buf);
inline ssize_t https_recv(int, char *);
inline int is_valid_port(const char *);
inline size_t parse_command(char *, HTTPCommand *);
inline size_t parse_headers(char *, HTTPHeader *, size_t *);
inline void print_header(HTTPHeader);
inline void print_headers(HTTPHeader *, size_t);
inline void print_command(HTTPCommand);
inline size_t read_until(char *buf, char *out, char end);
inline int validate_port(const char *);

// debug
inline void todo(const char *func);

void alloc_hdr(HTTPHeader *hdrs, size_t size, size_t nmemb) {
  for (size_t i = 0; i < nmemb; ++i) {
    hdrs[i].key = (char *)malloc(size + 1);
    hdrs[i].value = (char *)malloc(size + 1);
  }
}

void chk_alloc_err(void *mem, const char *allocator, const char *func,
                   int line) {
  if (mem == NULL) {
    fprintf(stderr, "%s failed @%s:%d\n", allocator, func, line);
    exit(EXIT_FAILURE);
  }
}

int fill_socket_info(struct addrinfo **srv_entries, struct addrinfo **srv_entry,
                     const char *port) {
  int sockfd, addrinfo_status;
  struct addrinfo hints;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  if ((addrinfo_status = getaddrinfo(NULL, port, &hints, srv_entries)) < 0) {
    fprintf(stderr, "[ERROR] getaddrinfo: %s\n", gai_strerror(addrinfo_status));
    exit(EXIT_FAILURE);
  }

  // loop through results of call to getaddrinfo
  for (*srv_entry = *srv_entries; *srv_entry != NULL;
       *srv_entry = (*srv_entry)->ai_next) {
    // create socket through which server communication will be facililated
    if ((sockfd = socket((*srv_entry)->ai_family, (*srv_entry)->ai_socktype,
                         (*srv_entry)->ai_protocol)) < 0) {
      perror("socket");
      continue;
    }

    // convenience socket option for rapid reuse of sockets
    int enable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) <
        0) {
      perror("setsockopt");
      exit(EXIT_FAILURE);
    }

    // bind socket to network address(es)
    if (bind(sockfd, (*srv_entry)->ai_addr, (*srv_entry)->ai_addrlen) < 0) {
      close(sockfd);
      perror("bind");
      continue;
    }

    break;  // successfully created socket and binded to address
  }

  if (*srv_entry == NULL) {
    fprintf(stderr, "[ERROR] could not bind to any address\n");
    close(sockfd);
    freeaddrinfo(*srv_entries);

    exit(EXIT_FAILURE);
  }

  return sockfd;
}

size_t find_crlf(char *buf) {
  char needle[] = "\r\n";
  size_t len_recv_buf, needle_idx, len_needle;

  len_needle = strlen(needle);
  len_recv_buf = strlen(buf);

  for (needle_idx = 0; needle_idx < len_recv_buf; ++needle_idx) {
    if (strncmp(buf + needle_idx, "\r\n", len_needle) == 0) {
      break;
    }
  }

  return needle_idx;
}

void free_hdr(HTTPHeader *hdrs, size_t nmemb) {
  for (size_t i = 0; i < nmemb; ++i) {
    free(hdrs[i].key);
    free(hdrs[i].value);
  }
}

void *get_inetaddr(struct sockaddr *sa) {
  if (sa->sa_family == AF_INET) return &(((struct sockaddr_in *)sa)->sin_addr);

  return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

void get_ipstr(char *ipstr, struct addrinfo *srv_entry) {
  inet_ntop(srv_entry->ai_family,
            get_inetaddr((struct sockaddr *)srv_entry->ai_addr), ipstr,
            sizeof(ipstr));
}

size_t http_readline(char *recv_buf, char *line_buf) {
  size_t needle_idx;

  if ((needle_idx = find_crlf(recv_buf)) == 0) {
    return 0;
  }

  strncpy(line_buf, recv_buf, needle_idx);
  line_buf[needle_idx] = '\0';

  return needle_idx + 2;  // move past CRLF
}

ssize_t https_recv(int sockfd, char *recv_buf) {
  ssize_t nb_recv;

  if ((nb_recv = recv(sockfd, recv_buf, HTTP_MAX_RECV, 0)) < 0) {
    perror("recv");
    return -1;
  }
  recv_buf[nb_recv] = '\0';

  return nb_recv;
}

int is_valid_port(const char *arg) {
  int port = atoi(arg);
  return (port >= 1024 && port <= 65535);
}

size_t parse_command(char *recv_buf, HTTPCommand *command) {
  char line_buf[HTTP_MAX_METHOD_LENGTH + HTTP_MAX_URI_LENGTH +
                HTTP_MAX_VERSION_LENGTH + 3];  // 1 for each string's null term.
  size_t offset, i;

  offset = http_readline(recv_buf, line_buf);

  i = 0;
  i += read_until(line_buf, command->method, ' ');
  i += read_until(line_buf + i, command->uri, ' ');
  i += read_until(line_buf + i, command->version, ' ');

  return offset;
}

size_t parse_headers(char *buf, HTTPHeader *hdrs, size_t *n_hdrs) {
  char line[HTTP_MAXLINE + 1];
  size_t global_offset, local_offset, i;

  global_offset = 0;
  local_offset = 0;
  *n_hdrs = 0;
  while ((local_offset = http_readline(buf, line)) != 0) {
    i = 0;
    i += read_until(line + i, hdrs[*n_hdrs].key, ':');
    i += read_until(line + i, hdrs[*n_hdrs].value, '\0');
    buf += local_offset;
    global_offset += local_offset;
    (*n_hdrs)++;
  }

  return global_offset + 2;  // move past final CRLF
}

void print_header(HTTPHeader hdr) {
  puts("HTTPHeader {");
  printf("  key: %s\n  value: %s\n", hdr.key, hdr.value);
  puts("}");
}

void print_headers(HTTPHeader *hdrs, size_t n_hdrs) {
  for (size_t i = 0; i < n_hdrs; ++i) {
    print_header(hdrs[i]);
  }
}

void print_command(HTTPCommand command) {
  puts("HTTPCommand {");
  printf("  method: %s\n  uri: %s\n  version: %s\n", command.method,
         command.uri, command.version);
  puts("}");
}

size_t read_until(char *buf, char *out, char end) {
  size_t len_out, i;

  while (isspace(*buf)) {
    buf += 1;
  }

  i = 0;
  len_out = strlen(buf);
  while (i < len_out && buf[i] != end) {
    out[i] = buf[i];
    i++;
  }
  out[i] = '\0';

  return i + 1;
}

int validate_port(const char *user_port) {
  int port;

  port = atoi(user_port);
  return port >= MIN_PORT && port <= MAX_PORT;
}

// debu functions
void todo(const char *func) {
  fprintf(stderr, "%s is not implemented.. yet\n", func);
}

#endif  // HTTP_SERVER_H
