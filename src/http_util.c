#include "../include/http_util.h"

/*
 * these change:
 *   1. Status Line
 *   2. Content-Type
 *   3. Content-Length
 *   4. Date: Tue, 15 Feb 2024 08:00:00 GMT (just an example)
 * these don't:
 *   1. Server: Apache/2.4.41 (Unix) (just an example)
 *   2. Cache-Control: max-age=3600 instructs clients to cache the response for 1
 *                  hour
 */

const char *server_version = "Server: NetSysHTTPServer/0.1";

char *alloc_buf(size_t size) {
  char *buf;

  buf = (char*)malloc(size + 1);
  chk_alloc_err(buf, "malloc", __func__, __LINE__ - 1);

  return buf;
}

void alloc_hdr(HTTPHeader *hdrs, size_t size, size_t nmemb) {
  for (size_t i = 0; i < nmemb; ++i) {
    hdrs[i].key = alloc_buf(size);
    hdrs[i].value = alloc_buf(size);
  }
}

char *http_build_response(size_t *response_sz, const char *fpath) {
  char *send_buf, *file_contents;
  size_t nb_read, hdr_sz;

  hdr_sz = HTTP_MAX_HDR_SZ * 4;
  char content_length_fmt[] = "Content-Length: %zu";
  char content_length[64];
  char status_line[] = "HTTP/1.1 200 OK";
  char content_type[] = "Content-Type: text/plain";
  char headers[hdr_sz];

  if ((file_contents = read_file(fpath, &nb_read)) == 0) {
    return NULL;
  }

  snprintf(content_length, sizeof(content_length), content_length_fmt, nb_read);
  snprintf(headers, sizeof(headers), "%s\r\n%s\r\n%s\r\n\r\n",
           status_line, content_length, content_type);

  *response_sz = strlen(headers) + nb_read;
  send_buf = alloc_buf(*response_sz);

  strncpy(send_buf, headers, strlen(headers));
  send_buf[strlen(headers)] = '\0';
  strncat(send_buf, file_contents, nb_read);

  return send_buf;
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

ssize_t http_recv(int sockfd) {
  HTTPCommand command;
  HTTPHeader hdrs[HTTP_MAX_HDRS];
  char *recv_buf;
  ssize_t nb_recv;
  size_t skip, n_hdrs;

  recv_buf = alloc_buf(HTTP_MAX_RECV);

  if ((nb_recv = recv(sockfd, recv_buf, HTTP_MAX_RECV, 0)) < 0) {
    perror("recv");
    return -1;
  }
  recv_buf[nb_recv] = '\0';

  alloc_hdr(hdrs, HTTP_MAX_HDR_SZ, HTTP_MAX_HDRS);

  memset(&command, 0, sizeof(command));
  skip = parse_command(recv_buf, &command);
  print_command(command);

  skip = parse_headers(recv_buf + skip, hdrs, &n_hdrs);
  print_headers(hdrs, n_hdrs);

  free_hdr(hdrs, HTTP_MAX_HDRS);
  free(recv_buf);

  return nb_recv;
}

ssize_t http_send(int sockfd) {
  char *send_buf;
  ssize_t nb_sent;
  size_t send_buf_sz;
  const char fpath[] = "src/http_server.c";

  if ((send_buf = http_build_response(&send_buf_sz, fpath)) == NULL) {
    return -1;
  }

  // TODO: check to see if nb_sent = nb_read after first implementation
  if ((nb_sent = send(sockfd, send_buf, send_buf_sz, 0)) < 0) {
    perror("send");
    return -1;
  }
  fwrite(send_buf, 1, send_buf_sz, stdout);

  free(send_buf);

  return nb_sent;
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

char *read_file(const char *fpath, size_t *nb_read) {
  char *out_buf;
  FILE *fp;
  struct stat st;

  if (stat(fpath, &st) < 0) {
    fprintf(stderr, "unable to stat file: %s", strerror(errno));

    return 0;
  }

  if ((fp = fopen(fpath, "r")) == NULL) {
    fprintf(stderr, "unable to open file: %s", strerror(errno));

    return 0;
  }

  out_buf = alloc_buf(st.st_size);

  if ((*nb_read = fread(out_buf, 1, st.st_size, fp)) < (size_t)st.st_size) {
    fprintf(stderr, "unable to read file");
    fclose(fp);

    return 0;
  }

  fclose(fp);

  return out_buf;
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

// debug functions
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

void todo(const char *func) {
  fprintf(stderr, "%s is not implemented.. yet\n", func);
}
