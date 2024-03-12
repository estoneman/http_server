#include "../include/http_util.h"

/*
 * these change:
 *   1. Status Line (e.g., HTTP/1.1 200 OK)
 *   2. Content-Type (e.g., application/json)
 *   3. Content-Length (e.g., 1234)
 *   4. Date (e.g., Tue, 15 Feb 2024 08:00:00 GMT)
 * these don't:
 *   1. Server: Apache/2.4.41 (Unix) (just an example)
 *   2. Cache-Control: max-age=3600 instructs clients to cache the response for
 *      1 hour
 */

const char *server_version = "Server: NetSysHTTPServer/0.1";

char *alloc_buf(size_t size) {
  char *buf;

  buf = (char *)malloc(size + 1);
  chk_alloc_err(buf, "malloc", __func__, __LINE__ - 1);

  return buf;
}

void alloc_hdr(HTTPHeader *hdrs, size_t size, size_t nmemb) {
  for (size_t i = 0; i < nmemb; ++i) {
    hdrs[i].key = alloc_buf(size);
    hdrs[i].value = alloc_buf(size);
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

size_t http_access(const char *fpath) {
  size_t exists, readable;

  exists = fexists(fpath);
  readable = freadable(fpath);

  if (exists != HTTP_OK) {
    return HTTP_NOT_FOUND;
  }

  return readable == HTTP_OK ? HTTP_OK : HTTP_FORBIDDEN;
}

size_t fexists(const char *fpath) {
  if (access(fpath, F_OK) < 0) {
    return HTTP_NOT_FOUND;
  }

  return HTTP_OK;
}

size_t freadable(const char *fpath) {
  if (access(fpath, R_OK) < 0) {
    return HTTP_FORBIDDEN;
  }

  return HTTP_OK;
}

// return a full http response
char *http_build_response(size_t rc, HTTPCommand command, char *connection,
                          size_t *len_send_buf) {
  char *send_buf, *file_contents, *file_type;
  const char *status_msg;
  size_t nb_read, free_buf_flag;

  file_contents = read_file(command.uri, &nb_read);
  char content_type[HTTP_MAX_FILE_TYPE_LENGTH + 1];
  char headers[HTTP_MAX_HDR_SZ * 3 + 1];

  status_msg = http_status(rc);
  free_buf_flag = 0;
  file_type = get_file_type(command.uri, &free_buf_flag);

  strncpy(content_type, file_type, HTTP_MAX_FILE_TYPE_LENGTH);
  snprintf(headers, sizeof(headers),
           "%s %zu %s\r\n"
           "Content-Length: %zu\r\n"
           "Content-Type: %s\r\n"
           "Connection: %s\r\n\r\n",
           command.version, rc, status_msg, nb_read, content_type, connection);

  *len_send_buf = nb_read + strlen(headers);
  send_buf = alloc_buf(*len_send_buf);
  memcpy(send_buf, headers, strlen(headers));
  memcpy(send_buf + strlen(headers), file_contents, nb_read);

  if (free_buf_flag == 1) {
    free(file_type);
  }

  return send_buf;
}

char *get_ext(const char *fpath) {
  char ext[HTTP_MAX_FILE_NAME_LENGTH + 1];

  strcpy(ext, strrchr(fpath, '.'));

  if (strncmp(ext, ".html", strlen(".html")) == 0) {
    return "text/html";
  } else if (strncmp(ext, ".txt", strlen(".txt")) == 0) {
    return "text/plain";
  } else if (strncmp(ext, ".png", strlen(".png")) == 0) {
    return "image/png";
  } else if (strncmp(ext, ".gif", strlen(".gif")) == 0) {
    return "image/gif";
  } else if (strncmp(ext, ".jpg", strlen(".jpg")) == 0) {
    return "image/jpg";
  } else if (strncmp(ext, ".ico", strlen(".ico")) == 0) {
    return "image/x-icon";
  } else if (strncmp(ext, ".css", strlen(".css")) == 0) {
    return "text/css";
  } else if (strncmp(ext, ".js", strlen(".js")) == 0) {
    return "application/javascript";
  }

  return NULL;
}

char *get_file_type(const char *fpath, size_t *free_buf_flag) {
  char *file_type;

  if ((file_type = get_ext(fpath)) != NULL) {
    return file_type;
  } else if ((file_type = file_cmd(fpath)) != NULL) {
    *free_buf_flag = 1;
    return file_type;
  }

  return "application/octet-stream";
}

char *get_http_header(char *key, HTTPHeader *hdrs, size_t n_hdrs) {
  for (size_t i = 0; i < n_hdrs; ++i) {
    if (strncmp(key, hdrs[i].key, strlen(key)) == 0) {
      return hdrs[i].value;
    }
  }

  return NULL;
}

char *file_cmd(const char *fpath) {
  char *proc_out;
  char cmd[HTTP_MAX_FILE_NAME_LENGTH + 1];

  snprintf(cmd, HTTP_MAX_FILE_NAME_LENGTH, "file --mime-type %s", fpath);
  FILE *proc_p = popen(cmd, "r");
  if (proc_p == NULL) {
    fprintf(stderr, "could not open process: %s", strerror(errno));
    return NULL;
  }

  proc_out = alloc_buf(HTTP_MAX_FILE_TYPE_LENGTH);

  // skip until mime type is read
  while (fgetc(proc_p) != ' ') {
  }

  if (fgets(proc_out, HTTP_MAX_FILE_TYPE_LENGTH, proc_p) == NULL) {
    fprintf(stderr, "could not read from process stdout\n");
    return NULL;
  }

  proc_out[strlen(proc_out) - 1] = '\0';

  pclose(proc_p);

  return proc_out;
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

void *handle_request(void *connfdp) {
  HTTPCommand command;
  HTTPHeader hdrs[HTTP_MAX_HDRS];
  char *send_buf, *connection;
  struct stat st;

  int connfd = *(int *)connfdp;
  size_t partial_response_code, len_response, n_hdrs, keep_alive;

  alloc_hdr(hdrs, HTTP_MAX_HDR_SZ, HTTP_MAX_HDRS);
  memset(&command, 0, sizeof(command));

  keep_alive = 1;
  do {
    partial_response_code = http_recv(connfd, &command, hdrs, &n_hdrs);

    connection = get_http_header("Connection", hdrs, n_hdrs);
    if (connection == NULL ||
        strncmp(connection, "keep-alive", strlen("keep-alive")) != 0) {
      keep_alive = 0;
      connection = "close";
    }

    char index_htm[strlen(command.uri) + HTTP_INDEX_FILE_LENGTH + 1];
    char index_html[strlen(command.uri) + HTTP_INDEX_FILE_LENGTH + 1];

    if (partial_response_code != HTTP_OK) {  // either 400, 405, or 505
      snprintf(command.uri, sizeof(command.uri), "/%zu.html",
               partial_response_code);
      strnins(command.uri, ERROR_DOCUMENT_ROOT, strlen(ERROR_DOCUMENT_ROOT));
      connection = "close";
    } else {
      strnins(command.uri, DOCUMENT_ROOT, strlen(DOCUMENT_ROOT));
      stat(command.uri, &st);
      if (S_ISDIR(st.st_mode)) {
        snprintf(index_htm, sizeof(index_htm), "%s%s", command.uri, INDEX_HTM);
        snprintf(index_html, sizeof(index_html), "%s%s", command.uri, INDEX_HTML);

        if (fexists(index_htm) == HTTP_OK) {
          strncpy(command.uri, index_htm, sizeof(command.uri));
        } else if (fexists(index_html) == HTTP_OK) {
          strncpy(command.uri, index_html, sizeof(command.uri));
        }
      }

      partial_response_code = http_access(command.uri);
      if (partial_response_code != HTTP_OK) {  // either 403 or 404
        snprintf(command.uri, sizeof(command.uri), "%s/%zu.html",
                 ERROR_DOCUMENT_ROOT, partial_response_code);
        connection = "close";
      }
    }

    send_buf = http_build_response(partial_response_code, command, connection,
                                   &len_response);

    http_send(connfd, send_buf, len_response);

    free_hdr(hdrs, HTTP_MAX_HDRS);
    free(send_buf);
  } while (keep_alive);

  close(connfd);

  return NULL;
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

size_t http_recv(int sockfd, HTTPCommand *command, HTTPHeader *hdrs,
                 size_t *n_hdrs) {
  char *recv_buf;
  ssize_t nb_recv, skip;

  recv_buf = alloc_buf(HTTP_MAX_RECV);

  if ((nb_recv = recv(sockfd, recv_buf, HTTP_MAX_RECV, 0)) < 0) {
    perror("recv");
    exit(EXIT_FAILURE);
  }
  recv_buf[nb_recv] = '\0';

  skip = parse_command(recv_buf, command);
  if (skip == -1) {  // parser failed, malformed request
    *n_hdrs = 0;
    return 400;
  }

  if (strncmp(command->method, "GET", strlen(command->method)) != 0) {
    *n_hdrs = 0;
    return 405;
  } else if (strncmp(command->version, "HTTP/1.1", HTTP_MAX_VERSION_LENGTH) !=
                 0 &&
             strncmp(command->version, "HTTP/1.0", HTTP_MAX_VERSION_LENGTH) !=
                 0) {
    strcpy(command->version, "HTTP/1.1");
    *n_hdrs = 0;
    return 505;
  }

  skip = parse_headers(recv_buf + skip, hdrs, n_hdrs);
  if (skip == -1) {  // parser failed, malformed request
    return 400;
  }

  free(recv_buf);

  return 200;
}

ssize_t http_send(int sockfd, char *send_buf, size_t len_send_buf) {
  ssize_t nb_sent;

  // TODO: check to see if nb_sent = nb_read after first implementation
  if ((nb_sent = send(sockfd, send_buf, len_send_buf, 0)) < 0) {
    perror("send");
    return -1;
  }

  return nb_sent;
}

const char *http_status(size_t response_code) {
  switch (response_code) {
    case HTTP_FORBIDDEN:
      return "Forbidden";
    case HTTP_NOT_FOUND:
      return "Not Found";
    case HTTP_BAD_REQUEST:
      return "Bad Request";
    case HTTP_METHOD_NOT_ALLOWED:
      return "Method Not Allowed";
    case HTTP_VERSION_NOT_SUPPORTED:
      return "HTTP Version Not Supported";
    case HTTP_OK:
      return "OK";
    default:
      fprintf(stderr, "[FATAL] %s:%d: this code should be unreachable\n",
              __func__, __LINE__ - 1);
      exit(EXIT_FAILURE);
  }
}

int is_valid_port(const char *arg) {
  int port = atoi(arg);
  return (port >= 1024 && port <= 65535);
}

ssize_t parse_command(char *recv_buf, HTTPCommand *command) {
  char line_buf[HTTP_MAX_METHOD_LENGTH + HTTP_MAX_URI_LENGTH +
                HTTP_MAX_VERSION_LENGTH + 3];  // 1 for each string's null term.
  size_t offset;
  ssize_t i, j;

  offset = http_readline(recv_buf, line_buf);

  i = 0;
  j = read_until(line_buf, command->method, sizeof(command->method), ' ');
  if (j == -1) return -1;
  i += j;

  j = read_until(line_buf + i, command->uri, sizeof(command->uri), ' ');
  if (j == -1) return -1;
  i += j;

  j = read_until(line_buf + i, command->version, sizeof(command->version),
                 '\0');
  if (j == -1) return -1;
  i += j;

  return offset;
}

ssize_t parse_headers(char *read_buf, HTTPHeader *hdrs, size_t *n_hdrs) {
  char line_buf[HTTP_MAXLINE + 1];
  size_t global_offset, local_offset;
  ssize_t i, j;

  global_offset = 0;
  local_offset = 0;
  *n_hdrs = 0;
  while ((local_offset = http_readline(read_buf, line_buf)) != 0) {
    i = 0;
    j = read_until(line_buf + i, hdrs[*n_hdrs].key, HTTP_MAX_HDR_SZ, ':');
    if (j == -1) return -1;

    i += j;

    j = read_until(line_buf + i, hdrs[*n_hdrs].value, HTTP_MAX_HDR_SZ, '\0');
    if (j == -1) return -1;

    i += j;

    read_buf += local_offset;
    global_offset += local_offset;
    if (*n_hdrs == HTTP_MAX_HDRS - 1) {
      return -1;
    }
    (*n_hdrs)++;
  }

  return global_offset + 2;  // move past final CRLF
}

char *read_file(char *fpath, size_t *nb_read) {
  char *out_buf;
  FILE *fp;
  struct stat st;

  if ((fp = fopen(fpath, "rb")) == NULL) {
    // server error
    return NULL;
  }

  if (stat(fpath, &st) < 0) {
    // server error
    return NULL;
  }

  out_buf = alloc_buf(st.st_size);

  if ((*nb_read = fread(out_buf, 1, st.st_size, fp)) < (size_t)st.st_size) {
    fclose(fp);

    return NULL;
  }

  fclose(fp);

  return out_buf;
}

ssize_t read_until(char *read_buf, char *out_buf, size_t len_out_buf,
                   char end) {
  size_t len_read_buf, i;

  // move past space between ':' and header value
  while (isspace(*read_buf)) {
    read_buf += 1;
  }

  len_read_buf = strlen(read_buf);
  // up to the length of the input buffer, read as many characters are allowed
  // in `out_buf`
  for (i = 0; i < len_read_buf && i < len_out_buf && read_buf[i] != end; ++i) {
    out_buf[i] = read_buf[i];
  }

  // if nothing found, bad request
  if (read_buf[i] != end) {
    return -1;
  }

  out_buf[i] = '\0';

  return (ssize_t)i + 1;  // move pointer to next field of http status line
}

size_t strnins(char *dst, const char *src, size_t n) {
  size_t src_len, dst_len;

  src_len = strlen(src);
  dst_len = strlen(dst);

  if (n > src_len) {
    n = src_len;
  }

  char tmp[dst_len + n + 1];
  strncpy(tmp, src, n);
  strncpy(tmp + n, dst, dst_len);
  strncpy(dst, tmp, src_len + dst_len);

  return n;
}

size_t strrnins(char *dst, const char *src, size_t n) {
  size_t src_len, dst_len;

  src_len = strlen(src);
  dst_len = strlen(dst);

  if (n > src_len) {
    n = src_len;
  }

  strncpy(dst + dst_len, src, n);

  return n;
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
