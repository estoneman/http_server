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

const char *server_version = "Server: NetSysHTTPServer/0.3";

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

size_t fexists(const char *fpath) {
  if (access(fpath, F_OK) < 0) {
    return HTTP_NOT_FOUND;
  }

  return HTTP_OK;
}

char *file_cmd(const char *fpath) {
  char *proc_out;
  char cmd[HTTP_MAX_FILE_NAME_LENGTH + 1];

  snprintf(cmd, HTTP_MAX_FILE_NAME_LENGTH, "file -b --mime-type %s", fpath);
  FILE *proc_p = popen(cmd, "r");
  if (proc_p == NULL) {
    fprintf(stderr, "could not open process: %s", strerror(errno));
    return NULL;
  }

  proc_out = alloc_buf(HTTP_MAX_FILE_TYPE_LENGTH);

  if (fgets(proc_out, HTTP_MAX_FILE_TYPE_LENGTH, proc_p) == NULL) {
    fprintf(stderr, "could not read from process stdout\n");
    return NULL;
  }

  proc_out[strlen(proc_out) - 1] = '\0';

  pclose(proc_p);

  return proc_out;
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
      perror("bind");
      continue;
    }

    break;  // successfully created socket and binded to address
  }

  if (*srv_entry == NULL) {
    fprintf(stderr, "[ERROR] could not bind to any address\n");
    freeaddrinfo(*srv_entries);

    exit(EXIT_FAILURE);
  }

  return sockfd;
}

ssize_t find_crlf(char *buf) {
  char needle[] = "\r\n";
  size_t len_recv_buf, needle_idx, len_needle;

  len_needle = strlen(needle);
  len_recv_buf = strlen(buf);

  for (needle_idx = 0; needle_idx < len_recv_buf; ++needle_idx) {
    if (strncmp(buf + needle_idx, needle, len_needle) == 0) {
      return needle_idx;
    }
  }

  return -1;
}

size_t freadable(const char *fpath) {
  if (access(fpath, R_OK) < 0) {
    return HTTP_FORBIDDEN;
  }

  return HTTP_OK;
}

void free_hdr(HTTPHeader *hdrs, size_t nmemb) {
  for (size_t i = 0; i < nmemb; ++i) {
    free(hdrs[i].key);
    free(hdrs[i].value);
  }
}

char *file_ext(const char *fpath) {
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

  if ((file_type = file_ext(fpath)) != NULL) {
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

void *get_inetaddr(struct sockaddr *sa) {
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in *)sa)->sin_addr);
  }

  return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

void get_ipstr(char *ipstr, struct sockaddr *addr) {
  inet_ntop(addr->sa_family, get_inetaddr(addr), ipstr, INET6_ADDRSTRLEN);
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

// return a full http response
char *http_build_response(size_t rc, HTTPCommand command, char *connection,
                          size_t *len_send_buf) {
  char *send_buf, *file_contents, *file_type;
  const char *status_msg;
  size_t nb_read, free_buf_flag;

  if ((file_contents = read_file(command.uri, &nb_read)) == NULL) {
    fprintf(stderr, "[FATAL] file should always be able to be read\n");
    exit(EXIT_FAILURE);
  }

  char content_type[HTTP_MAX_FILE_TYPE_LENGTH + 1];
  char headers[HTTP_MAX_HDR_SZ * 3 + 1];

  status_msg = http_status(rc);
  free_buf_flag = 0;
  file_type = get_file_type(command.uri, &free_buf_flag);

  strncpy(content_type, file_type, HTTP_MAX_FILE_TYPE_LENGTH);
  snprintf(headers, sizeof(headers),
           "%s %zu %s\r\n"
           "%s\r\n"
           "Content-Length: %zu\r\n"
           "Content-Type: %s\r\n"
           "Connection: %s\r\n\r\n",
           command.version, rc, status_msg, server_version, nb_read,
           content_type, connection);

  *len_send_buf = nb_read + strlen(headers);
  send_buf = alloc_buf(*len_send_buf);
  memcpy(send_buf, headers, strlen(headers));
  memcpy(send_buf + strlen(headers), file_contents, nb_read);

  if (free_buf_flag == 1) {
    free(file_type);
  }

  return send_buf;
}

void *handle_request(void *connfdp) {
  HTTPCommand http_cmd;
  HTTPHeader http_hdrs[HTTP_MAX_HDRS];
  char *send_buf, *recv_buf, *connection;
  struct stat st;

  int connfd;
  size_t partial_response_code, len_response, n_hdrs, keep_alive;
  ssize_t nb_recv;

  connfd = *(int *)connfdp;
  keep_alive = 0;
  do {
    alloc_hdr(http_hdrs, HTTP_MAX_HDR_SZ, HTTP_MAX_HDRS);
    memset(&http_cmd, 0, sizeof(http_cmd));

    recv_buf = alloc_buf(HTTP_MAX_RECV);
    nb_recv = http_recv(connfd, recv_buf, keep_alive);
    if (nb_recv == HTTP_TIMEOUT) {
      keep_alive = 0;
      continue;
    }

    partial_response_code =
        parse_request(recv_buf, &http_cmd, http_hdrs, &n_hdrs);

    connection = get_http_header("Connection", http_hdrs, n_hdrs);
    if (connection == NULL ||
        strncmp(connection, "keep-alive", strlen("keep-alive")) != 0) {
      keep_alive = 0;
      connection = "close";
    } else {
      keep_alive = 1;
    }

    if (partial_response_code != HTTP_OK) {  // either 400, 405, or 505
      snprintf(http_cmd.uri, sizeof(http_cmd.uri), "/%zu.html",
               partial_response_code);
      strnins(http_cmd.uri, ERROR_DOCUMENT_ROOT, strlen(ERROR_DOCUMENT_ROOT));
      keep_alive = 0;
      connection = "close";
    } else {
      strnins(http_cmd.uri, DOCUMENT_ROOT, strlen(DOCUMENT_ROOT));

      char index_htm[strlen(http_cmd.uri) + HTTP_INDEX_FILE_LENGTH + 1];
      char index_html[strlen(http_cmd.uri) + HTTP_INDEX_FILE_LENGTH + 1];

      stat(http_cmd.uri, &st);
      if (S_ISDIR(st.st_mode)) {
        snprintf(index_htm, sizeof(index_htm), "%s%s", http_cmd.uri, INDEX_HTM);
        snprintf(index_html, sizeof(index_html), "%s%s", http_cmd.uri,
                 INDEX_HTML);

        if (fexists(index_htm) == HTTP_OK) {
          strncpy(http_cmd.uri, index_htm, sizeof(http_cmd.uri));
        } else if (fexists(index_html) == HTTP_OK) {
          strncpy(http_cmd.uri, index_html, sizeof(http_cmd.uri));
        }
      }

      partial_response_code = http_access(http_cmd.uri);
      if (partial_response_code != HTTP_OK) {  // either 403 or 404
        snprintf(http_cmd.uri, sizeof(http_cmd.uri), "%s/%zu.html",
                 ERROR_DOCUMENT_ROOT, partial_response_code);
        keep_alive = 0;
        connection = "close";
      }
    }

    send_buf = http_build_response(partial_response_code, http_cmd, connection,
                                   &len_response);

    http_send(connfd, send_buf, len_response);

    free_hdr(http_hdrs, HTTP_MAX_HDRS);
    free(recv_buf);
    free(send_buf);
  } while (keep_alive);

  fprintf(stderr, "[INFO] socket %d: closing\n", connfd);
  close(connfd);

  return NULL;
}

ssize_t http_readline(char *recv_buf, char *line_buf) {
  ssize_t needle_idx;

  if ((needle_idx = find_crlf(recv_buf)) <= 0) {
    return needle_idx;
  }

  strncpy(line_buf, recv_buf, needle_idx);
  line_buf[needle_idx] = '\0';

  return needle_idx + 2;  // move past CRLF
}

ssize_t http_recv(int sockfd, char *recv_buf, size_t keep_alive) {
  ssize_t nb_recv;
  struct timeval rcv_timeo;

  rcv_timeo.tv_usec = 0;
  fprintf(stderr, "[INFO] socket %d: keep_alive=%zu, ", sockfd, keep_alive);
  if (keep_alive) {
    rcv_timeo.tv_sec = 10;
    fprintf(stderr, "enabling timeout\n");
  } else {
    rcv_timeo.tv_sec = 0;
    fprintf(stderr, "disabling timeout\n");
  }

  if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &rcv_timeo,
                 sizeof(rcv_timeo)) < 0) {
    perror("setsockopt");

    exit(EXIT_FAILURE);
  }

  if ((nb_recv = recv(sockfd, recv_buf, HTTP_MAX_RECV, 0)) < 0) {
    fprintf(stderr, "[INFO] timeout received when keep_alive=%zu\n", keep_alive);
    return HTTP_TIMEOUT;
  }
  recv_buf[nb_recv] = '\0';

  return nb_recv;
}

size_t parse_request(char *recv_buf, HTTPCommand *http_cmd,
                     HTTPHeader *http_hdrs, size_t *n_hdrs) {
  ssize_t skip;

  skip = parse_command(recv_buf, http_cmd);
  if (skip == -1) {  // parser failed, malformed request
    *n_hdrs = 0;
    return HTTP_BAD_REQUEST;
  }

  if (strncmp(http_cmd->method, "GET", strlen(http_cmd->method)) != 0) {
    *n_hdrs = 0;
    return HTTP_METHOD_NOT_ALLOWED;
  } else if (strncmp(http_cmd->version, "HTTP/1.1", HTTP_MAX_VERSION_LENGTH) !=
                 0 &&
             strncmp(http_cmd->version, "HTTP/1.0", HTTP_MAX_VERSION_LENGTH) !=
                 0) {
    strcpy(http_cmd->version, "HTTP/1.1");
    *n_hdrs = 0;
    return HTTP_VERSION_NOT_SUPPORTED;
  }

  skip = parse_headers(recv_buf + skip, http_hdrs, n_hdrs);
  if (skip == -1) {  // parser failed, malformed request
    return HTTP_BAD_REQUEST;
  }

  return HTTP_OK;
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
  ssize_t local_offset, global_offset, i, j;

  global_offset = 0;
  local_offset = 0;
  *n_hdrs = 0;
  while ((local_offset = http_readline(read_buf, line_buf)) > 0) {
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

  // move past final CRLF
  return local_offset < 0 ? local_offset : global_offset + 2;
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
    fclose(fp);
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
  strncpy(tmp, dst, dst_len);
  strncpy(dst, src, src_len);
  strncpy(dst + src_len, tmp, dst_len);

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
