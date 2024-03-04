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

char *http_build_response(size_t response_code, size_t *response_sz, char *uri) {
  char *send_buf, *file_contents, *ftype;
  char mime_type[HTTP_MAX_FILE_TYPE_LENGTH + 1];
  size_t nb_read, hdr_sz;
  char response_uri[HTTP_MAX_FILE_NAME_LENGTH + 1];
  const char *status_line;

  switch (response_code) {
    case HTTP_BAD_REQUEST:
      strcpy(response_uri, "400.html");
      status_line = "HTTP/1.1 400 Bad Request";
      break;
    case HTTP_METHOD_NOT_ALLOWED:
      strcpy(response_uri, "405.html");
      status_line = "HTTP/1.1 405 Method Not Allowed";
      break;
    case HTTP_VERSION_NOT_SUPPORTED:
      strcpy(response_uri, "505.html");
      status_line = "HTTP/1.1 505 HTTP Version Not Supported";
      break;
    default:  // HTTP_OK (for now)
      strcpy(response_uri, uri + 1);
      status_line = "HTTP/1.1 200 OK";
      break;
  }

  if ((ftype = file_type(response_uri)) != NULL) {
    strcpy(mime_type, strchr(ftype, ' '));
  } else {
    strcpy(mime_type, "application/octet-stream");
  }
// ssize_t read_until(char *read_buf, char *out_buf, size_t len_out_buf,
//                    char end) {

  hdr_sz = HTTP_MAX_HDR_SZ * 4;
  char content_length_fmt[] = "Content-Length: %zu";
  char content_length[64];
  char content_type_fmt[] = "Content-Type:%s";
  char content_type[128];
  char headers[hdr_sz];

  // two errors can happen here
  //   1. 404 file does not exist
  //   2. 403 server does not have permission to read the file
  if ((file_contents = read_file(response_uri, &nb_read)) == 0) {
    return NULL;
  }

  snprintf(content_length, sizeof(content_length), content_length_fmt, nb_read);
  snprintf(content_type, sizeof(content_type), content_type_fmt, mime_type);
  snprintf(headers, sizeof(headers), "%s\r\n%s\r\n%s\r\n\r\n",
           status_line, content_length, content_type);

  *response_sz = strlen(headers) + nb_read;
  send_buf = alloc_buf(*response_sz);

  strncpy(send_buf, headers, strlen(headers));
  send_buf[strlen(headers)] = '\0';
  strncat(send_buf, file_contents, nb_read);

  free(ftype);

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

char *file_type(const char *fpath) {
  char *proc_out;
  char cmd[HTTP_MAX_FILE_NAME_LENGTH + 1];

  snprintf(cmd, HTTP_MAX_FILE_NAME_LENGTH, "file --mime-type %s", fpath);
  FILE *proc_p = popen(cmd, "r");
  if (proc_p == NULL) {
    fprintf(stderr, "could not open process: %s", strerror(errno));
    return NULL;
  }

  proc_out = alloc_buf(HTTP_MAX_FILE_TYPE_LENGTH + 1);

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

void *handle_request(void *connfdp) {
  HTTPCommand command;
  HTTPHeader hdrs[HTTP_MAX_HDRS];

  int connfd = *(int*)connfdp;
  size_t response_code;

  alloc_hdr(hdrs, HTTP_MAX_HDR_SZ, HTTP_MAX_HDRS);
  memset(&command, 0, sizeof(command));

  response_code = http_recv(connfd, &command, hdrs);

  http_send(connfd, response_code, command.uri);

  close(connfd);

  free_hdr(hdrs, HTTP_MAX_HDRS);

  return NULL;
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

size_t http_recv(int sockfd, HTTPCommand *command, HTTPHeader *hdrs) {
  size_t n_hdrs;
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
    return 400;
  }

  if (strncmp(command->method, "GET", strlen(command->method)) != 0) {
    return 405;
  } else if (strncmp(command->version, "HTTP/1.1", HTTP_MAX_VERSION_LENGTH) != 0 
             &&
             strncmp(command->version, "HTTP/1.0", HTTP_MAX_VERSION_LENGTH)
             != 0) {
    return 505;
  }

  skip = parse_headers(recv_buf + skip, hdrs, &n_hdrs);
  if (skip == -1) {   // parser failed, malformed request
    return 400;
  }

  free(recv_buf);

  return 200;
}

ssize_t http_send(int sockfd, size_t response_code, char *uri) {
  char *send_buf;
  ssize_t nb_sent;
  size_t send_buf_sz;

  if ((send_buf = http_build_response(response_code, &send_buf_sz, uri))
      == NULL) {
    return -1;
  }

  // TODO: check to see if nb_sent = nb_read after first implementation
  if ((nb_sent = send(sockfd, send_buf, send_buf_sz, 0)) < 0) {
    perror("send");
    return -1;
  }

  free(send_buf);

  return nb_sent;
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
  if (j == -1)
    return -1;
  i += j;

  j = read_until(line_buf + i, command->uri, sizeof(command->uri), ' ');
  if (j == -1)
    return -1;
  i += j;

  j = read_until(line_buf + i, command->version, sizeof(command->version),
                 '\0');
  if (j == -1)
    return -1;
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
    if (j == -1)
      return -1;

    i += j;

    j = read_until(line_buf + i, hdrs[*n_hdrs].value, HTTP_MAX_HDR_SZ, '\0');
    if (j == -1)
      return -1;

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

char *read_file(const char *fpath, size_t *nb_read) {
  char *out_buf;
  FILE *fp;
  struct stat st;

  fprintf(stderr, "[INFO] attempting to read %s\n", fpath);
  if (stat(fpath, &st) < 0) {
    fprintf(stderr, "unable to stat file: %s\n", strerror(errno));

    return 0;
  }

  if ((fp = fopen(fpath, "r")) == NULL) {
    fprintf(stderr, "unable to open file: %s\n", strerror(errno));

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

  return (ssize_t)i + 1; // move pointer to next field of http status line
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
