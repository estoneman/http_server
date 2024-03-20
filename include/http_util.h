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
#define HTTP_MAX_HDRS 32
#define HTTP_MAX_HDR_SZ 1024
#define HTTP_MAX_RECV (1024 * 1024)
#define HTTP_MAX_SEND (1024 * 1024)  // change me when responding w/ files
#define HTTP_MAX_SEND_HDRS 5
#define HTTP_MAX_METHOD_LENGTH 32
#define HTTP_MAX_URI_LENGTH 1024
#define HTTP_MAX_VERSION_LENGTH 9
#define HTTP_MAX_FILE_TYPE_LENGTH 128
#define HTTP_MAX_FILE_NAME_LENGTH 255
#define HTTP_ERR_FILE_NAME_LENGTH 8
#define HTTP_INDEX_FILE_LENGTH \
  10  // at most, this length will be 10
      // (index.html)

#define HTTP_TIMEOUT -1
#define HTTP_OK 200
#define HTTP_BAD_REQUEST 400
#define HTTP_FORBIDDEN 403
#define HTTP_NOT_FOUND 404
#define HTTP_METHOD_NOT_ALLOWED 405
#define HTTP_VERSION_NOT_SUPPORTED 505

#define DOCUMENT_ROOT "www"
#define ERROR_DOCUMENT_ROOT "err"
#define INDEX_HTM "index.htm"
#define INDEX_HTML "index.html"

#define MIN_PORT 1024
#define MAX_PORT 65535

typedef struct {
  char method[HTTP_MAX_METHOD_LENGTH + 1];
  char uri[HTTP_MAX_URI_LENGTH + 1];
  char version[HTTP_MAX_VERSION_LENGTH + 1];
} HTTPCommand;

typedef struct {
  char *key;
  char *value;
} HTTPHeader;

char *alloc_buf(size_t);
void alloc_hdr(HTTPHeader *, size_t, size_t);
void chk_alloc_err(void *, const char *, const char *, int);
size_t fexists(const char *);
int fill_socket_info(struct addrinfo **, struct addrinfo **, const char *);
ssize_t find_crlf(char *);
char *file_cmd(const char *);
size_t freadable(const char *);
void free_hdr(HTTPHeader *, size_t);
char *file_ext(const char *);
char *get_file_type(const char *, size_t *);
char *get_http_header(char *, HTTPHeader *, size_t);
void *get_inetaddr(struct sockaddr *);
void get_ipstr(char *, struct sockaddr *);
size_t http_access(const char *);
char *http_build_response(size_t, HTTPCommand, char *, size_t *);
void *handle_request(void *);
ssize_t http_readline(char *, char *);
ssize_t http_recv(int, char *, size_t);
ssize_t http_send(int, char *, size_t);
const char *http_status(size_t);
int is_valid_port(const char *);
ssize_t parse_command(char *, HTTPCommand *);
ssize_t parse_headers(char *, HTTPHeader *, size_t *);
size_t parse_request(char *, HTTPCommand *, HTTPHeader *, size_t *);
char *read_file(char *, size_t *);
ssize_t read_until(char *, char *, size_t, char);
size_t strnins(char *, const char *, size_t n);
size_t strrnins(char *, const char *, size_t n);

// debug
void print_headers(HTTPHeader *, size_t);
void print_command(HTTPCommand);

#endif  // HTTP_SERVER_H
