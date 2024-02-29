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
#define HTTP_MAX_SEND (1024 * 1024) // change me when responding w/ files
#define HTTP_MAX_SEND_HDRS 5                                  
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

char *alloc_buf(size_t size);
void alloc_hdr(HTTPHeader *, size_t, size_t);
char *http_build_response(size_t *, const char *);
void chk_alloc_err(void *, const char *, const char *, int);
int fill_socket_info(struct addrinfo **, struct addrinfo **,
                            const char *);
size_t find_crlf(char *buf);
void free_hdr(HTTPHeader *, size_t);
void *get_inetaddr(struct sockaddr *);
void get_ipstr(char *, struct addrinfo *);
size_t http_readline(char *recv_buf, char *line_buf);
ssize_t http_recv(int);
ssize_t http_send(int);
int is_valid_port(const char *);
size_t parse_command(char *, HTTPCommand *);
size_t parse_headers(char *, HTTPHeader *, size_t *);
char *read_file(const char *, size_t *);
size_t read_until(char *buf, char *out, char end);
int validate_port(const char *);

// debug
void print_header(HTTPHeader);
void print_headers(HTTPHeader *, size_t);
void print_command(HTTPCommand);
void todo(const char *func);

#endif  // HTTP_SERVER_H
