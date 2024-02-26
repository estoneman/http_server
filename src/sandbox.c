/* sandbox.c */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/http_server.h"

#define MAX_HDRS 1024
#define MAX_HDR_SZ 1024

typedef struct {
  int major;
  int minor;
} HTTPVersionInfo;

typedef struct {
  char *method;
  char *uri;
  HTTPVersionInfo version;
} HTTPCommand;

typedef struct {
  char *key;
  char *value;
} HTTPHeader;

HTTPHeader hdrs[MAX_HDRS];
size_t n_hdrs = 0;

void chk_alloc_err(void *mem, const char *allocator, const char *func,
                   int line) {
  if (mem == NULL) {
    fprintf(stderr, "%s failed @%s:%d\n", allocator, func, line);
    exit(EXIT_FAILURE);
  }
}

void parse_command(char *request) {
  todo(__func__);
}

/* 
 * -- NOTE --
 * parser unstable when delimiter occurs in unexpected locations of a given
 * header
 */
void parse_headers(char *request) {
  char *line, *field, *sub_field, *saveptr1, *saveptr2;
  const char *field_delim = "\r\n", *kv_delim = ":";
  uint8_t pos;

  pos = 0;
  for (size_t i = 1; ; ++i, ++n_hdrs, request = NULL) {
    line = strtok_r(request, field_delim, &saveptr1);
    if (line == NULL)
      break;

    for (field = line; ; field = NULL) {
      sub_field = strtok_r(field, kv_delim, &saveptr2); 
      if (sub_field == NULL)
        break;
      strncpy(pos == 0 ? hdrs[n_hdrs].key : hdrs[n_hdrs].value, sub_field,
              strlen(sub_field) + 1);
      pos = !pos;
    }
  }
}

void alloc_hdr(size_t size, size_t nmemb) {
  for (size_t i = 0; i < nmemb; ++i) {
    hdrs[i].key = malloc(size + 1);
    hdrs[i].value = malloc(size + 1);
  }
}

void free_hdr(size_t nmemb) {
  for (size_t i = 0; i < nmemb; ++i) {
    free(hdrs[i].key);
    free(hdrs[i].value);
  }
}

void print_headers(void) {
  for (size_t i = 0; i < n_hdrs; ++i) {
    printf("%s: %s\n", hdrs[i].key, hdrs[i].value);
  }
}

void print_command(HTTPCommand command) {
  puts("HTTPCommand {"); 
  printf("  method: %s\n  uri: %s\n  version: HTTP/%d.%d\n",
         command.method, command.uri, command.version.major,
         command.version.minor);
  puts("}"); 
}

int main(void) {
  char *request;
  size_t skip;
  HTTPCommand command;

  request = malloc(1024 * 1024);
  chk_alloc_err(request, "malloc", __func__, __LINE__ - 1);

  // what happens if you had data?
  //   - need to give the header parser an end (not as simple as an EOF marker)
  strcpy(request, "Host: example.com\r\n"
                  "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36\r\n"
                  "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n"
                  "Accept-Encoding: gzip, deflate, br\r\n"
                  "Accept-Language: en-US,en;q=0.9\r\n"
                  "Connection: keep-alive\r\n"
                  "Upgrade-Insecure-Requests: 1\r\n"
                  "Referer: https://www.google.com/\r\n"
                  "Cache-Control: max-age=0\r\n"
                  "If-Modified-Since: Mon, 29 Nov 2021 12:00:00 GMT\r\n"
                  "If-None-Match: \"etag123\"\r\n"
                  "Cookie: session_id=1234567890\r\n"
                  "Content-Type: application/json\r\n"
                  "Content-Length: 123\r\n"
                  "Authorization: Bearer token123\r\n"
                  "X-Requested-With: XMLHttpRequest\r\n"
                  "X-Forwarded-For: 192.168.1.1\r\n"
                  "X-Forwarded-Proto: https\r\n"
                  "X-Real-IP: 192.168.1.1\r\n"
                  "DNT: 1\r\n"
                  "Pragma: no-cache\r\n"
                  "ETag: \"etag123\"\r\n"
                  "Last-Modified: Tue, 01 Feb 2022 08:00:00 GMT\r\n"
                  "Origin: https://example.com\r\n"
                  "Access-Control-Allow-Origin: *\r\n"
                  "Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept\r\n"
                  "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
                  "Allow: GET, POST\r\n"
                  "Content-Disposition: attachment; filename=\"example.txt\"\r\n"
                  "Location: https://example.com/redirect\r\n"
                  "Set-Cookie: session_id=987654321; Path=/; Secure; HttpOnly; SameSite=None\r\n"
                  "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\n"
                  "X-Content-Type-Options: nosniff\r\n"
                  "X-Frame-Options: DENY\r\n\r\n");

  alloc_hdr(MAX_HDR_SZ, MAX_HDRS);

  parse_command(request);
  print_command(command);

  parse_headers(request + skip);
  print_headers();

  free_hdr(MAX_HDRS);
  free(request);

  return EXIT_SUCCESS;
}
