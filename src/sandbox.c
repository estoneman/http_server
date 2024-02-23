/* sandbox.c */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INIT_HDR_SZ 1024
#define MAX_HDR_VAL_LEN 1024

typedef char ** HttpHeader;

void chk_alloc_err(void *mem, const char *allocator, const char *func,
                   int line) {
  if (mem == NULL) {
    fprintf(stderr, "%s failed @%s:%d\n", allocator, func, line);
    exit(EXIT_FAILURE);
  }
}

// void get_header(char *request) {}

void parse_request(HttpHeader hdr, char *request) {
  (void)hdr;
  const char *field_delim = "\r\n";
  const char *kv_delim = ": ";
  (void)kv_delim;
  char *line, *field, *sub_field, *saveptr1, *saveptr2;
  size_t pos;

  // change this, but for now it's fine
  for (size_t i = 1; ; ++i, request = NULL) {
    pos = 0;
    line = strtok_r(request, field_delim, &saveptr1);
    if (line == NULL)
      break;
    printf("%zu: %s\n", i, line);
    for (field = line; ; field = NULL) {
      sub_field = strtok_r(field, kv_delim, &saveptr2); 
      if (sub_field == NULL)
        break;
      if (pos == 0)
        printf("  --> key: %s\n", sub_field);
      else if (pos == 1)
        printf("  --> value: %s\n", sub_field);
      pos++;
    }
  }
}

HttpHeader alloc_hdr() {
  HttpHeader hdr;

  hdr = malloc(INIT_HDR_SZ * sizeof(char*));
  chk_alloc_err(hdr, "malloc", __func__, __LINE__ - 1);

  for (size_t i = 0; i < INIT_HDR_SZ; ++i) {
    hdr[i] = malloc(MAX_HDR_VAL_LEN + 1);
    chk_alloc_err(hdr[i], "malloc", __func__, __LINE__ - 1);
  }

  return hdr;
}

void free_hdr(HttpHeader hdr) {
  for (size_t i = 0; i < INIT_HDR_SZ; ++i) {
    free(hdr[i]);
  }

  free(hdr);
}

size_t skip_http_cmd(char *request) {
  size_t i = 0;
  while (request[i] != '\r' && request[i + 1] != '\n') { i += 1; }

  return i;
}

int main(void) {
  char *request;
  HttpHeader hdr;
  size_t skip;

  request = malloc(1024 * 1024);
  chk_alloc_err(request, "malloc", __func__, __LINE__ - 1);

  strcpy(request, "GET / HTTP/1.1\r\n"
                  "Host: localhost\r\n"
                  "Content-Type: text/html\r\n"
                  "Content-Length: 100\r\n"
                  "Connection: keep-alive\r\n"
                  "X-Content-Type-Options: nosiff\r\n"
                  "Referrer-Policy: same-origin\r\n\r\n");

  hdr = alloc_hdr();

  skip = skip_http_cmd(request);
  parse_request(hdr, request + skip);

  free_hdr(hdr);
  free(request);

  return EXIT_SUCCESS;
}
