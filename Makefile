CC:=$(shell which gcc)

CFLAGS:=-Wall -Werror -Wextra -pedantic -fsanitize=address -fanalyzer -O0 -g -std=gnu11
LDFLAGS:=-lpthread

SRC_DIR:=src
SRC:=$(wildcard $(SRC_DIR)/*.c)
OUT_DIR:=out

DEFAULT_TARGET:=http_server
VALID_TARGETS:=build clean help

all: $(DEFAULT_TARGET)

$(DEFAULT_TARGET): % : $(SRC_DIR)/%.c
	@mkdir -p $(OUT_DIR)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $(OUT_DIR)/$@ $(SRC)

.PHONY:
clean:
	$(info Removing $(OUT_DIR))
	@rm -rf $(OUT_DIR)

.PHONY:
help: ;
	$(info Valid targets: $(VALID_TARGETS))
