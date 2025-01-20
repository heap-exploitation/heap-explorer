.PHONY: all clean fmt

CC ?= gcc
CFLAGS ?= -ggdb -O0 -Wall -Wextra -pedantic -std=c23

all: print_chunk

print_chunk: print_chunk.c
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f print_chunk

fmt: print_chunk.c
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i $^
