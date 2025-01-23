.PHONY: all clean fmt

CC ?= gcc
CFLAGS ?= -ggdb -O0 -Wall -Wextra -pedantic -std=c23

all: dump_heap

dump_heap: dump_heap.c
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f dump_heap

fmt: dump_heap.c
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i $^
