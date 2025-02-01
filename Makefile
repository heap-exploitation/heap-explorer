.PHONY: all clean fmt

CC ?= gcc
CFLAGS ?= -ggdb -O0 -Wall -Wextra -pedantic -std=c23

all: test libdump_heap.so

libdump_heap.so: dump_heap.c
	$(CC) -shared $(CFLAGS) $^ -o $@

test: test.c dump_heap.c
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f *.so *.o test

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c
