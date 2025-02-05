.PHONY: all clean fmt

CC ?= gcc
CFLAGS ?= -ggdb -O0 -Wall -Wextra -pedantic -std=c23 -fPIC

all: playground libheap_explorer.so

libheap_explorer.so: heap_explorer.c
	$(CC) -shared $(CFLAGS) $^ -o $@

playground: playground.c heap_explorer.c
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f *.so *.o playground

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c
