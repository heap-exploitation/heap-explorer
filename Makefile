.PHONY: all clean fmt

CC ?= gcc
CFLAGS ?= -ggdb -O0 -Wall -Wextra -Wpedantic -Wvla -std=c23 -fPIC

all: playground libheap_explorer.so

heap_explorer.o: heap_explorer.c
	$(CC) -c $(CFLAGS) $^ -o $@

libheap_explorer.so: heap_explorer.o
	$(CC) -shared $(CFLAGS) $^ -o $@

playground: playground.c heap_explorer.o
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f *.so *.o playground

fmt:
	clang-format --style='{IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' -i *.c
