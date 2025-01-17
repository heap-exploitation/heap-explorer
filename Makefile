.PHONY: all clean

CC ?= gcc
CFLAGS ?= -ggdb -O0 -Wall


all: print_chunk

print_chunk: print_chunk.c
	$(CC) $(CFLAGS) print_chunk.c -o print_chunk

clean:
	rm -f print_chunk
