# Heap Explorer

Heap Explorer is an `LD_PRELOAD`able library that exports only 1 function:
```C
void explore_heap(void);
```

`explore_heap` starts a REPL that allows the user to perform a few different actions, such as `free`ing chunks, `malloc`ing chunks, printing freelists, etc.

`libheap_explorer.so` installs `explore_heap` as the `SIGINT` handler at load time, so you can do stuff like this:
```
$ LD_PRELOAD=/the/path/to/libheap_explorer.so python3 -c 'while True: print("Dave and Dale are cool cats")'
Dave and Dale are cool cats
Dave and Dale are cool cats
Dave and Dale are cool cats
...
^C
Welcome to Heap Explorer!
You are TID 821537, viewing arena 0 (main_arena)
1. Allocate chunk(s).
2. Free a chunk.
3. Print this arena.
4. Print a tcache list.
5. Print a fastbin list.
6. Print a bin list.
7. Switch to next arena.
8. Switch to next thread.
9. Exit Heap Explorer.
> 3
[0]:	0x55e6d9316008, data size: 0x288
[1]:	0x55e6d9316298, data size: 0x18 (arena 0, tcache 0)
[2]:	0x55e6d93162b8, data size: 0x18
[3]:	0x55e6d93162d8, data size: 0x78
[4]:	0x55e6d9316358, data size: 0x318
...
[1614]:	0x55e6d93c7a28, data size: 0x2e8 (arena 0, tcache 45)
[1615]:	0x55e6d93c7d18, data size: 0x128 (arena 0, tcache 17)
[1616]:	0x55e6d93c7e48, data size: 0x3d8 (arena 0, tcache 60)
[1617]:	0x55e6d93c8228, data size: 0x5c8
[1618]:	0x55e6d93c87f8, data size: 0xb68 (free 92)
[1619]:	0x55e6d93c9368, data size: 0x288 (arena 0, tcache 39)
[1620]:	0x55e6d93c95f8, data size: 0x878 (free 0)
[1621]:	0x55e6d93c9e78, data size: 0x2008
[1622]:	0x55e6d93cbe88, data size: 0x308
[1623]:	0x55e6d93cc198, data size: 0x1de68 (top chunk)

You are TID 821551, viewing arena 0 (main_arena)
1. Allocate chunk(s).
2. Free a chunk.
3. Print all chunks.
4. Print a tcache list.
5. Print a fastbin list.
6. Print a bin list.
7. Switch to next arena.
8. Switch to next thread.
9. Exit Heap Explorer.
> 9
Dave and Dale are cool cats
Dave and Dale are cool cats
Dave and Dale are cool cats
...
```

## Compatibility

This library has been tested only on programs using Arch's glibc package, version `2.41+r6+gcf88351b685d-1`.
It's pretty easy to port to other modern versions of glibc; just change the `*_OFFSET` constants in `heap_explorer.c`.

## Why should I use this over $OTHER_TOOL?

You shouldn't :)
