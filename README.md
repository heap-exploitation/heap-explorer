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
You are exploring arena 0.
1. Allocate chunk(s).
2. Free a chunk.
3. Print all chunks.
4. Print a tcache list.
5. Print a fastbin list.
6. Print a bin list.
7. Switch to next arena.
8. Exit Heap Explorer.
> 3
[0]:	0x617ba3f17008, data size: 0x288 (base chunk)
[1]:	0x617ba3f17298, data size: 0x18 (arena 0, tcache 0)
[2]:	0x617ba3f172b8, data size: 0x18
[3]:	0x617ba3f172d8, data size: 0x78
[4]:	0x617ba3f17358, data size: 0x318
[5]:	0x617ba3f17678, data size: 0x68
[6]:	0x617ba3f176e8, data size: 0x538
[7]:	0x617ba3f17c28, data size: 0xd8
[8]:	0x617ba3f17d08, data size: 0x1a8
[9]:	0x617ba3f17eb8, data size: 0x68
[10]:	0x617ba3f17f28, data size: 0x58
[11]:	0x617ba3f17f88, data size: 0x78
[12]:	0x617ba3f18008, data size: 0xa8
[13]:	0x617ba3f180b8, data size: 0x68
[14]:	0x617ba3f18128, data size: 0x48
[15]:	0x617ba3f18178, data size: 0xb8
[16]:	0x617ba3f18238, data size: 0x18
[17]:	0x617ba3f18258, data size: 0xb8
[18]:	0x617ba3f18318, data size: 0x18
[19]:	0x617ba3f18338, data size: 0x28
[20]:	0x617ba3f18368, data size: 0xd8
[21]:	0x617ba3f18448, data size: 0xd8
[22]:	0x617ba3f18528, data size: 0x28 (arena 0, tcache 1)
[23]:	0x617ba3f18558, data size: 0x18
[24]:	0x617ba3f18578, data size: 0xc8 (arena 0, tcache 11)
[25]:	0x617ba3f18648, data size: 0x28 (arena 0, tcache 1)
[26]:	0x617ba3f18678, data size: 0x18
[27]:	0x617ba3f18698, data size: 0xc8 (arena 0, tcache 11)
...
You are exploring arena 0.
1. Allocate chunk(s).
2. Free a chunk.
3. Print all chunks.
4. Print a tcache list.
5. Print a fastbin list.
6. Print a bin list.
7. Switch to next arena.
8. Exit Heap Explorer.
> 8
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
