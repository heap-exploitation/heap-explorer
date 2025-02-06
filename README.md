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
Welcome to the heap explorer!
1. Allocate chunk(s).
2. Free a chunk.
3. Print all chunks.
4. Print a tcache list.
5. Print a fastbin list.
6. Print a bin list.
7. Exit the heap explorer.
> 3
[0]:	0x5fe4fb8ef008, data size: 0x288 (base chunk)
[1]:	0x5fe4fb8ef298, data size: 0x18 (tcache 0)
[2]:	0x5fe4fb8ef2b8, data size: 0x18
[3]:	0x5fe4fb8ef2d8, data size: 0x78
[4]:	0x5fe4fb8ef358, data size: 0x318
[5]:	0x5fe4fb8ef678, data size: 0x68
[6]:	0x5fe4fb8ef6e8, data size: 0x538
[7]:	0x5fe4fb8efc28, data size: 0xd8
[8]:	0x5fe4fb8efd08, data size: 0x1a8
[9]:	0x5fe4fb8efeb8, data size: 0x68
[10]:	0x5fe4fb8eff28, data size: 0x58
[11]:	0x5fe4fb8eff88, data size: 0x78
[12]:	0x5fe4fb8f0008, data size: 0xa8
[13]:	0x5fe4fb8f00b8, data size: 0x68
[14]:	0x5fe4fb8f0128, data size: 0x48
[15]:	0x5fe4fb8f0178, data size: 0xb8
[16]:	0x5fe4fb8f0238, data size: 0x18
[17]:	0x5fe4fb8f0258, data size: 0xb8
[18]:	0x5fe4fb8f0318, data size: 0x18
[19]:	0x5fe4fb8f0338, data size: 0x28
[20]:	0x5fe4fb8f0368, data size: 0xd8
[21]:	0x5fe4fb8f0448, data size: 0xd8
[22]:	0x5fe4fb8f0528, data size: 0x28 (free 2)
[23]:	0x5fe4fb8f0558, data size: 0x18
[24]:	0x5fe4fb8f0578, data size: 0x48 (tcache 3)
[25]:	0x5fe4fb8f05c8, data size: 0x28 (tcache 1)
...

1. Allocate chunk(s).
2. Free a chunk.
3. Print all chunks.
4. Print a tcache list.
5. Print a fastbin list.
6. Print a bin list.
7. Exit the heap explorer.
> 7
Bye!
Dave and Dale are cool cats
Dave and Dale are cool cats
Dave and Dale are cool cats
...
```

## Compatibility

This library has been tested only on programs using Arch's glibc package, version `2.41+r2+g0a7c7a3e283a-1`.
It's pretty easy to port to other modern versions of glibc; just change the `*_OFFSET` constants in `heap_explorer.c`.

## Why should I use this over $OTHER_TOOL?

You shouldn't :)
