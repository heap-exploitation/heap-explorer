/*
 * This is a glibc heap exploration program.
 * It allows you to allocate and free chunks,
 * and observe how various heap data structures
 * change.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Converts an int to a hex string.
// Returns a pointer to static memory.
static char *itoa_hex(uint64_t n) {
    static char const UINT64_MAX_STR_HEX[] = "0xffffffffffffffff";
    static char result_data[sizeof(UINT64_MAX_STR_HEX)];
    char *result = result_data;
    memset(result, 0, sizeof(result_data));

    static char PREFIX[] = "0x";
    strcpy(result, PREFIX);
    for (size_t i = 0; i < strlen(PREFIX); i++) {
        result++;
    }

    if (n == 0) {
        result[0] = '0';
        return result;
    }

    char const HEXDIGS[] = "0123456789abcdef";

    for (int i = 0; n > 0; i++) {
        result[i] = *(HEXDIGS + n % 16);
        n /= 16;
    }

    for (uint64_t i = 0; i < strlen(result) / 2; i++) {
        char tmp = result[i];
        result[i] = result[strlen(result) - i - 1];
        result[strlen(result) - i - 1] = tmp;
    }

    return result - strlen(PREFIX);
}

static char const UINT64_MAX_STR_DEC[] = "18446744073709551615";

// Converts an int to a decimal string
// Returns a pointer to static memory.
static char *itoa(uint64_t n) {
    static char result[sizeof(UINT64_MAX_STR_DEC)];
    memset(result, 0, sizeof(result));

    if (n == 0) {
        result[0] = '0';
        return result;
    }

    for (int i = 0; n > 0; i++) {
        result[i] = '0' + n % 10;
        n /= 10;
    }

    for (uint64_t i = 0; i < strlen(result) / 2; i++) {
        char tmp = result[i];
        result[i] = result[strlen(result) - i - 1];
        result[strlen(result) - i - 1] = tmp;
    }

    return result;
}

// Writes a null-terminated string to stdout
static void print(char const *const s) {
    write(STDOUT_FILENO, s, strlen(s));
}

// Writes a null-terminated string to stdout,
// followed by a newline
static void println(char const *const s) {
    static char const NL[] = "\n";
    print(s);
    print(NL);
}

// Writes `array_len` 8-byte values from ptrs to stdout, in hex, with indices.
static void println_ptrs(void *const ptrs[], uint64_t const array_len) {
    print("{ ");
    bool first = true;
    for (uint64_t i = 0; i < array_len; i++) {
        if (ptrs[i] != NULL) {
            if (!first) {
                print(", ");
            }
            print("[");
            print(itoa(i));
            print("]: ");
            print(itoa_hex((intptr_t)ptrs[i]));
            first = false;
        }
    }
    println(" }");
}

// The glibc malloc_state struct, with some slight simplifications.
// Should still be binary-compatible.
struct malloc_state {
    uint32_t mutex;
    uint32_t flags;
    uint32_t have_fastchunks;
    void *fastbinsY[10];
    void *top;
    void *last_remainder;
    void *bins[255];
    uint32_t binmap[4];
    void *next;
    void *next_free;
    uint64_t attached_threads;
    uint64_t system_mem;
    uint64_t max_system_mem;
};

#define ARRAY_LEN(A) (sizeof(A) / sizeof(A[0]))

// The offset of malloc within glibc
static intptr_t const MALLOC_OFFSET = 0xa7e50;

// The base address of glibc.
// Note that this is not the base of the first entry from `info proc mappings`
// that came from libc.so.6. Instead, this is the base of the entry before that,
// because that mapping (which I believe is the libc .bss) is randomized
// contiguously with glibc.
static intptr_t const LIBC_BASE = (intptr_t)malloc - MALLOC_OFFSET;

// The offset of main_arena within glibc.
static intptr_t const MAIN_ARENA_OFFSET = 0x1eaac0;

// A pointer to main_arena in glibc. This is the
// struct that stores most of the heap state.
static struct malloc_state const *const the_main_arena =
    (struct malloc_state *)(LIBC_BASE + MAIN_ARENA_OFFSET);
#define NFASTBINS (ARRAY_LEN(the_main_arena->fastbinsY))

// Lists out the head of each fastbin
static void print_fastbin_heads(struct malloc_state const *const m) {
    print("fastbins: ");
    println_ptrs(m->fastbinsY, NFASTBINS);
}

static uint64_t get_chunk_data_size(void const *const chunk) {
    // We mask off the low 3 bits because they store metadata.
    // We subtract 10 because the size includes the chunk
    // header, but this unintuitive.
    return (*(uint64_t const *)chunk & ~7ull) - 0x10;
}

// Takes a pointer to a heap chunk's size (not prev_size),
// and dumps information about that chunk.
static void print_chunk(void const *const chunk) {
    uint64_t const size = get_chunk_data_size(chunk);

    print(itoa_hex((intptr_t)chunk));
    println(":");

    print("    size: ");
    print(itoa(size));
    println("");
}

#define TCACHE_SIZE (64)
struct tcache_perthread_struct {
    uint16_t counts[TCACHE_SIZE];
    void *entries[TCACHE_SIZE];
};

// Gets the address of the main tcache struct.
// This can't be hardcoded, because tcache is on the
// heap.
static struct tcache_perthread_struct *get_the_tcache(void) {
    intptr_t const TCACHE_PTR_OFFSET = 0x700;
    return *(struct tcache_perthread_struct **)(LIBC_BASE + TCACHE_PTR_OFFSET);
}

static void print_top_chunk(void const *const chunk) {
    uint64_t const size = get_chunk_data_size(chunk);

    print(itoa_hex((intptr_t)chunk));
    println(": (top chunk)");

    print("    data size: ");
    print(itoa(size));
    println("");
}

static void print_all_chunks(void) {
    // (Adding 8 to get to the chunk size)
    if (the_main_arena->top == NULL) {
        println("The heap is empty.");
        return;
    }
    void const *const top_chunk = (char const *)(the_main_arena->top) + 0x8;

    // It happens that tcache is the first thing on the heap.
    // We use that to get the base of the heap.
    // (Subtracting 8 to get to the chunk size)
    void const *curr_chunk = (char const *)get_the_tcache() - 0x8;

    while (curr_chunk != top_chunk) {
        print_chunk(curr_chunk);
        curr_chunk =
            (char const *)curr_chunk + get_chunk_data_size(curr_chunk) + 0x10;
    }

    print_top_chunk(top_chunk);
}

// Prints the heads of the tcache free lists
static void print_tcache_heads(struct tcache_perthread_struct *tcache) {
    print("entries: ");
    println_ptrs(tcache->entries, TCACHE_SIZE);
}

// Takes the address of a list link from tcache or fastbin,
// and deobfuscates it. Equivalent to REVEAL_PTR from glibc.
static void *deobfuscate_next_link(void *p) {
    return (void *)((((intptr_t)p) >> 12) ^ *(intptr_t *)p);
}

#define MAX_FASTBIN_SIZE (128)
static void print_fastbin_list(void *head) {
    static void *list_entries[MAX_FASTBIN_SIZE] = {};
    char *curr = (char *)head;
    uint64_t i = 0;
    while (curr != NULL) {
        list_entries[i] = curr;
        curr = deobfuscate_next_link(curr + 0x10);
        i++;
        if (i == MAX_FASTBIN_SIZE) {
            println("Fastbin too full! This should never happen.");
            exit(1);
        }
    }
    println_ptrs(list_entries, i);
}

static void print_tcache_list(void *head) {
    void *list_entries[TCACHE_SIZE] = {};
    void *curr = head;
    uint64_t i = 0;
    while (curr != NULL) {
        list_entries[i] = curr;
        curr = deobfuscate_next_link(curr);
        i++;
    }
    println_ptrs(list_entries, i);
}

// Reads a base-10 int from stdin
static uint64_t parse_base10(char const *s) {
    uint64_t result = 0;
    while ('0' <= *s && *s <= '9') {
        result *= 10;
        result += *s - '0';
        s++;
    }

    return result;
}

// Reads a hex int from stdin
static uint64_t parse_base16(char const *s) {
    uint64_t result = 0;
    while (('0' <= *s && *s <= '9') || ('a' <= *s && *s <= 'f') ||
           ('A' <= *s && *s <= 'F')) {
        result *= 16;
        if ('0' <= *s && *s <= '9') {
            result += *s - '0';
        } else if ('a' <= *s && *s <= 'f') {
            result += *s - 'a' + 10;
        } else if ('A' <= *s && *s <= 'F') {
            result += *s - 'A' + 10;
        }
        s++;
    }

    return result;
}

static uint64_t get_number(void) {
    char num[sizeof(UINT64_MAX_STR_DEC)] = {};
    read(STDIN_FILENO, num, sizeof(num) - 1);
    return num[0] == '0' && (num[1] == 'x' || num[1] == 'X')
               ? parse_base16(num + 2)
               : parse_base10(num);
}

int main(void) {
    void *chunks[128] = {};
    uint64_t chunk_count = 0;
    while (true) {
        println("1. Allocate chunk(s).");
        println("2. Free a chunk.");
        println("4. Print all chunks.");
        println("5. Print the fastbin heads.");
        println("6. Print the tcache heads.");
        println("7. Print a tcache list.");
        println("8. Print a fastbin list.");
        switch (get_number()) {
        case 0: {
            break;
        }
        case 1: {
            println("How many?");
            uint64_t count = get_number();
            println("How big?");
            uint64_t size = get_number();
            for (uint64_t i = 0; i < count; i++) {
                void *curr_chunk = malloc(size);
                bool is_already_there = false;
                for (uint64_t j = 0; j < chunk_count; j++) {
                    if ((intptr_t)chunks[i] == (intptr_t)curr_chunk) {
                        is_already_there = true;
                        break;
                    }
                }
                if (!is_already_there) {
                    chunks[chunk_count] = curr_chunk;
                    chunk_count++;
                }
            }
            break;
        }
        case 2: {
            println("Free which chunk?");
            uint64_t chunk_idx = get_number();
            if (chunk_idx > ARRAY_LEN(chunks)) {
                println("Index out of bounds.");
            } else {
                free(chunks[chunk_idx]);
            }
            break;
        }
        case 4: {
            print_all_chunks();
            break;
        }
        case 5: {
            print_fastbin_heads(the_main_arena);
            break;
        }
        case 6: {
            print_tcache_heads(get_the_tcache());
            break;
        }
        case 7: {
            println("Print which tcache list?");
            uint64_t tcache_idx = get_number();
            if (tcache_idx > TCACHE_SIZE) {
                println("Index out of bounds.");
            } else {
                print_tcache_list(get_the_tcache()->entries[tcache_idx]);
            }
            break;
        }
        case 8: {
            println("Print which fastbin list?");
            uint64_t fastbin_idx = get_number();
            if (fastbin_idx > NFASTBINS) {
                println("Index out of bounds.");
            } else {
                print_fastbin_list(the_main_arena->fastbinsY[fastbin_idx]);
            }
            break;
        }
        default: {
            println("Unrecognized command.");
            break;
        }
        }
    }
}
