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

static char const BLUE[] = "\x1b[0;34m";
static char const PURPLE[] = "\x1b[0;35m";
static char const GREEN[] = "\x1b[0;32m";
static char const CLEAR_COLOR[] = "\x1b[0m";

// Takes a pointer to chunk's data,
// returns a pointer to its size
static void *data2chunk(void const *const data) {
    return (char *)data - sizeof(size_t);
}

// Takes a pointer to a chunk's size,
// returns a pointer to its data
static void *chunk2data(void const *const chunk) {
    return (char *)chunk + sizeof(size_t);
}

// Takes a pointer to a glibc chunk struct (starting with PREV_SIZE),
// returns a pointer to the next chunk's size.
static void *glibc_chunk2chunk(void const *const glibc_chunk) {
    return (char *)glibc_chunk + sizeof(size_t);
}

static void *glibc_chunk2data(void const *const glibc_chunk) {
    return (char *)glibc_chunk + 2 * sizeof(size_t);
}

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

static char *ptoa(void const *const p) {
    return itoa_hex((intptr_t)p);
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

// Gets a chunk's data size.
// Note that this is 8 less than its size field,
// because the size itself is 8 bytes wide.
static uint64_t get_chunk_data_size(void const *const chunk) {
    // We mask off the low 3 bits because they store metadata.
    return (*(uint64_t const *)chunk & ~7ull) - sizeof(size_t);
}

// Prints a chunk's data size.
static void println_chunk_data_size(void const *const chunk) {
    uint64_t const size = get_chunk_data_size(chunk);
    print(", data size: ");
    print(itoa_hex(size));
}

// Takes a pointer to a heap chunk's size (not prev_size),
// and dumps information about that chunk.
static void println_chunk(void const *const chunk, char const *const msg,
                          int64_t const bin_index, char const *const color) {
    print(ptoa(chunk));
    println_chunk_data_size(chunk);
    print(" ");
    if (color != NULL) {
        print(color);
    }
    if (msg != NULL) {
        print("(");
        print(msg);
    }
    if (bin_index != -1) {
        print(" ");
        print(itoa(bin_index));
    }
    if (msg != NULL) {
        print(")");
    }
    if (color != NULL) {
        print(CLEAR_COLOR);
    }
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

// Takes a pointer to a chunk size, and returns a pointer
// to the next chunk's size.
static void *get_next_chunk(void const *const chunk) {
    return (char *)chunk2data(chunk) + get_chunk_data_size(chunk);
}

// Gets the first chunk on the heap.
// This almost certainly contains the tcache structure.
// If the heap is uninitialized, this will likely segfault.
static void *get_first_chunk(void) {
    return data2chunk(get_the_tcache());
}

// Gets the first chunk on the heap.
// This almost certainly contains the tcache structure.
// If the heap is uninitialized, this will likely segfault.
static void *get_last_chunk(void) {
    return glibc_chunk2chunk(the_main_arena->top);
}

// Returns whether chunk's is inuse (according to the following chunk's
// PREV_INUSE bit).
static bool is_in_use(void const *const chunk) {
    return (*(uint64_t *)get_next_chunk(chunk)) & 1;
}

// Takes the address of a list link from tcache or fastbin,
// and deobfuscates it. Equivalent to REVEAL_PTR from glibc.
static void *deobfuscate_next_link(void const *const p) {
    return (void *)((((intptr_t)p) >> 12) ^ *(intptr_t const *)p);
}

// If `chunk` is in a fastbin, returns which one.
// Otherwise, returns -1
static int64_t fastbin_lookup(void const *const chunk) {
    for (int64_t i = 0; i < (int64_t)NFASTBINS; i++) {
        if (the_main_arena->fastbinsY[i] != NULL) {
            void const *curr = the_main_arena->fastbinsY[i];
            while (curr != NULL) {
                if (glibc_chunk2chunk(curr) == chunk) {
                    return i;
                }
                curr = deobfuscate_next_link(glibc_chunk2data(curr));
            }
        }
    }
    return -1;
}

// If `chunk` is in tcache bin, returns which one.
// Otherwise, returns -1
static int64_t tcache_lookup(void const *const chunk) {
    struct tcache_perthread_struct const *const tcache = get_the_tcache();
    for (int64_t i = 0; i < TCACHE_SIZE; i++) {
        if (tcache->entries[i] != NULL) {
            void const *curr = tcache->entries[i];
            while (curr != NULL) {
                if (chunk == data2chunk(curr)) {
                    return i;
                }
                curr = deobfuscate_next_link(curr);
            }
        }
    }
    return -1;
}

// Prints all the chunks in the heap.
static void print_all_chunks(void) {
    if (the_main_arena->top == NULL) {
        println("The heap is empty.");
        return;
    }
    void const *const last_chunk = get_last_chunk();
    void const *curr_chunk = get_first_chunk();

    uint64_t i = 0;
    while (curr_chunk < last_chunk) {
        print("[");
        print(itoa(i));
        print("]:\t");
        char const *msg = NULL;
        char const *color = NULL;
        int64_t bin_idx = -1;
        int const tcache_idx = tcache_lookup(curr_chunk);
        int const fastbin_idx = fastbin_lookup(curr_chunk);
        if (!is_in_use(curr_chunk)) {
            msg = "free";
            color = GREEN;
        } else if (i == 0) {
            msg = "base chunk";
            color = PURPLE;
        } else if (tcache_idx != -1) {
            msg = "tcache";
            color = GREEN;
            bin_idx = tcache_idx;
        } else if (fastbin_idx != -1) {
            msg = "fastbin";
            color = GREEN;
            bin_idx = fastbin_idx;
        }
        println_chunk(curr_chunk, msg, bin_idx, color);
        void const *const next_chunk = get_next_chunk(curr_chunk);
        curr_chunk = next_chunk;
        i++;
    }

    if (curr_chunk == last_chunk) {
        print("[");
        print(itoa(i));
        print("]:\t");
        println_chunk(last_chunk, "top chunk", -1, BLUE);
    } else {
        print("Heap corrupted!");
    }
}

// Frees the `n`th chunk on the heap.
static void free_chunk_by_index(uint64_t n) {
    if (the_main_arena->top == NULL) {
        println("The heap is empty.");
        return;
    }

    void const *const last_chunk = get_last_chunk();
    void *curr_chunk = get_first_chunk();

    uint64_t i = 0;
    while (curr_chunk != last_chunk && i < n) {
        curr_chunk = get_next_chunk(curr_chunk);
        i++;
    }

    if (i == n) {
        free(chunk2data(curr_chunk));
    } else {
        print("Couldn't find chunk ");
        print(itoa(n));
        println(".");
    }
}

// Returns the index of `chunk` in the heap.
// i.e., if `chunk` is the first thing allocated, returns 1
// (because of the bottom chunk), and if `chunk` is the top chunk,
// returns (num_chunks-1).
static uint64_t get_chunk_index(void const *const target_chunk) {
    void const *const last_chunk = get_last_chunk();
    void *curr_chunk = get_first_chunk();

    uint64_t i = 0;
    while (curr_chunk != last_chunk && curr_chunk != target_chunk) {
        curr_chunk = get_next_chunk(curr_chunk);
        i++;
    }

    if (curr_chunk == target_chunk) {
        return i;
    } else {
        print("Couldn't find chunk at ");
        print(ptoa(target_chunk));
        println(".");
        exit(1); // TODO: Figure out a better way to signal an error here.
    }
}

static void print_fastbin_list(void *head) {
    char *curr = head;
    uint64_t i = 0;
    print("{ ");
    while (curr != NULL) {
        if (i != 0) {
            print(" -> ");
        }
        print(ptoa(glibc_chunk2chunk(curr)));
        curr = deobfuscate_next_link(glibc_chunk2data(curr));
        i++;
    }
    println(" }");
}

static void print_tcache_list(void *head) {
    void *curr = head;
    uint64_t i = 0;
    print("{ ");
    while (curr != NULL) {
        if (i != 0) {
            print(" -> ");
        }
        print(ptoa(data2chunk(curr)));
        curr = deobfuscate_next_link(curr);
        i++;
    }
    println(" }");
}

// Parses a decimal int
static uint64_t parse_base10(char const *s) {
    uint64_t result = 0;
    while ('0' <= *s && *s <= '9') {
        result *= 10;
        result += *s - '0';
        s++;
    }

    return result;
}

// Parses a hex int
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

// Reads a decimal or hex int from stdin
static uint64_t get_number(void) {
    char num[sizeof(UINT64_MAX_STR_DEC)] = {};
    for (uint64_t i = 0; i < sizeof(num) - 1; i++) {
        int const rc = read(STDIN_FILENO, num + i, 1);
        if (rc <= 0) {
            exit(rc);
        }
        if (num[i] == '\n') {
            num[i] = '\0';
            break;
        }
    }
    return num[0] == '0' && (num[1] == 'x' || num[1] == 'X')
               ? parse_base16(num + 2)
               : parse_base10(num);
}

static char const PS1[] = "> ";
static char const PS2[] = ">> ";

int main(void) {
    while (true) {
        println("1. Allocate chunk(s).");
        println("2. Free a chunk.");
        println("3. Print all chunks.");
        println("4. Print a tcache list.");
        println("5. Print a fastbin list.");
        print(PS1);
        switch (get_number()) {
        case 0: {
            println("Command not recognized.");
            break;
        }
        case 1: {
            println("How many?");
            print(PS2);
            uint64_t count = get_number();
            println("How big?");
            print(PS2);
            uint64_t size = get_number();
            for (uint64_t i = 0; i < count; i++) {
                void const *const chunk = data2chunk(malloc(size));
                uint64_t chunk_idx = get_chunk_index(chunk);
                print("-> [");
                print(itoa(chunk_idx));
                println("]");
            }
            break;
        }
        case 2: {
            println("Free which chunk?");
            print(PS2);
            free_chunk_by_index(get_number());
            break;
        }
        case 3: {
            print_all_chunks();
            break;
        }
        case 4: {
            struct tcache_perthread_struct const *const the_tcache =
                get_the_tcache();
            if (the_tcache == NULL) {
                println("The tcache is uninitialized.");
                break;
            }
            println("Print which tcache list?");
            print(PS2);
            uint64_t tcache_idx = get_number();
            if (tcache_idx > TCACHE_SIZE) {
                println("Index out of bounds.");
            } else {
                print_tcache_list(the_tcache->entries[tcache_idx]);
            }
            break;
        }
        case 5: {
            println("Print which fastbin list?");
            print(PS2);
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
        println("");
    }
}
