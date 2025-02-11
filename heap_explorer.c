/*
 * This is a glibc heap exploration program.
 * It allows you to allocate and free chunks,
 * and observe how various heap data structures
 * change.
 */

#define _GNU_SOURCE

#include <asm/prctl.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "heap_explorer.h"

static char const GREEN[] = "\x1b[0;32m";
static char const YELLOW[] = "\x1b[0;33m";
static char const BLUE[] = "\x1b[0;34m";
static char const PURPLE[] = "\x1b[0;35m";
static char const CLEAR_COLOR[] = "\x1b[0m";

// Takes a pointer to chunk's data,
// returns a pointer to its size
static void *data2chunk(void const *const data) {
    return (uint8_t *)data - sizeof(size_t);
}

// Takes a pointer to a chunk's size,
// returns a pointer to its data
static void *chunk2data(void const *const chunk) {
    return (uint8_t *)chunk + sizeof(size_t);
}

// Takes a pointer to a chunk's prev_size,
// returns a pointer to its size.
static void *glibc_chunk2chunk(void const *const glibc_chunk) {
    return (uint8_t *)glibc_chunk + sizeof(size_t);
}

// Takes a pointer to a chunk's size,
// returns a pointer to its prev_size.
static void *chunk2glibc_chunk(void const *const chunk) {
    return (uint8_t *)chunk - sizeof(size_t);
}

// Takes a pointer to a chunk's size,
// returns a pointer to its data.
static void *glibc_chunk2data(void const *const glibc_chunk) {
    return (uint8_t *)glibc_chunk + 2 * sizeof(size_t);
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

static int32_t atoi32(uint8_t const *s) {
    while (*s == '0') {
        s++;
    }
    int32_t result = 0;
    while ('0' <= *s && *s <= '9') {
        result *= 10;
        result += *s - '0';
        s++;
    }
    if (*s != '\0') {
        _exit(EXIT_FAILURE);
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

// The glibc malloc_state struct, from glibc's malloc/malloc.c,
// with some slight simplifications. Should still be binary-compatible.
struct malloc_state {
    uint32_t mutex;
    uint32_t flags;
    uint32_t have_fastchunks;
    void *fastbinsY[10];
    void *top;
    void *last_remainder;
    void *bins[254];
    uint32_t binmap[4];
    void *next;
    void *next_free;
    uint64_t attached_threads;
    uint64_t system_mem;
    uint64_t max_system_mem;
};

#define ARRAY_LEN(A) (sizeof(A) / sizeof(A[0]))

// The offset of malloc within the glibc mapping
static intptr_t const MALLOC_OFFSET = 0xa9190;

// The base address of glibc.
// Note that this is not the base of the first entry from `info proc mappings`
// that came from libc.so.6. Instead, this is the base of the entry before that,
// because that mapping (which I believe is the libc .bss) is randomized
// contiguously with glibc.
static intptr_t const LIBC_BASE = (intptr_t)malloc - MALLOC_OFFSET;

// The offset of main_arena within glibc.
static intptr_t const MAIN_ARENA_OFFSET = 0x1ebac0;

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
static void print_chunk_data_size(void const *const chunk) {
    uint64_t const size = get_chunk_data_size(chunk);
    print(", ");
    print(PURPLE);
    print("data size: ");
    print(CLEAR_COLOR);
    print(itoa_hex(size));
}

// Takes a pointer to a chunk's size (not prev_size),
// and dumps information about that chunk.
static void print_chunk(void const *const chunk, char const *const msg,
                        int64_t const arena_index, int64_t const bin_index,
                        char const *const color) {
    print(ptoa(chunk));
    print_chunk_data_size(chunk);
    print(" ");
    if (color != NULL) {
        print(color);
    }

    if (msg != NULL) {
        print("(");
        if (arena_index != -1) {
            print("arena ");
            print(itoa(arena_index));
            print(", ");
        }
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

// Takes a pointer to chunk's size, and returns a pointer
// to the next chunk's size.
static void *get_next_chunk(void const *const chunk) {
    return (uint8_t *)chunk2data(chunk) + get_chunk_data_size(chunk);
}

// Gets the address of the given arena's tcache struct.
static struct tcache_perthread_struct *
get_the_tcache(struct malloc_state const *const arena) {
    if (arena == the_main_arena) {
        // Just get the first chunk on this heap
        return (struct tcache_perthread_struct *)glibc_chunk2data(
            ((uint8_t *)chunk2glibc_chunk(
                 get_next_chunk(glibc_chunk2chunk(arena->top))) -
             arena->system_mem));
    } else {
        // Get the chunk after the chunk containing the arena
        return (struct tcache_perthread_struct *)((uint64_t *)(arena + 1) + 3);
    }
}

// Gets the first chunk on the heap.
// If the heap is uninitialized, this will likely segfault.
static void *get_first_chunk(struct malloc_state const *const arena) {
    return data2chunk(get_the_tcache(arena));
}

// Gets the last chunk on the heap.
// If the heap is uninitialized, this will likely segfault.
static void *get_last_chunk(struct malloc_state const *const arena) {
    return glibc_chunk2chunk(arena->top);
}

// Returns whether chunk is in use (according to the following chunk's
// PREV_INUSE bit).
static bool is_in_use(void const *const chunk) {
    return (*(uint64_t *)get_next_chunk(chunk)) & 1;
}

// Takes the address of a list link from tcache or fastbin,
// and deobfuscates it. Equivalent to REVEAL_PTR from glibc.
static void *deobfuscate_next_link(void const *const p) {
    return (void *)((((intptr_t)p) >> 12) ^ *(intptr_t const *)p);
}

struct lookup_result {
    int64_t idx;
    int64_t arena;
};

static struct lookup_result const LOOKUP_FAILED = {.idx = -1, .arena = -1};

static bool lookup_failed(struct lookup_result lookup) {
    return memcmp(&lookup, &LOOKUP_FAILED, sizeof(struct lookup_result)) == 0;
}

static bool lookup_succeeded(struct lookup_result lookup) {
    return !lookup_failed(lookup);
}

// If `chunk` is in a fastbin, returns which one.
// Otherwise, returns -1
static int64_t arena_fastbin_lookup(struct malloc_state const *const arena,
                                    void const *const chunk) {
    for (int64_t i = 0; i < (int64_t)NFASTBINS; i++) {
        if (arena->fastbinsY[i] != NULL) {
            void const *curr = arena->fastbinsY[i];
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

// If `chunk` is in a tcache bin, returns which one.
// Otherwise, returns -1
static int64_t arena_tcache_lookup(struct malloc_state const *const arena,
                                   void const *const chunk) {
    struct tcache_perthread_struct const *const tcache = get_the_tcache(arena);
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

static struct lookup_result tcache_lookup(void const *const chunk) {
    struct malloc_state const *arena = the_main_arena;
    int64_t arena_idx = 0;
    do {
        int64_t i = arena_tcache_lookup(arena, chunk);
        if (i != -1) {
            return (struct lookup_result){.idx = i, .arena = arena_idx};
        }
        arena = arena->next;
        arena_idx++;
    } while (arena != the_main_arena);
    return LOOKUP_FAILED;
}

// If `chunk` is in a normal (small/large/unsorted) bin, returns which one.
// Otherwise, returns -1
static int64_t const NBINS = ARRAY_LEN(the_main_arena->bins) / 2;
static int64_t arena_bin_lookup(struct malloc_state const *const arena,
                                void const *const chunk) {
    for (int64_t i = 0; i < NBINS; i++) {
        void const *const head = data2chunk(arena->bins + i * 2);
        void const *const head_link = *(void **)chunk2data(head);
        if (head_link == NULL) {
            continue;
        }

        void const *curr = glibc_chunk2chunk(head_link);
        while (curr != head) {
            if (curr == chunk) {
                return i;
            }
            curr = glibc_chunk2chunk(*(void **)chunk2data(curr));
        }
    }
    return -1;
}

// Prints all the chunks in the heap.
static void print_arena(struct malloc_state const *const arena) {
    if (arena->top == NULL) {
        println("This arena is empty.");
        return;
    }
    void const *const last_chunk = get_last_chunk(arena);
    void const *curr_chunk = get_first_chunk(arena);

    uint64_t i = 0;
    while (curr_chunk < last_chunk) {
        print(YELLOW);
        print("[");
        print(itoa(i));
        print("]:\t");
        print(CLEAR_COLOR);
        char const *msg = NULL;
        char const *color = NULL;
        int64_t bin_idx = -1;
        int64_t arena_idx = -1;
        struct lookup_result const tcache_lookup_result =
            tcache_lookup(curr_chunk);
        int64_t fastbin_idx = arena_fastbin_lookup(arena, curr_chunk);
        if (!is_in_use(curr_chunk)) {
            msg = "free";
            color = GREEN;
            bin_idx = arena_bin_lookup(arena, curr_chunk);
        } else if (lookup_succeeded(tcache_lookup_result)) {
            msg = "tcache";
            color = GREEN;
            bin_idx = tcache_lookup_result.idx;
            arena_idx = tcache_lookup_result.arena;
        } else if (fastbin_idx != -1) {
            msg = "fastbin";
            color = GREEN;
            bin_idx = fastbin_idx;
        }
        print_chunk(curr_chunk, msg, arena_idx, bin_idx, color);
        void const *const next_chunk = get_next_chunk(curr_chunk);
        curr_chunk = next_chunk;
        i++;
    }

    if (curr_chunk == last_chunk) {
        print(YELLOW);
        print("[");
        print(itoa(i));
        print("]:\t");
        print(CLEAR_COLOR);
        print_chunk(last_chunk, "top chunk", -1, -1, BLUE);
    } else {
        print("Heap corrupted!");
    }
}

static void *get_chunk_by_index(struct malloc_state const *const arena,
                                uint64_t const n) {
    if (arena->top == NULL) {
        println("The heap is empty.");
        return NULL;
    }

    void const *const last_chunk = get_last_chunk(arena);
    void *curr_chunk = get_first_chunk(arena);

    uint64_t i = 0;
    while (curr_chunk != last_chunk && i < n) {
        curr_chunk = get_next_chunk(curr_chunk);
        i++;
    }

    if (i != n) {
        print("Couldn't find chunk ");
        print(itoa(n));
        println(".");
        return NULL;
    } else {
        return curr_chunk;
    }
}

// Frees the `n`th chunk on the heap.
static void free_chunk(void *const chunk) {
    free(chunk2data(chunk));
}

// Returns the index of `chunk` in the heap.
// i.e., if `chunk` is the first thing allocated, returns 1
// (because of the bottom chunk), and if `chunk` is the top chunk,
// returns (num_chunks-1).
static int64_t arena_chunk_lookup(struct malloc_state const *const arena,
                                  void const *const target_chunk) {
    void const *const last_chunk = get_last_chunk(arena);
    void *curr_chunk = get_first_chunk(arena);

    int64_t i = 0;
    while (curr_chunk != last_chunk && curr_chunk != target_chunk) {
        curr_chunk = get_next_chunk(curr_chunk);
        i++;
    }

    if (curr_chunk == target_chunk) {
        return i;
    } else {
        return -1;
    }
}

static struct lookup_result chunk_lookup(void const *const chunk) {
    struct malloc_state const *arena = the_main_arena;
    int64_t arena_idx = 0;
    do {
        int64_t i = arena_chunk_lookup(arena, chunk);
        if (i != -1) {
            return (struct lookup_result){.idx = i, .arena = arena_idx};
        }
        arena = arena->next;
        arena_idx++;
    } while (arena != the_main_arena);
    return LOOKUP_FAILED;
}

static void print_bin_list(struct malloc_state const *const arena,
                           int64_t const bin_idx) {
    if (bin_idx >= NBINS) {
        println("Index out of bounds.");
        return;
    }

    void const *const head = data2chunk(arena->bins + bin_idx * 2);
    void const *const head_link = *(void **)chunk2data(head);
    if (head_link == NULL) {
        println("The bins are uninitialized.");
        return;
    }

    void const *curr = glibc_chunk2chunk(head_link);
    uint64_t i = 0;
    print("{ ");
    while (curr != head) {
        if (i != 0) {
            print(" -> ");
        }
        print(ptoa(curr));
        curr = glibc_chunk2chunk(*(void **)chunk2data(curr));
        i++;
    }
    println(" }");
}

static void print_fastbin_list(struct malloc_state const *const arena,
                               uint64_t const fastbin_idx) {
    if (fastbin_idx >= NFASTBINS) {
        println("Index out of bounds.");
        return;
    }
    void const *const head = arena->fastbinsY[fastbin_idx];
    void const *curr = head;
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

static void print_tcache_list(struct malloc_state const *const arena,
                              uint64_t const tcache_idx) {
    if (tcache_idx >= TCACHE_SIZE) {
        println("Index out of bounds.");
        return;
    }

    struct tcache_perthread_struct const *const the_tcache =
        get_the_tcache(arena);
    void const *const head = the_tcache->entries[tcache_idx];
    void const *curr = head;
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
    char num[sizeof(UINT64_MAX_STR_DEC)] =
        {}; // we use UINT64_MAX_STR_DEC because it's longer than
            // UINT64_MAX_STR_HEX
    for (uint64_t i = 0; i < sizeof(num) - 1; i++) {
        int const rc = read(STDIN_FILENO, num + i, 1);
        if (rc <= 0) {
            _exit(rc);
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

static bool is_mmapped(void const *const chunk) {
    return (*(uint64_t *)chunk) & 2;
}

static uint64_t arena_lookup(struct malloc_state const *const arena) {
    struct malloc_state const *curr = the_main_arena;
    int64_t arena_idx = 0;
    do {
        if (curr == arena) {
            return arena_idx;
        }
        curr = curr->next;
        arena_idx++;
    } while (curr != the_main_arena);
    _exit(EXIT_FAILURE);
}

static pid_t get_next_tid(void) {
    pid_t const my_tid = syscall(SYS_gettid);
    uint8_t dirents[4096];
    int const procfs_fd = open("/proc/self/task", O_DIRECTORY);
    uint64_t const bytes_read =
        syscall(SYS_getdents64, procfs_fd, dirents, sizeof(dirents));
    if (bytes_read == 0) {
        _exit(EXIT_FAILURE);
    }

    uint64_t offset = 0;
    bool found_a_thread = false;
    uint64_t first_valid_offset = 0;
    while (offset < bytes_read) {
        uint16_t const d_reclen = *(
            uint16_t *)(dirents + offset + sizeof(uint64_t) + sizeof(uint64_t));
        uint8_t *const filename = dirents + offset + sizeof(uint64_t) +
                                  sizeof(uint64_t) + sizeof(uint16_t) +
                                  sizeof(uint8_t);
        int32_t received_tid = 0;
        if (strcmp((char *)filename, ".") != 0 &&
            strcmp((char *)filename, "..") != 0) {
            received_tid = atoi32(filename);
            if (!found_a_thread) {
                first_valid_offset = offset;
                found_a_thread = true;
            }
        }
        offset += d_reclen;
        if (received_tid == my_tid) {
            break;
        }
    }
    if (offset > bytes_read) {
        _exit(EXIT_FAILURE);
    }
    if (offset == bytes_read) { // Wrap back around to the beginning
        offset = first_valid_offset;
    }
    offset += sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint16_t) +
              sizeof(uint8_t);
    pid_t result = atoi32(dirents + offset);
    close(procfs_fd);
    if (result == my_tid) {
        return -1;
    }
    return result;
}

static void *get_fs_base(void) {
    void *const fs_base;
    syscall(SYS_arch_prctl, ARCH_GET_FS, &fs_base);
    return fs_base;
}

static int const TRIGGER_SIGNAL = SIGINT;

void explore_heap(void) {
    static char const PS1[] = "> ";
    static char const PS2[] = ">> ";

    println("\nWelcome to Heap Explorer!");

    struct malloc_state const *const my_arena =
        *(struct malloc_state const **)((uint8_t *)get_fs_base() - 0x30);
    struct malloc_state const *arena = my_arena;
    if (arena == NULL) {
        arena = the_main_arena;
    }

    while (true) {
        print("You are TID ");
        print(itoa(syscall(SYS_gettid)));
        print(", viewing arena ");
        uint64_t arena_idx = arena_lookup(arena);
        print(itoa(arena_idx));
        if (arena_idx == 0) {
            print(" (main_arena)");
        }
        if (arena == my_arena) {
            print(" (this thread's arena)");
        }
        println("");

        println("1. Allocate chunk(s).");
        println("2. Free a chunk.");
        println("3. Print all chunks.");
        println("4. Print a tcache list.");
        println("5. Print a fastbin list.");
        println("6. Print a bin list.");
        println("7. Switch to next arena.");
        println("8. Switch to next thread.");
        println("9. Exit Heap Explorer.");
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
                if (is_mmapped(chunk)) {
                    print("-> (mmapped)");
                } else {
                    struct lookup_result const lookup_result =
                        chunk_lookup(chunk);
                    if (lookup_failed(lookup_result)) {
                        println("Couldn't find the chunk we requested. "
                                "Possibly, the allocation failed.");
                        _exit(EXIT_FAILURE);
                    }
                    print("-> [arena ");
                    print(itoa(lookup_result.arena));
                    print(", chunk ");
                    print(itoa(lookup_result.idx));
                    println("]");
                }
            }
            break;
        }
        case 2: {
            println("Free which chunk?");
            print(PS2);
            uint64_t const chunk_idx = get_number();
            void *const chunk = get_chunk_by_index(arena, chunk_idx);
            free_chunk(chunk);
            break;
        }
        case 3: {
            print_arena(arena);
            break;
        }
        case 4: {
            println("Print which tcache list?");
            print(PS2);
            print_tcache_list(arena, get_number());
            break;
        }
        case 5: {
            println("Print which fastbin list?");
            print(PS2);
            print_fastbin_list(arena, get_number());
            break;
        }
        case 6: {
            println("Print which bin list?");
            print(PS2);
            print_bin_list(arena, get_number());
            break;
        }
        case 7: {
            arena = arena->next;
            break;
        }
        case 8: {
            pid_t const next_tid = get_next_tid();
            if (next_tid != -1) {
                syscall(SYS_tkill, next_tid, TRIGGER_SIGNAL);
                return;
            } else {
                println("This is the only thread. Not switching.");
            }
            break;
        }
        case 9: {
            println("Bye!");
            return;
        }
        default: {
            println("Unrecognized command.");
            break;
        }
        }
        println("");
    }
}

static void explore_heap_sighandler(int) {
    explore_heap();
}

static void __attribute__((constructor)) install_signal_handler(void) {
    struct sigaction sa;
    sa.sa_handler = explore_heap_sighandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(TRIGGER_SIGNAL, &sa, NULL) == -1) {
        println("libheap_explorer: Couldn't install signal handler!");
        _exit(EXIT_FAILURE);
    }
}
