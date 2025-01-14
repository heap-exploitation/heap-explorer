#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

static uint64_t const CHUNK_HDR_SZ = 2 * sizeof(void *);

#define PREV_INUSE (0x1)
#define IS_MMAPPED (0x2)
#define NON_MAIN_ARENA (0x4)

static char *itoa_hex(uint64_t n) {
    static char const UINT64_MAX_STR[] = "0xffffffffffffffff";
    static char result_data[sizeof(UINT64_MAX_STR)];
    char *result = result_data;
    memset(result, 0, sizeof(result));

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

static char const UINT64_MAX_STR[] = "18446744073709551615";
static char *itoa(uint64_t n) {
    static char result[sizeof(UINT64_MAX_STR)];
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

void print(char const * const s) {
    write(STDOUT_FILENO, s, strlen(s));
}

void println(char const * const s) {
    static char const NL[] = "\n";
    print(s);
    print(NL);
}

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

extern struct malloc_state main_arena;

void print_chunk_containing(void const * const p) {
    void const * const chunk_base = (char const *)p - sizeof(void *);
    uint64_t const raw_chunk_size = *(uint64_t const *)(chunk_base);

    bool const is_mmapped = !!(raw_chunk_size & IS_MMAPPED);
    bool const is_main_arena = !(raw_chunk_size & NON_MAIN_ARENA);

    uint64_t const chunk_size = raw_chunk_size & ~(PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA);

    uint64_t const data_size = chunk_size - CHUNK_HDR_SZ;

    void const * const end_of_data = (char const *)p + data_size;

    bool const is_topchunk = (intptr_t)chunk_base == (intptr_t)(main_arena.top);
    bool const is_inuse = is_topchunk ? false : (*(uint64_t const *)((char const *)end_of_data + sizeof(void *))) & PREV_INUSE;

    print("    data address: ");
    println(itoa_hex((intptr_t)p));

    print("    chunk size: ");
    println(itoa(chunk_size));

    print("    in main arena: ");
    println(itoa(is_main_arena));

    print("    mmapped: ");
    println(itoa(is_mmapped));

    println("    in use: (0 -> free, 1 -> not free or in tcache)");
    print("        ");
    println(itoa(is_inuse));

    println("");
}

struct tcache_perthread_struct {
    uint16_t counts[64];
    void *entries[64];
};

extern struct tcache_perthread_struct *tcache;

uint64_t parse_base10(char const *s) {
    uint64_t result = 0;
    while ('0' <= *s && *s <= '9') {
        result *= 10;
        result += *s - '0';
        s++;
    }

    return result;
}

uint64_t get_number(void) {
    char num[sizeof(UINT64_MAX_STR)] = {};
    read(STDIN_FILENO, num, sizeof(num) - 1);
    return parse_base10(num);
}

#define ARRAY_LEN(A) (sizeof(A) / sizeof(A[0]))

int main(void) {
    void *chunks[4096] = {};
    uint64_t chunk_count = 0;
    while (true) {
        println("0. Exit.");
        println("1. Allocate a chunk.");
        println("2. Free a chunk.");
        println("3. Print a chunk.");
        println("4. List all chunks.");
        uint64_t const num = get_number();
        switch (num) {
        case 0:
            return 0;
        case 1:
            println("How big?");
            void *curr_chunk = malloc(get_number());
            bool is_already_there = false;
            for (uint64_t i = 0; i < chunk_count; i++) {
                if ((intptr_t)chunks[i] == (intptr_t)curr_chunk) {
                    is_already_there = true;
                    break;
                }
            }
            if (!is_already_there) {
                chunks[chunk_count] = curr_chunk;
                chunk_count++;
            }
            break;
        case 2:
            println("Free which one?");
            free(chunks[get_number()]);
            break;
        case 3:
            println("Print which one?");
            print_chunk_containing(chunks[get_number()]);
            break;
        case 4:
            print("{ ");
            for (uint64_t i = 0; i < ARRAY_LEN(chunks); i++) {
                if (chunks[i] == NULL) {
                    break;
                }
                if (i != 0) {
                    print(", ");
                }
                print("[");
                print(itoa(i));
                print("]: ");
                print(itoa_hex((intptr_t)chunks[i]));
            }
            println(" }");
            break;
        default:
            return -1;
        }
    }
}
