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

void println_ptrs(void * const ptrs[], uint64_t const array_len) {
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

struct malloc_state * const main_arena = (struct malloc_state *)0x7ffff7f8eac0; // Pulled from gdb; won't work without setarch -R
#define NFASTBINS (ARRAY_LEN(main_arena->fastbinsY))

void print_malloc_state(struct malloc_state const * const m) {
    print("fastbinsY: ");
    println_ptrs(m->fastbinsY, NFASTBINS);
}

void print_chunk_containing(void const * const p) {
    void const * const chunk_base = (char const *)p - sizeof(void *);
    uint64_t const raw_chunk_size = *(uint64_t const *)(chunk_base);

    bool const is_mmapped = !!(raw_chunk_size & IS_MMAPPED);
    bool const is_main_arena = !(raw_chunk_size & NON_MAIN_ARENA);

    uint64_t const chunk_size = raw_chunk_size & ~(PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA);

    uint64_t const data_size = chunk_size - CHUNK_HDR_SZ;

    void const * const end_of_data = (char const *)p + data_size;

    bool const is_topchunk = (intptr_t)chunk_base == (intptr_t)(main_arena->top);
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

struct tcache_perthread_struct *tcache = (struct tcache_perthread_struct *)0x555555559010;
#define TCACHE_SIZE (ARRAY_LEN(tcache->counts))

void print_tcache(struct tcache_perthread_struct *tcache) {
    print("entries: ");
    println_ptrs(tcache->entries, ARRAY_LEN(tcache->entries));
    print("counts:  { ");
    bool first = true;
    for (size_t i = 0; i < TCACHE_SIZE; i++) {
        if (tcache->counts[i] == 0) {
            continue;
        }

        if (!first) {
            print(", ");
        } else {
            first = false;
        }

        print("[");
        print(itoa(i));
        print("]: ");
        print(itoa(tcache->counts[i]));
    }
    println(" }");
}


void *tcache_next(void *p) {
    return (void *)((((intptr_t)p) >> 12) ^ *(intptr_t *)p);
}

void print_tcache_entry(uint64_t n) {
    void *list_entries[TCACHE_SIZE] = {};
    void *curr = tcache->entries[n];
    uint64_t i = 0;
    for (; i < tcache->counts[n]; i++) {
        list_entries[i] = curr;
        curr = tcache_next(curr);
    }
    println_ptrs(list_entries, i);
}

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

int main(void) {
    void *chunks[128] = {};
    uint64_t chunk_count = 0;
    while (true) {
        uint64_t arg;
        println("1. Allocate a chunk.");
        println("2. Free a chunk.");
        println("3. Print a chunk.");
        println("4. List all chunks.");
        println("5. Print the main arena.");
        println("6. Print the tcache.");
        println("7. Print a tcache list.");
        switch (get_number()) {
        case 0:
            break;
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
            println("Free which chunk?");
            arg = get_number();
            if (arg > ARRAY_LEN(chunks)) {
                println("Index out of bounds.");
            } else {
                free(chunks[arg]);
            }
            break;
        case 3:
            println("Print which chunk?");
            arg = get_number();
            if (arg > ARRAY_LEN(chunks)) {
                println("Index out of bounds.");
            } else {
                print_chunk_containing(chunks[arg]);
            }
            break;
        case 4:
            println_ptrs(chunks, ARRAY_LEN(chunks));
            break;
        case 5:
            print_malloc_state(main_arena);
            break;
        case 6:
            print_tcache(tcache);
            break;
        case 7:
            println("Print which tcache list?");
            arg = get_number();
            if (arg > NFASTBINS) {
                println("Index out of bounds.");
            } else {
                print_tcache_entry(arg);
            }
            break;
        default:
            return -1;
        }
    }
}
