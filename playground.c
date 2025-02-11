#define _GNU_SOURCE

#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "heap_explorer.h"

void *wait_forever(void *) {
    free(malloc(1));
    while (1) {
        sleep(UINT_MAX);
    }
    return NULL;
}

int main(int argc, char **argv) {
    int const threads_to_spawn = argc >= 2 ? atoi(argv[1]) : 0;

    for (int i = 0; i < threads_to_spawn; i++) {
        pthread_t thread;
        pthread_create(&thread, NULL, wait_forever, NULL);
    }

    kill(getpid(), SIGINT);

    wait_forever(NULL);
}
