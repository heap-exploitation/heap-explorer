#include <stdlib.h>

int main(void) {
    malloc(10);
    void *p = malloc(8000);
    malloc(10);
    free(p);
    while (1)
        ;
}
