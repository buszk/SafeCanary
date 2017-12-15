#include <stdio.h>
#include <unistd.h>

int main(int argc, char** argv) {
    int c = 0;
    int test = 0xdeadbeef;
    if (argc == 2) {
        c = atoi(argv[1]);
    }
    printf("input: %i\n", c);
    printf("input(hex): %x\n", c);
    printf("input(ptr): %p\n", (void*)c);
    write(1, (void*)c, 100);
    write(1, &test, 4);
    printf("printed\n");
}
