#include <stdio.h>


int main(int argc, char** args) {
    int list[10];
    for (int i = 0; i < 10; i++ ) {
        list[i] = i;
    }
    for (int i = 0; i < 12; i++ ) {
        printf("%p\n", list[i]);
    }
}
