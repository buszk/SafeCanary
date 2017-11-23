#include <stdio.h>


int main(int argc, char** args) {
    int list[10];
    int input;
    while(1) {
        scanf("%d", &input);
        printf("Index is: %d, location is: %x\n", input, &list[input]);
        //write(1, &list[input], 4);
        printf("\n%d\n", list[input]);
        printf("%s\n", &list[input]+1);
        puts((char*)(&list[input])+1);
    }
}
