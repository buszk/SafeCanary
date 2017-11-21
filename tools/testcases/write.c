#include <stdio.h>
#include <unistd.h>
void another_hello() {
    int x;
    x = 10;
    printf("Another hello\n");
    write(1, &x, 64);
    return;
}

int main(int argc, char ** argv) {
	printf("Hello world!\n");
    
    another_hello();
    printf("Bye!\n");
	return 0;
}
