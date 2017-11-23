CC=gcc
CFLAGS=-m32 -fstack-protector-all -g


all: write socket printf
	
write: write.c
	$(CC) $(CFLAGS) -o write write.c

socket: socket.c
	$(CC) $(CFLAGS) -o socket socket.c

printf: printf.c
	$(CC) $(CFLAGS) -o printf printf.c

clean:
	rm write socket printf
