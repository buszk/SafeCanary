CC=gcc
CFLAGS=-m32 -fstack-protector-all -g


all: write socket printf got
	
write: write.c
	$(CC) $(CFLAGS) -o write write.c

socket: socket.c
	$(CC) $(CFLAGS) -o socket socket.c

printf: printf.c
	$(CC) $(CFLAGS) -o printf printf.c

got: got.c
	$(CC) $(CFLAGS) -o got got.c

clean:
	rm write socket printf got
