CC=gcc
CFLAGS=-m32 -fstack-protector-all


all: write socket
	
write: write.c
	$(CC) $(CFLAGS) -o write write.c

socket: socket.c
	$(CC) $(CFLAGS) -o socket socket.c

clean:
	rm write socket
