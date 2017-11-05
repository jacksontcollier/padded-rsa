CC = gcc
CFLAGS = -Wall
TARGET_EXE = rsa-enc rsa-dec rsa-keygen

.PHONY: all
all: $(TARGET_EXE)

.PHONY: clean
clean:
	rm -rf rsa-enc rsa-dec rsa-keygen *.o

rsa-enc: rsa-enc.o padded-rsa.o
	$(CC) rsa-enc.o padded-rsa.o -o rsa-enc

rsa-dec: rsa-dec.o padded-rsa.o
	$(CC) rsa-dec.o padded-rsa.o -o rsa-dec

rsa-keygen: rsa-keygen.o padded-rsa.o
	$(CC) rsa-keygen.o padded-rsa.o -o rsa-keygen

rsa-enc.o: rsa-enc.c padded-rsa.h
	$(CC) -c $(CFLAGS) rsa-enc.c -o rsa-enc.o

rsa-dec.o: rsa-dec.c padded-rsa.h
	$(CC) -c $(CFLAGS) rsa-dec.c -o rsa-dec.o

rsa-keygen.o: rsa-keygen.c padded-rsa.h
	$(CC) -c $(CFLAGS) rsa-keygen.c -o rsa-keygen.o

padded-rsa.o: padded-rsa.h padded-rsa.c
	$(CC) -c $(CFLAGS) padded-rsa.c -o padded-rsa.o
