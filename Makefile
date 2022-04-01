CC = gcc

spoof: main.o arpspoof.o dnsspoof.o
	$(CC) -o spoof main.o arpspoof.o dnsspoof.o -lpthread
main.o: main.c 
	$(CC) -c main.c -lpthread
arpspoof.o: arpspoof.c arpspoof.h
	$(CC) -c arpspoof.c
dnsspoof.o: dnsspoof.c dnsspoof.h
	$(CC) -c dnsspoof.c