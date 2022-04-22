CC = gcc

spoof: main.o arpspoof.o dnsspoof.o utils.o
	$(CC) -o spoof main.o arpspoof.o dnsspoof.o utils.o -lpthread
main.o: 
	$(CC) -c main.c -lpthread
arpspoof.o: arpspoof.c arpspoof.h 
	$(CC) -c arpspoof.c
dnsspoof.o: dnsspoof.c dnsspoof.h 
	$(CC) -c dnsspoof.c
utils.o: utils.c utils.h
	$(CC) -c utils.c