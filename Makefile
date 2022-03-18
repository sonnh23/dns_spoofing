CC = gcc

arpspoof: main.o arpspoof.o 
	$(CC) -o arpspoof main.o arpspoof.o
main.o: main.c
	$(CC) -c main.c
arospoof.o: arpspoof.c arpspoof.h
	$(CC) -c arpspoof.c