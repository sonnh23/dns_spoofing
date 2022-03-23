CC = gcc

arpspoof: main.o arpspoof.o 
	$(CC) -o arpspoof main.o arpspoof.o -lpthread
main.o: main.c 
	$(CC) -c main.c -lpthread
arospoof.o: arpspoof.c arpspoof.h
	$(CC) -c arpspoof.c