CC = gcc
CFLAGS=-O
LIBS= -lpfring -lpcap 

OBJECTS= sniffer.o pf_ring.o runner.o 
UNITOBJECTS= sniffer.o pf_ring.o unittest.o

.PHONY: all testit

%.o: %.c
	$(CC) -c $(CFLAGS) $<
	
all: sniffer testit
	
testit: unittest
	-./unittest

sniffer: $(OBJECTS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)
	 
unittest: $(UNITOBJECTS)
	$(CC) $(CFLAGS) $^ $(LIBS) -o $@

sniffer.o: sniffer.c sniffer.h
pf_ring.o: pf_ring.c sniffer.h

clean:
	-rm *~ *.o sniffer unittest
	-rm output

