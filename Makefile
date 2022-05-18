CC=cc
AR=ar
OPT=-O2
CFLAGS=-Werror -Wall -Wextra -std=gnu99 $(OPT) -fPIC
LDFLAGS=-lseccomp

seccomp: libenableseccomp.a main.o
	$(CC) -o seccomp main.o libenableseccomp.a $(CFLAGS) $(LDFLAGS)

main.o: main.c
	$(CC) -c main.c $(CFLAGS)

enableseccomp.o: enableseccomp.c
	$(CC) -c enableseccomp.c $(CFLAGS)

libenableseccomp.so: enableseccomp.o
	$(CC) -shared -o libenableseccomp.so $(CFLAGS) enableseccomp.o

libenableseccomp.a: enableseccomp.o
	ar rcs -o  libenableseccomp.a enableseccomp.o

.PHONY: clean
clean:
	rm -f *.a
	rm -f *.so
	rm -f *.o
	rm -f seccomp
