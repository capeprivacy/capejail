CC=cc
AR=ar
OPT=-O2
CFLAGS=
LDFLAGS=-lseccomp

release: CFLAGS=-Werror -Wall -Wextra -std=gnu99 $(OPT) -fPIC
release: all

debug: CFLAGS=-Werror -Wall -Wextra -std=gnu99 -O0 -ggdb3 -fPIC
debug: all

.PHONY: all
all: capejail libenableseccomp.so libenableseccomp.a

capejail: libenableseccomp.a main.o
	$(CC) -o capejail main.o libenableseccomp.a $(CFLAGS) $(LDFLAGS)

main.o: main.c enableseccomp.h
	$(CC) -c main.c $(CFLAGS)

enableseccomp.o: enableseccomp.c enableseccomp.h
	$(CC) -c enableseccomp.c $(CFLAGS)

libenableseccomp.so: enableseccomp.o
	$(CC) -shared -o libenableseccomp.so $(CFLAGS) enableseccomp.o

libenableseccomp.a: enableseccomp.o
	$(AR) rcs -o  libenableseccomp.a enableseccomp.o

.PHONY: clean
clean:
	rm -f *.a
	rm -f *.so
	rm -f *.o
	rm -f capejail
