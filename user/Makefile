PREFIX = /usr/local
INSTALLDIR = $(PREFIX)/kmemcache

CC = gcc
CFLAGS = -g -O2 -Wall
LDFLAGS = 

CFLAGS += -I$(PWD)/include

umemcached-obj = umemcached.o settings.o daemon.o

all: umemcached

umemcached: $(umemcached-obj)
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	rm -f umemcached *.o

distclean: clean

install:
	install -d $(INSTALLDIR)
	install -m 755 umemcached $(INSTALLDIR)

uninstall:
	rm -f $(INSTALLDIR)/umemcached
