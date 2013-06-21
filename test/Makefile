CC = gcc
CFLAGS = -g -O2 -Wall -std=gnu99
LDFLAGS = -lpthread

CFLAGS += -I$(PWD)/../include

testapp-obj = testapp.o util.o

timedrun-obj = timedrun.o

kmcstart-obj = kmcstart.o util.o

kmcstop-obj = kmcstop.o util.o

all: testapp timedrun kmcstart kmcstop

testapp: $(testapp-obj)
	$(CC) $(LDFLAGS) -o $@ $^

timedrun: $(timedrun-obj)
	$(CC) -o $@ $^

kmcstart: $(kmcstart-obj)
	$(CC) -o $@ $^

kmcstop: $(kmcstop-obj)
	$(CC) -o $@ $^

clean:
	rm -f testapp timedrun kmcstart kmcstop *.o
