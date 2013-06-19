CC = gcc
CFLAGS = -g -O2 -Wall -std=gnu99
LDFLAGS = -lpthread

CFLAGS += -I$(PWD)/../include

testapp-obj = testapp.o

all: testapp

testapp: $(testapp-obj)
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	rm -f testapp *.o
