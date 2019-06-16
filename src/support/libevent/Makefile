CC = gcc 
CCC = g++

CFLAGS = -D_GNU_SOURCE -D_BSD_SOURCE -std=c99 -Wall -Wextra -fPIC
# to compile for debug: make DEBUG=1
# to compile for no debug: make
CFLAGS += -O0 -g

LIB = ../../lib/libevent.a


all: $(LIB) 


../../lib/libevent.a: 
	cp ./libevent.a ../../lib;
