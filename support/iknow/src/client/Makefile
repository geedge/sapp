CC=gcc
CCC=g++

CFLAGS=-g -Wall -D_GNU_SOURCE=1
LIBPATH=../../lib
LIB=-lpthread
H_DIR=-I../../include

OBJS=iknow_client.o ../common/MESA_socket_wrap.o

TARGET=iclient

all:$(TARGET)

.c.o:
	$(CC) -c $(CFLAGS) -I. $(H_DIR) $<

.cpp.o:
	$(CCC) -c $(CFLAGS) -I. $(H_DIR) $<

$(TARGET): $(OBJS)
	$(CC) -o $@ $^

clean:
	rm -f *.o $(TARGET)
