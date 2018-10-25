CC=gcc
CCC=g++

CFLAGS=-g -O0 -Wall -fPIC -shared -D_GNU_SOURCE=1
H_DIR=-I../inc
LIBPATH=../lib
LIB=-lpthread

OBJS=libping.o ../lib/libMESA_socket_wrap.a

TARGET=libping.so libping.a

all:$(TARGET)

.c.o:
	$(CC) -c $(CFLAGS) -I. $(H_DIR) $<

.cpp.o:
	$(CCC) -c $(CFLAGS) -I. $(H_DIR) $<

libping.so: $(OBJS)
	(rm -f $@; gcc -o $@ $(CFLAGS) $^ $(LIB); cp $@ $(LIBPATH); cp $@ /opt/MESA/lib/;)

libping.a: $(OBJS)
	(rm -f $@ ;ar -r $@ $^; cp $@ $(LIBPATH); cp $@ ../../../lib/ )	

install:
	cp $(TARGET) /opt/MESA/lib;

clean:
	rm -f *.o $(TARGET)
