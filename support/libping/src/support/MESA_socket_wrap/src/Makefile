CC=gcc -g -fPIC 
CCC=gcc -g -fPIC

TARGET=libMESA_socket_wrap.a libMESA_socket_wrap.so
INC=-I../include
LIBPATH=../lib

OBJS=MESA_socket_wrap.o

all:$(TARGET)

.c.o:
	$(CC) -c $(CFLAGS) -I. $(INC) $<

.cpp.o:
	$(CCC) -c $(CFLAGS) -I. $(INC) $<

libMESA_socket_wrap.a: $(OBJS)
	echo  making lib ...
	(rm -f $@ ;ar -r $@ $^; cp $@ $(LIBPATH); cp $@ ../../../../lib/)

libMESA_socket_wrap.so: $(OBJS)
	$(CC) -o $@ $^ -shared

clean:
	rm -f *.o $(TARGET)
