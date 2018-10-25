CC=gcc
CCC=g++

CFLAGS=-g -O0 -Wall -fPIC -shared -D_GNU_SOURCE=1
LIBPATH=../../lib
LIB=-lpthread
H_DIR=-I../../include

OBJS=iknow_cmd_parser.o iknow_server.o iknow_task_scheduler.o

TARGET=libiknow.a libiknow.so

all:$(TARGET)

.c.o:
	$(CC) -c $(CFLAGS) -I. $(H_DIR) $<

.cpp.o:
	$(CCC) -c $(CFLAGS) -I. $(H_DIR) $<

libiknow.a: $(OBJS)
	#echo  making static lib ...
	(rm -f $@ ;ar -r $@ $^; cp $@ $(LIBPATH); cp $@ ../../../../lib/;)

libiknow.so: $(OBJS)
	#echo  making dynamic lib ...
	(rm -f $@; gcc -o $@ $(CFLAGS) $^ $(LIB); cp $@ $(LIBPATH);)

clean:
	rm -f *.o $(TARGET)
