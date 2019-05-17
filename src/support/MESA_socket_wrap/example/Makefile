CC=gcc 
CCC=gcc

TARGET=MESA_sock_example multi_thread_example udp_example test_read tcp_example

all:$(TARGET)

INC=-I../include
LIBPATH=-L../lib
LIB=-lpthread ../lib/libMESA_socket_wrap.a

multi_thread_example:multi_thread_example.c
	$(CC) $(CFLAGS) -o $@ $(INC) $^ $(LIBPATH) $(LIB)

MESA_sock_example:MESA_sock_example.c
	$(CC) $(CFLAGS) -o $@ $(INC) $^ $(LIBPATH) $(LIB)

tcp_example:tcp_example.c
	$(CC) $(CFLAGS)  -o $@ $(INC) $^ $(LIBPATH) $(LIB)

udp_example:udp_example.c
	$(CC) $(CFLAGS)  -o $@ $(INC) $^ $(LIBPATH) $(LIB)

test_read:test_read.c
	$(CC) $(CFLAGS) -o $@ $(INC) $^ $(LIBPATH) $(LIB)

clean:
	rm -f *.o $(TARGET)
