all: test_master test_slave
CFLAGS=-g -L/opt/MESA/lib

test_master:test_master.c
	gcc -o $@ -g -I../inc $^ $(CFLAGS) -lping

test_slave:test_slave.c
	gcc -o $@ -g -I../inc $^ $(CFLAGS) -lping

clean:
	rm -f test_master test_slave 
