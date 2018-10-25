CC=gcc
CCC=g++ -O2

CFLAGS=-g -Wall -fPIC
LIBPATH=../

OBJS=MESA_hash_v2.o D_kernel_list.o MESA_list_v2.o list_common.o

.c.o:
	$(CC) -c $(CFLAGS) -I. $(H_DIR) $<

.cpp.o:
	$(CCC) -c $(CFLAGS) -I. $(H_DIR) $<

libMESA_hash_v2.a: $(OBJS)
	echo  making lib ...
	(rm -f $@ ;ar -r $@ $^; cp $(OBJS) $(LIBPATH);)

clean:
	rm -f *.o libMESA_hash_v2.a
