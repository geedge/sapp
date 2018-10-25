all:librbtree.a
INC = -I../../include
INC += -I../../include/net
INC += -I../../include/stream_inc
INC += -I../../dealpkt
INC += -I../../include/support/
INC += -I/opt/MESA/include
INC += -I/opt/MESA/include/MESA

librbtree.a:rbtree_sapp.o rbtree.o
	ar -cr $@ $^
	cp $@ ../../lib

rbtree_sapp.o:rbtree_sapp.c
	gcc -g -c $(CFLAGS) $(INC) -o $@ $^

rbtree.o:rbtree.c
	gcc -g -c $(CFLAGS) $(INC) -o $@ $^

clean:
	rm -f *.o  librbtree.a

