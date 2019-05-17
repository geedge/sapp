all:librbtree.a
INC = -I../../../include/
INC += -I../../../include/private
INC += -I../../../include/public
INC += -I../../../include/support/
INC += -I/opt/MESA/include
INC += -I/opt/MESA/include/MESA

CFLAGS = -D__FAVOR_BSD=1 -D__USE_BSD=1 -D_GNU_SOURCE=1 -fPIC

librbtree.a:rbtree_sapp.o rbtree.o
	ar -cr $@ $^
	cp $@ ../../lib

rbtree_sapp.o:rbtree_sapp.cpp
	g++ -g -c $(CFLAGS) $(INC) -o $@ $^

rbtree.o:rbtree.c
	gcc -g -c $(CFLAGS) $(INC) -o $@ $^

clean:
	rm -f *.o  librbtree.a

