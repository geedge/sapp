all:libavltree.a

libavltree.a:avltree.o
	ar -cr $@ $^
	cp $@ ../../lib

avltree.o:avltree.c
	gcc -c -fPIC -g -o $@ $^

clean:
	rm -f *.o  libavltree.a

