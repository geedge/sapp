all:libmd5.a

libmd5.a:md5.o
	ar -cr $@ $^
	cp $@ ../../lib

md5.o:md5.c
	gcc -c -o $@ $^

clean:
	rm -f *.o  libmd5.a

