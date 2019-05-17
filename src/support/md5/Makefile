all:libmd5.a
CFLAGS = -D__FAVOR_BSD=1 -D__USE_BSD=1 -D_GNU_SOURCE=1 -fPIC

libmd5.a:md5.o
	ar -cr $@ $^
	cp $@ ../../lib

md5.o:md5.c
	gcc -c -o $@ $(CFLAGS) $^

clean:
	rm -f *.o  libmd5.a

