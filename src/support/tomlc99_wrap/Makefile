CC = gcc 
CCC = g++
CFILES = toml.c

CFLAGS = -D_GNU_SOURCE -D_BSD_SOURCE -std=c99 -Wall -Wextra -fPIC
# to compile for debug: make DEBUG=1
# to compile for no debug: make
CFLAGS += -O0 -g

EXEC = toml_json toml_cat test_toml

LIB = libtoml.a libtomlc99_wrap.so libtomlc99_wrap.a

all: $(LIB) $(EXEC)


libtoml.a: toml.o
	ar -rcs $@ $^;

toml_json: toml_json.c $(LIB)

toml_cat: toml_cat.c $(LIB)

test_toml: test_toml.c 
	gcc -o $@ -ltomlc99_wrap $^

libtomlc99_wrap.so:tomlc99_wrap.o  toml.o
	gcc -o $@ -shared -fPIC $^; cp tomlc99_wrap.h ../../../include/support/; 

libtomlc99_wrap.a:tomlc99_wrap.o  toml.o
	ar -rcs $@ $^; cp tomlc99_wrap.h ../../../include/support/; cp $@ ../../lib/
	
.c.o:
	$(CC) -c $(CFLAGS) -I.  $<

.cpp.o:
	$(CCC) -c $(CFLAGS) -I.  $<


prefix ?= /usr/local

install: all
	install -d ${prefix}/include ${prefix}/lib
	install toml.h ${prefix}/include
	install libtoml.a ${prefix}/lib

clean:
	rm -f *.o $(EXEC) $(LIB)
