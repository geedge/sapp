all:libsymbol_check.a test_symbol_check
INC = -I/opt/MESA/include
INC += -I/opt/MESA/include/MESA
LIBS = -L/opt/MESA/lib
CFLAGS = -D__FAVOR_BSD=1 -D__USE_BSD=1 -D_GNU_SOURCE=1 -fPIC

test_symbol_check:test_symbol_check.c libsymbol_check.a
	gcc -o $@ $^ -g $(INC) -D_GNU_SOURCE=1 $(LIBS) -ldl -lpthread -lMESA_htable

libsymbol_check.a:libsymbol_check.o
	ar -cr $@ $^
	cp $@ ../../lib/

libsymbol_check.o:libsymbol_check.c
	gcc -c $^ -Wall $(CFLAGS) $(INC) -ldl -g $(LIBS)

clean:
	rm -f test_symbol_check *.o *.a
