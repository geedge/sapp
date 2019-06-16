all:libsymbol_check.a

INC=-I./
INC+=-I/opt/MESA/include
INC+=-I/opt/MESA/include/MESA
INC+=-I../../../include/
INC+=-I../../../include/public
INC+=-I../../../include/private
LIBS = -L/opt/MESA/lib
CFLAGS = -D__FAVOR_BSD=1 -D__USE_BSD=1 -D_GNU_SOURCE=1 -fPIC

test_symbol_check:test_symbol_check.c libsymbol_check.a
	gcc -o $@ $(INC) $^ -g  -D_GNU_SOURCE=1 -ldl -lpthread -lMESA_htable

libsymbol_check.a:libsymbol_check.o
	ar -cr $@ $^
	cp $@ ../../lib/

libsymbol_check.o:libsymbol_check.cpp
	g++ -c $^ $(INC) $(CFLAGS) -ldl -g

clean:
	rm -f test_symbol_check *.o *.a
