all:libsymbol_check.a

INC=-I./
INC+=-I/opt/MESA/include
INC+=-I/opt/MESA/include/MESA

test_symbol_check:test_symbol_check.c libsymbol_check.a
	gcc -o $@ $(INC) $^ -g  -D_GNU_SOURCE=1 -ldl -lpthread -lMESA_htable

libsymbol_check.a:libsymbol_check.o
	ar -cr $@ $^
	cp $@ ../../lib/

libsymbol_check.o:libsymbol_check.c
	gcc -c $^ $(INC) -Wall -D_GNU_SOURCE=1 -ldl -g

clean:
	rm -f test_symbol_check *.o *.a
