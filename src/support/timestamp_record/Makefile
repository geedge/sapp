all:libtimestamp_record.a

INC = -I../../../include
INC += -I../../../include/public
INC += -I../../../include/private
INC += -I../../../include/support
INC += -I/opt/MESA/include
INC += -I/opt/MESA/include/MESA

libtimestamp_record.a:timestamp_record.o
	ar -cr $@ $^
	cp $@ ../../lib

timestamp_record.o:timestamp_record.cpp
	g++ -c $(CFLAGS) -fPIC $(INC) -o $@ $^

clean:
	rm -f *.o libtimestamp_record.a

