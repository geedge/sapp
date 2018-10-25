all:libtimestamp_record.a

INC = -I../../include
INC += -I../../include/net
INC += -I../../dealpkt
INC += -I../../include/stream_inc
INC += -I../../packet_io
INC += -I/opt/MESA/include
INC += -I/opt/MESA/include/MESA

libtimestamp_record.a:timestamp_record.o
	ar -cr $@ $^
	cp $@ ../../lib

timestamp_record.o:timestamp_record.c
	gcc -c $(CFLAGS) $(INC) -o $@ $^

clean:
	rm -f *.o libtimestamp_record.a

