all:demo libMESA_sleep.so  libMESA_sleep.a



demo:demo.o libMESA_sleep.so
	gcc -g -Wall demo.o -o demo -lpthread ./libMESA_sleep.so
demo.o: demo.c
	gcc -g -c demo.c -o demo.o -W

libMESA_sleep.so:MESA_sleep.o
	gcc -o $@ -fPIC -shared $^ -lpthread	

libMESA_sleep.a:MESA_sleep.o
	ar -cr $@ $^
	cp $@ ../../lib/

#MESA_sleep.o:MESA_sleep.c
MESA_sleep.o:mesa_sleep_nowatchBGT.c
	gcc -g -Wall -fPIC -shared -c $^ -o $@
clean:
	rm -f *.o demo libMESA_sleep.so  libMESA_sleep.a

