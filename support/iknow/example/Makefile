TARGET=iknow_server

all:$(TARGET)

iknow_server:
	gcc -g -o $@ -I../include example_server.c ../lib/libiknow.a -lpthread

clean:
	rm -f $(TARGET)
