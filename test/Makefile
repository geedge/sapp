CC	= gcc
CCC	= g++
CFLAGS	= -g -fPIC 
CFLAGS	+= -D__USE_BSD=1 -D__FAVOR_BSD=1 -D__USE_MISC=1 -D_GNU_SOURCE=1
CFLAGS  += $(OPTFLAGS)
OBJECTS = test_app_sapp.o  trace_delay.o terminal_tag.o g_device_plug.o
MODULES	=  

BIN_PATH = ../bin/

TARGET	= test_app_sapp.so
TARGET += inline_device_measurement.so
TARGET += test_sendpacket_performance.so
#TARGET  += test_anti_flood_hijack
#TARGET  += sapp_so_run

TARGET += test_sapp_dev_static test_sapp_dev_dynamic

INCS = 

INCS	+= -I ../include 
INCS	+= -I../include/private
INCS	+= -I../include/public
INCS	+= -I../include/public/stream_inc/
INCS	+= -I../include/support/
INCS	+= -I/opt/MESA/include
INCS	+= -I/opt/MESA/include/MESA


.PHONY: all 
all: $(TARGET)
	
test_app_sapp.so: test_app_sapp.o
	$(CC) -o $@ -shared -fPIC $(CFLAGS) $^ $(MODULES)
	
test_sendpacket_performance.so: test_sendpacket_performance.o
	$(CC) -o $@ -shared -fPIC $(CFLAGS) $^ $(MODULES)

trace_delay.so: trace_delay.o
	$(CC) -o $@ -shared -fPIC $(CFLAGS) $^ $(MODULES)

terminal_tag.so: terminal_tag.o
	$(CC) -o $@ -shared -fPIC $(CFLAGS) $^ $(MODULES)

g_device_plug.so: g_device_plug.o
	$(CC) -o $@ -shared -fPIC $(CFLAGS) $^ $(MODULES)

test_http.so:test_http.o
	$(CC) -o $@ -shared -fPIC $(CFLAGS) $^ $(MODULES)

test_anti_flood_hijack:test_anti_flood_hijack.c ../lib/libavltree.a
	g++ -o $@ $(CFLAGS) $^ -I../inner_plug -I../support/avl_tree -lpcap -lpthread -lanti_flood_hijack -lMESA_htable -lMESA_handle_logger

inline_device_measurement.so:inline_device_measurement.c
	$(CC) -o $@ -shared -fPIC $(INCS) $(CFLAGS) -DIOMODE_MARSIO=1 $^ $(MODULES)


sapp_so_run:test_sapp_so.o
	$(CC) -o $@ -g $(INCS) $(CFLAGS) $^ -lpcap -ldl

test_sapp_dev_static:test_sapp_dev.c
	gcc -o $@ $^ ../build/src/sapp_dev/libsapp_dev.a  -I/opt/MESA/include/MESA -I/opt/MESA/include/MESA/stream_inc -L/opt/MESA/lib -lpcap -lpthread -ldl -lMESA_htable -lMESA_prof_load -lMESA_handle_logger -lMESA_field_stat2
	
test_sapp_dev_dynamic:test_sapp_dev.c
	gcc -o $@ $^ -lsapp_devel  -I/opt/MESA/include/MESA -I/opt/MESA/include/MESA/stream_inc -L/opt/MESA/lib -lpcap -lpthread -ldl -lMESA_htable -lMESA_prof_load -lMESA_handle_logger -lMESA_field_stat2 -lsystemd -lMESA_jump_layer

.c.o:  
	$(CC) -c -o $@ $(CFLAGS) -I. $(INCS) $<

.cpp.o:  
	$(CCC) -c -o  $@ $(CFLAGS) -I. $(INCS) $<

clean:
	rm -f $(TARGET)	$(OBJECTS) 

