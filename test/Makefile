CC	= gcc
CFLAGS	= -g -fPIC 
CFLAGS	+= -D__USE_BSD=1 -D__FAVOR_BSD=1 -D__USE_MISC=1 -D_GNU_SOURCE=1
CFLAGS  += $(OPTFLAGS)
OBJECTS = test_app_sapp.o  trace_delay.o terminal_tag.o g_device_plug.o
MODULES	=  

BIN_PATH = ../bin/

TARGET	= test_app_sapp.so
TARGET += wangyan_gdev_measurement.so
#TARGET  += test_anti_flood_hijack

INCS = 

INCS	+= -I ../include 
INCS	+= -I../include/private
INCS	+= -I../include/public
INCS	+= -I../include/support/
INCS	+= -I/opt/MESA/include
INCS	+= -I/opt/MESA/include/MESA


.PHONY: all clean 
all: $(TARGET)
	
test_app_sapp.so: test_app_sapp.o
	$(CC) -o $@ -shared -fPIC $(CFLAGS) $^ $(MODULES)
	cp $@ $(BIN_PATH)/plug/business/test_app/
	
trace_delay.so: trace_delay.o
	$(CC) -o $@ -shared -fPIC $(CFLAGS) $^ $(MODULES)
	cp $@ $(BIN_PATH)/plug/business/test_app/

terminal_tag.so: terminal_tag.o
	$(CC) -o $@ -shared -fPIC $(CFLAGS) $^ $(MODULES)

g_device_plug.so: g_device_plug.o
	$(CC) -o $@ -shared -fPIC $(CFLAGS) $^ $(MODULES)
	cp $@ $(BIN_PATH)/plug/business/g_device_plug/


test_http.so:test_http.o
	$(CC) -o $@ -shared -fPIC $(CFLAGS) $^ $(MODULES)
	cp $@ $(BIN_PATH)/plug/business/test_http/

test_anti_flood_hijack:test_anti_flood_hijack.c ../lib/libavltree.a
	g++ -o $@ $(CFLAGS) $^ -I../inner_plug -I../support/avl_tree -lpcap -lpthread -lanti_flood_hijack -lMESA_htable -lMESA_handle_logger

wangyan_gdev_measurement.so:wangyan_gdev_measurement.c
	$(CC) -o $@ -shared -fPIC $(INCS) $(CFLAGS) $^ $(MODULES)
	cp $@ ../bin/plug/business/wangyan_gdev_measurement/$@
	
.c.o:  
	$(CC) -c -o $@ $(CFLAGS) -I. $(INCS) $<
clean:
	rm -f $(TARGET)	$(OBJECTS) 

