CC	= gcc
CFLAGS	= -g -fPIC 
CFLAGS	+= -D__USE_BSD=1 -D__FAVOR_BSD=1 -D__USE_MISC=1 -D_GNU_SOURCE=1
CFLAGS  += $(OPTFLAGS)
OBJECTS = test_app_sapp.o  trace_delay.o terminal_tag.o g_device_plug.o
MODULES	=  

TARGET	= test_app_sapp.so  trace_delay.so terminal_tag.so test_http.so test_wangyan.so
TARGET += test_ct_plug.so
TARGET += wangyan_demo.so

INCS	= -I ../include 
INCS	+= -I ../inner_plug/
INCS	+= -I ../dealpkt
INCS	+= -I ../packet_io
INCS	+= -I ../include/net
INCS	+= -I ../inner_plug
INCS	+= -I../include/stream_inc
INCS	+= -I/usr/include/MESA
INCS	+= -I../include/support/
INCS	+= -I/opt/MESA/include
INCS	+= -I/opt/MESA/include/MESA


.PHONY: all clean 
all: $(TARGET)

test_wangyan.so: test_wangyan.o
	$(CC) -o $@ -shared -fPIC $(CFLAGS) $^ $(MODULES)
	cp $@ ../run/plug/business/test_wangyan/
	
wangyan_demo.so: wangyan_demo.o
	$(CC) -o $@ -shared -fPIC $(CFLAGS) $^ $(MODULES)
	cp $@ ../run/plug/business/test_wangyan/
	
trace_delay.so: trace_delay.o
	
test_app_sapp.so: test_app_sapp.o
	$(CC) -o $@ -shared -fPIC $(CFLAGS) $^ $(MODULES)
	cp $@ ../run/plug/business/test_app/
	
trace_delay.so: trace_delay.o
	$(CC) -o $@ -shared -fPIC $(CFLAGS) $^ $(MODULES)
	cp $@ ../run/plug/business/test_app/

terminal_tag.so: terminal_tag.o
	$(CC) -o $@ -shared -fPIC $(CFLAGS) $^ $(MODULES)
	cp $@ ../run/plug/business/terminal_tag/

test_http.so:test_http.o
	$(CC) -o $@ -shared -fPIC $(CFLAGS) $^ $(MODULES)
	cp $@ ../run/plug/business/test_http/

test_sapp_so:test_sapp_so.c
	$(CC) -o $@ -fPIC $(CFLAGS) $^ $(INCS) -L/opt/MESA/lib -lMESA_IP_PLUG -lpcap -lmarsio

test_ct_plug.so:test_ct_plug.c
	$(CC) -o $@ -shared -fPIC $(CFLAGS) $(INCS) $^ $(MODULES)
	cp $@ ../run/plug/business/test_ct_plug/

.c.o:  
	$(CC) -c -o $@ $(CFLAGS) -I. $(INCS) $<
clean:
	rm -f $(TARGET)	$(OBJECTS) 

