#opt: OPTFLAGS = -O2
#export OPTFLAGS

#CC		= g++
#CCC		= g++
CFLAGS      	+= -Wall 
CFLAGS		+= -g -fPIC -shared -D_BSD_SOURCE -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H
CFLAGS		+= $(OPTFLAGS)
CFLAGS		+= -DPLATFORM_NSDPF_PAPP=1


RELEASE_PLT_PATH=../run/plug/platform
RELEASE_PRO_PATH=../run/plug/protocol
RELEASE_BIZ_PATH=../run/plug/business

H_DIR += $(INC)   
H_DIR += -I../include
H_DIR += -I../include/net
H_DIR += -I../include/support
H_DIR += -I../include/stream_inc
H_DIR += -I../dealpkt
H_DIR += -I../packet_io
H_DIR += -I/opt/MESA/include
H_DIR += -I/opt/MESA/include/MESA
H_DIR += -I../support/avl_tree/


TARGET = isakmp_protocol_plug.so ipsec_biz_sample.so l2tp_protocol_plug.so l2tp_biz_sample.so 
TARGET += pptp_protocol_plug.so pptp_biz_sample.so
TARGET += g_device_plug.so
TARGET += libsapp_assistant.so

all: $(TARGET)

.c.o:
	$(CC) -c $(CFLAGS) -I. $(H_DIR) $<

.cpp.o:
	$(CCC) -c $(CFLAGS) -I. $(H_DIR) $<


#isakmp_protocol_plug.so:isakmp_protocol_plug.o
isakmp_protocol_plug.so:isakmp_protocol_plug_add_nat.o
	$(CC) -o $@ -fPIC -shared -g -Wall $^;
	mkdir -p $(RELEASE_PRO_PATH)/isakmp_protocol_plug;
	cp $@ $(RELEASE_PRO_PATH)/isakmp_protocol_plug/ ;

ipsec_biz_sample.so:ipsec_biz_sample.o
	$(CC) -o $@ -fPIC -shared -g -Wall $^;
	mkdir -p $(RELEASE_BIZ_PATH)/ipsec_biz_sample;
	cp $@ $(RELEASE_BIZ_PATH)/ipsec_biz_sample/ ;

l2tp_protocol_plug.so:l2tp_protocol_plug.o
	$(CC) -o $@ -fPIC -shared -g -Wall $^;
	mkdir -p $(RELEASE_PRO_PATH)/l2tp_protocol_plug;
	cp $@ $(RELEASE_PRO_PATH)/l2tp_protocol_plug/ ;

l2tp_biz_sample.so:l2tp_biz_sample.o
	$(CC) -o $@ -fPIC -shared -g -Wall $^;
	mkdir -p $(RELEASE_BIZ_PATH)/l2tp_biz_sample;
	cp $@ $(RELEASE_BIZ_PATH)/l2tp_biz_sample/ ;

pptp_protocol_plug.so:pptp_protocol_plug.o
	$(CC) -o $@ -fPIC -shared -g -Wall $^;
	mkdir -p $(RELEASE_PRO_PATH)/pptp_protocol_plug;
	cp $@ $(RELEASE_PRO_PATH)/pptp_protocol_plug/ ;

pptp_biz_sample.so:pptp_biz_sample.o
	$(CC) -o $@ -fPIC -shared -g -Wall $^;
	mkdir -p $(RELEASE_BIZ_PATH)/pptp_biz_sample;
	cp $@ $(RELEASE_BIZ_PATH)/pptp_biz_sample/ ;

g_device_plug.so: g_device_plug.o
	$(CC) -o $@ -shared -fPIC $(CFLAGS) $^ $(MODULES);
	mkdir -p $(RELEASE_BIZ_PATH)/g_device_plug;
	cp $@ $(RELEASE_BIZ_PATH)/g_device_plug/

libsapp_assistant.so: sapp_assistant.o  gdev_assistant.o
	mkdir -p /opt/MESA/lib; 
	cp ../lib/libc3client.so /opt/MESA/lib/;
	ldconfig;
	$(CC) -o $@ -shared -fPIC $(H_DIR) $(CFLAGS) $^ $(MODULES) -L/opt/MESA/lib -lMESA_field_stat2;
	cp $@ /opt/MESA/lib/;

libanti_flood_hijack.so:anti_flood_plug.o anti_flood_hijack.o
	$(CC) -o $@ -shared -fPIC $(CFLAGS) $^ $(MODULES);
	mkdir -p $(RELEASE_BIZ_PATH)/anti_flood;
	cp $@ $(RELEASE_BIZ_PATH)/anti_flood/;
	cp $@ /opt/MESA/lib/libanti_flood_hijack.so;
	
clean:
	rm -f *.o *.so *.a $(TARGET)

opt:
	$(MAKE) all
