#opt: OPTFLAGS = -O2
#export OPTFLAGS

CC		= gcc
CCC		= g++
CFLAGS      	+= -Wall 
CFLAGS		+= -fPIC -shared -D_GNU_SOURCE -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H
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

LIB=-L/opt/MESA/lib

TARGET = isakmp_protocol_plug.so ipsec_biz_sample.so l2tp_protocol_plug.so l2tp_biz_sample.so 
TARGET += pptp_protocol_plug.so pptp_biz_sample.so
TARGET += g_device_plug.so
TARGET += wangyan_keepalive_plug.so
TARGET += libsapp_assistant.so

ifeq ($(iomode), $(_MODE_PCAP))
CFLAGS += -DIOMODE_PCAP=1
endif

ifeq ($(iomode), $(_MODE_PAG))
CFLAGS += -DIOMODE_PAG=1
endif

ifeq ($(iomode), $(_MODE_PPF))
CFLAGS += -DIOMODE_PPF=1
endif

ifeq ($(iomode), $(_MODE_PFRING))
CFLAGS += -DIOMODE_PFRING=1
endif

ifeq ($(iomode), $(_MODE_DPDK))
CFLAGS += -DIOMODE_DPDK=1
endif

ifeq ($(iomode), $(_MODE_TOPSEC))
CFLAGS += -DIOMODE_TOPSEC=1
endif

ifeq ($(iomode), $(_MODE_IPFILE))
CFLAGS += -DIOMODE_IPFILE=1
endif

ifeq ($(iomode), $(_MODE_MARSIO))
CFLAGS += -DIOMODE_MARSIO=1
LIB += -lmarsio
endif

ifeq ($(iomode), $(_MODE_SMITH))
CFLAGS += -DIOMODE_SMITH=1
endif

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
	$(CC) -o $@ -fPIC -shared -g -Wall $^ $(H_DIR);
	mkdir -p $(RELEASE_BIZ_PATH)/l2tp_biz_sample;
	cp $@ $(RELEASE_BIZ_PATH)/l2tp_biz_sample/ ;

pptp_protocol_plug.so:pptp_protocol_plug.o
	$(CC) -o $@ -fPIC -shared -g -Wall $^ $(H_DIR);
	mkdir -p $(RELEASE_PRO_PATH)/pptp_protocol_plug;
	cp $@ $(RELEASE_PRO_PATH)/pptp_protocol_plug/ ;

pptp_biz_sample.so:pptp_biz_sample.o
	$(CC) -o $@ -fPIC -shared -g -Wall $^ $(H_DIR);
	mkdir -p $(RELEASE_BIZ_PATH)/pptp_biz_sample;
	cp $@ $(RELEASE_BIZ_PATH)/pptp_biz_sample/ ;

g_device_plug.so: g_device_plug.o
	$(CC) -o $@ -shared -fPIC $(CFLAGS) $^ $(MODULES) $(H_DIR) $(LIB) -lMESA_handle_logger -lMESA_prof_load;
	mkdir -p $(RELEASE_PLT_PATH)/g_device_plug;
	cp $@ $(RELEASE_PLT_PATH)/g_device_plug/

wangyan_keepalive_plug.so:wangyan_keepalive_plug.c ../lib/libping.a
	$(CC) -o $@ -shared -fPIC $(CFLAGS) $^ $(MODULES) $(H_DIR)  $(LIB) ../lib/libping.a;
	mkdir -p $(RELEASE_PLT_PATH)/wangyan_keepalive_plug;
	cp $@ $(RELEASE_PLT_PATH)/wangyan_keepalive_plug/;

libsapp_assistant.so: sapp_assistant.c
	$(CCC) -o $@ -shared -fPIC $(H_DIR) $(CFLAGS) $^ $(MODULES) $(LIB) -lMESA_field_stat2;
	mkdir -p /opt/MESA/lib; 
	cp $@ /opt/MESA/lib/;
	mkdir -p $(RELEASE_PLT_PATH)/sapp_assistant/;
	cp $@ $(RELEASE_PLT_PATH)/sapp_assistant/$@


clean:
	rm -f *.o *.so *.a $(TARGET)

opt:
	$(MAKE) all
