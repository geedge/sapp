ifeq ($(target_mode), $(__TARGET_MODE_ELF))
TARGET=sapp
else
TARGET=MESA_IP_PLUG.so
endif

all: $(TARGET)

LIB_PATH=-L../lib
CFLAGS += -fPIC -D_BSD_SOURCE -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD
CFLAGS += -DPLATFORM_NSDPF_PAPP=1

ifeq ($(USE_PAG_GET_FRAME), $(YES))
CFLAGS += -DUSE_PAG_GET_FRAME=1
else
CFLAGS += -DUSE_PAG_GET_FRAME=0
endif

ifeq ($(USE_MEM_POOL), $(YES))
CFLAGS += -DUSE_MEMPOOL=1
endif

CFLAGS += -rdynamic 

ifeq ($(USE_MEM_POOL), $(YES))
#LD_DICTATOR = -Wl,-wrap,malloc -Wl,-wrap,calloc -Wl,-wrap,free -Wl,-wrap,realloc
WHOLE_ARCH=../lib/libdealpkt.a ../lib/libproject.a ../lib/libMESA_sleep.a ../lib/libdictator.a ../lib/libtimestamp_record.a  
WHOLE_ARCH+=../lib/libpacket_io.a
else
WHOLE_ARCH=../lib/libdealpkt.a ../lib/libproject.a ../lib/libMESA_sleep.a ../lib/libtimestamp_record.a  
WHOLE_ARCH+=../lib/libpacket_io.a
endif

LDFLAGS =
LDFLAGS += $(LD_DICTATOR)

LIB=
LIB+=../lib/plugctrl.a
LIB+=../lib/libmd5.a
LIB+=../lib/librbtree.a
LIB+= ../lib/libsymbol_check.a
LIB+= ../lib/libMESA_socket_wrap.a

ifeq ($(target_mode), $(__TARGET_MODE_SO))
WHOLE_ARCH += ../lib/libpacket_io.a ../lib/plugctrl.a ../lib/libmd5.a ../lib/librbtree.a ../lib/libsymbol_check.a ../lib/libMESA_socket_wrap.a ../lib/libiknow.a 
endif

ifeq ($(debug), $(_DEBUG2))
LIB += ../lib/libiknow.a -lpcap
endif

ifeq ($(IIEFD_DUAL_STACK), $(YES))
CFLAGS += -g -DIIEFD_DUAL_STACK=1
endif
ifeq ($(iomode), $(_MODE_DPDK))
CFLAGS += -DIOMODE_DPDK=1
endif

INC+=-I../include 
INC+=-I../include/support
INC+=-I../include/net
INC+=-I../dealpkt 
INC += -I../packet_io
INC+=-I/opt/MESA/include
INC+=-I/opt/MESA/include/MESA
INC+=-I/opt/MESA/include/MESA/stream_inc

LIB += -L/opt/MESA/lib -lpthread -ldl -lrt 
LIB += -lMESA_htable -lMESA_handle_logger -lMESA_prof_load
#LIB += -lsesame_door
LIB += -lsapp_assistant

ifeq ($(iomode), $(_MODE_MARSIO))
LIB += -lmarsio
endif

#DEP=support/libMESA_prof_load.so 
#DEP+=support/libMESA_htable.so 
#DEP+=support/libnet_common.so 
#DEP+=support/old_Profile.so
#DEP+=support/libMESA_handle_logger.so
#DEP+=support/liblogger.so

iiefd_dual_stack: sapp_main.o  sapp_init.o

sapp:sapp_main.o  sapp_init.o sapp_global_val.o
	g++ -g -Wl,--export-dynamic -o $@ $(CFLAGS) $(INC) $^ $(LDFLAGS) $(LIB_PATH)  -Wl,--whole-archive $(WHOLE_ARCH)  -Wl,--no-whole-archive $(LIB);
	cp ../packet_io/*.so ../run/platform_lib/;
	cp $@ ../run/;
	#ldconfig;

MESA_IP_PLUG.so:sapp_plug.o  sapp_init.o sapp_global_val.o
	g++ -g -o $@ -fPIC -shared  $^ -Wl,--whole-archive $(WHOLE_ARCH)  -Wl,--no-whole-archive $(LIB)
	cp $@ ../run/
	cp $@ /opt/MESA/lib/libMESA_IP_PLUG.so

sapp_plug.o:sapp_plug.c
	g++ -c -g -o $@ -fPIC $^ $(INC) -D_BSD_SOURCE -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DSAPP_AS_TARGET_SO=1

.c.o:
	$(CC) -c $(CFLAGS) -I. $(INC) $<

.cpp.o:
	$(CCC) -c $(CFLAGS) -I. $(INC) $<

clean:
	rm -f $(TARGET) *.o
