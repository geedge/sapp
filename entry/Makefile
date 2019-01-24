TARGET=sapp

all: $(TARGET)
LIB_PATH=-L../lib
CFLAGS     += -DPLATFORM_NSDPF_PAPP=1

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
WHOLE_ARCH+=../lib/libavltree.a 
else
WHOLE_ARCH=../lib/libdealpkt.a ../lib/libproject.a ../lib/libMESA_sleep.a ../lib/libtimestamp_record.a  
WHOLE_ARCH+=../lib/libavltree.a 
endif

LDFLAGS =
LDFLAGS += $(LD_DICTATOR)

LIB=../lib/libpacket_io.a
LIB+=../lib/plugctrl.a
LIB+=../lib/libmd5.a
LIB+=../lib/librbtree.a
LIB+= ../lib/libsymbol_check.a
LIB+= ../lib/libMESA_socket_wrap.a

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
INC+=-I../include/net
INC+=-I../include/support
INC+=-I../dealpkt 
INC += -I../packet_io
INC+=-I/opt/MESA/include
INC+=-I/opt/MESA/include/MESA
INC+=-I/opt/MESA/include/MESA/stream_inc

LIB += -L/opt/MESA/lib -lpthread -ldl
LIB += -lMESA_htable -lMESA_handle_logger -lMESA_prof_load
LIB += -lMESA_field_stat2
LIB += -lsapp_assistant
#LIB += -lsesame_door

#DEP=support/libMESA_prof_load.so 
#DEP+=support/libMESA_htable.so 
#DEP+=support/libnet_common.so 
#DEP+=support/old_Profile.so
#DEP+=support/libMESA_handle_logger.so
#DEP+=support/liblogger.so

iiefd_dual_stack: sapp_main.o  sapp_init.o

$(TARGET):sapp_main.o  sapp_init.o sapp_global_val.o
	g++ -g -Wl,--export-dynamic -o $@ $(CFLAGS) $(INC) $^ $(LDFLAGS) $(LIB_PATH)  -Wl,--whole-archive $(WHOLE_ARCH)  -Wl,--no-whole-archive $(LIB)
	cp ../packet_io/*.so ../run/platform_lib/;
	cp $@ ../run/;
	#ldconfig;

.c.o:
	$(CC) -c $(CFLAGS) -I. $(INC) $<

.cpp.o:
	$(CCC) -c $(CFLAGS) -I. $(INC) $<

clean:
	rm -f $(TARGET) *.o
