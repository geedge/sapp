#opt: OPTFLAGS = -O2
#export OPTFLAGS

#CC		= g++
#CCC		= g++
CFLAGS     	+= -Wall 
CFLAGS		+= -fPIC -shared -D_BSD_SOURCE -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H
CFLAGS		+= $(OPTFLAGS)
CFLAGS		+= $(PACKET_TAG_863)
CFLAGS		+= -DPLATFORM_NSDPF_PAPP=1

ifeq ($(USE_PAG_GET_FRAME), 1)
CFLAGS += -DUSE_PAG_GET_FRAME=1
endif

RELEASE_PATH=../../bin/platform_lib/
LIBPATH = -L../lib -L/opt/mrzcpd/lib
DEP = ../support/libnet_common.so

H_DIR += $(INC)   
H_DIR += -I../../include/
H_DIR += -I../../include/public
H_DIR += -I../../include/private
H_DIR += -I../../include/support
H_DIR += -I/opt/MESA/include
H_DIR += -I/opt/MESA/include/MESA
H_DIR += -I/opt/mrzcpd/include

OBJS=sendpacket.o packet_io.o packet_io_log.o
OBJS+=packet_io_lib_load.o
OBJS+=packet_io_status.o
OBJS+=packet_io_status_new.o
#OBJS += cycle_pkt_dump.o
#OBJS += cycle_pkt_dump_unix.o
OBJS += cycle_pkt_dump_through_write_offset.o
OBJS += packet_io_device.o
OBJS += sapp_compat_wangyan_api.o


DLL_LIB=
#ifeq ($(iomode), $(_MODE_PCAP))
CFLAGS += -DIOMODE_PCAP=1
DLL_LIB += packet_io_pcap.so 
ifeq ($(link_mode), $(__LINK_MODE_STATIC))
  OBJS += packet_io_pcap.o
endif
#endif

ifeq ($(iomode), $(_MODE_PAG))
CFLAGS += -DIOMODE_PAG=1
DLL_LIB += packet_io_pag.so 
  ifeq ($(link_mode), $(__LINK_MODE_STATIC))
    OBJS += packet_io_pag.o
  endif
endif

ifeq ($(iomode), $(_MODE_PPF))
CFLAGS += -DIOMODE_PPF=1
DLL_LIB += packet_io_ppf.so 
endif

ifeq ($(iomode), $(_MODE_PFRING))
CFLAGS += -DIOMODE_PFRING=1
DLL_LIB += packet_io_pfring.so 
endif

ifeq ($(iomode), $(_MODE_DPDK))
CFLAGS += -DIOMODE_DPDK=1
DLL_LIB += packet_io_dpdk.so 
endif

ifeq ($(iomode), $(_MODE_TOPSEC))
CFLAGS += -DIOMODE_TOPSEC=1
DLL_LIB += packet_io_topsec.so 
endif

ifeq ($(iomode), $(_MODE_IPFILE))
CFLAGS += -DIOMODE_IPFILE=1
DLL_LIB += packet_io_ipfile.so 
endif

ifeq ($(iomode), $(_MODE_MARSIO))                                                                                               
CFLAGS += -DIOMODE_MARSIO=1
DLL_LIB += packet_io_marsio.so
    ifeq ($(link_mode), $(__LINK_MODE_STATIC))                                                                                               
        OBJS += packet_io_marsio.o
    endif
endif

ifeq ($(iomode), $(_MODE_SMITH))
CFLAGS += -DIOMODE_SMITH=1
DLL_LIB += packet_io_agent_smith.so
endif

ifeq ($(IIEFD_DUAL_STACK), $(YES))
CFLAGS += -g -DIIEFD_DUAL_STACK=1
endif

ifeq ($(iomode), $(_MODE_DPDK_VXLAN))
CFLAGS += -DIOMODE_DPDK_VXLAN=1
DLL_LIB += packet_io_dpdk_vxlan.so 
endif

ifeq ($(iomode), $(_MODE_PAG_MARSIO))
CFLAGS += -DIOMODE_PAG_MARSIO=1
DLL_LIB += packet_io_pag_marsio.so 
endif


TARGET = libpacket_io.a 

ifeq ($(debug), $(_DEBUG2))
OBJS += iknow_info.o 
endif

all: $(TARGET) $(DLL_LIB)

.c.o:
	$(CC) -c $(CFLAGS) -I. $(H_DIR) $<

.cpp.o:
	$(CCC) -c $(CFLAGS) -I. $(H_DIR) $<


$(TARGET): $(OBJS)
	rm -f $@ ;ar -r $@ $^; 
	cp $(TARGET)  ../lib

packet_io_pcap.so:packet_io_pcap.o  
	$(CC) -o $@ -fPIC -shared -g -Wall $^ $(LIBPATH) $(LIBS) -lpcap;
	cp $@ $(RELEASE_PATH) 
	
packet_io_pag.so:packet_io_pag.o 
	#$(CC) -o $@ -fPIC -shared -g -Wall $^ $(LIBPATH) $(LIBS) -lpag;
	gcc -o $@ -fPIC -shared -g -Wall $^ $(LIBPATH) $(LIBS) -lpag;
	cp $@ $(RELEASE_PATH) 

packet_io_ppf.so:packet_io_ppf.o 
	$(CC) -o $@ -fPIC -shared -g -Wall $^ $(LIBPATH) $(LIBS) -lppf;
	cp $@ $(RELEASE_PATH) 
	
packet_io_pfring.so:packet_io_pfring.o 
	$(CC) -o $@ -fPIC -shared -g -Wall $^ $(IBPATH) $(LIBS) -lpfring;
	cp $@ $(RELEASE_PATH) 

packet_io_qnf.so:packet_io_qnf.o 
	$(CC) -o $@ -fPIC -shared -g -Wall $^ $(LIBPATH) $(LIBS) -lqnfapi;
	cp $@ $(RELEASE_PATH) 

packet_io_dpdk.so:packet_io_dpdk.o 
	$(CC) -o $@ -fPIC -shared -g -Wall $^ $(LIBPATH) $(LIBS) -L$(LIBPATH) -lmarsio;
	cp $@ $(RELEASE_PATH) 

packet_io_topsec.so:packet_io_topsec.o 
	gcc -o $@ -fPIC -shared -g -Wall $^ $(LIBPATH) $(LIBS) -L$(LIBPATH) -lpag;
	cp $@ $(RELEASE_PATH) 
	
packet_io_ipfile.so:packet_io_ipfile.o 
	gcc -o $@ -fPIC -shared -g -Wall $^ $(LIBPATH) $(LIBS) -L$(LIBPATH);
	cp $@ $(RELEASE_PATH) 

packet_io_agent_smith.so:packet_io_agent_smith.o
	gcc -o $@ -fPIC -shared -g -Wall $^ $(LIBPATH) $(LIBS) -L$(LIBPATH) -lagent_smith;
	cp $@ $(RELEASE_PATH) 
		    
packet_io_marsio.so:packet_io_marsio.o
	gcc -o $@ -fPIC -shared -g -Wall $^ $(LIBPATH) $(LIBS) -L$(LIBPATH) -lmarsio;
	cp $@ $(RELEASE_PATH) 

packet_io_dpdk_vxlan.so:packet_io_dpdk_vxlan.o
	$(CC) -o $@ -fPIC -shared -g -Wall $^ $(LIBPATH) $(LIBS) -L$(LIBPATH) -lmarsio;
	cp $@ $(RELEASE_PATH) 
	
packet_io_pag_marsio.so:packet_io_pag_marsio.o
	gcc -o $@ -fPIC -shared -g -Wall $^ $(LIBPATH) $(LIBS) -L$(LIBPATH) -lmarsio;
	cp $@ $(RELEASE_PATH) 

clean:
	rm -f *.o packet_io*.so *.a $(TARGET) $(DLL_LIB)  *~

opt:
	$(MAKE) all
