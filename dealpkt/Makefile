#opt: OPTFLAGS = -O2
#export OPTFLAGS

CC		= g++
CCC		= g++
CFLAGS		+= -Wall
CFLAGS		+= -fPIC -shared -D_BSD_SOURCE -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H
CFLAGS		+= $(OPTFLAGS)
CFLAGS		+= $(PACKET_TAG_863)
CFLAGS		+= -DPLATFORM_NSDPF_PAPP=1

LIBPATH = ../lib

H_DIR += $(INC)
H_DIR += -I../packet_io
H_DIR += -I../include
H_DIR += -I../include/net
H_DIR += -I../include/support
H_DIR += -I../include/stream_inc
H_DIR += -I../project_requirement
H_DIR += -I../support/rbtree
H_DIR += -I/usr/include/MESA/
H_DIR += -I/opt/MESA/include
H_DIR += -I/opt/MESA/include/MESA

TARGET = libdealpkt.a

OBJS=deal_udp.o deal_tcp.o stream_manage.o callapp.o deal_ipv6.o deal_ipv4.o deal_vlan.o ip_reassembly.o hash.o synflood_detect.o
OBJS+=deal_ethernet.o deal_arp.o deal_pppoe.o deal_gre.o deal_teredo.o
OBJS += deal_icmp.o
OBJS += g_device.o net_common.o
OBJS += deal_mpls.o
OBJS += deal_proxy.o
OBJS += deal_ppp.o
OBJS += deal_pptp.o
OBJS += stream_addr_inet.o
OBJS += linux_kernel_jhash.o
OBJS += plug_support.o
OBJS += deal_l2tp.o
OBJS += deal_isakmp.o
OBJS += deal_mac_in_mac.o
OBJS += deal_gprs_tunnel.o


ifeq ($(IIEFD_DUAL_STACK), $(YES))
CFLAGS += -g -DIIEFD_DUAL_STACK=1
endif

ifeq ($(USE_MEM_POOL), 1)
CFLAGS += -DUSE_MEMPOOL=1
endif

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
endif

ifeq ($(iomode), $(_MODE_SMITH))
CFLAGS += -DIOMODE_SMITH=1
endif

ifeq ($(iomode), $(_MODE_DPDK_VXLAN))
CFLAGS += -DIOMODE_DPDK_VXLAN=1
endif

ifeq ($(iomode), $(_MODE_PAG_MARSIO))                                                                                        
CFLAGS += -DIOMODE_PAG_MARSIO=1
endif

all: $(TARGET)

$(TARGET): $(OBJS)
	rm -f $@ ;ar -r $@ $^; 
	cp $(TARGET) $(LIBPATH) 

linux_kernel_jhash.o:linux_kernel_jhash.c
	$(CC) -c $(CFLAGS) -O3 -I. $(H_DIR) $<
	
.c.o:
	$(CC) -c $(CFLAGS) -I. $(H_DIR) $<

.cpp.o:
	$(CCC) -c $(CFLAGS) -I. $(H_DIR) $<

clean:
	rm -f *.o $(TARGET)  *~

opt:
	$(MAKE) all
