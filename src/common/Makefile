#opt: OPTFLAGS = -O2
#export OPTFLAGS

CC		= g++
CCC		= g++
CFLAGS		+= -Wall
CFLAGS		+= -fPIC -shared -D_DEFAULT_SOURCE -D_DEFAULT_SOURCE -D__DEFAULT_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H
CFLAGS		+= $(OPTFLAGS)
CFLAGS		+= $(PACKET_TAG_863)
CFLAGS		+= -DPLATFORM_NSDPF_PAPP=1

LIBPATH = ../lib

H_DIR += $(INC)
H_DIR += -I../../include
H_DIR += -I../../include/private
H_DIR += -I../../include/public
H_DIR += -I../../include/support

H_DIR += -I/opt/MESA/include
H_DIR += -I/opt/MESA/include/MESA

TARGET = libcommon.a

OBJS= net_common.o stream_addr_inet.o linux_kernel_jhash.o sapp_log.o

ifeq ($(IIEFD_DUAL_STACK), $(YES))
CFLAGS += -g -DIIEFD_DUAL_STACK=1
endif

ifeq ($(USE_MEM_POOL), 1)
CFLAGS += -DUSE_MEMPOOL=1
endif


all: $(TARGET)

$(TARGET): $(OBJS)
	rm -f $@ ;ar -r $@ $^; 
	cp $(TARGET) $(LIBPATH) 
	
.c.o:
	$(CC) -c $(CFLAGS) -I. $(H_DIR) $<

.cpp.o:
	$(CCC) -c $(CFLAGS) -I. $(H_DIR) $<

clean:
	rm -f *.o $(TARGET)  *~

opt:
	$(MAKE) all
