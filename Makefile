##################### MESA Makefile Common Definition Start #################
MESA_MAKE_VERSION=20170626

#CC=gcc
CC=g++
CCC=g++
CFLAGS = 
#CFLAGS = -march=native
#CFLAGS += -D__FAVOR_BSD=1 -D__USE_BSD=1 -D_GNU_SOURCE=1 -Werror -DMESA_SAPP_PLATFORM=1
CFLAGS += -D__FAVOR_BSD=1 -D__USE_BSD=1 -D_GNU_SOURCE=1  -DMESA_SAPP_PLATFORM=1
LIBS= -L/opt/MESA/lib
INC=-I./
INC+=-I/opt/MESA/include
OBJS=

_MODE_PCAP=pcap
_MODE_PAG=pag
_MODE_PPF=ppf
_MODE_PFRING=pfring
_MODE_DPDK=dpdk
_MODE_PAG_N95=pag_n95
_MODE_TOPSEC=topsec
_MODE_MARSIO=marsio
_MODE_SMITH=smith
_MODE_DPDK_VXLAN=dpdk_vxlan
_MODE_PAG_MARSIO=pag_marsio
_MODE_IPFILE=ipfile
_MODE_CHK=0
iomode=pcap

_OPT0=0
_OPT1=1
_OPT2=2
_OPT3=3
_OPT_HIGH_PERF=high_perf
#default level is 0
opt=0
_OPT_CHK=0

_DEBUG_CHK=0
_DEBUG0=0
_DEBUG1=1
_DEBUG2=2
#default is 2
debug=2

ifeq ($(debug), $(_DEBUG0))
#do nothing
_DEBUG_CHK=1
endif

ifeq ($(debug), $(_DEBUG1))
CFLAGS += -g
_DEBUG_CHK=1
#do nothing
endif
ifeq ($(debug), $(_DEBUG2))
CFLAGS += -g -DDEBUG=1
_DEBUG_CHK=1
endif

ifneq ($(_DEBUG_CHK), 0)
else
    ifeq ($(debug), 0)
    #
    else
        $(error args debug error)
        exit
    endif
endif

ifeq ($(iomode), $(_MODE_PCAP))
_MODE_CHK=1
LIBS += -lpcap
endif
ifeq ($(iomode), $(_MODE_PAG))
LIBS += -lpag -lpthread
_MODE_CHK=1
endif
ifeq ($(iomode), $(_MODE_PPF))
LIBS += -lppf
_MODE_CHK=1
endif
ifeq ($(iomode), $(_MODE_PFRING))
LIBS += -lpfring
_MODE_CHK=1
endif

ifeq ($(iomode), $(_MODE_DPDK))
LIBS += -lmarsio
_MODE_CHK=1
endif

ifeq ($(iomode), $(_MODE_TOPSEC))
_MODE_CHK=1
endif

ifeq ($(iomode), $(_MODE_MARSIO))                                                                                               
LIBS += -lmarsio
_MODE_CHK=1
endif

ifeq ($(iomode), $(_MODE_SMITH))
LIBS += -lagent_smith
_MODE_CHK=1
endif

ifeq ($(iomode), $(_MODE_DPDK_VXLAN))
LIBS += -lmarsio
_MODE_CHK=1
endif

ifeq ($(iomode), $(_MODE_PAG_MARSIO))
LIBS += -lpag
_MODE_CHK=1
endif

ifeq ($(iomode), $(_MODE_IPFILE))
_MODE_CHK=1
endif

ifneq ($(_MODE_CHK), 0)
else
    ifeq ($(iomode), "pcap")
    else
        $(error args iomode error)
        exit
    endif
endif

ifeq ($(opt), $(_OPT0))
opt=0
CFLAGS += -O0
_OPT_CHK=1
endif
ifeq ($(opt), $(_OPT1))
opt=1
CFLAGS += -O1
_OPT_CHK=1
endif
ifeq ($(opt), $(_OPT2))
opt=2
CFLAGS += -O2
_OPT_CHK=1
endif
ifeq ($(opt), $(_OPT3))
opt=3
CFLAGS += -O3
_OPT_CHK=1
endif
ifeq ($(opt), $(_OPT_HIGH_PERF))
opt=2
CFLAGS += -O2 -DHIGH_PERF=1 -UDEBUG -march=native
_OPT_CHK=1
endif

ifneq ($(_OPT_CHK), 0)
else
    ifeq ($(opt), 0)
		#
    else
        $(error args opt error)
    exit
    endif
endif

.PHONY:help clean target

export CC
export CCC
export CFLAGS
export LIBS
export INC
export iomode 
export debug
export _OPT_HIGH_PERF
export _DEBUG0
export _DEBUG1
export _DEBUG2
export _MODE_PCAP
export _MODE_PAG
export _MODE_PPF
export _MODE_PFRING
export _MODE_DPDK
export _MODE_TOPSEC
export _MODE_MARSIO                                                                                                             
export _MODE_SMITH
export _MODE_DPDK_VXLAN
export _MODE_IPFILE
export _MODE_PAG_MARSIO

target:all

version:
	@echo -e "MESA Makefile version:\033[31;49;1m $(MESA_MAKE_VERSION)\033[0m"
	
help:
	@echo -e "MESA Makefile version:\033[31;49;1m $(MESA_MAKE_VERSION)\033[0m"
	@echo "MESA-Makefile usage:"
	@echo -e "\treserved args:"
	@echo -e "\t\t\033[31;49;1m debug={0,1,2},0:release version; 1:-g; 2:-g -DDEBUG, default is 2.\033[0m"
	@echo -e "\t\t\033[31;49;1m opt={0,1,2,3,high_perf}, optimize level, default is 0.\033[0m"
	@echo -e "\t\t\033[31;49;1m iomode={pcap,ppf,pag,prfing,dpdk,tilera,topsec,ipfile,marsio,smith,dpdk_vxlan,pag_marsio}, default is pcap.\033[0m"

##################### MESA Makefile Common Definition End ####################

YES=1
NO=0
USE_MEM_POOL=$(YES)
#USE_MEM_POOL=$(NO)
USE_PAG_GET_FRAME=$(YES)
#USE_PAG_GET_FRAME=$(NO)
INSTALL_PATH=./run

#md5sum "./include/stream_inc/stream_base.h"

MD5_STREAM_BASE=$(shell md5sum "./include/stream_inc/stream_base.h"|cut -d ' ' -f1)
MD5_STREAM_ENTRY=$(shell md5sum "./include/stream_inc/stream_entry.h"|cut -d ' ' -f1)
MD5_STREAM_CONTROL=$(shell md5sum "./include/stream_inc/stream_control.h"|cut -d ' ' -f1)
MD5_STREAM_INJECT=$(shell md5sum "./include/stream_inc/stream_inject.h"|cut -d ' ' -f1)
MD5_STREAM_PROJECT=$(shell md5sum "./include/stream_inc/stream_project.h"|cut -d ' ' -f1)
MD5_STREAM_PROXY=$(shell md5sum "./include/stream_inc/stream_proxy.h"|cut -d ' ' -f1)
MD5_STREAM_RAWPKT=$(shell md5sum "./include/stream_inc/stream_rawpkt.h"|cut -d ' ' -f1)
MD5_STREAM_TUNNEL=$(shell md5sum "./include/stream_inc/stream_tunnel.h"|cut -d ' ' -f1)

HEADER_CHECK_FLAGS += 	-DSTREAM_BASE_MD5_CHECK=\"$(MD5_STREAM_BASE)\"
HEADER_CHECK_FLAGS += 	-DSTREAM_CONTROL_MD5_CHECK=\"$(MD5_STREAM_CONTROL)\" 
HEADER_CHECK_FLAGS +=   -DSTREAM_ENTRY_MD5_CHECK=\"$(MD5_STREAM_ENTRY)\"
HEADER_CHECK_FLAGS +=   -DSTREAM_INJECT_MD5_CHECK=\"$(MD5_STREAM_INJECT)\"
HEADER_CHECK_FLAGS +=	-DSTREAM_PROJECT_MD5_CHECK=\"$(MD5_STREAM_PROJECT)\"
HEADER_CHECK_FLAGS +=	-DSTREAM_PROXY_MD5_CHECK=\"$(MD5_STREAM_PROXY)\"
HEADER_CHECK_FLAGS +=	-DSTREAM_RAWPKT_MD5_CHECK=\"$(MD5_STREAM_RAWPKT)\"
HEADER_CHECK_FLAGS +=	-DSTREAM_TUNNEL_MD5_CHECK=\"$(MD5_STREAM_TUNNEL)\"

GIT_BRANCH=$(shell git symbolic-ref --short -q HEAD)
GIT_SHA1=$(shell git rev-parse HEAD)
MAKE_TIME=$(shell date "+%Y-%m-%d_%H:%M:%S")
VERSION_FLAGS += -DGITVER=\"3.0.0-$(GIT_BRANCH)-$(GIT_SHA1)-$(MAKE_TIME)\"

CFLAGS += ${HEADER_CHECK_FLAGS} ${VERSION_FLAGS}
CXXFLAGS += ${HEADER_CHECK_FLAGS} ${VERSION_FLAGS}


export USE_MEM_POOL
export USE_PAG_GET_FRAME
export YES
export NO

all:
	cd support/avl_tree; $(MAKE);
	cd support/MESA_sleep; $(MAKE);
	cd support/dictator2/src; $(MAKE);
	cd support/md5; $(MAKE);
	cd support/rb_tree; $(MAKE);
	cd support/symbol_check; $(MAKE);
	cd support/timestamp_record; $(MAKE);
	cd support/iknow; $(MAKE);
	cd support/MESA_socket_wrap; $(MAKE);
	cd support/c3_client; $(MAKE);
	cd dealpkt; $(MAKE);
	cd packet_io; $(MAKE);
	cd project; $(MAKE);
	cd plugin; $(MAKE);
	cd inner_plug; $(MAKE);
	cd entry; $(MAKE);
	nm run/sapp | grep version_VERSION;

clean:
	rm -rf build/*;
	rm -f run/sapp;
	rm -f lib/*.a;
	cd test_so; $(MAKE) clean;
	cd dealpkt; $(MAKE) clean;
	cd packet_io; $(MAKE) clean;
	cd project; $(MAKE) clean;
	cd plugin; $(MAKE) clean; 
	cd inner_plug; $(MAKE) clean;
	cd entry; $(MAKE) clean;
	cd support/c3_client; $(MAKE) clean;
	cd support/dictator2/src; $(MAKE) clean;
	cd support/MESA_sleep; $(MAKE) clean;
	cd support/md5; $(MAKE) clean;
	cd support/rb_tree; $(MAKE) clean;
	cd support/symbol_check; $(MAKE) clean;
	cd support/timestamp_record; $(MAKE) clean;
	cd support/iknow; $(MAKE) clean;
	cd support/MESA_socket_wrap; $(MAKE) clean;
	cd support/avl_tree; $(MAKE) clean;

install:
	mkdir -p /opt/MESA/include;
	mkdir -p /opt/MESA/lib;
	cp -r -f include/support/pcap* /opt/MESA/include
	ln -sf /usr/lib64/libpcap.so.1 /opt/MESA/lib/libpcap.so;
	cp packet_io/*.so $(INSTALL_PATH)/platform_lib/
