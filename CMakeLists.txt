
cmake_minimum_required(VERSION 2.8)

set(CMAKE_MACOSX_RPATH 0)

# MESA SDK Root
set(MESA_SDK_PREFIX "/opt/MESA/" CACHE STRING "MESA Framework Prefix")
# Capture Mode
option(OPT_IOMODE_PCAP "Capture network traffic with libpcap" ON)
option(OPT_IOMODE_PAG "Capture network traffic with libpag" OFF)
option(OPT_IOMODE_PPF "Capture network traffic with libppf" OFF)
option(OPT_IOMODE_PFRING "Capture network traffic with PF-RING" OFF)
option(OPT_IOMODE_DPDK "Capture network traffic with DPDK" OFF)
option(OPT_IOMODE_PAG_N95 "Capture network traffic with N95" OFF)

if(OPT_IOMODE_PCAP)
	set(CAPTURE_MODE "PCAP")	
endif()

if(OPT_IOMODE_PAG)
	set(CAPTURE_MODE "PAG")
endif()

if(OPT_IOMODE_PPF)
	set(CAPTURE_MODE "PPF")
endif()

if(OPT_IOMODE_PFRING)
	set(CAPTURE_MODE "PFRING")
endif()

if(OPT_IOMODE_DPDK)
	set(CAPTURE_MODE "DPDK")
endif()

if(OPT_IOMODE_PAG_N95)
	set(CAPTURE_MODE "PAG_N95")
endif()

if(CAPTURE_MODE MATCHES "PCAP")
    set(CAPTURE_DEFINITIONS -DONLY_PCAP -DIOMODE_PCAP)
endif()

if(CAPTURE_MODE MATCHES "PAG")
	set(CAPTURE_DEFINITIONS -DCAPTURE_MODE_PAG)
endif()

if(CAPTURE_MODE MATCHES "PPF")
	set(CAPTURE_DEFINITIONS -DCAPTURE_MODE_PPF)
endif()

if(CAPTURE_MODE MATCHES "PFRING")
	set(CAPTURE_DEFINITIONS -DCAPTURE_MODE_PFRING)
endif()

if(CAPTURE_MODE MATCHES "DPDK")
	set(CAPTURE_DEFINITIONS -DCAPTURE_MODE_DPDK)
endif()

# Memory Allocator
option(OPT_USE_DICTATOR	"Use Dictator2 memory allocator" OFF)
option(OPT_USE_TXMEM "Use Dictator2 for TileGX memory allocator" OFF)
option(OPT_USE_TCMALLOC "Use TCmalloc memory allocator" OFF)
option(OPT_USE_JEMALLOC "Use JEmalloc memory allocator" OFF)

if(OPT_USE_DICTATOR)
	set(MEM_POOL_DEFINITIONS -DUSE_MEM_POOL=1)
endif()

add_definitions(${CAPTURE_DEFINITIONS} ${MEM_POOL_DEFINITIONS} -D__FAVOR_BSD=1
    -D__USE_BSD=1 -D_GNU_SOURCE=1  -DMESA_SAPP_PLATFORM=1)

set(SAPP_DEPEND_DYN_LIB  MESA_handle_logger MESA_htable pthread MESA_field_stat2)

#set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG -fno-inline")

add_subdirectory(support)
add_subdirectory(dealpkt)
add_subdirectory(packet_io)
add_subdirectory(plugin)
add_subdirectory(project)
add_subdirectory(inner_plug)
add_subdirectory(entry)
