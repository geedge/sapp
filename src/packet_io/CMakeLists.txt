cmake_minimum_required(VERSION 2.8...3.10)
add_definitions(-D_DEFAULT_SOURCE -D_DEFAULT_SOURCE -D__DEFAULT_SOURCE -D__FAVOR_BSD=1 -DHAVE_NET_ETHERNET_H)
add_definitions(-DPLATFORM_NSDPF_PAPP=1)

LINK_DIRECTORIES(/opt/mrzcpd/lib)

include_directories(${CMAKE_SOURCE_DIR}/include/private)
include_directories(${CMAKE_SOURCE_DIR}/include/public)
include_directories(${CMAKE_SOURCE_DIR}/include/support)
include_directories(${MESA_SDK_PREFIX}/include)
include_directories(${MESA_SDK_PREFIX}/include/MESA)
include_directories(${CMAKE_SOURCE_DIR}/include)

if(CAPTURE_MODE STREQUAL "MARSIO")
    include_directories(${MARSIO_SDK_PREFIX}/include)
endif()

add_definitions(-fPIC)

#always add libpcap
set(PACKET_IO_SOURCE ${PACKET_IO_SOURCE} packet_io_pcap.c)
add_library(packet_io_pcap STATIC ${PACKET_IO_SOURCE})

set_target_properties(packet_io_pcap  PROPERTIES PREFIX "")

if(CAPTURE_MODE STREQUAL "PAG")
	set(PACKET_IO_SOURCE  packet_io_pag_marsio.c)
    add_library(packet_io_pag_marsio STATIC ${PACKET_IO_SOURCE})
endif()

if(CAPTURE_MODE STREQUAL "MARSIO")
	set(PACKET_IO_SOURCE packet_io_marsio.c)
    add_library(packet_io_marsio STATIC ${PACKET_IO_SOURCE})
	set_target_properties(packet_io_marsio  PROPERTIES PREFIX "")
endif()

if(CAPTURE_MODE STREQUAL "TUN")
	set(PACKET_IO_SOURCE packet_io_tun.c)
    add_library(packet_io_tun STATIC ${PACKET_IO_SOURCE})
endif()

set(PACKET_IO_STATIC_SOURCE cycle_pkt_dump_through_write_offset.c  packet_io_lib_load.c
packet_io_log.c         sendpacket.c
packet_io.c
packet_io_status.cpp packet_io_status_new.c 
packet_io_device.c sapp_compat_old_papp_api.c
sapp_inject.c packet_io_hook.c under_ddos.cpp)

add_library(packet_io STATIC ${PACKET_IO_STATIC_SOURCE})
if(CAPTURE_MODE STREQUAL "MARSIO")
    ##target_link_libraries(packet_io marsio)
endif() 

target_link_libraries(packet_io timestamp_record)
