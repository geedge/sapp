cmake_minimum_required(VERSION 2.8)
add_definitions(-D_BSD_SOURCE -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD=1 -DHAVE_NET_ETHERNET_H)
add_definitions(-DPLATFORM_NSDPF_PAPP=1)

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/include/net)
include_directories(${CMAKE_SOURCE_DIR}/include/support)
include_directories(${CMAKE_SOURCE_DIR}/dealpkt)
include_directories(${CMAKE_SOURCE_DIR}/packet_io)

if(CAPTURE_MODE MATCHES "PAG")
	set(PACKET_IO_SOURCE ${PACKET_IO_SOURCE} packet_io_pag_marsio.c)
endif()

if(CAPTURE_MODE MATCHES "PPF")
	set(PACKET_IO_SOURCE ${PACKET_IO_SOURCE} packet_io_ppf.c)
endif()

if(CAPTURE_MODE MATCHES "PFRING")
	set(PACKET_IO_SOURCE ${PACKET_IO_SOURCE} capture_pfring.c)
endif()

if(CAPTURE_MODE MATCHES "DPDK")
	set(PACKET_IO_SOURCE ${PACKET_IO_SOURCE} packet_io_dpdk.c)
endif()

if(CAPTURE_MODE MATCHES "MARSIO")
	set(PACKET_IO_SOURCE ${PACKET_IO_SOURCE} packet_io_marsio.c)
endif()

set(PACKET_IO_SOURCE ${PACKET_IO_SOURCE}  cycle_pkt_dump_through_write_offset.c  packet_io_lib_load.c pkt_dispatch_new.c
iknow_info.c                           packet_io_log.c         sendpacket.c
sendpacket_wrap.c   packet_io.c
packet_io_status_by_mesafs.cpp packet_io_status.cpp
packet_io_status_new.c  packet_io_pcap.c)

add_library(packet_io STATIC ${PACKET_IO_SOURCE})

target_link_libraries(packet_io timestamp_record iknow)
