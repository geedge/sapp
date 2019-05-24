cmake_minimum_required(VERSION 2.8)
add_definitions(-D_BSD_SOURCE -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD=1 -DHAVE_NET_ETHERNET_H)
add_definitions(-DPLATFORM_NSDPF_PAPP=1)

include_directories(${MESA_SDK_PREFIX}/include)
include_directories(${MESA_SDK_PREFIX}/include/MESA)
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/include/net)
include_directories(${CMAKE_SOURCE_DIR}/include/support)
include_directories(${CMAKE_SOURCE_DIR}/dealpkt)
include_directories(${CMAKE_SOURCE_DIR}/packet_io)

add_definitions(-fPIC)

#if(CAPTURE_MODE MATCHES "PCAP")
    #set(PACKET_IO_SOURCE ${PACKET_IO_SOURCE} packet_io_pcap.c)
    add_library(packet_io_pcap SHARED packet_io_pcap.c)
	set_target_properties(packet_io_pcap  PROPERTIES PREFIX "")
#endif()

if(CAPTURE_MODE MATCHES "PAG")
	set(PACKET_IO_SOURCE ${PACKET_IO_SOURCE} packet_io_pag_marsio.c)
    add_library(packet_io_pag_marsio SHARED ${PACKET_IO_SOURCE})
endif()

#if(CAPTURE_MODE MATCHES "PPF")
#	set(PACKET_IO_SOURCE ${PACKET_IO_SOURCE} packet_io_ppf.c)
#    add_library(packet_io_ppf SHARED ${PACKET_IO_SOURCE})
#endif()
#
#if(CAPTURE_MODE MATCHES "DPDK")
#	set(PACKET_IO_SOURCE ${PACKET_IO_SOURCE} packet_io_dpdk.c)
#    add_library(packet_io_dpdk SHARED ${PACKET_IO_SOURCE})
#endif()

if(CAPTURE_MODE MATCHES "MARSIO")
	set(PACKET_IO_SOURCE ${PACKET_IO_SOURCE} packet_io_marsio.c)
    add_library(packet_io_marsio SHARED ${PACKET_IO_SOURCE})
	target_link_libraries(packet_io_marsio marsio)
	set_target_properties(packet_io_marsio  PROPERTIES PREFIX "")
endif()

set(PACKET_IO_STATIC_SOURCE cycle_pkt_dump_through_write_offset.c  packet_io_lib_load.c pkt_dispatch_new.c
iknow_info.c                           packet_io_log.c         sendpacket.c
sendpacket_wrap.c   packet_io.c
packet_io_status_by_mesafs.cpp packet_io_status.cpp packet_io_status_new.c )

add_library(packet_io STATIC ${PACKET_IO_STATIC_SOURCE})

target_link_libraries(packet_io timestamp_record iknow)
