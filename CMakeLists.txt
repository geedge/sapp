
cmake_minimum_required(VERSION 2.8)

set(CMAKE_MACOSX_RPATH 0)

#set(CMAKE_INSTALL_PREFIX /home/ceiec/sapp/)
set(CMAKE_INSTALL_PREFIX ${CMAKE_SOURCE_DIR}/run/)

# MESA SDK Root
set(MESA_SDK_PREFIX "/opt/MESA/" CACHE STRING "MESA Framework Prefix")
# Capture Mode
option(OPT_IOMODE_PCAP "Capture network traffic with libpcap" ON)
option(OPT_IOMODE_PAG "Capture network traffic with libpag" OFF)
option(OPT_IOMODE_PPF "Capture network traffic with libppf" OFF)
option(OPT_IOMODE_PFRING "Capture network traffic with PF-RING" OFF)
option(OPT_IOMODE_DPDK "Capture network traffic with DPDK" OFF)
option(OPT_IOMODE_PAG_N95 "Capture network traffic with N95" OFF)
option(OPT_IOMODE_MARSIO "Capture network traffic with MARSIO" ON)

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

if(OPT_IOMODE_MARSIO)
	set(CAPTURE_MODE "MARSIO")	
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

if(CAPTURE_MODE MATCHES "MARSIO")
	set(CAPTURE_DEFINITIONS -DCAPTURE_MODE_MARSIO -DIOMODE_MARSIO)
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

set(CMAKE_C_FLAGS_RELEASE "-Werror")

add_subdirectory(support)
add_subdirectory(dealpkt)
add_subdirectory(packet_io)
add_subdirectory(plugin)
add_subdirectory(project)
add_subdirectory(inner_plug)
add_subdirectory(entry)

#set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_SOURCE_DIR}/run/)

install(PROGRAMS ${CMAKE_BINARY_DIR}/entry/sapp DESTINATION .)

install(PROGRAMS run/r2 DESTINATION .)
install(PROGRAMS run/r3 DESTINATION .)
install(PROGRAMS run/vv.py DESTINATION .)
install(PROGRAMS run/pag.conf DESTINATION .)
install(PROGRAMS run/memchk.sh DESTINATION .)
install(FILES run/conf/gdev_block.conf DESTINATION conf)
install(FILES run/conf/gdev.conf DESTINATION conf)
install(FILES run/conf/main.conf DESTINATION conf)
install(FILES run/conf/project_list.conf DESTINATION conf)
install(FILES run/conf/route_table.conf DESTINATION conf)
install(FILES run/conf/send_gdev.conf DESTINATION conf)
install(FILES run/conf/send_raw_pkt.conf DESTINATION conf)
install(FILES run/conf/send_route.conf DESTINATION conf)
install(FILES run/conf/streamid.txt DESTINATION conf)
install(FILES run/conf/plugin/entrylist.conf DESTINATION conf/plugin)
install(FILES run/conf/plugin/plugin.conf DESTINATION conf/plugin)

if(CAPTURE_MODE MATCHES "MARSIO")
	install(FILES ${CMAKE_BINARY_DIR}/packet_io/packet_io_marsio.so DESTINATION platform_lib)
endif()

if(CAPTURE_MODE MATCHES "PCAP")
	install(FILES ${CMAKE_BINARY_DIR}/packet_io/packet_io_pcap.so DESTINATION platform_lib)
endif()

install(FILES run/plug/platform/conflist_platform.inf DESTINATION plug/platform)
install(FILES run/plug/protocol/conflist_protocol.inf DESTINATION plug/protocol)
install(FILES run/plug/protocol/isakmp_protocol_plug/isakmp_protocol_plug.inf DESTINATION plug/protocol/isakmp_protocol_plug)
install(FILES run/plug/protocol/isakmp_protocol_plug/isakmp_protocol_plug.so DESTINATION plug/protocol/isakmp_protocol_plug)
install(FILES run/plug/protocol/l2tp_protocol_plug/l2tp_protocol_plug.inf DESTINATION plug/protocol/l2tp_protocol_plug)
install(FILES run/plug/protocol/l2tp_protocol_plug/l2tp_protocol_plug.so DESTINATION plug/protocol/l2tp_protocol_plug)
install(FILES run/plug/protocol/pptp_protocol_plug/pptp_protocol_plug.inf DESTINATION plug/protocol/pptp_protocol_plug)
install(FILES run/plug/protocol/pptp_protocol_plug/pptp_protocol_plug.so DESTINATION plug/protocol/pptp_protocol_plug)
install(FILES run/plug/business/conflist_business.inf DESTINATION plug/business)
#install(FILES run/plug/business/g_device_plug/g_device_plug.inf DESTINATION plug/business/g_device_plug)
#install(FILES run/plug/business/g_device_plug/g_device_plug.so DESTINATION plug/business/g_device_plug)
install(FILES run/plug/business/test_app/test_app.inf DESTINATION plug/business/test_app)
install(FILES run/plug/business/test_app/test_app_sapp.so DESTINATION plug/business/test_app)
install(FILES run/plug/business/test_app/trace_delay.so DESTINATION plug/business/test_app)
#install(FILES src/hello.h DESTINATION )

set(CPACK_PACKAGE_NAME "sapp")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Simple CPack sapp")
set(CPACK_PACKAGE_VENDOR "MESA")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_PACKAGE_VERSION_MAJOR "1")
set(CPACK_PACKAGE_VERSION_MINOR "0")
set(CPACK_PACKAGE_VERSION_PATCH "0")
set(CPACK_RPM_PACKAGE_GROUP "MESA")
set(CPACK_RPM_PACKAGE_URL "http://git.mesalab.cn")
set(CPACK_RPM_PACKAGE_DESCRIPTION "Sapp Server Dependencies")
set(CPACK_PACKAGE_RELEASE 1)
set(CPACK_RPM_PACKAGE_LICENSE "mesalab.cn")

set(CPACK_GENERATOR "RPM")

include(CPack)
