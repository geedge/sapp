cmake_minimum_required(VERSION 2.8)

set(project_name sapp)

project(${project_name})

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
include(Version)

set(CMAKE_MACOSX_RPATH 0)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DDEBUG")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DDEBUG")
endif()

set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Werror -DHIGH_PERF=1")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Werror -DHIGH_PERF=1")


set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG -DHIGH_PERF=0")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG -DHIGH_PERF=0")

set(CMAKE_INSTALL_PREFIX /home/mesasoft/sapp_run/)

option(PLATFORM_MODE_SERIAL "Using serial mode" FALSE)

#static link option
option(ENABLE_STATIC_LINK "Enable static link" TRUE)
if(ENABLE_STATIC_LINK)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLINK_MODE_DYNAMIC=0")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DLINK_MODE_DYNAMIC=0")
else()
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLINK_MODE_DYNAMIC=1")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DLINK_MODE_DYNAMIC=1")
endif()

# CPU profiler
option(OPT_USE_PROFILER	"Use gperf cpu profiler" OFF)
if(OPT_USE_PROFILER)
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lprofiler")
endif()

#ASAN option
option(ENABLE_SANITIZE_ADDRESS "Enable AddressSanitizer" FALSE)
option(ENABLE_SANITIZE_THREAD "Enable ThreadSanitizer" FALSE)

if(ENABLE_SANITIZE_ADDRESS)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=address -fno-omit-frame-pointer")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=address -fno-omit-frame-pointer")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
	set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
elseif(ENABLE_SANITIZE_THREAD)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=thread -fno-omit-frame-pointer")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=thread -fno-omit-frame-pointer")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
	set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
endif()


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
	set(MARSIO_SDK_PREFIX "/opt/mrzcpd/" CACHE STRING "MARSIO Prefix")
endif()

#if(CAPTURE_MODE MATCHES "PCAP")
set(CAPTURE_DEFINITIONS -DIOMODE_PCAP)
add_definitions(-DIOMODE_PCAP=1)
#endif()

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
	add_definitions(-DIOMODE_MARSIO=1)
endif()

# Memory Allocator
option(OPT_USE_DICTATOR	"Use Dictator2 memory allocator" OFF)
option(OPT_USE_DICTATOR_DEBUG	"Use Dictator2 memory allocator" OFF)
option(OPT_USE_TCMALLOC "Use TCmalloc memory allocator" OFF)
option(OPT_USE_TCMALLOC_MINI "Use TCmalloc memory allocator" OFF)
option(OPT_USE_JEMALLOC "Use JEmalloc memory allocator" OFF)

if(OPT_USE_DICTATOR_DEBUG)
	set(MEM_POOL_DEFINITIONS -DDICTATOR_DEBUG)
endif()

if(OPT_USE_DICTATOR OR OPT_USE_DICTATOR_DEBUG)
    set(MEM_POOL_DEFINITIONS ${MEM_POOL_DEFINITIONS} -DUSE_MEM_POOL=1
        -DUSE_MEMPOOL)
elseif(OPT_USE_TCMALLOC_MINI)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -ltcmalloc_minimal -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free")
elseif(OPT_USE_TCMALLOC)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -ltcmalloc -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free")
elseif(OPT_USE_JEMALLOC)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -ljemalloc -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free")
endif()

add_definitions(${CAPTURE_DEFINITIONS} ${MEM_POOL_DEFINITIONS} -D__FAVOR_BSD=1
    -D__USE_BSD=1 -D_GNU_SOURCE=1  -DMESA_SAPP_PLATFORM=1)

set(SAPP_DEPEND_DYN_LIB  MESA_handle_logger MESA_htable pthread MESA_field_stat2 cjson)

set(CMAKE_C_FLAGS_RELEASE "-Werror")

file(MD5 ${PROJECT_SOURCE_DIR}/include/public/stream_inc/stream_base.h MD5_STREAM_BASE)
file(MD5 ${PROJECT_SOURCE_DIR}/include/public/stream_inc/stream_control.h MD5_STREAM_CONTROL)
file(MD5 ${PROJECT_SOURCE_DIR}/include/public/stream_inc/stream_entry.h MD5_STREAM_ENTRY)
file(MD5 ${PROJECT_SOURCE_DIR}/include/public/stream_inc/stream_inject.h MD5_STREAM_INJECT)
file(MD5 ${PROJECT_SOURCE_DIR}/include/public/stream_inc/stream_project.h MD5_STREAM_PROJECT)
file(MD5 ${PROJECT_SOURCE_DIR}/include/public/stream_inc/stream_proxy.h MD5_STREAM_PROXY)
file(MD5 ${PROJECT_SOURCE_DIR}/include/public/stream_inc/stream_rawpkt.h MD5_STREAM_RAWPKT)
file(MD5 ${PROJECT_SOURCE_DIR}/include/public/stream_inc/stream_tunnel.h MD5_STREAM_TUNNEL)

add_definitions(${HEADER_CHECK_DEFINITIONS}
				-DSTREAM_BASE_MD5_CHECK="${MD5_STREAM_BASE}"
				-DSTREAM_CONTROL_MD5_CHECK="${MD5_STREAM_CONTROL}"
				-DSTREAM_ENTRY_MD5_CHECK="${MD5_STREAM_ENTRY}"
   			        -DSTREAM_INJECT_MD5_CHECK="${MD5_STREAM_INJECT}"
				-DSTREAM_PROJECT_MD5_CHECK="${MD5_STREAM_PROJECT}"
				-DSTREAM_PROXY_MD5_CHECK="${MD5_STREAM_PROXY}"
				-DSTREAM_RAWPKT_MD5_CHECK="${MD5_STREAM_RAWPKT}"
				-DSTREAM_TUNNEL_MD5_CHECK="${MD5_STREAM_TUNNEL}")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${HEADER_CHECK_DEFINITIONS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${HEADER_CHECK_DEFINITIONS}")

add_subdirectory(./src/support)
add_subdirectory(./src/dealpkt)
add_subdirectory(./src/packet_io)
add_subdirectory(./src/plugin)
add_subdirectory(./src/project)
add_subdirectory(./src/common)
add_subdirectory(./src/config)
add_subdirectory(./src/inner_plug)
add_subdirectory(./src/timer)
add_subdirectory(./src/entry)
add_subdirectory(./test)
add_subdirectory(./test/google_test)

install(PROGRAMS ${CMAKE_BINARY_DIR}/src/entry/sapp DESTINATION .)

install(PROGRAMS bin/r2 DESTINATION .)
install(PROGRAMS bin/r3 DESTINATION .)
#install(PROGRAMS bin/vv.py DESTINATION .)
#install(PROGRAMS bin/pag.conf DESTINATION .)
#install(PROGRAMS bin/memchk.sh DESTINATION .)
#install(FILES bin/conf/gdev_block.conf DESTINATION conf)
#install(FILES bin/conf/gdev.conf DESTINATION conf)
#install(FILES bin/conf/main.conf DESTINATION conf)
#install(FILES bin/conf/project_list.conf DESTINATION conf)
#install(FILES bin/conf/route_table.conf DESTINATION conf)
#install(FILES bin/conf/send_gdev.conf DESTINATION conf)
#install(FILES bin/conf/send_raw_pkt.conf DESTINATION conf)
#install(FILES bin/conf/send_route.conf DESTINATION conf)
#install(FILES bin/conf/streamid.txt DESTINATION conf)
#install(FILES bin/conf/plugin/entrylist.conf DESTINATION conf/plugin)
#install(FILES bin/conf/plugin/plugin.conf DESTINATION conf/plugin)

install(FILES bin/etc/sapp.toml DESTINATION etc)
install(FILES bin/etc/send_raw_pkt.conf DESTINATION etc)
install(FILES bin/etc/project_list.conf DESTINATION etc)
install(FILES bin/etc/plugin.conf DESTINATION etc)
install(FILES bin/etc/entrylist.conf DESTINATION etc)
install(FILES bin/plug/conflist.inf DESTINATION plug)

if(NOT ENABLE_STATIC_LINK)

if(CAPTURE_MODE MATCHES "MARSIO")
	install(FILES ${CMAKE_BINARY_DIR}/src/packet_io/packet_io_marsio.so DESTINATION platform_lib)
endif()

if(CAPTURE_MODE MATCHES "PCAP")
	install(FILES ${CMAKE_BINARY_DIR}/src/packet_io/packet_io_pcap.so DESTINATION platform_lib)
endif()

endif()

#install(FILES bin/plug/protocol/conflist_protocol.inf DESTINATION plug/protocol)

install(FILES bin/plug/protocol/isakmp_protocol_plug/isakmp_protocol_plug.inf DESTINATION plug/protocol/isakmp_protocol_plug)
install(FILES ${CMAKE_BINARY_DIR}/src/inner_plug/isakmp_protocol_plug.so DESTINATION plug/protocol/isakmp_protocol_plug)

install(FILES bin/plug/protocol/l2tp_protocol_plug/l2tp_protocol_plug.inf DESTINATION plug/protocol/l2tp_protocol_plug)
install(FILES ${CMAKE_BINARY_DIR}/src/inner_plug/l2tp_protocol_plug.so DESTINATION plug/protocol/l2tp_protocol_plug)

install(FILES bin/plug/protocol/pptp_protocol_plug/pptp_protocol_plug.inf DESTINATION plug/protocol/pptp_protocol_plug)
install(FILES ${CMAKE_BINARY_DIR}/src/inner_plug/pptp_protocol_plug.so DESTINATION plug/protocol/pptp_protocol_plug)


#install(FILES bin/plug/platform/conflist_platform.inf DESTINATION plug/platform)

if(PLATFORM_MODE_SERIAL)
    install(FILES bin/plug/platform/g_device_plug/g_device_plug.inf DESTINATION plug/platform/g_device_plug)
    install(FILES ${CMAKE_BINARY_DIR}/src/inner_plug/g_device_plug.so DESTINATION plug/platform/g_device_plug)
endif()


install(FILES bin/plug/business/test_app/test_app.inf DESTINATION plug/business/test_app)
install(FILES ${CMAKE_BINARY_DIR}/test/test_app_sapp.so DESTINATION plug/business/test_app)

install(PROGRAMS ${CMAKE_BINARY_DIR}/test/google_test/gtest_sapp_v4 DESTINATION .)
install(FILES ${CMAKE_BINARY_DIR}/test/google_test/libgtest_sapp.so DESTINATION plug/business/gtest_sapp)
install(FILES bin/plug/business/gtest_sapp/gtest_sapp.inf  DESTINATION plug/business/gtest_sapp)


include(Package)
