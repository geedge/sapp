
cmake_minimum_required(VERSION 2.8)

set(project_name sapp)

project(${project_name})


set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
include(Version)

set(CMAKE_MACOSX_RPATH 0)

set(CMAKE_BUILD_TYPE "DEBUG" CACHE STRING
    " set CMAKE_BUILD_TYPE chosen by the user, using DEBUG as default")
set_property(CACHE CMAKE_BUILD_TYPE  PROPERTY STRINGS DEBUG RELEASE
    RELWITHDEBINFO MINSIZEREL)


set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLINK_MODE_DYNAMIC=1")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DLINK_MODE_DYNAMIC=1")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DDEBUG")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DDEBUG")
endif()

set(CMAKE_INSTALL_PREFIX /home/mesasoft/sapp_run/)


set(PLATFORM_MODE "INLINE" CACHE STRING
    " set platform mode chosen by the user, using mirror as default")
set_property(CACHE PLATFORM_MODE PROPERTY STRINGS MIRROR INLINE)
message(STATUS "PLATFORM_MODE='${PLATFORM_MODE}'")

#static link option
option(ENABLE_STATIC_LINK "Enable static link" TRUE)

# CPU profiler
set(CPU_PROFILE "OFF" CACHE STRING
    " set cpu profiler chosen by the user, using OFF as default")
set_property(CACHE CPU_PROFILE  PROPERTY STRINGS OFF GPERF GPROF)
message(STATUS "CPU_PROFILE='${CPU_PROFILE}'")
if(CPU_PROFILE MATCHES "GPERF")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lprofiler")
elseif(CPU_PROFILE MATCHES "GPROF")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lpg")
endif()

#ASAN option
set(ASAN_OPTION "OFF" CACHE STRING
    " set asan type chosen by the user, using OFF as default")
set_property(CACHE ASAN_OPTION  PROPERTY STRINGS OFF ADDRESS THREAD)
message(STATUS "ASAN_OPTION='${ASAN_OPTION}'")

if(ASAN_OPTION MATCHES "ADDRESS")
    set(CMAKE_C_FLAGS "${CMAKADDRESS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=address -fno-omit-frame-pointer")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=address -fno-omit-frame-pointer")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
	set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
elseif(ASAN_OPTION MATCHES "THREAD")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=thread -fno-omit-frame-pointer")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=thread -fno-omit-frame-pointer")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
	set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
endif()



# MESA SDK Root
set(MESA_SDK_PREFIX "/opt/MESA/" CACHE STRING "MESA Framework Prefix")

# Capture Mode
set(CAPTURE_MODE "PCAP" CACHE STRING
    "CAPTURE_MODE set Capture network traffic chosen by the user, using PCAP as default")

set_property(CACHE CAPTURE_MODE PROPERTY STRINGS PCAP MARSIO PAG)

message(STATUS "CAPTURE_MODE='${CAPTURE_MODE}'")

if(CAPTURE_MODE MATCHES "PCAP")
    set(CAPTURE_DEFINITIONS -DONLY_PCAP -DIOMODE_PCAP)
endif()

if(CAPTURE_MODE MATCHES "PAG")
	set(CAPTURE_DEFINITIONS -DCAPTURE_MODE_PAG)
endif()


if(CAPTURE_MODE MATCHES "MARSIO")
	set(MARSIO_SDK_PREFIX "/opt/mrzcpd/" CACHE STRING "MARSIO Prefix")
    set(CAPTURE_DEFINITIONS -DCAPTURE_MODE_MARSIO -DIOMODE_MARSIO)
endif()

# Memory Allocator
set(MEM_POOL "OFF" CACHE STRING
    " set mem alloc chosen by the user, using off as default")
set_property(CACHE MEM_POOL PROPERTY STRINGS OFF DICTATOR DICTATOR_DEBUG
    TCMALLOC TCMALLOC_MINI JEMALLOC)
message(STATUS "MEM_POOL='${MEM_POOL}'")

if(MEM_POOL MATCHES "DICTATOR")
	set(MEM_POOL_DEFINITIONS -DDICTATOR_DEBUG)

elseif(MEM_POOL MATCHES "DICTATOR_DEBUG")
    set(MEM_POOL_DEFINITIONS ${MEM_POOL_DEFINITIONS} -DUSE_MEM_POOL=1
        -DUSE_MEMPOOL)
elseif(MEM_POOL MATCHES "TCMALLOC_MINI")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -ltcmalloc_minimal -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free")
elseif(MEM_POOL MATCHES "TCMALLOC")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -ltcmalloc -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free")
elseif(MEM_POOL MATCHES "JEMALLOC")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -ljemalloc -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free")
endif()

add_definitions(${CAPTURE_DEFINITIONS} ${MEM_POOL_DEFINITIONS} -D__FAVOR_BSD=1
    -D__USE_BSD=1 -D_GNU_SOURCE=1  -DMESA_SAPP_PLATFORM=1)

set(SAPP_DEPEND_DYN_LIB  MESA_handle_logger MESA_htable pthread MESA_field_stat2 cjson)

set(CMAKE_C_FLAGS_RELEASE "-Werror")

file(MD5 ${PROJECT_SOURCE_DIR}/include/stream_inc/stream_base.h MD5_STREAM_BASE)
file(MD5 ${PROJECT_SOURCE_DIR}/include/stream_inc/stream_control.h MD5_STREAM_CONTROL)
file(MD5 ${PROJECT_SOURCE_DIR}/include/stream_inc/stream_entry.h MD5_STREAM_ENTRY)
file(MD5 ${PROJECT_SOURCE_DIR}/include/stream_inc/stream_inject.h MD5_STREAM_INJECT)
file(MD5 ${PROJECT_SOURCE_DIR}/include/stream_inc/stream_project.h MD5_STREAM_PROJECT)
file(MD5 ${PROJECT_SOURCE_DIR}/include/stream_inc/stream_proxy.h MD5_STREAM_PROXY)
file(MD5 ${PROJECT_SOURCE_DIR}/include/stream_inc/stream_rawpkt.h MD5_STREAM_RAWPKT)
file(MD5 ${PROJECT_SOURCE_DIR}/include/stream_inc/stream_tunnel.h MD5_STREAM_TUNNEL)

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

add_subdirectory(test_so)
add_subdirectory(support)
add_subdirectory(dealpkt)
add_subdirectory(packet_io)
add_subdirectory(plugin)
add_subdirectory(project)
add_subdirectory(inner_plug)
add_subdirectory(entry)

install(PROGRAMS ${CMAKE_BINARY_DIR}/entry/sapp DESTINATION .)

install(PROGRAMS run/r2 DESTINATION .)
install(PROGRAMS run/r3 DESTINATION .)
#install(PROGRAMS run/vv.py DESTINATION .)
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
install(FILES run/conf/vxlan_sport_service_map.conf DESTINATION conf)

if(CAPTURE_MODE MATCHES "MARSIO")
	install(FILES ${CMAKE_BINARY_DIR}/packet_io/packet_io_marsio.so DESTINATION platform_lib)
endif()

#if(CAPTURE_MODE MATCHES "PCAP")
	install(FILES ${CMAKE_BINARY_DIR}/packet_io/packet_io_pcap.so DESTINATION platform_lib)
#endif()

install(FILES run/plug/protocol/conflist_protocol.inf DESTINATION plug/protocol)

if(PLATFORM_MODE MATCHES "MIRROR")
	install(FILES run/plug/protocol/isakmp_protocol_plug/isakmp_protocol_plug.inf DESTINATION plug/protocol/isakmp_protocol_plug)
	install(FILES ${CMAKE_BINARY_DIR}/inner_plug/isakmp_protocol_plug.so DESTINATION plug/protocol/isakmp_protocol_plug)

	install(FILES run/plug/protocol/l2tp_protocol_plug/l2tp_protocol_plug.inf DESTINATION plug/protocol/l2tp_protocol_plug)
	install(FILES ${CMAKE_BINARY_DIR}/inner_plug/l2tp_protocol_plug.so DESTINATION plug/protocol/l2tp_protocol_plug)

	install(FILES run/plug/protocol/pptp_protocol_plug/pptp_protocol_plug.inf DESTINATION plug/protocol/pptp_protocol_plug)
	install(FILES ${CMAKE_BINARY_DIR}/inner_plug/pptp_protocol_plug.so DESTINATION plug/protocol/pptp_protocol_plug)
endif()

install(FILES run/plug/platform/conflist_platform.inf DESTINATION plug/platform)

if(PLATFORM_MODE MATCHES "INLINE")
    install(FILES run/plug/platform/g_device_plug/g_device_plug.inf DESTINATION plug/platform/g_device_plug)
    install(FILES ${CMAKE_BINARY_DIR}/inner_plug/g_device_plug.so DESTINATION plug/platform/g_device_plug)
endif()

install(FILES run/plug/business/conflist_business.inf DESTINATION plug/business)

install(FILES run/plug/business/conflist_business.inf DESTINATION plug/business)
install(FILES run/plug/business/test_app/test_app.inf DESTINATION plug/business/test_app)
install(FILES ${CMAKE_BINARY_DIR}/test_so/test_app_sapp.so DESTINATION plug/business/test_app)
install(FILES ${CMAKE_BINARY_DIR}/test_so/trace_delay.so DESTINATION plug/business/test_app)


include(Package)
