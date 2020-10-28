cmake_minimum_required(VERSION 2.8)

set(project_name sapp)

project(${project_name})

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
include(Version)

set(CMAKE_MACOSX_RPATH 0)

# see here: https://github.com/PointCloudLibrary/pcl/issues/3680
# when this is fixed, we can remove the following 3 lines.
if(NOT DEFINED CMAKE_SUPPRESS_DEVELOPER_WARNINGS)
     set(CMAKE_SUPPRESS_DEVELOPER_WARNINGS 1 CACHE INTERNAL "No dev warnings")
endif()
find_package(SYSTEMD REQUIRED)

set(CMAKE_BUILD_TYPE "DEBUG" CACHE STRING
    " set CMAKE_BUILD_TYPE chosen by the user, using DEBUG as default")
set_property(CACHE CMAKE_BUILD_TYPE  PROPERTY STRINGS DEBUG RELEASE
    RELWITHDEBINFO MINSIZEREL)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DDEBUG")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DDEBUG")
endif()

set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Werror -O2 -DNDEBUG -DHIGH_PERF=1")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Werror -O2 -DNDEBUG -DHIGH_PERF=1")


set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG -DHIGH_PERF=0")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG -DHIGH_PERF=0")

set(CMAKE_INSTALL_PREFIX /home/mesasoft/sapp_run)

set(PLATFORM_MODE "MIRROR" CACHE STRING
    " set platform mode chosen by the user, using mirror as default")
set_property(CACHE PLATFORM_MODE PROPERTY STRINGS MIRROR INLINE)
message(STATUS "PLATFORM_MODE='${PLATFORM_MODE}'")


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

set_property(CACHE CAPTURE_MODE PROPERTY STRINGS PCAP MARSIO PAG TUN)

message(STATUS "CAPTURE_MODE='${CAPTURE_MODE}'")

set(CAPTURE_DEFINITIONS -DIOMODE_PCAP)
add_definitions(-DIOMODE_PCAP=1)

#if(CAPTURE_MODE MATCHES "PCAP")
#    set(CAPTURE_DEFINITIONS -DONLY_PCAP -DIOMODE_PCAP)
#endif()

if(CAPTURE_MODE MATCHES "PAG")
	set(CAPTURE_DEFINITIONS -DCAPTURE_MODE_PAG)
endif()

if(CAPTURE_MODE MATCHES "MARSIO")
	set(CAPTURE_DEFINITIONS -DCAPTURE_MODE_MARSIO -DIOMODE_MARSIO)
	add_definitions(-DIOMODE_MARSIO=1)
endif()

if(CAPTURE_MODE MATCHES "TUN")
	set(CAPTURE_DEFINITIONS -DCAPTURE_MODE_TUN)
	add_definitions(-DIOMODE_TUN=1)
endif()

# Memory Allocator
set(MEM_POOL "OFF" CACHE STRING
    " set mem alloc chosen by the user, using off as default")
set_property(CACHE MEM_POOL PROPERTY STRINGS OFF DICTATOR DICTATOR_DEBUG
    TCMALLOC TCMALLOC_MINI JEMALLOC)
message(STATUS "MEM_POOL='${MEM_POOL}'")

if(MEM_POOL MATCHES "DICTATOR_DEBUG")
	set(MEM_POOL_DEFINITIONS ${MEM_POOL_DEFINITIONS} -DDICTATOR_DEBUG -DUSE_MEMPOOL=1)
elseif(MEM_POOL MATCHES "DICTATOR")
    set(MEM_POOL_DEFINITIONS ${MEM_POOL_DEFINITIONS} -DUSE_MEMPOOL=1)
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

#for sapp_module_test
option(SAPP_V4 "test for sapp v4.0" TRUE)

add_subdirectory(./vendor)
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
add_subdirectory(./service)
add_subdirectory(./tools)

#by default, not include sapp_module_test dir
#add_subdirectory(./test/sapp_module_test/src)


set(CMAKE_INSTALL_FULL_LIBEXECDIR ${CMAKE_INSTALL_PREFIX})
set(CMAKE_INSTALL_FULL_SHAREDSTATEDIR ${CMAKE_INSTALL_PREFIX}/etc)
#set(CMAKE_INSTALL_FULL_LIBDIR ${CMAKE_INSTALL_PREFIX}/plug)
set(CMAKE_INSTALL_FULL_DATAROOTDIR ${CMAKE_INSTALL_PREFIX}/plug)
set(CMAKE_INSTALL_FULL_SYSCONFDIR /usr/lib/systemd/system)

#install(PROGRAMS ${CMAKE_BINARY_DIR}/src/entry/sapp DESTINATION . COMPONENT EXECUTABLE)
install(PROGRAMS ${CMAKE_BINARY_DIR}/src/entry/sapp DESTINATION . COMPONENT EXECUTABLE)

install(PROGRAMS bin/r2 DESTINATION . COMPONENT EXECUTABLE)
install(PROGRAMS bin/r3 DESTINATION . COMPONENT EXECUTABLE)


install(FILES bin/etc/sapp.toml DESTINATION etc COMPONENT PROFILE)
install(FILES bin/etc/send_raw_pkt.conf DESTINATION etc COMPONENT PROFILE)
install(FILES bin/etc/project_list.conf DESTINATION etc COMPONENT PROFILE)
install(FILES bin/etc/plugin.conf DESTINATION etc COMPONENT PROFILE)
install(FILES bin/etc/entrylist.conf DESTINATION etc COMPONENT PROFILE)
install(FILES bin/etc/gdev.conf DESTINATION etc COMPONENT PROFILE)
install(FILES bin/etc/gdev_block.conf DESTINATION etc COMPONENT PROFILE)
install(FILES bin/plug/conflist.inf DESTINATION plug COMPONENT PROFILE)
install(FILES bin/etc/send_gdev.conf DESTINATION etc COMPONENT PROFILE)
install(FILES bin/etc/send_route.conf DESTINATION etc COMPONENT PROFILE)
install(FILES bin/etc/sapp_log.conf DESTINATION etc COMPONENT PROFILE)
install(FILES bin/etc/asymmetric_addr_layer.conf DESTINATION etc COMPONENT PROFILE)
install(FILES bin/etc/asymmetric_presence_layer.conf DESTINATION etc COMPONENT PROFILE)
install(FILES bin/etc/vlan_flipping_map.conf DESTINATION etc COMPONENT PROFILE)
install(FILES bin/etc/stream_compare_layer.conf DESTINATION etc COMPONENT PROFILE)

if(NOT ENABLE_STATIC_LINK)

if(CAPTURE_MODE MATCHES "MARSIO")
	install(FILES ${CMAKE_BINARY_DIR}/src/packet_io/packet_io_marsio.so DESTINATION platform_lib COMPONENT LIBRARY)
endif()

if(CAPTURE_MODE MATCHES "PCAP")
	install(FILES ${CMAKE_BINARY_DIR}/src/packet_io/packet_io_pcap.so DESTINATION platform_lib COMPONENT LIBRARY)
endif()

if(CAPTURE_MODE MATCHES "TUN")
	install(FILES ${CMAKE_BINARY_DIR}/src/packet_io/packet_io_tun.so DESTINATION platform_lib COMPONENT LIBRARY)
endif()

endif()

#install(FILES bin/plug/protocol/conflist_protocol.inf DESTINATION plug/protocol COMPONENT PROFILE)

install(FILES bin/plug/protocol/isakmp_protocol_plug/isakmp_protocol_plug.inf DESTINATION plug/protocol/isakmp_protocol_plug COMPONENT PROFILE)
install(FILES ${CMAKE_BINARY_DIR}/src/inner_plug/isakmp_protocol_plug.so DESTINATION plug/protocol/isakmp_protocol_plug COMPONENT LIBRARY)

install(FILES bin/plug/protocol/l2tp_protocol_plug/l2tp_protocol_plug.inf DESTINATION plug/protocol/l2tp_protocol_plug COMPONENT PROFILE)
install(FILES ${CMAKE_BINARY_DIR}/src/inner_plug/l2tp_protocol_plug.so DESTINATION plug/protocol/l2tp_protocol_plug COMPONENT LIBRARY)

install(FILES bin/plug/protocol/pptp_protocol_plug/pptp_protocol_plug.inf DESTINATION plug/protocol/pptp_protocol_plug COMPONENT PROFILE)
install(FILES ${CMAKE_BINARY_DIR}/src/inner_plug/pptp_protocol_plug.so DESTINATION plug/protocol/pptp_protocol_plug COMPONENT LIBRARY)


#install(FILES bin/plug/platform/conflist_platform.inf DESTINATION plug/platform COMPONENT PROFILE)

if(PLATFORM_MODE MATCHES "INLINE")
    install(FILES bin/plug/platform/g_device_plug/g_device_plug.inf DESTINATION plug/platform/g_device_plug COMPONENT PROFILE)
    install(FILES ${CMAKE_BINARY_DIR}/src/inner_plug/g_device_plug.so DESTINATION plug/platform/g_device_plug COMPONENT LIBRARY)
endif()


install(FILES bin/plug/business/test_app/test_app.inf DESTINATION plug/business/test_app COMPONENT PROFILE)
install(FILES ${CMAKE_BINARY_DIR}/test/test_app_sapp.so DESTINATION plug/business/test_app COMPONENT LIBRARY)

install(PROGRAMS ${CMAKE_BINARY_DIR}/tools/stream_id_decode DESTINATION ./tools/ COMPONENT EXECUTABLE)

install(FILES ${PROJECT_SOURCE_DIR}/include/public/stream.h DESTINATION /opt/MESA/include/MESA/ COMPONENT HEADER)
install(FILES ${PROJECT_SOURCE_DIR}/include/public/stream_inc/stream_base.h DESTINATION /opt/MESA/include/MESA/stream_inc COMPONENT HEADER)
install(FILES  ${PROJECT_SOURCE_DIR}/include/public/stream_inc/stream_control.h DESTINATION  /opt/MESA/include/MESA/stream_inc COMPONENT HEADER)
install(FILES ${PROJECT_SOURCE_DIR}/include/public/stream_inc/stream_entry.h DESTINATION  /opt/MESA/include/MESA/stream_inc COMPONENT HEADER)
install(FILES ${PROJECT_SOURCE_DIR}/include/public/stream_inc/stream_inject.h DESTINATION  /opt/MESA/include/MESA/stream_inc COMPONENT HEADER)
install(FILES ${PROJECT_SOURCE_DIR}/include/public/stream_inc/stream_project.h DESTINATION  /opt/MESA/include/MESA/stream_inc COMPONENT HEADER)
install(FILES ${PROJECT_SOURCE_DIR}/include/public/stream_inc/stream_proxy.h DESTINATION  /opt/MESA/include/MESA/stream_inc COMPONENT HEADER)
install(FILES ${PROJECT_SOURCE_DIR}/include/public/stream_inc/stream_rawpkt.h DESTINATION  /opt/MESA/include/MESA/stream_inc COMPONENT HEADER)
install(FILES ${PROJECT_SOURCE_DIR}/include/public/stream_inc/stream_tunnel.h DESTINATION  /opt/MESA/include/MESA/stream_inc COMPONENT HEADER)
install(FILES ${PROJECT_SOURCE_DIR}/include/public/stream_inc/sapp_inject.h DESTINATION  /opt/MESA/include/MESA/stream_inc COMPONENT HEADER)

install(FILES ${CMAKE_BINARY_DIR}/service/sapp.service DESTINATION /usr/lib/systemd/system/ COMPONENT PROFILE)

include(Package)
