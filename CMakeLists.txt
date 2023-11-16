cmake_minimum_required(VERSION 2.8...3.10)

set(project_name sapp)

project(${project_name})

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
include(Version)

set(CMAKE_MACOSX_RPATH 0)
set(CMAKE_EXPORT_COMPILECOMMANDS ON)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)
# see here: https://github.com/PointCloudLibrary/pcl/issues/3680
# when this is fixed, we can remove the following 3 lines.
if(NOT DEFINED CMAKE_SUPPRESS_DEVELOPER_WARNINGS)
     set(CMAKE_SUPPRESS_DEVELOPER_WARNINGS 1 CACHE INTERNAL "No dev warnings")
endif()
find_package(SYSTEMD REQUIRED)

#add_compile_options(-march=znver2)

execute_process(COMMAND nproc OUTPUT_VARIABLE CPU_COUNT)
string(STRIP ${CPU_COUNT} CPU_COUNT) # remove trailing newline
message(STATUS "Detected ${CPU_COUNT} CPU cores")
if (CPU_COUNT GREATER 16)
    set(CPU_COUNT 16)
endif()
message(STATUS "Using ${CPU_COUNT} CPU cores")


find_program(CMAKE_CXX_CPPCHECK NAMES cppcheck)
if (CMAKE_CXX_CPPCHECK)
    list(
        APPEND CMAKE_CXX_CPPCHECK 
            "--enable=all"
            "--error-exitcode=1"
			"--std=c++11"
            "--suppress=unusedFunction"
            "--suppress=missingInclude"
            "--suppress=uselessAssignmentPtrArg"
            "--suppress=unmatchedSuppression"
            "--suppress=variableScope"
            "--suppress=unreadVariable"
            "--suppress=cstyleCast"
            "--suppress=memleakOnRealloc"
            "--suppress=constParameter"
            "--suppress=uselessAssignmentArg"
            "--suppress=uninitvar"
            "--suppress=unusedStructMember"
    )
    set(CMAKE_C_CPPCHECK ${CMAKE_CXX_CPPCHECK})
else()
  message(FATAL_ERROR "Could not find the program cppcheck.")
endif()


set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING
    " set CMAKE_BUILD_TYPE chosen by the user, using DEBUG as default")
set_property(CACHE CMAKE_BUILD_TYPE  PROPERTY STRINGS Debug Release
RelWithDebInfo MinSizeRel)

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -rdynamic")

set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Werror -O3 -DNDEBUG -DHIGH_PERF=1")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Werror -O3 -DNDEBUG -DHIGH_PERF=1")

set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} -O3")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} -O3")

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG -DHIGH_PERF=0")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG -DHIGH_PERF=0")

set(CMAKE_INSTALL_PREFIX /home/mesasoft/sapp_run)

set(PLATFORM_MODE "INLINE" CACHE STRING
    " set platform mode chosen by the user, using INLINE as default")
set_property(CACHE PLATFORM_MODE PROPERTY STRINGS MIRROR INLINE)
message(STATUS "PLATFORM_MODE='${PLATFORM_MODE}'")



#static link option
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLINK_MODE_DYNAMIC=0")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DLINK_MODE_DYNAMIC=0")

# CPU profiler
set(CPU_PROFILE "OFF" CACHE STRING
    " set cpu profiler chosen by the user, using OFF as default")
set_property(CACHE CPU_PROFILE  PROPERTY STRINGS OFF GPERF GPROF)
message(STATUS "CPU_PROFILE='${CPU_PROFILE}'")
if(CPU_PROFILE STREQUAL "GPERF")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lprofiler")
elseif(CPU_PROFILE STREQUAL "GPROF")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lpg")
endif()

#ASAN option
set(ASAN_OPTION "OFF" CACHE STRING
    " set asan type chosen by the user, using OFF as default")
set_property(CACHE ASAN_OPTION  PROPERTY STRINGS OFF ADDRESS THREAD)
message(STATUS "ASAN_OPTION='${ASAN_OPTION}'")

if(ASAN_OPTION STREQUAL "ADDRESS")
    set(CMAKE_C_FLAGS "${CMAKADDRESS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=address -fno-omit-frame-pointer")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=address -fno-omit-frame-pointer")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
	set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
	add_definitions(-DASAN_ENABLED=1)
elseif(ASAN_OPTION STREQUAL "THREAD")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=thread -fno-omit-frame-pointer")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=thread -fno-omit-frame-pointer")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
	set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
	add_definitions(-DASAN_ENABLED=1)
endif()




# MESA SDK Root
set(MESA_SDK_PREFIX "/opt/MESA/" CACHE STRING "MESA Framework Prefix")
# Capture Mode
set(CAPTURE_MODE "MARSIO" CACHE STRING
    "CAPTURE_MODE set Capture network traffic chosen by the user, using MARSIO as default")

set_property(CACHE CAPTURE_MODE PROPERTY STRINGS PCAP MARSIO PAG TUN)

message(STATUS "CAPTURE_MODE='${CAPTURE_MODE}'")

set(CAPTURE_DEFINITIONS -DIOMODE_PCAP)
add_definitions(-DIOMODE_PCAP=1)

#if(CAPTURE_MODE STREQUAL "PCAP")
#    set(CAPTURE_DEFINITIONS -DONLY_PCAP -DIOMODE_PCAP)
#endif()

set(DIST_MODE "JHASH" CACHE STRING
    "DIST_MODE set Tuple4 hash algorithm chosen by the user, using JHASH in linux kernel as default")
set_property(CACHE DIST_MODE PROPERTY STRINGS JHASH CRCHASH)
message(STATUS "DIST_MODE='${DIST_MODE}'")
if(DIST_MODE STREQUAL "JHASH")
	add_definitions(-DUSE_LINUX_KERNEL_HASH_ALGO=1)
else()
	add_definitions(-DUSE_LINUX_KERNEL_HASH_ALGO=0)
endif()

if(CAPTURE_MODE STREQUAL "PAG")
	set(CAPTURE_DEFINITIONS -DCAPTURE_MODE_PAG)
endif()

if(CAPTURE_MODE STREQUAL "MARSIO")
	set(CAPTURE_DEFINITIONS -DCAPTURE_MODE_MARSIO -DIOMODE_MARSIO)
	add_definitions(-DIOMODE_MARSIO=1)
endif()

if(CAPTURE_MODE STREQUAL "TUN")
	set(CAPTURE_DEFINITIONS -DCAPTURE_MODE_TUN)
	add_definitions(-DIOMODE_TUN=1)
endif()

# Memory Allocator
set(MEM_POOL "JEMALLOC_STATIC" CACHE STRING
    " set mem alloc chosen by the user, using JEMALLOC as default")
set_property(CACHE MEM_POOL PROPERTY STRINGS OFF 
    TCMALLOC TCMALLOC_MINI JEMALLOC JEMALLOC_STATIC MIMALLOC)
message(STATUS "MEM_POOL='${MEM_POOL}'")

if(MEM_POOL STREQUAL "TCMALLOC_MINI")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -ltcmalloc_minimal -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free")
	add_definitions(-DUSE_TCMALLOC=1)	
elseif(MEM_POOL STREQUAL "TCMALLOC")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -ltcmalloc -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free")
	add_definitions(-DUSE_TCMALLOC=1)	
elseif(MEM_POOL STREQUAL "JEMALLOC")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -ljemalloc -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free")
	add_definitions(-DUSE_JEMALLOC=1)	
elseif(MEM_POOL STREQUAL "JEMALLOC_STATIC")
	add_definitions(-DUSE_JEMALLOC=1)	
elseif(MEM_POOL STREQUAL "MIMALLOC")
	add_definitions(-DUSE_MIMALLOC=1)		
endif()

# 定义宏 LIBEVENT_ENABLED
option(LIBEVENT_ENABLED "Enable libevent" OFF)
if(LIBEVENT_ENABLED STREQUAL "ON")
	add_definitions(-DLIBEVENT_ENABLED=1)	
endif()

option(HASP_ENABLED "Enable hasp envelope" OFF)
if(HASP_ENABLED STREQUAL "ON")
	add_definitions(-DHASP_ENABLED=1)	
	set(project_name sapp-pr)
endif()

add_definitions(${CAPTURE_DEFINITIONS} ${MEM_POOL_DEFINITIONS} -D__FAVOR_BSD=1
    -D__USE_BSD=1 -D_GNU_SOURCE=1  -DMESA_SAPP_PLATFORM=1)

set(SAPP_DEPEND_DYN_LIB MESA_handle_logger MESA_prof_load MESA_htable  MESA_field_stat2 fieldstat3 cjson MESA_jump_layer breakpad_mini ${SYSTEMD_LIBRARIES} pthread dl pcap)
set(SAPP_INNER_STATIC_LIB sapp_dev dealpkt packet_io  packet_io_pcap packet_io_marsio common 
			config inline_keepalive gdev_assistant sapp_assistant sapp_metrics plugctrl project timer
			md5 symbol_check tomlc99_wrap MESA_socket_wrap timestamp_record  
			MESA_sleep dpdk_ip_hash  cpu_limit timeout libdabloom)

if(LIBEVENT_ENABLED)
    set(SAPP_INNER_STATIC_LIB ${SAPP_INNER_STATIC_LIB} libevent-static)
endif()

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
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

add_subdirectory(./vendor)
add_subdirectory(./src/support)
add_subdirectory(./src/dealpkt)
add_subdirectory(./src/packet_io)
add_subdirectory(./src/plugin)
add_subdirectory(./src/project)
add_subdirectory(./src/common)
add_subdirectory(./src/config)
add_subdirectory(./src/extensions)
add_subdirectory(./src/timer)
add_subdirectory(./src/sapp_dev)
add_subdirectory(./src/entry)
add_subdirectory(./test)
add_subdirectory(./service)
add_subdirectory(./tools)

option(BUILD_TEST "Enable test build" ON)
if(BUILD_TEST STREQUAL "ON")
#for sapp_module_test
add_subdirectory(./benchmark)
add_subdirectory(./module_test)

enable_testing()
add_subdirectory(./ctest)
endif()
#by default, not include sapp_module_test dir
#add_subdirectory(./test/sapp_module_test/src)


set(CMAKE_INSTALL_FULL_LIBEXECDIR ${CMAKE_INSTALL_PREFIX})
set(CMAKE_INSTALL_FULL_SHAREDSTATEDIR ${CMAKE_INSTALL_PREFIX}/etc)
#set(CMAKE_INSTALL_FULL_LIBDIR ${CMAKE_INSTALL_PREFIX}/plug)
set(CMAKE_INSTALL_FULL_DATAROOTDIR ${CMAKE_INSTALL_PREFIX}/plug)
set(CMAKE_INSTALL_FULL_SYSCONFDIR /usr/lib/systemd/system)

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
install(FILES bin/etc/vlan_flipping_map.conf DESTINATION etc COMPONENT PROFILE)
install(FILES bin/etc/stream_compare_layer.conf DESTINATION etc COMPONENT PROFILE)
install(FILES bin/etc/necessary_plug_list.conf DESTINATION etc COMPONENT PROFILE)
install(FILES bin/etc/well_known_port.conf DESTINATION etc COMPONENT PROFILE)
install(FILES bin/etc/vxlan_sport_service_map.conf DESTINATION etc COMPONENT PROFILE)


install(FILES bin/plug/protocol/isakmp_protocol_plug/isakmp_protocol_plug.inf DESTINATION plug/protocol/isakmp_protocol_plug COMPONENT PROFILE)
install(FILES ${CMAKE_BINARY_DIR}/src/extensions/isakmp_protocol_plug.so DESTINATION plug/protocol/isakmp_protocol_plug COMPONENT LIBRARY)

install(FILES bin/plug/protocol/l2tp_protocol_plug/l2tp_protocol_plug.inf DESTINATION plug/protocol/l2tp_protocol_plug COMPONENT PROFILE)
install(FILES ${CMAKE_BINARY_DIR}/src/extensions/l2tp_protocol_plug.so DESTINATION plug/protocol/l2tp_protocol_plug COMPONENT LIBRARY)

install(FILES bin/plug/protocol/pptp_protocol_plug/pptp_protocol_plug.inf DESTINATION plug/protocol/pptp_protocol_plug COMPONENT PROFILE)
install(FILES ${CMAKE_BINARY_DIR}/src/extensions/pptp_protocol_plug.so DESTINATION plug/protocol/pptp_protocol_plug COMPONENT LIBRARY)


install(FILES bin/plug/business/test_app/test_app.inf DESTINATION plug/business/test_app COMPONENT PROFILE)
install(FILES ${CMAKE_BINARY_DIR}/test/test_app_sapp.so DESTINATION plug/business/test_app COMPONENT LIBRARY)

install(PROGRAMS ${CMAKE_BINARY_DIR}/tools/stream_id_decode DESTINATION ./tools/ COMPONENT EXECUTABLE)
install(PROGRAMS ${CMAKE_BINARY_DIR}/module_test/plugin_test_main/plugin_test_main DESTINATION ./tools/ COMPONENT EXECUTABLE)

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
install(FILES ${PROJECT_SOURCE_DIR}/include/public/stream_inc/stream_bridge.h DESTINATION  /opt/MESA/include/MESA/stream_inc COMPONENT HEADER)
install(FILES ${PROJECT_SOURCE_DIR}/include/public/stream_inc/gdev_keepalive.h DESTINATION  /opt/MESA/include/MESA/stream_inc COMPONENT HEADER)

install(FILES ${CMAKE_BINARY_DIR}/test/libsapp_devel.so DESTINATION ${CMAKE_INSTALL_PREFIX}/lib COMPONENT HEADER)
install(FILES ${CMAKE_BINARY_DIR}/service/sapp.service DESTINATION /usr/lib/systemd/system/ COMPONENT PROFILE)

include(Package)
