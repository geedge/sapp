cmake_minimum_required(VERSION 2.8...3.10)

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/include/private)
include_directories(${CMAKE_SOURCE_DIR}/include/public)
include_directories(${CMAKE_SOURCE_DIR}/include/support)
include_directories(${MESA_SDK_PREFIX}/include)
include_directories(${MESA_SDK_PREFIX}/include/MESA)

add_definitions(-fPIC)

LINK_DIRECTORIES(/opt/MESA/lib)
LINK_DIRECTORIES(${CMAKE_SOURCE_DIR}/src/lib)

if(CAPTURE_MODE STREQUAL "MARSIO")
	LINK_DIRECTORIES(/opt/mrzcpd/lib)
endif()



if(HASP_ENABLED)
	include_directories(/opt/tsg/hasp-tools/include/)
endif()



add_executable(sapp sapp_main.c)
target_compile_options(sapp PUBLIC ${MEM_POOL_DEFINITIONS})
target_link_libraries(sapp nsl pthread dl m pcap)
target_link_libraries(sapp MESA_handle_logger MESA_prof_load)
target_link_libraries(sapp sapp_assistant sapp_metrics)
target_link_libraries(sapp breakpad_mini)
target_include_directories(sapp PRIVATE ${SYSTEMD_INCLUDE_DIRS})

if(HASP_ENABLED STREQUAL "ON")
	find_library(HASP_TOOLS_LIB NAMES hasp-tools PATHS /opt/tsg/hasp-tools/lib)
	target_link_libraries(sapp ${HASP_TOOLS_LIB})
endif()

set(SAPP_MODULES timestamp_record md5 
	symbol_check MESA_sleep MESA_socket_wrap 
	packet_io dealpkt project plugctrl common 
	config timer tomlc99_wrap dpdk_ip_hash  
	gdev_assistant inline_keepalive libdabloom-static 
	sapp_dev sapp_assistant sapp_metrics cpu_limit timeout)

if(LIBEVENT_ENABLED STREQUAL "ON")
	set(SAPP_MODULES ${SAPP_MODULES} libevent-static)
endif()

if(MEM_POOL STREQUAL "JEMALLOC_STATIC")
	set(SAPP_MODULES ${SAPP_MODULES} libjemalloc-static)
endif()

if(MEM_POOL STREQUAL "MIMALLOC")
	set(SAPP_MODULES ${SAPP_MODULES} libmimalloc-static)
endif()

target_link_libraries(sapp -Wl,--whole-archive ${SAPP_MODULES} -Wl,--no-whole-archive ${SAPP_DEPEND_DYN_LIB} ${SYSTEMD_LIBRARIES})

target_link_libraries(sapp packet_io_pcap)
if(CAPTURE_MODE STREQUAL "MARSIO")
	target_link_libraries(sapp packet_io_marsio)
endif()
	
if(CAPTURE_MODE STREQUAL "TUN")
	target_link_libraries(sapp packet_io_tun)
endif()	

