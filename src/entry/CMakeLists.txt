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

if(CAPTURE_MODE MATCHES "MARSIO")
	LINK_DIRECTORIES(/opt/mrzcpd/lib)
endif()

add_executable(sapp sapp_main.c)
target_compile_options(sapp PUBLIC ${MEM_POOL_DEFINITIONS})
target_link_libraries(sapp nsl pthread dl m pcap)
target_link_libraries(sapp MESA_handle_logger MESA_prof_load)
target_link_libraries(sapp sapp_assistant)
target_link_libraries(sapp breakpad_mini)
target_include_directories(sapp PRIVATE ${SYSTEMD_INCLUDE_DIRS})


set(SAPP_MODULES timestamp_record md5 symbol_check MESA_sleep MESA_socket_wrap packet_io dealpkt project plugctrl common config timer tomlc99_wrap dpdk_ip_hash libevent-static gdev_assistant inner_plug libdabloom-static sapp_dev sapp_assistant cpu_limit timeout)

if(MEM_POOL MATCHES "DICTATOR_DEBUG")
   set(SAPP_MODULES ${SAPP_MODULES} dictator2_debug)
elseif(MEM_POOL MATCHES "DICTATOR")
   set(SAPP_MODULES ${SAPP_MODULES} dictator2)
endif()
target_link_libraries(sapp -Wl,--whole-archive ${SAPP_MODULES} -Wl,--no-whole-archive ${SAPP_DEPEND_DYN_LIB} ${SYSTEMD_LIBRARIES})

if(ENABLE_STATIC_LINK)
	#if(CAPTURE_MODE MATCHES "PAG")
	#	target_link_libraries(sapp pag)
	#endif()
	#
	#if(CAPTURE_MODE MATCHES "PPF")
	#	target_link_libraries(sapp ppf)
	#endif()
#
	#if(CAPTURE_MODE MATCHES "PFRING")
	#	target_link_libraries(sapp pfring)
	#endif()
#
	#if(CAPTURE_MODE MATCHES "DPDK")
	#	target_link_libraries(sapp nl2fwd)
	#endif()
	#if(CAPTURE_MODE MATCHES "PCAP")
	target_link_libraries(sapp packet_io_pcap)
	#endif()
	if(CAPTURE_MODE MATCHES "MARSIO")
		target_link_libraries(sapp packet_io_marsio)
	endif()
	
	if(CAPTURE_MODE MATCHES "TUN")
		target_link_libraries(sapp packet_io_tun)
	endif()	
endif()

