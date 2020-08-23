cmake_minimum_required(VERSION 2.8)

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/include/private)
include_directories(${CMAKE_SOURCE_DIR}/include/public)
include_directories(${CMAKE_SOURCE_DIR}/include/support)
include_directories(${MESA_SDK_PREFIX}/include)
include_directories(${MESA_SDK_PREFIX}/include/MESA)



LINK_DIRECTORIES(/opt/MESA/lib)
LINK_DIRECTORIES(${CMAKE_SOURCE_DIR}/src/lib)

if(CAPTURE_MODE MATCHES "MARSIO")
	LINK_DIRECTORIES(/opt/mrzcpd/lib)
endif()

add_executable(sapp sapp_init.c sapp_main.c sapp_global_val.c)
target_compile_options(sapp PUBLIC ${MEM_POOL_DEFINITIONS})
target_link_libraries(sapp nsl pthread dl m pcap)
target_link_libraries(sapp MESA_handle_logger MESA_prof_load)
target_link_libraries(sapp sapp_assistant)

#set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin)  
#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)  
#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_SOURCE_DIR}/bin)  
#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_SOURCE_DIR}/bin)  


set(SAPP_MODULES breakpad_mini_static breakpad-client-static iknow timestamp_record md5 symbol_check MESA_sleep MESA_socket_wrap packet_io dealpkt project plugctrl common config timer tomlc99_wrap libevent-static gdev_assistant  )

target_link_libraries(sapp -Wl,--whole-archive ${SAPP_MODULES} -Wl,--no-whole-archive ${SAPP_DEPEND_DYN_LIB})

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
# Target Install
#install(TARGETS sapp DESTINATION ${CMAKE_SOURCE_DIR}/bin/)
#install(FILES ${CMAKE_BINARY_DIR}/inner_plug/libsapp_assistant.so DESTINATION /opt/MESA/lib)
#install(FILES ${CMAKE_BINARY_DIR}/inner_plug/libgdev_assistant.so DESTINATION /opt/MESA/lib)

#install(DIRECTORY conf/ DESTINATION ${CMAKE_SOURCE_DIR}/run/conf)
#install(DIRECTORY log/ DESTINATION ${CMAKE_SOURCE_DIR}/run/log)

# SDK Headers Install
#install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/stream_inc DESTINATION ${MESA_SDK_PREFIX}/include/MESA)
#install(FILES ${CMAKE_SOURCE_DIR}/include/stream.h DESTINATION ${MESA_SDK_PREFIX}/include/MESA)
