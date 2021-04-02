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

add_executable(sapp sapp_main.c libsapp_phony.a)
target_compile_options(sapp PUBLIC ${MEM_POOL_DEFINITIONS})
target_link_libraries(sapp nsl pthread dl m pcap)
target_link_libraries(sapp MESA_handle_logger MESA_prof_load)
target_link_libraries(sapp sapp_assistant)
target_link_libraries(sapp breakpad_mini)
target_include_directories(sapp PRIVATE ${SYSTEMD_INCLUDE_DIRS})


add_custom_command(OUTPUT  libsapp_phony.a
        COMMAND rm -f *.o
        COMMAND ar -x ${CMAKE_BINARY_DIR}/src/dealpkt/libdealpkt.a
        COMMAND ar -x ${CMAKE_BINARY_DIR}/src/packet_io/libpacket_io.a
		COMMAND ar -x ${CMAKE_BINARY_DIR}/src/common/libcommon.a
		COMMAND ar -x ${CMAKE_BINARY_DIR}/src/config/libconfig.a
		COMMAND ar -x ${CMAKE_BINARY_DIR}/src/inner_plug/libinner_plug.a
		COMMAND ar -x ${CMAKE_BINARY_DIR}/src/inner_plug/libgdev_assistant.a
		COMMAND ar -x ${CMAKE_BINARY_DIR}/src/inner_plug/libsapp_assistant.a
		COMMAND ar -x ${CMAKE_BINARY_DIR}/src/plugin/libplugctrl.a
		COMMAND ar -x ${CMAKE_BINARY_DIR}/src/project/libproject.a
		COMMAND ar -x ${CMAKE_BINARY_DIR}/src/timer/libtimer.a
		COMMAND ar -x ${CMAKE_BINARY_DIR}/src/support/dictator2/src/libdictator2.a
		COMMAND ar -x ${CMAKE_BINARY_DIR}/src/support/md5/libmd5.a
		COMMAND ar -x ${CMAKE_BINARY_DIR}/src/support/symbol_check/libsymbol_check.a
		COMMAND ar -x ${CMAKE_BINARY_DIR}/src/support/tomlc99_wrap/libtomlc99_wrap.a
		COMMAND ar -x ${CMAKE_BINARY_DIR}/src/support/MESA_socket_wrap/src/libMESA_socket_wrap.a
		COMMAND ar -x ${CMAKE_BINARY_DIR}/src/support/timestamp_record/libtimestamp_record.a
		COMMAND ar -x ${CMAKE_BINARY_DIR}/src/support/MESA_sleep/libMESA_sleep.a
		COMMAND ar -x ${CMAKE_BINARY_DIR}/src/support/iknow/libiknow.a
		COMMAND ar -x ${CMAKE_BINARY_DIR}/src/sapp_dev/libsapp_dev.a
        	COMMAND ar -rc libsapp_dev.a  *.o
        	COMMAND cp libsapp_dev.a  ${CMAKE_BINARY_DIR}/src/sapp_dev/
		#COMMAND rm -f *.o
        )


#set(SAPP_MODULES iknow timestamp_record md5 symbol_check MESA_sleep MESA_socket_wrap packet_io dealpkt project plugctrl common config timer tomlc99_wrap libevent-static gdev_assistant inner_plug libdabloom-static sapp_dev)
set(SAPP_MODULES libdabloom-static libevent-static sapp_dev)

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
# Target Install
#install(TARGETS sapp DESTINATION ${CMAKE_SOURCE_DIR}/bin/)
#install(FILES ${CMAKE_BINARY_DIR}/inner_plug/libsapp_assistant.so DESTINATION /opt/MESA/lib)
#install(FILES ${CMAKE_BINARY_DIR}/inner_plug/libgdev_assistant.so DESTINATION /opt/MESA/lib)

#install(DIRECTORY conf/ DESTINATION ${CMAKE_SOURCE_DIR}/run/conf)
#install(DIRECTORY log/ DESTINATION ${CMAKE_SOURCE_DIR}/run/log)

# SDK Headers Install
#install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/stream_inc DESTINATION ${MESA_SDK_PREFIX}/include/MESA)
#install(FILES ${CMAKE_SOURCE_DIR}/include/stream.h DESTINATION ${MESA_SDK_PREFIX}/include/MESA)
