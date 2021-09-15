cmake_minimum_required(VERSION 2.8)

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/include/private)
include_directories(${CMAKE_SOURCE_DIR}/include/public)
include_directories(${CMAKE_SOURCE_DIR}/include/public/stream_inc)
include_directories(${CMAKE_SOURCE_DIR}/include/support)
include_directories(${MESA_SDK_PREFIX}/include)
include_directories(${MESA_SDK_PREFIX}/include/MESA)


if(CAPTURE_MODE MATCHES "MARSIO")
    include_directories(${MARSIO_SDK_PREFIX}/include)
endif()

add_definitions(-D_BSD_SOURCE -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H)
add_definitions(-fPIC)
LINK_DIRECTORIES(/opt/MESA/lib)
LINK_DIRECTORIES(${CMAKE_BINARY_DIR}/test)

add_custom_command(OUTPUT  libtest_phony.a
        COMMAND rm -f *.o
        COMMAND ar -x ${CMAKE_BINARY_DIR}/src/dealpkt/libdealpkt.a
        COMMAND ar -x ${CMAKE_BINARY_DIR}/src/packet_io/libpacket_io.a
		COMMAND ar -x ${CMAKE_BINARY_DIR}/src/packet_io/packet_io_marsio.a
		COMMAND ar -x ${CMAKE_BINARY_DIR}/src/packet_io/packet_io_pcap.a
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
		COMMAND ar -x ${CMAKE_BINARY_DIR}/src/support/dpdk_rte_hash/libdpdk_ip_hash.a
		COMMAND ar -x ${CMAKE_BINARY_DIR}/src/sapp_dev/libsapp_dev.a
		COMMAND ar -x ${CMAKE_BINARY_DIR}/src/support/cpu_limit/libcpu_limit.a
		COMMAND ar -x ${CMAKE_BINARY_DIR}/vendor/libdabloom/lib/libdablooms.a
		COMMAND ar -x ${CMAKE_BINARY_DIR}/vendor/libevent/lib/libevent.a 
		
		COMMAND ar -rc libsapp_devel.a  *.o
			#COMMAND cp libsapp_devel.a  /opt/MESA/lib/
        )

add_library(test_app_sapp SHARED test_app_sapp.c)
add_executable(test_sapp_dev test_sapp_dev.c libtest_phony.a)
target_link_libraries(test_sapp_dev sapp_devel)

target_link_libraries(test_sapp_dev nsl pthread dl m pcap systemd MESA_htable MESA_handle_logger MESA_prof_load  MESA_field_stat2 breakpad_mini MESA_jump_layer)


#add_library(test_sendpacket_performance SHARED test_sendpacket_performance.c)
set_target_properties(test_app_sapp  PROPERTIES PREFIX "")
#set_target_properties(test_sendpacket_performance PROPERTIES PREFIX "")


