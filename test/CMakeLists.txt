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

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/sapp_devel.cpp "")

add_library(sapp_devel SHARED sapp_devel.cpp)
target_link_libraries(sapp_devel -Wl,--whole-archive sapp_dev dealpkt packet_io  packet_io_pcap packet_io_marsio common 
			config inner_plug gdev_assistant sapp_assistant plugctrl project timer dictator2 
			md5 symbol_check tomlc99_wrap MESA_socket_wrap timestamp_record  
			MESA_sleep dpdk_ip_hash  cpu_limit timeout libevent-static libdabloom-static -Wl,--no-whole-archive)

add_library(sapp_devel_static STATIC sapp_devel.cpp)
target_link_libraries(sapp_devel sapp_dev dealpkt packet_io  packet_io_pcap packet_io_marsio common 
			config inner_plug gdev_assistant sapp_assistant plugctrl project timer dictator2 
			md5 symbol_check tomlc99_wrap MESA_socket_wrap timestamp_record  
			MESA_sleep dpdk_ip_hash  cpu_limit timeout libevent-static libdabloom-static)
set_target_properties(sapp_devel_static PROPERTIES OUTPUT_NAME sapp_devel)



add_library(test_app_sapp SHARED test_app_sapp.c)
add_executable(test_sapp_dev test_sapp_dev.c)
target_link_libraries(test_sapp_dev sapp_devel)

target_link_libraries(test_sapp_dev nsl pthread dl m pcap systemd MESA_htable MESA_handle_logger MESA_prof_load  MESA_field_stat2 breakpad_mini MESA_jump_layer)


#add_library(test_sendpacket_performance SHARED test_sendpacket_performance.c)
set_target_properties(test_app_sapp  PROPERTIES PREFIX "")
#set_target_properties(test_sendpacket_performance PROPERTIES PREFIX "")


