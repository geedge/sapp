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
add_library(test_app_sapp SHARED test_app_sapp.c)
add_library(test_sendpacket_performance SHARED test_sendpacket_performance.c)
set_target_properties(test_app_sapp  PROPERTIES PREFIX "")
set_target_properties(test_sendpacket_performance PROPERTIES PREFIX "")

#add_library(wy_demo SHARED wy_demo.c)
#set_target_properties(wy_demo  PROPERTIES PREFIX "")

#add_library(test_wy SHARED test_wy.c)
#set_target_properties(test_wy  PROPERTIES PREFIX "")

