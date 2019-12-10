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
set_target_properties(test_app_sapp  PROPERTIES PREFIX "")

#add_library(wangyan_demo SHARED wangyan_demo.c)
#set_target_properties(wangyan_demo  PROPERTIES PREFIX "")

#add_library(test_wangyan SHARED test_wangyan.c)
#set_target_properties(test_wangyan  PROPERTIES PREFIX "")

