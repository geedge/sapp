cmake_minimum_required(VERSION 2.8)

include_directories(${MESA_SDK_PREFIX}/include)
include_directories(${MESA_SDK_PREFIX}/include/MESA)
include_directories(${MESA_SDK_PREFIX}/include/MESA/stream_inc)
include_directories(${CMAKE_SOURCE_DIR}/packet_io)
#include_directories(${CMAKE_SOURCE_DIR}/project)
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/include/net)
include_directories(${CMAKE_SOURCE_DIR}/include/support)
include_directories(${CMAKE_SOURCE_DIR}/dealpkt)

add_definitions(-D_BSD_SOURCE -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H)

add_definitions(-fPIC)
add_library(l2tp_protocol_plug SHARED l2tp_protocol_plug.c)
set_target_properties(l2tp_protocol_plug  PROPERTIES PREFIX "")

add_library(pptp_protocol_plug SHARED pptp_protocol_plug.c)
set_target_properties(pptp_protocol_plug  PROPERTIES PREFIX "")

add_library(isakmp_protocol_plug SHARED isakmp_protocol_plug_add_nat.c)
set_target_properties(isakmp_protocol_plug  PROPERTIES PREFIX "")

#add_library(wangyan_keepalive_plug SHARED wangyan_keepalive_plug.c)
#set_target_properties(wangyan_keepalive_plug  PROPERTIES PREFIX "")

add_library(g_device_plug SHARED g_device_plug.c)
set_target_properties(g_device_plug  PROPERTIES PREFIX "")

if(ENABLE_STATIC_LINK)
    add_library(sapp_assistant STATIC sapp_assistant.cpp)
    add_library(gdev_assistant STATIC gdev_assistant.c)
else()
    add_definitions(-fPIC)
    add_library(sapp_assistant SHARED sapp_assistant.cpp)
    add_library(gdev_assistant SHARED gdev_assistant.c)
endif()

