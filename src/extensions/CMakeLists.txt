cmake_minimum_required(VERSION 2.8...3.10)

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/include/private)
include_directories(${CMAKE_SOURCE_DIR}/include/public)
include_directories(${CMAKE_SOURCE_DIR}/include/support)


if(CAPTURE_MODE STREQUAL "MARSIO")
    include_directories(${MARSIO_SDK_PREFIX}/include)
endif()

add_definitions(-D_DEFAULT_SOURCE -D_DEFAULT_SOURCE -D__DEFAULT_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H)

add_definitions(-fPIC)
add_library(l2tp_protocol_plug SHARED l2tp_protocol_plug.c)
set_target_properties(l2tp_protocol_plug  PROPERTIES PREFIX "")

add_library(pptp_protocol_plug SHARED pptp_protocol_plug.c)
set_target_properties(pptp_protocol_plug  PROPERTIES PREFIX "")

add_library(isakmp_protocol_plug SHARED isakmp_protocol_plug_add_nat.c)
set_target_properties(isakmp_protocol_plug  PROPERTIES PREFIX "")

add_library(inline_keepalive STATIC inline_keepalive.cpp)

add_library(platform_support STATIC platform_support.cpp)
add_library(sapp_assistant STATIC sapp_assistant.cpp)
add_library(gdev_assistant STATIC gdev_assistant.c)

add_library(sapp_metrics STATIC sapp_metrics.cpp)


