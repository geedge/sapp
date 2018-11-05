cmake_minimum_required(VERSION 2.8)

#include_directories(${CMAKE_SOURCE_DIR}/packet_io)
#include_directories(${CMAKE_SOURCE_DIR}/project)
#include_directories(${CMAKE_SOURCE_DIR}/include)
#include_directories(${CMAKE_SOURCE_DIR}/include/support)
include_directories(./include)

add_definitions(-D_BSD_SOURCE -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H)

add_library(iknow STATIC  src/server/iknow_cmd_parser.c
    src/server/iknow_server.c  src/server/iknow_task_scheduler.c)
