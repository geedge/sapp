cmake_minimum_required(VERSION 2.8)

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/include/private)
include_directories(${CMAKE_SOURCE_DIR}/include/public)
include_directories(/opt/MESA/include/MESA)
include_directories(/opt/MESA/include/)

#add_definitions(-D_BSD_SOURCE -D_GNU_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H)
add_custom_command(
    OUTPUT  ${CMAKE_SOURCE_DIR}/src/lib/libevent.a
    COMMAND cp libevent.a ${CMAKE_SOURCE_DIR}/src/lib)

#add_library(event STATIC  libevent.a)
#add_custom_target(event STATIC)
link_directories(${CMAKE_SOURCE_DIR}/src/lib)
