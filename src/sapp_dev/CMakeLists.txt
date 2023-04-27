cmake_minimum_required(VERSION 2.8...3.10)

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/include/private)
include_directories(${CMAKE_SOURCE_DIR}/include/public)
include_directories(${CMAKE_SOURCE_DIR}/include/support)
include_directories(${MESA_SDK_PREFIX}/include)
include_directories(${MESA_SDK_PREFIX}/include/MESA)

add_definitions(-fPIC -D_DEFAULT_SOURCE -D_DEFAULT_SOURCE -D__DEFAULT_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H)

add_library(sapp_dev STATIC sapp_plug.c sapp_global_val.c sapp_init.c)

#add_custom_target(libsapp_plug.a
#j.	COMMAND rm -f *.o
        #COMMAND ar -x ${CMAKE_BINARY_DIR}/src/dealpkt/libdealpkt.a
        #COMMAND ar -rc libsapp_plug.a  *.o
        #)

#add_library(sapp_plug STATIC IMPORTED GLOBAL)
