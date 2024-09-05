cmake_minimum_required(VERSION 2.8...3.10)

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/include/private)
include_directories(${CMAKE_SOURCE_DIR}/include/public)
include_directories(${CMAKE_SOURCE_DIR}/include/public/stream_inc)
include_directories(${CMAKE_SOURCE_DIR}/include/support)


if(CAPTURE_MODE STREQUAL "MARSIO")
    include_directories(${MARSIO_SDK_PREFIX}/include)
endif()

add_definitions(-D_DEFAULT_SOURCE -D_DEFAULT_SOURCE -D__DEFAULT_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H)
add_definitions(-fPIC)
LINK_DIRECTORIES(/opt/MESA/lib)
LINK_DIRECTORIES(${CMAKE_BINARY_DIR}/test)

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/sapp_devel.cpp "")



add_library(sapp_devel SHARED sapp_devel.cpp)
target_link_libraries(sapp_devel -Wl,--whole-archive ${SAPP_MODULES} -Wl,--no-whole-archive ${SAPP_DEPEND_DYN_LIB})


add_library(test_app_sapp SHARED test_app_sapp.c)
set_target_properties(test_app_sapp  PROPERTIES PREFIX "")

#add_executable(test_sapp_dev test_sapp_dev.c)
#target_link_libraries(test_sapp_dev sapp_devel)
#target_link_libraries(test_sapp_dev ${SAPP_DEPEND_DYN_LIB})

#add_library(test_sendpacket_performance SHARED test_sendpacket_performance.c)
#set_target_properties(test_sendpacket_performance PROPERTIES PREFIX "")


