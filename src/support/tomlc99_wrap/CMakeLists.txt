cmake_minimum_required(VERSION 2.8...3.10)

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/include/private)
include_directories(${CMAKE_SOURCE_DIR}/include/public)

#set(CMAKE_C_FLAGS "-DLINK_MODE_DYNAMIC=1")
set(CMAKE_C_FLAGS "-std=c99")

add_definitions(-fPIC -D_DEFAULT_SOURCE -D_GNU_SOURCE -D__DEFAULT_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H)

add_library(tomlc99_wrap STATIC toml.c tomlc99_wrap.c)
