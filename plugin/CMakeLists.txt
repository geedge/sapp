cmake_minimum_required(VERSION 2.8)

include_directories(inc)
include_directories(${CMAKE_SOURCE_DIR}/include)
add_library(plugctrl STATIC src/plugin_proc.c src/plugin.c src/plugin_platform.c 
			src/plugin_protocol.c src/plugin_business.c)