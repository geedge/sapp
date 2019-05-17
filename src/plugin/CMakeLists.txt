cmake_minimum_required(VERSION 2.8)

include_directories(${MESA_SDK_PREFIX}/include)
include_directories(${MESA_SDK_PREFIX}/include/MESA)
include_directories(inc)
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/include/private)
include_directories(${CMAKE_SOURCE_DIR}/include/public)
include_directories(${CMAKE_SOURCE_DIR}/include/support)
add_library(plugctrl STATIC src/plugin_proc.c src/plugin.c src/plugin_platform.c 
			src/plugin_protocol.c src/plugin_business.c)