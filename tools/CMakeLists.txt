suppress_cppcheck_in_current_dir()

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/include/private)
include_directories(${CMAKE_SOURCE_DIR}/include/public)
include_directories(${CMAKE_SOURCE_DIR}/include/support)
include_directories(${MESA_SDK_PREFIX}/include)
include_directories(${MESA_SDK_PREFIX}/include/MESA)

add_definitions(-D_DEFAULT_SOURCE -D__FAVOR_BSD -D_XOPEN_SOURCE -D_ISOC99_SOURCE -DHAVE_NET_ETHERNET_H)

add_executable(stream_id_decode stream_id_decode.c)

