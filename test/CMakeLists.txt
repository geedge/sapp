cmake_minimum_required(VERSION 2.8...3.10)

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/include/private)
include_directories(${CMAKE_SOURCE_DIR}/include/public)
include_directories(${CMAKE_SOURCE_DIR}/include/public/stream_inc)
include_directories(${CMAKE_SOURCE_DIR}/include/support)
include_directories(${MESA_SDK_PREFIX}/include)
include_directories(${MESA_SDK_PREFIX}/include/MESA)


if(CAPTURE_MODE STREQUAL "MARSIO")
    include_directories(${MARSIO_SDK_PREFIX}/include)
endif()

add_definitions(-D_DEFAULT_SOURCE -D_DEFAULT_SOURCE -D__DEFAULT_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H)
add_definitions(-fPIC)
LINK_DIRECTORIES(/opt/MESA/lib)
LINK_DIRECTORIES(${CMAKE_BINARY_DIR}/test)

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/sapp_devel.cpp "")

set(LIBS sapp_dev dealpkt packet_io  packet_io_pcap packet_io_marsio common 
			config inline_keepalive gdev_assistant sapp_assistant sapp_metrics plugctrl project timer
			md5 symbol_check tomlc99_wrap MESA_socket_wrap timestamp_record  
			MESA_sleep dpdk_ip_hash  cpu_limit timeout libdabloom-static )

if(LIBEVENT_ENABLED)
            set(LIBS ${LIBS} libevent-static)
endif()

add_library(sapp_devel SHARED sapp_devel.cpp)
target_link_libraries(sapp_devel -Wl,--whole-archive ${LIBS} -Wl,--no-whole-archive)

#add_library(sapp_devel_static STATIC sapp_devel.cpp)

set(OBJECTS_DIR ${CMAKE_CURRENT_BINARY_DIR}/temp_objs)

file(MAKE_DIRECTORY ${OBJECTS_DIR})

foreach(lib IN LISTS LIBS)
    add_custom_command(OUTPUT "${OBJECTS_DIR}/${lib}_objects"
        COMMAND ${CMAKE_COMMAND} -E chdir "${OBJECTS_DIR}" ${CMAKE_AR} -x "$<TARGET_FILE:${lib}>"
        DEPENDS ${lib}
        )
        list(APPEND ALL_OBJECTS_TARGETS "${OBJECTS_DIR}/${lib}_objects")
endforeach()

file(GLOB_RECURSE OBJECTS "${OBJECTS_DIR}/*.o")

add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/libsapp_devel.a"
    COMMAND ${CMAKE_AR} -qc "${CMAKE_CURRENT_BINARY_DIR}/libsapp_devel.a" ${OBJECTS}
    DEPENDS ${ALL_OBJECTS_TARGETS}
)

add_custom_target(sapp_devel_static ALL DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/libsapp_devel.a")


add_library(test_app_sapp SHARED test_app_sapp.c)
add_executable(test_sapp_dev test_sapp_dev.c)
target_link_libraries(test_sapp_dev sapp_devel)

target_link_libraries(test_sapp_dev nsl pthread dl m pcap systemd MESA_htable MESA_handle_logger MESA_prof_load  MESA_field_stat2 fieldstat3 breakpad_mini MESA_jump_layer)


#add_library(test_sendpacket_performance SHARED test_sendpacket_performance.c)
set_target_properties(test_app_sapp  PROPERTIES PREFIX "")
#set_target_properties(test_sendpacket_performance PROPERTIES PREFIX "")


