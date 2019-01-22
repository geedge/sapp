cmake_minimum_required(VERSION 2.8)

include_directories(${MESA_SDK_PREFIX}/include)
include_directories(${MESA_SDK_PREFIX}/include/MESA)
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/include/support)
include_directories(${CMAKE_SOURCE_DIR}/include/net)
include_directories(${CMAKE_SOURCE_DIR}/include/stream_inc)
include_directories(${CMAKE_SOURCE_DIR}/dealpkt)
include_directories(${CMAKE_SOURCE_DIR}/packet_io)

add_executable(sapp sapp_init.c sapp_main.c sapp_global_val.c)
target_compile_options(sapp PUBLIC ${MEM_POOL_DEFINITIONS})
target_link_libraries(sapp nsl pthread dl m pcap)
target_link_libraries(sapp MESA_handle_logger MESA_prof_load)


set(SAPP_MODULES iknow timestamp_record md5 symbol_check MESA_sleep MESA_socket_wrap packet_io dealpkt project plugctrl)
if(OPT_USE_DICTATOR OR OPT_USE_DICTATOR_DEBUG)
    set(SAPP_MODULES ${SAPP_MODULES}  dictator2 )
endif()

if(ENABLE_STATIC_LINK)
    set(SAPP_MODULES ${SAPP_MODULES} sapp_assistant gdev_assistant )
else()
    target_link_libraries(sapp sapp_assistant gdev_assistant)
endif()

target_link_libraries(sapp -Wl,--whole-archive ${SAPP_MODULES} -Wl,--no-whole-archive ${SAPP_DEPEND_DYN_LIB})

if(CAPTURE_MODE MATCHES "PAG")
	target_link_libraries(sapp pag)
endif()

if(CAPTURE_MODE MATCHES "PPF")
	target_link_libraries(psapp ppf)
endif()

if(CAPTURE_MODE MATCHES "PFRING")
	target_link_libraries(sapp pfring)
endif()

if(CAPTURE_MODE MATCHES "DPDK")
	target_link_libraries(sapp nl2fwd)
endif()

# Target Install
install(TARGETS sapp DESTINATION ${CMAKE_SOURCE_DIR}/run/)
#install(FILES ${CMAKE_SOURCE_DIR}/build/inner_plug/libsapp_assistant.so DESTINATION /opt/MESA/lib)
#install(DIRECTORY conf/ DESTINATION ${CMAKE_SOURCE_DIR}/run/conf)
#install(DIRECTORY log/ DESTINATION ${CMAKE_SOURCE_DIR}/run/log)

# SDK Headers Install
#install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/stream_inc DESTINATION ${MESA_SDK_PREFIX}/include/MESA)
#install(FILES ${CMAKE_SOURCE_DIR}/include/stream.h DESTINATION ${MESA_SDK_PREFIX}/include/MESA)
