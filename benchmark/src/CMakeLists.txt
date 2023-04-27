cmake_minimum_required(VERSION 2.8...3.10)

set(MESA_SDK_PREFIX "/opt/MESA" CACHE STRING "MESA Framework Prefix")

include_directories(${PROJECT_SOURCE_DIR}/benchmark/include)
include_directories(${PROJECT_SOURCE_DIR}/include/public)
include_directories(${PROJECT_SOURCE_DIR}/include/private/)
include_directories(${PROJECT_SOURCE_DIR}/include/public/stream_inc)

LINK_DIRECTORIES(/opt/MESA/lib)

add_definitions(-D_DEFAULT_SOURCE -D_DEFAULT_SOURCE -D__DEFAULT_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H)
add_definitions(-fPIC)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

execute_process(COMMAND  xxd -i ${PROJECT_SOURCE_DIR}/benchmark/sapp_default_config/etc/asymmetric_addr_layer.conf  ${CMAKE_BINARY_DIR}/src/asymmetric_addr_layer.conf.c)
execute_process(COMMAND   bash "-c"  "sed -i '1 s/.*/const unsigned char templete_asymmetric_addr_layer[] = {/' ${CMAKE_BINARY_DIR}/src/asymmetric_addr_layer.conf.c")
execute_process(COMMAND   bash "-c"  "sed -i '$ s/.*/const int templete_asymmetric_addr_layer_len = sizeof(templete_asymmetric_addr_layer);/' ${CMAKE_BINARY_DIR}/src/asymmetric_addr_layer.conf.c")

execute_process(COMMAND  xxd -i ${PROJECT_SOURCE_DIR}/benchmark/sapp_default_config/etc/entrylist.conf  ${CMAKE_BINARY_DIR}/src/entrylist.conf.c)
execute_process(COMMAND   bash "-c"  "sed -i '1 s/.*/const unsigned char templete_entrylist[] = {/' ${CMAKE_BINARY_DIR}/src/entrylist.conf.c")
execute_process(COMMAND   bash "-c"  "sed -i '$ s/.*/const int templete_entrylist_len = sizeof(templete_entrylist);/' ${CMAKE_BINARY_DIR}/src/entrylist.conf.c")               

execute_process(COMMAND  xxd -i ${PROJECT_SOURCE_DIR}/benchmark/sapp_default_config/etc/gdev.conf  ${CMAKE_BINARY_DIR}/src/gdev.conf.c)
execute_process(COMMAND   bash "-c"  "sed -i '1 s/.*/const unsigned char templete_gdev[] = {/' ${CMAKE_BINARY_DIR}/src/gdev.conf.c")
execute_process(COMMAND   bash "-c"  "sed -i '$ s/.*/const int templete_gdev_len = sizeof(templete_gdev);/' ${CMAKE_BINARY_DIR}/src/gdev.conf.c")               

execute_process(COMMAND  xxd -i ${PROJECT_SOURCE_DIR}/benchmark/sapp_default_config/etc/plugin.conf  ${CMAKE_BINARY_DIR}/src/plugin.conf.c)
execute_process(COMMAND   bash "-c"  "sed -i '1 s/.*/const unsigned char templete_plugin[] = {/' ${CMAKE_BINARY_DIR}/src/plugin.conf.c")
execute_process(COMMAND   bash "-c"  "sed -i '$ s/.*/const int templete_plugin_len = sizeof(templete_plugin);/' ${CMAKE_BINARY_DIR}/src/plugin.conf.c")               

execute_process(COMMAND  xxd -i ${PROJECT_SOURCE_DIR}/benchmark/sapp_default_config/etc/sapp.toml  ${CMAKE_BINARY_DIR}/src/sapp.toml.c)
execute_process(COMMAND   bash "-c"  "sed -i '1 s/.*/const unsigned char templete_sapp_toml[] = {/' ${CMAKE_BINARY_DIR}/src/sapp.toml.c")
execute_process(COMMAND   bash "-c"  "sed -i '$ s/.*/const int templete_sapp_toml_len = sizeof(templete_sapp_toml);/' ${CMAKE_BINARY_DIR}/src/sapp.toml.c")               

execute_process(COMMAND  xxd -i ${PROJECT_SOURCE_DIR}/benchmark/sapp_default_config/etc/send_raw_pkt.conf  ${CMAKE_BINARY_DIR}/src/send_raw_pkt.conf.c)
execute_process(COMMAND   bash "-c"  "sed -i '1 s/.*/const unsigned char templete_send_raw_pkt[] = {/' ${CMAKE_BINARY_DIR}/src/send_raw_pkt.conf.c")
execute_process(COMMAND   bash "-c"  "sed -i '$ s/.*/const int templete_send_raw_pkt_len = sizeof(templete_send_raw_pkt);/' ${CMAKE_BINARY_DIR}/src/send_raw_pkt.conf.c")               

execute_process(COMMAND  xxd -i ${PROJECT_SOURCE_DIR}/benchmark/sapp_default_config/etc/sapp_log.conf  ${CMAKE_BINARY_DIR}/src/sapp_log.conf.c)
execute_process(COMMAND   bash "-c"  "sed -i '1 s/.*/const unsigned char templete_sapp_log[] = {/' ${CMAKE_BINARY_DIR}/src/sapp_log.conf.c")
execute_process(COMMAND   bash "-c"  "sed -i '$ s/.*/const int templete_sapp_log_len = sizeof(templete_sapp_log);/' ${CMAKE_BINARY_DIR}/src/sapp_log.conf.c")               

set(AUTO_CONF_C ${CMAKE_BINARY_DIR}/src/asymmetric_addr_layer.conf.c ${CMAKE_BINARY_DIR}/src/entrylist.conf.c ${CMAKE_BINARY_DIR}/src/gdev.conf.c ${CMAKE_BINARY_DIR}/src/plugin.conf.c ${CMAKE_BINARY_DIR}/src/sapp.toml.c ${CMAKE_BINARY_DIR}/src/send_raw_pkt.conf.c ${CMAKE_BINARY_DIR}/src/sapp_log.conf.c)
               
add_library(sapp_benchmark SHARED sapp_benchmark.cpp sapp_benchmark_comm.cpp sapp_benchmark_utils.cpp wrap_cJSON.c wrap_cJSON_Utils.c ${AUTO_CONF_C})		
set_target_properties(${lib_name}  PROPERTIES PREFIX "")  

target_link_libraries(sapp_benchmark  pthread pcap MESA_jump_layer MESA_htable MESA_field_stat2 MESA_handle_logger MESA_prof_load breakpad_mini dl systemd sapp_devel)

#add_test(NAME COPY_LIBBENCHMARK COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/benchmark/src/libsapp_benchmark.so ${CMAKE_BINARY_DIR}/testing/plug/business/gtest_sapp/")

