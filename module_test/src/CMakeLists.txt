cmake_minimum_required(VERSION 2.8)

include_directories(${PROJECT_SOURCE_DIR}/benchmark/include)
include_directories(${PROJECT_SOURCE_DIR}/module_test/include)
include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_SOURCE_DIR}/include/private)
include_directories(${PROJECT_SOURCE_DIR}/include/public)
include_directories(${PROJECT_SOURCE_DIR}/include/support)
include_directories(${PROJECT_SOURCE_DIR}/include/public/stream_inc)

add_definitions(-DSAPP_V4=1)
add_definitions(-fPIC)
add_definitions(-std=c++11)

add_executable(gtest_sapp_v4 gtest_main.cpp gtest_sapp_ipv4.cpp gtest_sapp_ipv6.cpp gtest_sapp_tcp.cpp gtest_sapp_udp.cpp gtest_sapp_comm.cpp gtest_sapp_support.cpp gtest_sapp_plug_ctrl.cpp gtest_sapp_tunnel.cpp 
               gtest_transparent_run.cpp  gtest_sapp_jump_layer.cpp gtest_inline_run.cpp  gtest_sapp_asymmetric.cpp gtest_sapp_inject.cpp gtest_sapp_app_state.cpp
               gtest_mpls.cpp gtest_vlan.cpp gtest_fake_marsio_run.cpp gtest_sapp_proxy.cpp gtest_sapp_pkt_dump.cpp
		../test_case/auto_gen_test_functions.cpp ../test_case/test_function_common.cpp)

target_link_libraries(gtest_sapp_v4 gtest-static pthread pcap m dl MESA_jump_layer MESA_field_stat2 MESA_htable MESA_handle_logger MESA_prof_load breakpad_mini systemd sapp_benchmark sapp_devel)

add_executable(transparent_test_sapp_v4 gtest_transparent_env.cpp gtest_sapp_comm.cpp)
target_link_libraries(transparent_test_sapp_v4 pthread pcap m dl MESA_jump_layer MESA_handle_logger)

add_executable(inline_test_sapp_v4 gtest_inline_env.cpp gtest_sapp_comm.cpp)
target_link_libraries(inline_test_sapp_v4 pthread pcap m dl MESA_jump_layer MESA_handle_logger)

add_library(gtest_sapp SHARED gtest_sapp_plug_entry.cpp gtest_sapp_ipv4_plug.cpp gtest_sapp_ipv6_plug.cpp gtest_sapp_tcp_plug.cpp gtest_sapp_udp_plug.cpp gtest_sapp_comm.cpp gtest_sapp_support_plug.cpp 
            gtest_sapp_plug_ctrl_plug.cpp gtest_transparent_plug.cpp gtest_sapp_tunnel_plug.cpp gtest_sapp_jump_layer_plug.cpp gtest_inline_plug.cpp  gtest_sapp_asymmetric_plug.cpp gtest_sapp_inject_plug.cpp
			gtest_sapp_app_state_plug.cpp gtest_mpls_plug.cpp  gtest_vlan_plug.cpp  gtest_fake_marsio_plug.cpp gtest_sapp_proxy_plug.cpp gtest_plug_comm.cpp
			gtest_sapp_by_benchmark_plug.cpp)


add_library(gtest_fake_marsio SHARED gtest_sapp_plug_entry.cpp gtest_sapp_comm.cpp gtest_fake_marsio_env.cpp )		
