cmake_minimum_required(VERSION 2.8...3.10)

set(MESA_SDK_PREFIX "/opt/MESA" CACHE STRING "MESA Framework Prefix")

include_directories(${CMAKE_SOURCE_DIR}/benchmark/include)
include_directories(${PROJECT_SOURCE_DIR}/include/public)
include_directories(${PROJECT_SOURCE_DIR}/include/private/)
include_directories(${PROJECT_SOURCE_DIR}/include/public/stream_inc)

LINK_DIRECTORIES(/opt/MESA/lib)

add_definitions(-D_DEFAULT_SOURCE -D_DEFAULT_SOURCE -D__DEFAULT_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H)
add_definitions(-fPIC)

#add_executable(test_cjson_compare test_cjson_compare.cpp)
#target_link_libraries(test_cjson_compare sapp_benchmark)

#add_executable(test_sapp_benchmark test_sapp_benchmark.cpp)
#target_link_libraries(test_sapp_benchmark sapp_benchmark)

add_library(test_benchmark_plug SHARED test_plug.cpp)		
target_link_libraries(test_benchmark_plug sapp_benchmark)
set_target_properties(test_benchmark_plug  PROPERTIES PREFIX "")  

#add_test(NAME COPY_BENCHMARK_PLUG COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/benchmark/example/test_benchmark_plug.so ${CMAKE_BINARY_DIR}/testing/plug/business/gtest_sapp/")
