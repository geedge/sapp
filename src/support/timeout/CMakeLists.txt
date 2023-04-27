cmake_minimum_required(VERSION 2.8...3.10)

include_directories(${CMAKE_SOURCE_DIR}/include/support)

add_definitions(-fPIC)

add_library(timeout timeout.c timeout-bitops.c)
