cmake_minimum_required(VERSION 2.8...3.10)


add_definitions(-fPIC)
include_directories(${CMAKE_SOURCE_DIR}/src/support/ap_bloom/deps)
add_library(ap_bloom STATIC  deps/xxhash.c deps/crdt_utils.c src/ap_bloom.c deps/ap_mempool.cpp)