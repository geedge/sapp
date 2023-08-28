cmake_minimum_required(VERSION 2.8...3.10)

add_subdirectory(${CMAKE_SOURCE_DIR}/module_test/vendor)
add_subdirectory(${CMAKE_SOURCE_DIR}/module_test/plugin_test_main)
add_subdirectory(${CMAKE_SOURCE_DIR}/module_test/test_case)
add_subdirectory(${CMAKE_SOURCE_DIR}/module_test/src/)

