cmake_minimum_required(VERSION 2.8...3.10)

include_directories(${CMAKE_SOURCE_DIR}/benchmark/inc/)
include_directories(${CMAKE_SOURCE_DIR}/include/private/)
include_directories(${CMAKE_SOURCE_DIR}/include/public/)
include_directories(${CMAKE_SOURCE_DIR}/include/public/stream_inc)

add_definitions(-fPIC)

execute_process(COMMAND sh ${CMAKE_SOURCE_DIR}/module_test/test_case/auto_gen_test_functions.sh  ${CMAKE_SOURCE_DIR}/module_test/test_case)
			
#add_test(NAME COPY_TEST_PCAP COMMAND sh -c "cp -r ${CMAKE_BINARY_DIR}/module_test/test_case/TEST_PCAP ${CMAKE_BINARY_DIR}/testing/")
#add_test(NAME COPY_TEST_PROFILE COMMAND sh -c "cp -r ${CMAKE_BINARY_DIR}/module_test/test_case/TEST_PROFILE ${CMAKE_BINARY_DIR}/testing/")
