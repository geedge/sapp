cmake_minimum_required(VERSION 2.8)

add_subdirectory(${CMAKE_SOURCE_DIR}/module_test/vendor)
add_subdirectory(${CMAKE_SOURCE_DIR}/module_test/test_case)
add_subdirectory(${CMAKE_SOURCE_DIR}/module_test/src/)

#add_test(NAME COPY_GTEST_SAPP COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/module_test/src/gtest_sapp_v4 ${CMAKE_BINARY_DIR}/testing/")
#add_test(NAME COPY_INLINE_SAPP COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/module_test/src/inline_test_sapp_v4 ${CMAKE_BINARY_DIR}/testing/")
#add_test(NAME COPY_TRANSPARENT_SAPP COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/module_test/src/transparent_test_sapp_v4 ${CMAKE_BINARY_DIR}/testing/")
#
#add_test(NAME COPY_GTEST_PLUG_SO COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/module_test/src/libgtest_sapp.so ${CMAKE_BINARY_DIR}/testing/plug/business/gtest_sapp")
#add_test(NAME COPY_GTEST_PLUG_INF COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/module_test/src/gtest_sapp.inf ${CMAKE_BINARY_DIR}/testing/plug/business/gtest_sapp")
#add_test(NAME COPY_FAKE_MARSIO COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/module_test/src/libgtest_fake_marsio.so ${CMAKE_BINARY_DIR}/testing/lib/")
