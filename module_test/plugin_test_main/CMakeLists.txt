include_directories(${PROJECT_SOURCE_DIR}/include/public)
add_executable(plugin_test_main plugin_test_main.cpp)
target_link_libraries(plugin_test_main sapp_devel)
target_link_libraries(plugin_test_main gtest-static)
target_link_libraries(plugin_test_main ${SAPP_DEPEND_DYN_LIB})

