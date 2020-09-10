set(DEPEND_DYN_LIB MESA_handle_logger2  MESA_prof_load)

# Shared Library Output
add_library(${lib_name} SHARED breakpad.cpp)
#add_dependencies(${lib_name} breakpad-client-static)

target_link_libraries(${lib_name} breakpad-client-static)
target_link_libraries(${lib_name} ${DEPEND_DYN_LIB})
set_target_properties(${lib_name}  PROPERTIES PREFIX "")

# static Library Output
add_library(${lib_name}_static STATIC breakpad.cpp)
#add_dependencies(${lib_name}_static breakpad-client-static)

target_link_libraries(${lib_name}_static breakpad-client-static)
target_link_libraries(${lib_name}_static ${DEPEND_DYN_LIB})
set_target_properties(${lib_name}_static PROPERTIES OUTPUT_NAME ${lib_name})

set(CMAKE_INSTALL_PREFIX /opt/MESA/)

#install(TARGETS ${plugin_name} LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib COMPONENT LIBRARY)
#install(FILES inc/${plugin_name}.h DESTINATION ${CMAKE_INSTALL_PREFIX}/include/MESA/ COMPONENT PROFILE)

include(Package)
