cmake_minimum_required (VERSION 2.8)

set(lib_name breakpad_mini)

project (${lib_name})

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
include(Version)

set(CMAKE_MACOSX_RPATH 0)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_STANDARD 11)

option(ENABLE_SANITIZE_ADDRESS "Enable AddressSanitizer" FALSE)
option(ENABLE_SANITIZE_THREAD "Enable ThreadSanitizer" FALSE)

if(ENABLE_SANITIZE_ADDRESS)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
elseif(ENABLE_SANITIZE_THREAD)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=thread -fno-omit-frame-pointer")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread -fno-omit-frame-pointer")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
endif()

LINK_DIRECTORIES(/opt/MESA/lib)

include_directories(${PROJECT_SOURCE_DIR}/inc/)
include_directories(/opt/MESA/include/)
include_directories(/opt/MESA/include/MESA)


add_subdirectory(vendor)
add_subdirectory(src)
add_subdirectory(demo)

set(DEPEND_DYN_LIB MESA_handle_logger2  MESA_prof_load)

set(CMAKE_INSTALL_PREFIX /opt/MESA/)

#install(TARGETS ${plugin_name} LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib COMPONENT LIBRARY)
#install(FILES inc/${plugin_name}.h DESTINATION ${CMAKE_INSTALL_PREFIX}/include/MESA/ COMPONENT PROFILE)

include(Package)
