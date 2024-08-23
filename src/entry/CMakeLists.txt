cmake_minimum_required(VERSION 2.8...3.10)

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/include/private)
include_directories(${CMAKE_SOURCE_DIR}/include/public)
include_directories(${CMAKE_SOURCE_DIR}/include/support)
include_directories(${MESA_SDK_PREFIX}/include)
include_directories(${MESA_SDK_PREFIX}/include/MESA)

add_definitions(-fPIC)

LINK_DIRECTORIES(/opt/MESA/lib)
LINK_DIRECTORIES(${CMAKE_SOURCE_DIR}/src/lib)

if(CAPTURE_MODE STREQUAL "MARSIO")
	LINK_DIRECTORIES(/opt/mrzcpd/lib)
endif()


if(HASP_ENABLED)
	include_directories(/opt/tsg/hasp-tools/include/)
endif()

add_executable(sapp sapp_main.c)
target_compile_options(sapp PUBLIC ${MEM_POOL_DEFINITIONS})
target_include_directories(sapp PRIVATE ${SYSTEMD_INCLUDE_DIRS})


if(HASP_ENABLED STREQUAL "ON")
	find_library(HASP_TOOLS_LIB NAMES hasp-tools PATHS /opt/tsg/hasp-tools/lib)
	target_link_libraries(sapp ${HASP_TOOLS_LIB})
endif()

target_link_libraries(sapp -Wl,--whole-archive ${SAPP_MODULES} -Wl,--no-whole-archive)
target_link_libraries(sapp ${SAPP_DEPEND_DYN_LIB})


