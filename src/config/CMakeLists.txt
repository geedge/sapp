cmake_minimum_required(VERSION 2.8...3.10)

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/include/private)
include_directories(${CMAKE_SOURCE_DIR}/include/public)
include_directories(${CMAKE_SOURCE_DIR}/include/support)
include_directories(${MESA_SDK_PREFIX}/include)
include_directories(${MESA_SDK_PREFIX}/include/MESA)


if(CAPTURE_MODE STREQUAL "MARSIO")
    include_directories(${MARSIO_SDK_PREFIX}/include)
endif()

add_definitions(-D_DEFAULT_SOURCE -D_DEFAULT_SOURCE -D__DEFAULT_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H)
add_definitions(-DPLATFORM_NSDPF_PAPP=1)
add_definitions(-fPIC)

#execute_process(COMMAND  echo "" > sapp.toml.hex.array.c ${CMAKE_SOURCE_DIR}/src/config)
execute_process(COMMAND  xxd -i ${CMAKE_SOURCE_DIR}/bin/etc/sapp.toml  ${CMAKE_BINARY_DIR}/src/config/sapp.toml.hex.array.c)
execute_process(COMMAND  bash "-c"  "sed -i '1 s/.*/const unsigned char _sapp_toml_sample_file_image[] = {/' ${CMAKE_BINARY_DIR}/src/config/sapp.toml.hex.array.c")
execute_process(COMMAND  bash "-c"  "sed -i '$ s/.*/const int _sapp_toml_sample_file_image_len = sizeof(_sapp_toml_sample_file_image);/' ${CMAKE_BINARY_DIR}/src/config/sapp.toml.hex.array.c")

add_library(config cmd_args.c config_parse.cpp ${CMAKE_BINARY_DIR}/src/config/sapp.toml.hex.array.c)
