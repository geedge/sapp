suppress_cppcheck_in_current_dir()

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/include/private)
include_directories(${CMAKE_SOURCE_DIR}/include/public)
include_directories(${CMAKE_SOURCE_DIR}/include/support)
include_directories(${MESA_SDK_PREFIX}/include)
include_directories(${MESA_SDK_PREFIX}/include/MESA)

add_definitions(-D_DEFAULT_SOURCE -D__FAVOR_BSD -D_XOPEN_SOURCE -D_ISOC99_SOURCE -DHAVE_NET_ETHERNET_H)

add_executable(stream_id_decode stream_id_decode.c)

set(TCPDUMPMESA_LIBS "-L${CMAKE_BINARY_DIR}/src/common -lMESA_jump_layer")
set(TCPDUMPMESA_CFLAGS "-I${CMAKE_SOURCE_DIR}/include/public/stream_inc -Wall -O2")
ExternalProject_Add(tcpdump_mesa
    PREFIX tcpdump_mesa
    URL ${CMAKE_CURRENT_SOURCE_DIR}/tcpdumpmesa.zip
    CONFIGURE_COMMAND env ADDITIONAL_LIBS=${TCPDUMPMESA_LIBS} ./configure
	BUILD_COMMAND make CFLAGS+=${TCPDUMPMESA_CFLAGS} 
    INSTALL_COMMAND ""
    BUILD_IN_SOURCE 1
)
ExternalProject_Get_Property(tcpdump_mesa BINARY_DIR)
install(PROGRAMS ${BINARY_DIR}/tcpdump 
        DESTINATION ./tools/ 
        RENAME tcpdump_mesa
        COMPONENT EXECUTABLE)