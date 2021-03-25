# CMakeFiles for 3rd vendor library

include(ExternalProject)
#### GoogleTest
ExternalProject_Add(GoogleTest PREFIX GoogleTest
        URL ${CMAKE_SOURCE_DIR}/vendor/googletest-release-1.8.1.tar.gz
        URL_MD5 2e6fbeb6a91310a16efe181886c59596
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR> -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE})

ExternalProject_Get_Property(GoogleTest INSTALL_DIR)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

add_library(gtest STATIC IMPORTED GLOBAL)
add_dependencies(gtest GoogleTest)
set_property(TARGET gtest PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib64/libgtest.a)
set_property(TARGET gtest PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)
set_property(TARGET gtest PROPERTY INTERFACE_LINK_LIBRARIES pthread)

#libevent
ExternalProject_Add(libevent PREFIX libevent
        URL ${CMAKE_CURRENT_SOURCE_DIR}/libevent-2.1.10-stable.tar.gz
        URL_MD5 999caf86f52943af2363bc8077f00167
        CONFIGURE_COMMAND ./configure --prefix=<INSTALL_DIR> --disable-shared --disable-samples --disable-openssl
        BUILD_COMMAND make LDFLAGS="-ldl"
        BUILD_IN_SOURCE 1)

ExternalProject_Get_Property(libevent INSTALL_DIR)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

add_library(libevent-static STATIC IMPORTED GLOBAL)
add_dependencies(libevent-static libevent)
set_property(TARGET libevent-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libevent.a)
set_property(TARGET libevent-static PROPERTY IMPORTED_INTERFACE_LINK_LIBRARIES pthread crypto)
set_property(TARGET libevent-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)

## dabloom
ExternalProject_Add(libdabloom PREFIX libdabloom
        URL ${CMAKE_CURRENT_SOURCE_DIR}/dablooms-v1.0.1.tar.gz
        URL_MD5 d5fe4df3533c21c55db961d525aead33
        CONFIGURE_COMMAND cd .
        BUILD_COMMAND make
		BUILD_IN_SOURCE 1
        INSTALL_COMMAND make install prefix=<INSTALL_DIR>)

ExternalProject_Get_Property(libdabloom INSTALL_DIR)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

add_library(libdabloom-static STATIC IMPORTED GLOBAL)
add_dependencies(libdabloom-static libdabloom)
set_property(TARGET libdabloom-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libdablooms.a)
set_property(TARGET libdabloom-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)



