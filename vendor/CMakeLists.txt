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
set_property(TARGET gtest PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib64/libgtest.a)
set_property(TARGET gtest PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)
set_property(TARGET gtest PROPERTY INTERFACE_LINK_LIBRARIES pthread)

#### open ssl
ExternalProject_Add(openssl PREFIX openssl
        URL ${CMAKE_SOURCE_DIR}/vendor/openssl-OpenSSL_1_1_1b.zip
        URL_MD5 6ceb7d73cb61c4c264b3065b29ce8f2c
        CONFIGURE_COMMAND ""
        BUILD_COMMAND make
        INSTALL_COMMAND ""
        BUILD_IN_SOURCE 1)

ExternalProject_Get_Property(openssl SOURCE_DIR)
set(HIREDIS_INCLUDE_DIRECTORIES ${SOURCE_DIR})
file(MAKE_DIRECTORY ${HIREDIS_INCLUDE_DIRECTORIES})

add_library(openssl-static STATIC IMPORTED GLOBAL)
set_property(TARGET openssl-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/libopenssl.a)
set_property(TARGET openssl-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR})


#### libevent
ExternalProject_Add(libevent PREFIX libevent
        URL ${CMAKE_SOURCE_DIR}/vendor/libevent-2.1.10-stable.tar.gz
        URL_MD5 999caf86f52943af2363bc8077f00167
        CMAKE_ARGS -DEVENT__DISABLE_OPENSSL=1 -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR> -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE})

ExternalProject_Get_Property(libevent INSTALL_DIR)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

add_library(event STATIC IMPORTED GLOBAL)
set_property(TARGET event PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libevent.a)
set_property(TARGET event PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)
set_property(TARGET event PROPERTY INTERFACE_LINK_LIBRARIES pthread)

