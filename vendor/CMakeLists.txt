# CMakeFiles for 3rd vendor library

include(ExternalProject)
# GoogleTest
#ExternalProject_Add(GoogleTest PREFIX GoogleTest
#        URL ${CMAKE_SOURCE_DIR}/vendor/googletest-release-1.8.1.tar.gz
#        URL_MD5 2e6fbeb6a91310a16efe181886c59596
#        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR> -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE})
#ExternalProject_Get_Property(GoogleTest INSTALL_DIR)
#file(MAKE_DIRECTORY ${INSTALL_DIR}/include)
#add_library(gtest STATIC IMPORTED GLOBAL)
#add_dependencies(gtest GoogleTest)
#set_property(TARGET gtest PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib64/libgtest.a)
#set_property(TARGET gtest PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)
#set_property(TARGET gtest PROPERTY INTERFACE_LINK_LIBRARIES pthread)


#libevent
if(LIBEVENT_ENABLED)
        ExternalProject_Add(libevent PREFIX libevent
                URL ${CMAKE_CURRENT_SOURCE_DIR}/libevent-2.1.10-stable.tar.gz
                URL_MD5 999caf86f52943af2363bc8077f00167
                CONFIGURE_COMMAND ./configure --prefix=<INSTALL_DIR> --enable-shared CFLAGS=-fPIC --disable-samples --disable-openssl
        BUILD_COMMAND make LDFLAGS="-ldl"
                BUILD_IN_SOURCE 1)

        ExternalProject_Get_Property(libevent INSTALL_DIR)
        file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

        add_library(libevent-static STATIC IMPORTED GLOBAL)
        add_dependencies(libevent-static libevent)
        set_property(TARGET libevent-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libevent.a)
        set_property(TARGET libevent-static PROPERTY IMPORTED_INTERFACE_LINK_LIBRARIES pthread crypto)
        set_property(TARGET libevent-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)
endif()

## dabloom
ExternalProject_Add(libdabloom PREFIX libdabloom
        URL ${CMAKE_CURRENT_SOURCE_DIR}/dablooms-v1.0.1.tar.gz
        URL_MD5 d18efc5e34bad9f96abd7104e6c0913f
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

### jemalloc
if(MEM_POOL STREQUAL "JEMALLOC_STATIC")
        ExternalProject_Add(libjemalloc PREFIX libjemalloc
                URL ${CMAKE_CURRENT_SOURCE_DIR}/jemalloc-5.3.0.tar.gz
                URL_MD5 594dd8e0a1e8c1ef8a1b210a1a5aff5b
                #CONFIGURE_COMMAND ./autogen.sh --prefix=<INSTALL_DIR>
                CONFIGURE_COMMAND ./configure --enable-prof --prefix=<INSTALL_DIR>
                BUILD_COMMAND make
                        BUILD_IN_SOURCE 1
                INSTALL_COMMAND make install prefix=<INSTALL_DIR>)

        ExternalProject_Get_Property(libjemalloc INSTALL_DIR)
        file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

        add_library(libjemalloc-static STATIC IMPORTED GLOBAL)
        add_dependencies(libjemalloc-static libjemalloc)
        set_property(TARGET libjemalloc-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libjemalloc.a)
        set_property(TARGET libjemalloc-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)
endif()

### mimalloc
if(MEM_POOL STREQUAL "MIMALLOC")
        ExternalProject_Add(libmimalloc PREFIX libmimalloc
                URL ${CMAKE_CURRENT_SOURCE_DIR}/mimalloc-2.1.2.tar.gz
                URL_MD5 5179c8f5cf1237d2300e2d8559a7bc55
                CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR> -DCMAKE_BUILD_TYPE=RELWITHDEBINFO)

        ExternalProject_Get_Property(libmimalloc INSTALL_DIR)
        file(MAKE_DIRECTORY ${INSTALL_DIR}/include/mimalloc-2.1)

        add_library(libmimalloc-static STATIC IMPORTED GLOBAL)
        add_dependencies(libmimalloc-static libmimalloc)
        set_property(TARGET libmimalloc-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib64/mimalloc-2.1/libmimalloc.a)
        set_property(TARGET libmimalloc-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include/mimalloc-2.1)

        add_library(libmimalloc-dynamic STATIC IMPORTED GLOBAL)
        add_dependencies(libmimalloc-dynamic libmimalloc)
        set_property(TARGET libmimalloc-dynamic PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib64/mimalloc-2.1/libmimalloc.so)
        set_property(TARGET libmimalloc-dynamic PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include/mimalloc-1.8)
endif()

