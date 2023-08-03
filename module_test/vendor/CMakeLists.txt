# CMakeFiles for 3rd vendor library

include(ExternalProject)
# libgtest
ExternalProject_Add(libgtest PREFIX libgtest
        URL ${CMAKE_SOURCE_DIR}/module_test/vendor/googletest-release-1.10.0.tgz
        URL_MD5 ad777f4af22026493ea2782c611b8809
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR> -DCMAKE_BUILD_TYPE=RELWITHDEBINFO
        BUILD_IN_SOURCE 1
        BUILD_COMMAND make -j${CPU_COUNT})
ExternalProject_Get_Property(libgtest INSTALL_DIR)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)
add_library(gtest-static STATIC IMPORTED GLOBAL)
add_dependencies(gtest-static libgtest)
set_property(TARGET gtest-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib64/libgtest.a)
set_property(TARGET gtest-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)
set_property(TARGET gtest-static PROPERTY INTERFACE_LINK_LIBRARIES pthread)
