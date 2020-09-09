include(ExternalProject)
### Google Breakpad Binary
### Caution: This package is a pre-compiled binary package, only used in x86_64 servers.
ExternalProject_Add(breakpad
	PREFIX breakpad
	URL ${CMAKE_CURRENT_SOURCE_DIR}/breakpad-master-abfe08e.tar.gz
	URL_MD5 96fb25a9d96cc55db71a7f374ad363b4
	CONFIGURE_COMMAND ./configure --prefix=<INSTALL_DIR>
	BUILD_IN_SOURCE 1)

ExternalProject_Get_Property(breakpad INSTALL_DIR)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include/breakpad)

add_library(breakpad-client-static STATIC IMPORTED GLOBAL)
add_dependencies(breakpad-client-static breakpad)
set_property(TARGET breakpad-client-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libbreakpad_client.a)
set_property(TARGET breakpad-client-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include/breakpad)
target_link_libraries(breakpad-client-static INTERFACE pthread)

# install the minidump tools to target binary dir
install(PROGRAMS ${INSTALL_DIR}/bin/minidump-2-core DESTINATION . COMPONENT EXECUTABLE)
install(PROGRAMS ${INSTALL_DIR}/bin/minidump_dump DESTINATION . COMPONENT EXECUTABLE)
install(PROGRAMS ${INSTALL_DIR}/bin/minidump_stackwalk DESTINATION . COMPONENT EXECUTABLE)
install(PROGRAMS ${INSTALL_DIR}/bin/minidump_upload DESTINATION . COMPONENT EXECUTABLE)

