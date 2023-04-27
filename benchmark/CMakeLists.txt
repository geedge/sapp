cmake_minimum_required(VERSION 2.8...3.10)

add_subdirectory(./src)
add_subdirectory(./example)

set(CMAKE_INSTALL_FULL_LIBEXECDIR ${CMAKE_INSTALL_PREFIX})
set(CMAKE_INSTALL_FULL_SHAREDSTATEDIR ${CMAKE_INSTALL_PREFIX}/etc)
set(CMAKE_INSTALL_FULL_DATAROOTDIR ${CMAKE_INSTALL_PREFIX}/plug)
set(CMAKE_INSTALL_FULL_SYSCONFDIR /usr/lib/systemd/system)

#add_test(NAME COPY_TSHARK COMMAND sh -c "cp ${PROJECT_SOURCE_DIR}/vendor/tshark_v3.2.17/tshark ${CMAKE_BINARY_DIR}/testing/bin")
