if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(MY_RPM_NAME_PREFIX "${PROJECT_NAME}-debug")
else()
    set(MY_RPM_NAME_PREFIX "${PROJECT_NAME}")
endif()

message(STATUS "Package: ${MY_RPM_NAME_PREFIX}")

set(CPACK_PACKAGE_VECDOR "MESA")
set(CPACK_PACKAGE_VERSION_MAJOR "${VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${VERSION_PATCH}.${VERSION_BUILD}")
set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
set(CPACK_PACKAGE_VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}.${VERSION_BUILD}")

#execute_process(COMMAND bash -c "echo -ne \"`uname -r | awk -F'.' '{print $(NF-1)\".\"$NF}'`\"" OUTPUT_VARIABLE SYSTEM_VERSION)

execute_process(COMMAND sh changelog.sh ${CMAKE_BINARY_DIR} WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/cmake)
SET(CPACK_RPM_CHANGELOG_FILE ${CMAKE_BINARY_DIR}/changelog.txt)

# RPM Build
set(CPACK_GENERATOR "RPM")
set(CPACK_RPM_AUTO_GENERATED_FILE_NAME ON)
set(CPACK_RPM_FILE_NAME "RPM-DEFAULT")
set(CPACK_RPM_PACKAGE_AUTOREQPROV "no")
set(CPACK_RPM_PACKAGE_RELEASE_DIST "on")
set(CPACK_RPM_DEBUGINFO_PACKAGE "on")
set(CPACK_RPM_PACKAGE_VENDOR "MESA")

set(CPACK_RPM_COMPONENT_INSTALL ON)
set(CPACK_COMPONENTS_IGNORE_GROUPS 1)
set(CPACK_COMPONENTS_GROUPING ONE_PER_GROUP)
set(CPACK_COMPONENT_HEADER_DISPLAY_NAME "develop")

set(CPACK_COMPONENT_EXECUTABLE_REQUIRED TRUE)
set(CPACK_RPM_EXECUTABLE_PACKAGE_NAME ${MY_RPM_NAME_PREFIX})

set(CPACK_COMPONENT_EXECUTABLE_GROUP "executable")
set(CPACK_COMPONENT_LIBRARY_GROUP "executable")
set(CPACK_COMPONENT_PROFILE_GROUP "executable")

set(CPACK_COMPONENT_HEADER_REQUIRED TRUE)
set(CPACK_RPM_HEADER_PACKAGE_NAME "${MY_RPM_NAME_PREFIX}-devel")
set(CPACK_COMPONENT_HEADER_GROUP "header")

set(CPACK_RPM_HEADER_PACKAGE_REQUIRES_PRE ${CPACK_RPM_LIBRARY_PACKAGE_NAME})
set(CPACK_RPM_HEADER_PACKAGE_CONFLICTS ${CPACK_RPM_HEADER_PACKAGE_NAME})

set(CPACK_COMPONENTS_ALL LIBRARY HEADER EXECUTABLE PROFILE)


set(CPACK_RPM_PACKAGE_AUTOREQPROV "no")
set(CPACK_RPM_PACKAGE_AUTOREQ "no")

# setup %config(noreplace)
set(CPACK_RPM_EXECUTABLE_USER_FILELIST "%config(noreplace) ${CMAKE_INSTALL_PREFIX}/etc/gdev.conf"
                "%config(noreplace) ${CMAKE_INSTALL_PREFIX}/etc/sapp.toml"
				"%config(noreplace) ${CMAKE_INSTALL_PREFIX}/etc/send_raw_pkt.conf"
				"%config(noreplace) ${CMAKE_INSTALL_PREFIX}/etc/project_list.conf"
				"%config(noreplace) ${CMAKE_INSTALL_PREFIX}/etc/plugin.conf"
				"%config(noreplace) ${CMAKE_INSTALL_PREFIX}/etc/entrylist.conf"
				"%config(noreplace) ${CMAKE_INSTALL_PREFIX}/plug/conflist.inf"
				"%config(noreplace) ${CMAKE_INSTALL_PREFIX}/etc/gdev_block.conf"
				"%config(noreplace) ${CMAKE_INSTALL_PREFIX}/etc/send_gdev.conf"
				"%config(noreplace) ${CMAKE_INSTALL_PREFIX}/etc/send_route.conf"
				"%config(noreplace) ${CMAKE_INSTALL_PREFIX}/etc/asymmetric_addr_layer.conf"
				"%config(noreplace) ${CMAKE_INSTALL_PREFIX}/etc/vlan_flipping_map.conf"
				"%config(noreplace) ${CMAKE_INSTALL_PREFIX}/etc/stream_compare_layer.conf"
				"%config(noreplace) ${CMAKE_INSTALL_PREFIX}/etc/necessary_plug_list.conf"
				"%config(noreplace) ${CMAKE_INSTALL_PREFIX}/etc/sapp_log.conf"
				"%config(noreplace) /etc/sysconfig/sapp"
				"%config(noreplace) /usr/lib/systemd/system/sapp.service")

# Must uninstall the debug package before install release package
set(CPACK_RPM_PACKAGE_CONFLICTS ${MY_RPM_NAME_PREFIX})

#    set(CPACK_STRIP_FILES TRUE)
include(CPack)



