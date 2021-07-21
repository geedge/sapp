set(SAPP_LOG_PATH_VAR "\${SAPP_LOG_ROOT}")

if(CAPTURE_MODE MATCHES "MARSIO")
	configure_file(${PROJECT_SOURCE_DIR}/service/sapp_marsio.service.in ${CMAKE_BINARY_DIR}/service/sapp.service)
	#execute_process(COMMAND cp ${PROJECT_SOURCE_DIR}/service/sapp_marsio.service.in ${CMAKE_BINARY_DIR}/service/sapp.service)
else()
    configure_file(${PROJECT_SOURCE_DIR}/service/sapp_default.service.in ${CMAKE_BINARY_DIR}/service/sapp.service)
	#execute_process(COMMAND cp ${PROJECT_SOURCE_DIR}/service/sapp_default.service.in ${CMAKE_BINARY_DIR}/service/sapp.service)
endif()

configure_file(${PROJECT_SOURCE_DIR}/service/sysconfig/sapp.in ${CMAKE_BINARY_DIR}/service/sapp)

install(FILES ${CMAKE_BINARY_DIR}/service/sapp DESTINATION /etc/sysconfig COMPONENT PROFILE)
install(FILES ${CMAKE_BINARY_DIR}/service/sapp.service DESTINATION /usr/lib/systemd/system)

execute_process(COMMAND sh sapp_tmpfile.sh ${CMAKE_INSTALL_PREFIX} ${CMAKE_BINARY_DIR} WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/service)
install(FILES ${CMAKE_BINARY_DIR}/sapp_tmpfile.conf DESTINATION /usr/lib/tmpfiles.d/ COMPONENT PROFILE)

