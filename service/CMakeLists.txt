if(CAPTURE_MODE MATCHES "MARSIO")
    configure_file(sapp_marsio.service.in sapp.service)
else()
    configure_file(sapp_default.service.in sapp.service)
endif()

install(FILES ${CMAKE_BINARY_DIR}/service/sapp.service DESTINATION /usr/lib/systemd/system)

execute_process(COMMAND sh sapp_tmpfile.sh ${CMAKE_INSTALL_PREFIX} ${CMAKE_BINARY_DIR} WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/service)
install(FILES ${CMAKE_BINARY_DIR}/sapp_tmpfile.conf DESTINATION /usr/lib/tmpfiles.d/ COMPONENT PROFILE)

