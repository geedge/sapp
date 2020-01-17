if(CAPTURE_MODE MATCHES "MARSIO")
    configure_file(sapp_marsio.service.in sapp.service)
else()
    configure_file(sapp_default.service.in sapp.service)
endif()

install(FILES ${CMAKE_BINARY_DIR}/service/sapp.service DESTINATION /usr/lib/systemd/system)

