
if(CAPTURE_MODE MATCHES "MARSIO")
    #configure_file(sapp_marsio.service.in sapp.service)
    install(FILES ${PROJECT_SOURCE_DIR}/service/sapp-env-marsio.service.in DESTINATION /usr/lib/systemd/system/ RENAME sapp-env.service)
    install(FILES ${PROJECT_SOURCE_DIR}/service/sapp_marsio.service.in DESTINATION /usr/lib/systemd/system/ RENAME sapp.service)
else()
    #configure_file(sapp_default.service.in sapp.service)
    install(FILES ${PROJECT_SOURCE_DIR}/service/sapp-env-default.service.in DESTINATION /usr/lib/systemd/system/ RENAME sapp-env.service)
    install(FILES ${PROJECT_SOURCE_DIR}/service/sapp_default.service.in DESTINATION /usr/lib/systemd/system/ RENAME sapp.service)
endif()

install(PROGRAMS ${PROJECT_SOURCE_DIR}/service/setup.sh DESTINATION /opt/sapp/env)
install(PROGRAMS ${PROJECT_SOURCE_DIR}/service/fake_sapp DESTINATION /opt/sapp/bin)

