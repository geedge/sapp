file(GLOB DEMO
    "*.cpp"
)

add_executable(${lib_name}_demo ${DEMO})
target_link_libraries(${lib_name}_demo  ${lib_name}_static breakpad-client-static MESA_prof_load MESA_handle_logger)

