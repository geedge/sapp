cmake_minimum_required(VERSION 2.8)


add_subdirectory(iknow)
add_subdirectory(timestamp_record)
add_subdirectory(symbol_check)
add_subdirectory(MESA_sleep)
add_subdirectory(md5)
add_subdirectory(MESA_socket_wrap/src)
add_subdirectory(dictator2/src)
add_subdirectory(tomlc99_wrap)

#if(OPT_USE_DICTATOR)
#	add_subdirectory(dictator2)
#endif()
#
#if(OPT_USE_TXMEM)
#	add_subdirectory(txmem2)
#endif()
