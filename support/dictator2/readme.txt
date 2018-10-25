LDDICTATOR      = -Wl,-wrap,malloc -Wl,-wrap,calloc -Wl,-wrap,free -Wl,-wrap,realloc
Define above variable in Makefile,then use this variable as a ld parameter to enable dictator.
This is enough for shared  dynamic library(.so).
Further more,final executable file need to link with libdictator.a or libdictator_debug.a to include dictator binary.