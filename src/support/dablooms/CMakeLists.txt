cmake_minimum_required(VERSION 2.8...3.10)

add_definitions(-fPIC)
add_library(libdabloom STATIC  src/dablooms.c src/murmur.c src/mem_util.c)