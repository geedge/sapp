suppress_cppcheck_in_current_dir()
add_definitions(-D_DEFAULT_SOURCE -D_GNU_SOURCE -D__DEFAULT_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H -fPIC)
add_library(ulid ulid_wrap.cpp)
