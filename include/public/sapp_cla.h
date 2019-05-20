#ifndef _SAPP_CLA_H_
#define _SAPP_CLA_H_ 1

#include "sapp_std.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
	For get command-line arguments(CLA).
	
	Note:
		The string value 'opt_string_value' is read-only, 
		caller must not modify or free it after call sapp_get_cla_raw().
		
	return value:
		-1: not found opt_long_name;
		 0: opt_long_name is set but no argument value. 
		 1: opt_long_name is set and has valid argument store in *opt_string_value. 
*/
int sapp_get_cla_raw(const char *opt_long_name, char ** const opt_string_value);


/*
	For get command-line arguments(CLA).
		
	return value:
		-1: not found opt_long_name;
		 0: opt_long_name is set but no argument value. 
		 1: opt_long_name is set and has valid argument store in *opt_long_value. 
*/
int sapp_get_cla_long(const char *opt_long_name, long long *opt_long_value);


#ifdef __cplusplus
}
#endif


#endif
