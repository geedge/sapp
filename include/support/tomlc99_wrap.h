#ifndef _TOMLC99_WRAP_H_
#define _TOMLC99_WRAP_H_ 1

#ifdef __cplusplus
extern "C" {
#endif


/* THis library is developed base on tomlc99 (https://github.com/cktan/tomlc99) */

// Read in specified integer value
//
// Return:
//	   0 : success
//	<  0 : error, val is set to default
int tomlc99_wrap_load_int_def(
	const char *file,	// [IN] initialization file path
	const char *section,	// [IN] section name in initialization file
	char *key,	// [IN] keyword name in initialization file
	int *val,	// [OUT] returned value
	int dval);	// [IN] default value


// Read in specified integer array value
//
// Return:
//	   0 : success
//	  -1 : error
//	  -2 : array_num is too small to store all configuration
int tomlc99_wrap_load_int_array(
	const char *file,	// [IN] initialization file path
	const char *section,	// [IN] section name in initialization file
	char *key,	// [IN] keyword name in initialization file
	long *array, // [OUT] returned value
	int *array_num); // [IN/OUT] IN: max array item number; OUT: config actual array number

		

// Read in specified string value
//
// Return:
//	   0 : success
//	<  0 : error, val is set to default
int tomlc99_wrap_load_string_def(
	const char *file,	// [IN] initialization file path
	const char *section,	// [IN] section name in initialization file
	char *key,	// [IN] keyword name in initialization file
	char *val,	// [OUT] returned value
	size_t size, // [IN] buffer size(bytes)
	const char *dval);	// [IN] default value	

#ifdef __cplusplus
}
#endif


#endif

