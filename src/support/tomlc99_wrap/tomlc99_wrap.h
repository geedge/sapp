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
	int *array, // [OUT] returned value
	int *array_num); // [IN/OUT] IN: max array item number; OUT: config actual array number
		


// Read in specified long integer array value
//
// Return:
//	   0 : success
//	  -1 : error
//	  -2 : array_num is too small to store all configuration
int tomlc99_wrap_load_long_array(
	const char *file,	// [IN] initialization file path
	const char *section,	// [IN] section name in initialization file
	char *key,	// [IN] keyword name in initialization file
	long *array, // [OUT] returned value
	int *array_num); // [IN/OUT] IN: max array item number; OUT: config actual array number

/*
	Consider the array elements value as bit index, set all index bit value as 1, 
	and the combine all the bits together.
	
	The lowest bit index starts from 1.

	example1:
		int int_array[] = {1, 2, 3, 4};
		int comb_int = tomlc99_int_array_combination(int_array, 4);
		the value of comb_int is 0xF, in binary mode is 1111B;
		
	example2:
		int int_array[] = {1, 4, 8, 10};
		int comb_int = tomlc99_int_array_combination(int_array, 4);
		the value of comb_int is 0x289, in binary mode is 0010 1000 1001B;
*/
int tomlc99_int_array_combination(const int *int_array, int array_num);	
long tomlc99_long_array_combination(const long *long_array, int array_num);	


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

