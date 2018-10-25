#ifndef SLIB_LOADPROF_H
#define SLIB_LOADPROF_H
#include <sys/types.h>

#ifdef WIN32
#define strncasecmp(x,y,z) memicmp(x,y,z)
#endif
#ifdef WIN32
#define LINE_BREAK_TAG	"\r\n"
#else
#define LINE_BREAK_TAG	"\n"
#endif

#define MAX_PROF_LINE	1024	/* MAX bytes in a single line */
#define MAX_IP_SIZE 	16      /* MAX bytes in a single ip string*/
#define COMMENT_CHAR	'#'	/* comments line prefix */
#define SECTION_PRE	'['	/* section name prefix */
#define SECTION_POST	']'	/* section name postfix */
#define VALUE_SET	'='	/* set key value operator */
#define HYPHEN 		'-'
#define TYPE_INT	1
#define TYPE_FLOAT	2
#define TYPE_STRING	3
#ifdef __cplusplus
extern "C" {
#endif


// Read in specified integer value
//
// Return:
//	   0 : success
//	<  0 : error, val is set to default
int MESA_load_profile_int_def(
	char *file,	// [IN] initialization file path
	char *section,	// [IN] section name in initialization file
	char *key,	// [IN] keyword name in initialization file
	int *val,	// [OUT] returned value
	int dval);	// [IN] default value



// Read in specified integer value
//
// Return:
//	0 : success
//	-1 : failed to get the key,may be have no thie section, key or the val which the key pointed error
//	-2 : error ,the val if out of range
int MESA_load_profile_int_nodef(
	char *file,	// [IN] initialization file path
	char *section,	// [IN] section name in initialization file
	char *key,	// [IN] keyword name in initialization file
	int *val);	// [OUT] returned value




// Read in specified unsigned integer value
//
// Return:
//	   0 : success
//	<  0 : error, val is set to default
int MESA_load_profile_uint_def(
	char *file,	// [IN] initialization file path
	char *section,	// [IN] section name in initialization file
	char *key,	// [IN] keyword name in initialization file
	unsigned int *val,	// [OUT] returned value
	unsigned int dval);	// [IN] default value



// Read in specified unsigned integer value
//
// Return:
//	0 : success
//	-1 : failed to get the key,may be have no thie section, key or the val which the key pointed error
//	-2 : error ,the val if out of range
int MESA_load_profile_uint_nodef(
	char *file,	// [IN] initialization file path
	char *section,	// [IN] section name in initialization file
	char *key,	// [IN] keyword name in initialization file
	unsigned int *val);	// [OUT] returned value



// Read in specified short integer value
//
// Return:
//	   0 : success
//	<  0 : error, val is set to default
int MESA_load_profile_short_def(
	char *file,	// [IN] initialization file path
	char *section,	// [IN] section name in initialization file
	char *key,	// [IN] keyword name in initialization file
	short *val,	// [OUT] returned value
	short dval);    // [IN] default value


 
// Read in specified short integer value
//
// Return:
//	0 : success
//	-1 : failed to get the key,may be have no thie section, key or the val which the key pointed error
//	-2 : error ,the val if out of range
int MESA_load_profile_short_nodef(
	char *file,	// [IN] initialization file path
	char *section,	// [IN] section name in initialization file
	char *key,	// [IN] keyword name in initialization file
	short *val);	// [OUT] returned value



// Read in specified string value,
// if value string is too long to return, extra chars truncated.
// prefix/postfix space chars cutted,
// space chars: ' ', '\t' '\n' '\r'
//
// Return:
//	>= 0 : length of val
//	  -1 : failed to get the key,may be have no thie section, key or the val which the key pointed error

int MESA_load_profile_string_nodef(
	char *file,	// [IN] initialization file path
	char *section,	// [IN] section name in initialization file
	char *key,	// [IN] keyword name in initialization file
	char *str,	// [OUT] returned string
	size_t size);	// [IN] buffer size(bytes)



// Read in specified string value,
// if value string is too long to return, extra chars truncated.
// prefix/postfix space chars cutted,
// space chars: ' ', '\t' '\n' '\r'
//
// Return:
//	>= 0 : length of val
//	<  0 : error, str is set to default
int MESA_load_profile_string_def(
	char *file,	// [IN] initialization file path
	char *section,	// [IN] section name in initialization file
	char *key,	// [IN] keyword name in initialization file
	char *str,	// [OUT] returned string
	size_t size,	// [IN] buffer size(bytes)
	char *dstr);	// [IN] default string



//read ips from config file
//return :
// 	>=0 : success,return the number of ip read from file successfully
// 	-1  : failed to get the key,may be have no thie section, key or the val which the key pointed error
//	-2  : error,invalid ip


int MESA_load_profile_ipset(
	char *file,	// [IN] initialization file path
	char *section,	// [IN] section name in initialization file
	char *key,	// [IN] keyword name in initialization file
	size_t size,  // [IN] the size of memory ips point,it must equel or greater than ip_num*sizeof(unsigned int)
	unsigned int *ipset); 	// [OUT] return ipset network bytes order

// Write the a int into specified position of the config file,the position is decided by section and key
// Return:
//	>= 0 : success
//	  -1 : failed to write profile,maybe fopen failed, or malloc failed 
int MESA_write_profile_int(
	const char *file,	// [IN] initialization file path
	const char *section,  // [IN] section name in initialization file
	const char *key,   // [IN] keyword name in initialization file
	int value);    // [IN] the integer need write 

// Write the a float into specified position of the config file,the position is decided by section and key
// Return:
//	>= 0 : success
//	  -1 : failed to write profile,maybe fopen failed, or malloc failed 
int MESA_write_profile_float(
	const char *file,	// [IN] initialization file path
	const char *section,  // [IN] section name in initialization file
	const char *key,   // [IN] keyword name in initialization file
	float value);    // [IN] the float need write 

// Write the a string into specified position of the config file,the position is decided by section and key
// Return:
//	>= 0 : success
//	  -1 : failed to write profile,maybe fopen failed, or malloc failed 
int MESA_write_profile_string(
	const char *file,	// [IN] initialization file path
	const char *section,  // [IN] section name in initialization file
	const char *key,   // [IN] keyword name in initialization file
	char *value);    // [IN] the string need write 
#ifdef __cplusplus
}
#endif

#endif /* #ifndef SLIB_LOADPROF_H */
