/* THis library is developed base on tomlc99 (https://github.com/cktan/tomlc99) */

#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "toml.h"
#include "tomlc99_wrap.h"

#ifdef __cplusplus
extern "C"{
#endif

int libtomlc99_wrap_version_VERSION_20190521;

static inline int tmlc99_is_file_exist(const char *filename)
{
	struct stat fstat;
	int fres, ret = 0;

	fres = stat(filename, &fstat);
	if(fres < 0){
		if(ENOENT == errno){
			ret = 0;
		}
	}else{
		ret = 1;
	}

	return ret;
}


static toml_table_t *twrap_get_file_handle(const char *file, char *errbuf, int errbuf_size)
{
	FILE* fp;
	toml_table_t* conf_file_handle;

	/* open file and parse */
	if (0 == (fp = fopen(file, "r"))) {
		strncpy(errbuf, strerror(errno), errbuf_size);
		return NULL;
	}
	conf_file_handle = toml_parse_file(fp, errbuf, errbuf_size);
	fclose(fp);

	if(NULL == conf_file_handle){
		printf("parse config file %s error, %s\n", file, errbuf);
	}

	return conf_file_handle;
}


static inline toml_table_t *twrap_get_section_handle(toml_table_t *file_handle, const char *section)
{
	
	toml_table_t* section_handle;
	char *saved_input_section, *tmp_csv_str;
	char *save_ptr;
	char *sub_section;

	if(strchr(section, '.') != NULL){
		section_handle = file_handle;

		saved_input_section = strdup(section);
		tmp_csv_str = saved_input_section;

		/* 递归查找.后续的最后一个section */
		while((sub_section = strtok_r(tmp_csv_str, ".", &save_ptr)) != NULL){
			section_handle = toml_table_in(section_handle, sub_section);
			if(NULL == section_handle){
				free(saved_input_section);
				return NULL;
			}

			tmp_csv_str = NULL;
		}
		
		free(saved_input_section);
	}else{
		section_handle = toml_table_in(file_handle, section);
	}
	
	return section_handle;
}


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
	int dval)	// [IN] default value
{
	toml_table_t* conf_file_handle;
	toml_table_t* conf_section_handle;
	char errbuf[256];
	const char* raw_str;
	int64_t intval;
	int ret = TOMLC99_RET_PARSE_ERROR;

	if(tmlc99_is_file_exist(file) == 0){
		ret = TOMLC99_RET_FILE_NOT_EXIST;
		goto def_val;
	}

	conf_file_handle = twrap_get_file_handle(file, errbuf, sizeof(errbuf));
	if(NULL == conf_file_handle){
		ret = TOMLC99_RET_PATTERN_ERROR;
		goto def_val;
	}

	conf_section_handle = twrap_get_section_handle(conf_file_handle, section);
	if(NULL == conf_section_handle){
		ret = TOMLC99_RET_SECTION_NOT_EXIST;
		goto err_1;
	}	
	
	/* extract config value */
	raw_str = toml_raw_in(conf_section_handle, key);
	if(NULL == raw_str){
		goto err_1;
	}

	if(toml_rtoi(raw_str, &intval) < 0){
		goto err_1;
	}

	*val = (int)intval;
	
	/* done with conf */
	toml_free(conf_file_handle);

	return TOMLC99_RET_SUCCESS;

err_1:
	toml_free(conf_file_handle);

def_val:
	*val = dval;
	return ret;
}


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
	int *array,	// [OUT] returned value
	int *array_num) // [IN/OUT] IN: max array item number; OUT: config actual array number
{
	toml_table_t* conf_file_handle;
	toml_table_t* conf_section_handle;
	char errbuf[256];
	toml_array_t *cfg_array;
	int cfg_array_num;
	const char* raw_str;
	int *int_val;
	long long tmp_long_val;
	int ret = TOMLC99_RET_PARSE_ERROR;

	if(tmlc99_is_file_exist(file) == 0){
		ret = TOMLC99_RET_FILE_NOT_EXIST;
		goto def_val;
	}
	

	conf_file_handle = twrap_get_file_handle(file, errbuf, sizeof(errbuf));
	if(NULL == conf_file_handle){
		ret =  TOMLC99_RET_PATTERN_ERROR;
		goto def_val;
	}

	conf_section_handle = twrap_get_section_handle(conf_file_handle, section);
	if(NULL == conf_section_handle){
		ret = TOMLC99_RET_SECTION_NOT_EXIST;
		goto err_1;
	}	
	
	/* extract host config value */
	cfg_array = toml_array_in(conf_section_handle, key);
	if(NULL == cfg_array){
		ret = TOMLC99_RET_PARSE_ERROR;
		goto err_1;
	}

	int_val = (int *)malloc(sizeof(int));
	
	for (cfg_array_num = 0; NULL != (raw_str = toml_raw_at(cfg_array, cfg_array_num)); cfg_array_num++){
		if(toml_rtoi(raw_str, (int64_t *)&tmp_long_val) < 0){ /* 2021-06-02 lijia fix memory overflow bug */
			ret = TOMLC99_RET_PARSE_ERROR;
			goto err_2;
		}

		int_val[cfg_array_num] = (int)tmp_long_val;
		 int *tmp = (int *)realloc(int_val, sizeof(int) * (cfg_array_num + 2));
		 if(tmp)int_val=tmp;
	}

	if(cfg_array_num > *array_num){
		ret = TOMLC99_RET_ARRAY_NUM_OVERFLOW;
		goto err_2;
	}

	memcpy(array, int_val, sizeof(int) * cfg_array_num);
	*array_num = cfg_array_num;

	/* done with conf */
	toml_free(conf_file_handle);
	free(int_val);

	return TOMLC99_RET_SUCCESS;

err_2:
	free(int_val);
	
err_1:
	toml_free(conf_file_handle);

def_val:
	*array_num = 0;
	return ret;
}


// Read in specified integer array value
//
// Return:
//	   0 : success
//	  -1 : error
//    -2 : array_num is too small to store all configuration
int tomlc99_wrap_load_long_array(
	const char *file,	// [IN] initialization file path
	const char *section,	// [IN] section name in initialization file
	char *key,	// [IN] keyword name in initialization file
	long *array,	// [OUT] returned value
	int *array_num)	// [IN/OUT] IN: max array item number; OUT: config actual array number
{
	toml_table_t* conf_file_handle;
	toml_table_t* conf_section_handle;
	char errbuf[256];
	toml_array_t *cfg_array;
	int cfg_array_num;
	const char* raw_str;
	long *long_val;
	int ret = TOMLC99_RET_PARSE_ERROR;

	if(tmlc99_is_file_exist(file) == 0){
		ret = TOMLC99_RET_FILE_NOT_EXIST;
		goto def_val;
	}
	

	conf_file_handle = twrap_get_file_handle(file, errbuf, sizeof(errbuf));
	if(NULL == conf_file_handle){
		ret = TOMLC99_RET_PATTERN_ERROR;
		goto def_val;
	}

	conf_section_handle = twrap_get_section_handle(conf_file_handle, section);
	if(NULL == conf_section_handle){
		ret = TOMLC99_RET_SECTION_NOT_EXIST;
		goto err_1;
	}	
	
	/* extract host config value */
	cfg_array = toml_array_in(conf_section_handle, key);
	if(NULL == cfg_array){
		goto err_1;
	}

	long_val = (long *)malloc(sizeof(long));
	
	for (cfg_array_num = 0; NULL != (raw_str = toml_raw_at(cfg_array, cfg_array_num)); cfg_array_num++){
		if(toml_rtoi(raw_str, (int64_t *)&long_val[cfg_array_num]) < 0){
			ret = TOMLC99_RET_PARSE_ERROR;
			goto err_2;
		}

		long_val = (long *)realloc(long_val, sizeof(long) * (cfg_array_num + 2));
	}

	if(cfg_array_num > *array_num){
		ret = TOMLC99_RET_ARRAY_NUM_OVERFLOW;
		goto err_2;
	}

	memcpy(array, long_val, sizeof(long) * cfg_array_num);
	*array_num = cfg_array_num;

	/* done with conf */
	toml_free(conf_file_handle);
	free(long_val);

	return TOMLC99_RET_SUCCESS;

err_2:
	free(long_val);
	
err_1:
	toml_free(conf_file_handle);

def_val:
	*array_num = 0;
	return ret;
}


// Read in specified integer value
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
	const char *dval)	// [IN] default value
{
	toml_table_t* conf_file_handle;
	toml_table_t* conf_section_handle;
	char errbuf[256];
	const char* raw_str;
	char *str_val;
	int ret = TOMLC99_RET_PARSE_ERROR;

	if(tmlc99_is_file_exist(file) == 0){
		ret = TOMLC99_RET_FILE_NOT_EXIST;
		goto def_val;
	}
	
	conf_file_handle = twrap_get_file_handle(file, errbuf, sizeof(errbuf));
	if(NULL == conf_file_handle){
		ret = TOMLC99_RET_PATTERN_ERROR;
		goto def_val;
	}

	conf_section_handle = twrap_get_section_handle(conf_file_handle, section);
	if(NULL == conf_section_handle){
		ret = TOMLC99_RET_SECTION_NOT_EXIST;
		goto err_1;
	}	
	
	/* extract host config value */
	raw_str = toml_raw_in(conf_section_handle, key);
	if(NULL == raw_str){
		goto err_1;
	}

	if (*raw_str != '\'' && *raw_str != '"'){
		strncpy(val, raw_str, size); /* 允许不以'或“开头的字符串类型, 兼容之前的main.conf配置 */
	}else{
		if(toml_rtos(raw_str, &str_val) < 0){
			goto err_1;
		}
		strncpy(val, str_val, size);
		free(str_val);
	}
	
	/* done with conf */
	toml_free(conf_file_handle);
	
	return TOMLC99_RET_SUCCESS;

err_1:
	toml_free(conf_file_handle);

def_val:
	strncpy(val, dval, size);
	
	return ret;
}


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
int tomlc99_int_array_combination(const int *int_array, int array_num)
{
	int i, res = 0;

	if(NULL == int_array || 0 == array_num){
		return 0;
	}

	for(i = 0; i < array_num; i++){
		res |= (1 << (int_array[i]-1));
	}

	return res;
}

long tomlc99_long_array_combination(const long *long_array, int array_num)
{
	int i;
	long res = 0;

	if(NULL == long_array || 0 == array_num){
		return 0;
	}

	for(i = 0; i < array_num; i++){
		res |= (1 << (long_array[i]-1));
	}

	return res;
}



#ifdef __cplusplus
}
#endif

