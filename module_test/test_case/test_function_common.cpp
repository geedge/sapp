#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sapp_benchmark.h"

extern void *g_sapp_test_log_handle;

sapp_benchmark_result_t sapp_benchmk_wrap_api(const char *json_file_name)
{
	sapp_benchmark_result_t res;
	sapp_benchmark_handle handle;
	
	handle = sapp_benchmark_create();
	if(NULL == handle){
		return SAPP_BCHMK_RES_ENV_ERROR;
	}

	sapp_benchmark_set_opt(handle, SAPP_BCHMK_OPT_JSON_FILE_NAME, (void *)json_file_name, strlen(json_file_name));
	sapp_benchmark_set_opt(handle, SAPP_BCHMK_OPT_LOG_HANDLE, (void *)g_sapp_test_log_handle, sizeof(void *));

	res = sapp_benchmark_run(handle);

	sapp_benchmark_destroy(handle);

	return res;
}
