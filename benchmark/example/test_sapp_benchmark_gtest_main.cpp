#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/types.h>	 
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include "stream.h"
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "sapp_benchmark.h"
#include <gtest/gtest.h>
#include "MESA_handle_logger.h"

extern int gtest_run(int argc, char *argv[]);
extern int gtest_run2(int argc, char *argv[]);
extern void *test_sapp_bchmk_lhand;
void *test_sapp_bchmk_lhand;

sapp_benchmark_result_t sapp_benchmk_wrap_api(const char *json_file_name)
{
	sapp_benchmark_result_t res;
	sapp_benchmark_handle handle;
	
	handle = sapp_benchmark_create();
	if(NULL == handle){
		return SAPP_BCHMK_RES_ENV_ERROR;
	}

	sapp_benchmark_set_opt(handle, SAPP_BCHMK_OPT_JSON_FILE_NAME, (void *)json_file_name, strlen(json_file_name));
	sapp_benchmark_set_opt(handle, SAPP_BCHMK_OPT_LOG_HANDLE, (void *)test_sapp_bchmk_lhand, sizeof(void *));

	res = sapp_benchmark_run(handle);

	sapp_benchmark_destroy(handle);

	return res;
}

static void usage(int argc, char *argv[])
{
	printf("args example:\n"); 
	printf("\t%s short-arg long-arg\n", argv[0]);
	printf("\t%s -l --gtest_list_tests\n", argv[0]);
	printf("\t%s -f --gtest_filter=forward.inline_simple\n", argv[0]);
	exit(1);
}


int main(int argc, char *argv[])
{
	int ret;

	char args_buf[1024]={};
	
	if((2 == argc)  && (strncasecmp(argv[1], "-h", 2) == 0)){
		usage(argc, argv);
	}
	if((argc >= 2) && (strncasecmp(argv[1], "-l", 2) == 0)){
		argv[1] = (char *)"--gtest_list_tests";
	}
	if((argc >= 2) && (strncasecmp(argv[1], "-f", 2) == 0)){
		if(argc!=3){
			usage(argc, argv);
		}
		strcpy(args_buf, "--gtest_filter=");
		strcat(args_buf, argv[2]);
		argv[1] = args_buf;
	}		
	
	MESA_handle_runtime_log_creation("./etc/sapp_log.conf");
	test_sapp_bchmk_lhand = MESA_create_runtime_log_handle("./log/test_sapp_benchmark.log", RLOG_LV_DEBUG);

	MESA_handle_runtime_log(test_sapp_bchmk_lhand, RLOG_LV_DEBUG, "sapp_benchmark", "starting sapp benchmark....\n");

	::testing::InitGoogleTest(&argc, argv);
	ret = gtest_run(argc, argv);
	
	MESA_destroy_runtime_log_handle(test_sapp_bchmk_lhand);

	_exit(ret);
	
	return ret;
}

