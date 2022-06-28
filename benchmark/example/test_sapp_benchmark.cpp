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
#include "sapp_bchmk_inner.h"

static void *test_sapp_bchmk_lhand;

/* 此文件仅为参考样例, 为了简单编译和发布, 没有使用gtest框架, 可根据需求自行添加 */

/*
	TODO:
		以下的TEST函数99%都是一样的, 只有json文件不一样,
		可以通过脚本遍历TEST_PROFILE文件夹, 第一级目录是TEST的suite_name, 第二级目录是TEST的name,
		新增用例时, 只需要精确构造json文件的内容, shell脚本会自动生成.c文件, 无需人工修改.c代码.
*/


static sapp_benchmark_result_t sapp_benchmk_wrap_api(const char *json_file_name)
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


void TEST_forward_inline_simple(void)
{
	sapp_benchmark_result_t res;
	const char *benchmark_json = "TEST_PROFILE/forward/inline_simple/entry.json";

	res = sapp_benchmk_wrap_api(benchmark_json);
	
	if(res != SAPP_BCHMK_RES_SUCC){
		printf("\033[41mTEST forward.inline_simple fail\033[0m\n");
		abort();
	}else{
		printf("\033[32mTEST forward.inline_simple succ\033[0m\n");
	}
}


void TEST_drop_inline_env(void)
{
	sapp_benchmark_result_t res;
	const char *benchmark_json = "TEST_PROFILE/drop/inline_env/entry.json";

	res = sapp_benchmk_wrap_api(benchmark_json);
	
	if(res != SAPP_BCHMK_RES_SUCC){
		printf("\033[41mTEST drop.inline_env fail\033[0m\n");
		abort();
	}else{
		printf("\033[32mTEST drop.inline_env succ\033[0m\n");
	}
}

void TEST_inject_inline_same_dir(void)
{
	sapp_benchmark_result_t res;
	const char *benchmark_json = "TEST_PROFILE/inject/inline_same_dir/entry.json";

	res = sapp_benchmk_wrap_api(benchmark_json);
	
	if(res != SAPP_BCHMK_RES_SUCC){
		printf("\033[41mTEST inject.inline_same_dir fail\033[0m\n");
		abort();
	}else{
		printf("\033[32mTEST inject.inline_same_dir succ\033[0m\n");
	}
}

void TEST_inject_inline_reverse_dir(void)
{
	sapp_benchmark_result_t res;
	const char *benchmark_json = "TEST_PROFILE/inject/inline_reverse_dir/entry.json";

	res = sapp_benchmk_wrap_api(benchmark_json);
	
	if(res != SAPP_BCHMK_RES_SUCC){
		printf("\033[41mTEST inject.inline_reverse_dir fail\033[0m\n");
		abort();
	}else{
		printf("\033[32mTEST inject.inline_reverse_dir succ\033[0m\n");
	}
}


void TEST_inject_inline_asymmetric_linkinfo(void)
{
	sapp_benchmark_result_t res;
	const char *benchmark_json = "TEST_PROFILE/inject/inline_asymmetric_linkinfo/entry.json";

	res = sapp_benchmk_wrap_api(benchmark_json);
	
	if(res != SAPP_BCHMK_RES_SUCC){
		printf("\033[41mTEST inject.asymmetric_linkinfo fail\033[0m\n");
		abort();
	}else{
		printf("\033[32mTEST inject.asymmetric_linkinfo succ\033[0m\n");
	}
}


void TEST_control_pkt_delay(void)
{
	sapp_benchmark_result_t res;
	const char *benchmark_json = "TEST_PROFILE/control/delay/entry.json";

	res = sapp_benchmk_wrap_api(benchmark_json);
	
	if(res != SAPP_BCHMK_RES_SUCC){
		printf("\033[41mTEST control.delay fail\033[0m\n");
		abort();
	}else{
		printf("\033[32mTEST control.delay succ\033[0m\n");
	}
}



int main(int argc, char *argv[])
{
	MESA_handle_runtime_log_creation("./etc/sapp_log.conf");
	test_sapp_bchmk_lhand = MESA_create_runtime_log_handle("./log/test_sapp_benchmark.log", RLOG_LV_DEBUG);

	MESA_handle_runtime_log(test_sapp_bchmk_lhand, RLOG_LV_DEBUG, "sapp_benchmark", "starting sapp benchmark....\n");

	TEST_forward_inline_simple();
	TEST_drop_inline_env();
	TEST_inject_inline_same_dir();
	TEST_inject_inline_reverse_dir();
	TEST_control_pkt_delay();
	TEST_inject_inline_asymmetric_linkinfo();

	MESA_destroy_runtime_log_handle(test_sapp_bchmk_lhand);

	printf("\033[32m-----------------\033[0m\n");
	printf("\033[32mAll test success!\033[0m\n");
	printf("\033[32m-----------------\033[0m\n");
	
	_exit(0);
	return 0;
}

