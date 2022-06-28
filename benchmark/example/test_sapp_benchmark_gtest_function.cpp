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

extern void *test_sapp_bchmk_lhand;
extern sapp_benchmark_result_t sapp_benchmk_wrap_api(const char *json_file_name);

/* 此文件仅为参考样例, 为了简单编译和发布, 没有使用gtest框架, 可根据需求自行添加 */

/*
	TODO:
		以下的TEST函数99%都是一样的, 只有json文件不一样,
		可以通过脚本遍历TEST_PROFILE文件夹, 第一级目录是TEST的suite_name, 第二级目录是TEST的name,
		新增用例时, 只需要精确构造json文件的内容, shell脚本会自动生成.c文件, 无需人工修改.c代码.
*/


TEST(forward, inline_simple)
{
	sapp_benchmark_result_t res;
	const char *benchmark_json = "TEST_PROFILE/forward/inline_simple/entry.json";

	res = sapp_benchmk_wrap_api(benchmark_json);
	
	if(res != SAPP_BCHMK_RES_SUCC){
		printf("\033[41mTEST forward.inline_simple fail\033[0m\n");
	}else{
		printf("\033[32mTEST forward.inline_simple succ\033[0m\n");
	}

	ASSERT_EQ(res, SAPP_BCHMK_RES_SUCC);
}


TEST(drop, inline_env)
{
	sapp_benchmark_result_t res;
	const char *benchmark_json = "TEST_PROFILE/drop/inline_env/entry.json";

	res = sapp_benchmk_wrap_api(benchmark_json);
	
	if(res != SAPP_BCHMK_RES_SUCC){
		printf("\033[41mTEST drop.inline_env fail\033[0m\n");
	}else{
		printf("\033[32mTEST drop.inline_env succ\033[0m\n");
	}

	ASSERT_EQ(res, SAPP_BCHMK_RES_SUCC);
}

TEST(inject, inline_same_dir)
{
	sapp_benchmark_result_t res;
	const char *benchmark_json = "TEST_PROFILE/inject/inline_same_dir/entry.json";

	res = sapp_benchmk_wrap_api(benchmark_json);
	
	if(res != SAPP_BCHMK_RES_SUCC){
		printf("\033[41mTEST inject.inline_same_dir fail\033[0m\n");
	}else{
		printf("\033[32mTEST inject.inline_same_dir succ\033[0m\n");
	}

	ASSERT_EQ(res, SAPP_BCHMK_RES_SUCC);
}

TEST(inject, inline_reverse_dir)
{
	sapp_benchmark_result_t res;
	const char *benchmark_json = "TEST_PROFILE/inject/inline_reverse_dir/entry.json";

	res = sapp_benchmk_wrap_api(benchmark_json);
	
	if(res != SAPP_BCHMK_RES_SUCC){
		printf("\033[41mTEST inject.inline_reverse_dir fail\033[0m\n");
	}else{
		printf("\033[32mTEST inject.inline_reverse_dir succ\033[0m\n");
	}

	ASSERT_EQ(res, SAPP_BCHMK_RES_SUCC);
}


TEST(control, pkt_delay)
{
	sapp_benchmark_result_t res;
	const char *benchmark_json = "TEST_PROFILE/control/delay/entry.json";

	res = sapp_benchmk_wrap_api(benchmark_json);
	
	if(res != SAPP_BCHMK_RES_SUCC){
		printf("\033[41mTEST control.delay fail\033[0m\n");
	}else{
		printf("\033[32mTEST control.delay succ\033[0m\n");
	}

	ASSERT_EQ(res, SAPP_BCHMK_RES_SUCC);
}


int gtest_run(int argc, char *argv[])
{

	int ret=RUN_ALL_TESTS();

	return ret;
}

