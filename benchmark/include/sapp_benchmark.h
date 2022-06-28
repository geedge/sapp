#ifndef _SAPP_BENCHMARK_H_
#define _SAPP_BENCHMARK_H_ 1

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
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "stream.h"


#ifdef __cplusplus
extern "C" {
#endif


typedef enum{
	SAPP_BCHMK_RES_SUCC			= 1<<0,	/* 测试OK */		
	SAPP_BCHMK_RES_FAIL			= 1<<1,	/* 插件返回错误, 或与json预期结果不一致 */	
	SAPP_BCHMK_RES_ENV_ERROR	= 1<<2,	/* 因配置文件格式错误, pcap包不存在, 或其他异常导致sapp或sapp_benchmark程序没有正常运行, 不一定是待测插件的BUG */
}sapp_benchmark_result_t;

typedef enum{
	SAPP_BCHMK_OPT_JSON_FILE_NAME	= 1<<0, /* 类型:char *, json在磁盘中的文件路径,C字符串格式, 以'\0'结尾      */
	SAPP_BCHMK_OPT_JSON_STRING		= 1<<1,	/* 类型:void *, json字符串在内存中的指针, json数据是C字符串格式, 以'\0'结尾 */
	SAPP_BCHMK_OPT_PLUG_RESULT		= 1<<2, /* 类型:sapp_benchmark_result_t, 插件处理数据包的返回结果 */
	SAPP_BCHMK_OPT_DEFAULT_RESULT	= 1<<3, /* 类型:sapp_benchmark_result_t, 如果因各种异常情况没有调用插件, 插件也就无法调用sapp_benchmark_set_plug_result()返回处理结果, 此时将返回默认结果, 如果不设置此选项默认为SUCC */
	SAPP_BCHMK_OPT_LOG_HANDLE		= 1<<4, /* 类型:void *, MESA_handle_logger句柄, 由外部调用者初始化, 用于输出日志 */ 
}sapp_bchmk_opt_t;

typedef void * sapp_benchmark_handle;

sapp_benchmark_handle sapp_benchmark_create(void);
int sapp_benchmark_set_opt(sapp_benchmark_handle h, sapp_bchmk_opt_t opt, void *value, int value_len);
sapp_benchmark_result_t sapp_benchmark_run(sapp_benchmark_handle h);
void sapp_benchmark_destroy(sapp_benchmark_handle h);

int sapp_benchmark_set_plug_result(sapp_benchmark_result_t res);

#ifdef __cplusplus
}
#endif


#endif


