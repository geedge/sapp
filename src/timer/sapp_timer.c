#include "sapp_api.h"
#include "sapp_private_api.h"

#ifdef __cplusplus
extern "C" {
#endif



static inline long long sapp_get_current_time_in_ms(void)
{
	struct timeval t;
	long long tms;

	gettimeofday(&t, NULL);

	tms = t.tv_sec * 1000 + t.tv_usec/1000;

	return tms;
}


void *sapp_time_event_thread(void *arg)
{
	time_t last_log_time;

#if(__GNUC__ * 100 + __GNUC_MINOR__ * 10 + __GNUC_PATCHLEVEL__ >= 480) /* 版本判断, 很多旧系统无法编译 */
#ifdef _GNU_SOURCE
	pthread_setname_np(pthread_self(), "sapp_time_event");
#endif
#endif

	last_log_time = time(NULL);
	
	while(1)
	{
		g_CurrentTime = time(NULL);
		ABBR_CURRENT_TIME = time(NULL);
		/*
			NOTE:
			为什么用下面这种方式, 而不是do_something(); sleep(1);

			因为do_something()函数因写硬盘, 本身可能就消耗几十ms, 再加上sleep(1)也并不是精确的休眠1秒, 会略微大于1秒,
			最后造成统计延时间隔实际比1秒大一些, 长时间运行后, 误差就会累积越来越大.
		*/
		if(ABBR_CURRENT_TIME > last_log_time){
			last_log_time = ABBR_CURRENT_TIME;
			sysinfo_output();
		}
		
		ABBR_CURRENT_TIME_MS = sapp_get_current_time_in_ms();
		
		usleep(900);
	}
	
	return NULL;
}

#ifdef __cplusplus
}
#endif


