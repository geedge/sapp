#include "sapp_api.h"
#include "sapp_private_api.h"
#include "public/sapp_timer.h"
#include "support/event2/event.h"
#include <systemd/sd-daemon.h>

#ifdef __cplusplus
extern "C" {
#endif

sapp_timer_handle sapp_get_platform_standalone_timer(void);
static void *sapp_standalone_timer_check_timeout(void *arg);
extern volatile int update_packet_io_status_sw;

static inline int __st_is_platform_timer(void *h)
{
	int i;

	for(i = 0; i < g_iThreadNum; i++){
		if(ABBR_SAPP_TIMER_HANDLE[i] == h){
			return 1;
		}
	}

	return 0;
}

static void __st_libev_callback(evutil_socket_t sd, short event, void *sapp_args)
{
	sapp_timer_event_inner_t *inner_ev = (sapp_timer_event_inner_t *)sapp_args;
	sapp_timer_handle_inner_t *inner_h = inner_ev->timer_handle;

	if(STO_EFFECTIVE_SCOPE_STANDALONE_THREAD == inner_h->effective_mode){
		inner_ev->sapp_plug_cb_fun(inner_ev->timer_handle, inner_ev, -1, inner_ev->user_arg); /* 这里传入外部调用者真正的user_args */
	}else{
		inner_ev->sapp_plug_cb_fun(inner_ev->timer_handle, inner_ev, inner_ev->timer_handle->effective_thread_index, inner_ev->user_arg); /* 这里传入外部调用者真正的user_args */
	}
}


/*
	NOTE:
		STO_EFFECTIVE_SCOPE_PKT_PROCESS_THREADS:
			running: 上下文必须在inner_ev->effective_thread_pid线程.
			not_run: 初始化阶段, 但effective_thread_index必须小于thread_num;

		STO_EFFECTIVE_SCOPE_STANDALONE_THREAD:
			
			
*/
static int __st_timer_event_sanity_check(sapp_timer_handle_inner_t *inner_h, sapp_timer_event_inner_t *inner_ev)
{
	if(NULL == inner_ev->sapp_plug_cb_fun){
		return -1;
	}
	if((0 == inner_ev->tval.tv_sec) && (0 == inner_ev->tval.tv_usec)){
		return -1;
	}

	if((STO_EFFECTIVE_SCOPE_PKT_PROCESS_THREADS == inner_h->effective_mode) 
	  && (-1 == inner_h->effective_thread_index)){
		return -1;
	}
	
	return 0;
}

static int __st_timer_add_online(sapp_timer_handle_inner_t *inner_h, sapp_timer_event_inner_t  *inner_ev)
{
	int ret;
	
	if(0 == pthread_equal(inner_h->effective_thread_pid, pthread_self())){
		return ST_RET_DIFF_THREAD_CONTEXT;
	}

	ret = event_assign(inner_ev->libev_event, inner_h->libev_base, -1, EV_PERSIST, 
				__st_libev_callback, (void*)inner_ev); /* 把inner_ev做为user_args传给libevent */
	if(ret < 0){
		return ST_RET_ERROR;
	}
	ret = event_add(inner_ev->libev_event, &inner_ev->tval);
	if(ret < 0){
		return ST_RET_ERROR;
	}

	return ST_RET_SUCC;
}

static int __st_timer_add_offline(sapp_timer_handle_inner_t *inner_h, sapp_timer_event_inner_t  *inner_ev)
{
	int ret;

	ret = event_assign(inner_ev->libev_event, inner_h->libev_base, -1, EV_PERSIST, 
				__st_libev_callback, (void*)inner_ev); /* 把inner_ev做为user_args传给libevent */
	if(ret < 0){
		return ST_RET_ERROR;
	}
	ret = event_add(inner_ev->libev_event, &inner_ev->tval);
	if(ret < 0){
		return ST_RET_ERROR;
	}

	return ST_RET_SUCC;
}


int sapp_timer_add(sapp_timer_handle sth, sapp_timer_event stev)
{
	sapp_timer_handle_inner_t *inner_h = (sapp_timer_handle_inner_t *)sth;
	sapp_timer_event_inner_t  *inner_ev = (sapp_timer_event_inner_t *)stev;
	int timer_running = 0;
	int ret;

	if(MESA_ATOMIC_READ(inner_h->running) != 0){
		timer_running = 1;
	}
	
	if(__st_timer_event_sanity_check(inner_h, inner_ev) < 0){
		return -1;
	}
	
	if(timer_running){
		ret = __st_timer_add_online(inner_h, inner_ev);
	}else{
		ret = __st_timer_add_offline(inner_h, inner_ev);
	}

	return ret;
}


int sapp_timer_del(sapp_timer_handle sth, sapp_timer_event stev)
{
	sapp_timer_handle_inner_t *inner_h = (sapp_timer_handle_inner_t *)sth;
	sapp_timer_event_inner_t *inner_ev = (sapp_timer_event_inner_t *)stev;
	int timer_running = 0;

	if(MESA_ATOMIC_READ(inner_h->running) != 0){
		timer_running = 1;
	}

	if(timer_running){
		if(0 == pthread_equal(inner_h->effective_thread_pid, pthread_self())){
			return ST_RET_DIFF_THREAD_CONTEXT;
		}

		event_remove_timer(inner_ev->libev_event);
		free(inner_ev->libev_event);
		free(inner_ev);
	}else{
		event_remove_timer(inner_ev->libev_event);
		free(inner_ev->libev_event);
		free(inner_ev);
	}

	return 0;
}

static void *__st_alone_timer_check_thread(void *arg)
{
	sapp_timer_handle_inner_t *inner_h = (sapp_timer_handle_inner_t *)arg;

	while(0 == MESA_ATOMIC_READ(inner_h->running)){
		sapp_usleep(1000);
	}
	
	while(MESA_ATOMIC_READ(inner_h->running)){
		event_base_loop(inner_h->libev_base, 0);
		sapp_usleep(100);
	}

	return NULL;
}

static sapp_timer_handle __st_timer_new(enum st_ef_scope_t scope)
{
	sapp_timer_handle_inner_t *inner_h;


	inner_h = (sapp_timer_handle_inner_t *)calloc(1, sizeof(sapp_timer_handle_inner_t));

	inner_h->libev_base = event_base_new();
	inner_h->effective_mode = scope;
	MESA_ATOMIC_SET(inner_h->running, 0);

	return inner_h;
}


sapp_timer_handle sapp_standalone_timer_new(void)
{
	return (void *)__st_timer_new(STO_EFFECTIVE_SCOPE_STANDALONE_THREAD);
}


sapp_timer_event sapp_timer_event_new(sapp_timer_handle sth)
{
	sapp_timer_event_inner_t *inner_ev;
	sapp_timer_handle_inner_t *inner_h = (sapp_timer_handle_inner_t *)sth;

	inner_ev = (sapp_timer_event_inner_t *)calloc(1, sizeof(sapp_timer_event_inner_t));
	inner_ev->libev_event = (struct event *)calloc(1, sizeof(struct event));
	inner_ev->timer_handle = inner_h;
	inner_h->effective_thread_index = -1;

	return inner_ev;
}


void __st_pkt_proc_context_check_timeout(int tid)
{
	sapp_timer_handle_inner_t *inner_h;

	inner_h = (sapp_timer_handle_inner_t *)ABBR_SAPP_TIMER_HANDLE[tid];

	if(NULL == sapp_global_val || NULL == inner_h){
		return;
	}
	
	if(0 == MESA_ATOMIC_READ(inner_h->running)){
		return;
	}	
	
	event_base_loop(inner_h->libev_base, EVLOOP_NONBLOCK);
}

static void line_protocol_timer_cbfun(sapp_timer_handle h, sapp_timer_event ev, int pkt_process_thread_id, void *user_arg)
{
	line_protocol_update_metrics();
}

static void __st_add_time_event_entry(void)
{
	sapp_timer_handle th;
	sapp_timer_event tev;
	int iopt, ret;
	struct timeval topt;

	th = sapp_get_platform_standalone_timer();
	assert(th);
	tev = sapp_timer_event_new(th);
	assert(tev);
	
	topt.tv_sec = sapp_global_val->config.profiling.log.interval;
	topt.tv_usec = 0;
	sapp_event_set_opt(tev, STEO_TIMEOUT_VAL, &topt, sizeof(topt));
	//sapp_event_set_opt(tev, STEO_CALLBACK_FUN, (void *)&line_protocol_timer_cbfun, sizeof(void *));

	ret = sapp_timer_add(th, tev);
	assert(ret >= 0);

}


int __sapp_timer_platform_init(void)
{
	int i;

	for(i = 0; i < g_iThreadNum; i++){
		ABBR_SAPP_TIMER_HANDLE[i] = __st_timer_new(STO_EFFECTIVE_SCOPE_PKT_PROCESS_THREADS);
	}

	sapp_global_val->individual_fixed.sapp_standalone_timer = __st_timer_new(STO_EFFECTIVE_SCOPE_STANDALONE_THREAD);

	//__st_add_time_event_entry();
	
	return 0;
}

void __sapp_timer_platform_run(void)
{
	int i;
	sapp_timer_handle_inner_t *inner_h;
	

	for(i = 0; i < g_iThreadNum; i++){
		inner_h = (sapp_timer_handle_inner_t *)ABBR_SAPP_TIMER_HANDLE[i];
		inner_h->effective_thread_pid = sapp_global_val->individual_fixed.thread_obtain_id[i];
		MESA_ATOMIC_SET(inner_h->running, 1);
	}

	inner_h = (sapp_timer_handle_inner_t *)sapp_global_val->individual_fixed.sapp_standalone_timer;
	pthread_create(&inner_h->effective_thread_pid, NULL, sapp_standalone_timer_check_timeout, NULL);
	MESA_ATOMIC_SET(inner_h->running, 1);
}

int sapp_event_set_opt(sapp_timer_event ev, sapp_event_opt ev_opt, void *ev_value, int ev_value_len)
{
	int ret = 0;
	sapp_timer_event_inner_t *inner_ev = (sapp_timer_event_inner_t *)ev;
	
	if(!ev || !ev_value){
		return -1;
	}
	
	switch((int)ev_opt){
		case STEO_EFFECTIVE_THREAD_ID:
		{
			int *int_opt_value = (int *)ev_value;
			inner_ev->timer_handle->effective_thread_index = *int_opt_value;
		}
		break;
		
		case STEO_TIMEOUT_VAL:
			memcpy(&inner_ev->tval, ev_value, sizeof(struct timeval));
		break;

		case STEO_CALLBACK_FUN:
			inner_ev->sapp_plug_cb_fun = (sapp_timer_cbfun_t *)ev_value;
		break;

		case STEO_CALLBACK_FUN_ARG:
			inner_ev->user_arg = ev_value;
		break;

		case STEO_CALLBACK_COUNT:
			ret = -1;
			// to do
		break;

		default:
			ret = -1;
	}

	return ret;
}


int sapp_timer_start(sapp_timer_handle h)
{
	pthread_t stand_alone_pid;

	if(__st_is_platform_timer(h)){
		return ST_RET_CANT_OP_PLATFORM_TIMER; /* 不允许外部调用者操作全局句柄 */
	}
	
	sapp_timer_handle_inner_t *inner_h = (sapp_timer_handle_inner_t *)h;
	if(MESA_ATOMIC_READ(inner_h->running) != 0){
		return ST_RET_SUCC; //already start
	}

	if(STO_EFFECTIVE_SCOPE_STANDALONE_THREAD == inner_h->effective_mode){
		pthread_create(&stand_alone_pid, NULL, __st_alone_timer_check_thread, h);
		inner_h->effective_thread_pid = stand_alone_pid;
	}else{
		inner_h->effective_thread_pid = sapp_global_val->individual_fixed.thread_obtain_id[inner_h->effective_thread_index];
	}

	MESA_ATOMIC_SET(inner_h->running, 1);
	
	return 0;
}




sapp_timer_handle sapp_get_platform_timer(int thread_index)
{
	return (void *)ABBR_SAPP_TIMER_HANDLE[thread_index];
}


sapp_timer_handle sapp_get_platform_standalone_timer(void)
{
	return (void *)sapp_global_val->individual_fixed.sapp_standalone_timer;
}


static inline long long sapp_get_current_time_in_ms(void)
{
	long long tms;

	//struct timeval t;
	//gettimeofday(&t, NULL);
	//tms = t.tv_sec * 1000 + t.tv_usec/1000;
	struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    tms = (t.tv_sec)*1000 + (t.tv_nsec)/(1000*1000);

	return tms;
}


static void *sapp_standalone_timer_check_timeout(void *arg)
{
	sapp_timer_handle_inner_t *inner_h = (sapp_timer_handle_inner_t *)sapp_global_val->individual_fixed.sapp_standalone_timer;
	
	while(MESA_ATOMIC_READ(inner_h->running)){
		event_base_loop(inner_h->libev_base, EVLOOP_NONBLOCK);
		sapp_usleep(1);
	}

	return NULL;
}

static void sapp_watch_dog(void)
{
	const char *check_result = "WATCHDOG=1";
	int thread_index;


	if(sapp_global_val->individual_volatile->current_state < SAPP_STATE_PROCESSING){
		return;
	}
	
	/* 需要在sapp.servie 里加入配置:   WatchdogSec=10s */
    if(sd_watchdog_enabled(0, NULL))
    {
	if(sapp_global_val->individual_volatile->current_state == SAPP_STATE_READY_TO_EXIT)
	{
        	sd_notify(0, check_result);
	}
	else
	{
		for (thread_index = 0; thread_index < sapp_global_val->config.cpu.worker_threads; thread_index++)
		{
			/*
				此处不用polling, 而是新增了 SAPP_STAT_FETCH_PKT, 因为没有Proxy时, polling功能可能是关闭的.
				当前时刻跟一秒之前的数一样, 说明线程死锁了
			*/
			if (sapp_global_val->mthread_volatile[thread_index]->sys_stat.count[SAPP_STAT_FETCH_PKT] <= 0)
			{
				check_result = "WATCHDOG=trigger";
				sapp_runtime_log(RLOG_LV_FATAL, "##### detect deadlock in PID:%ld, thread index:%d, TID(LWP):%u, send systemd notify WATCHDOG=trigger #####",
						 getpid(), thread_index, sapp_global_val->individual_fixed.thread_tid[thread_index]);
				break;
			}

			/* 每秒清零, 如果一直累加, SAPP_STAT_FETCH_PKT这个数太大了, 如果使用记录历史数据, 然后与当前数对比的方式, 可能会溢出, 导致判断错误 */
			sapp_global_val->mthread_volatile[thread_index]->sys_stat.count[SAPP_STAT_FETCH_PKT] = 0;
		}

		sd_notify(0, check_result);
	}
    }
    return;
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

	/* 为了避免在docker, 虚拟机, 内存不足的情况下, 此处不能用 current_state != SAPP_STATE_PROCESSING 判断条件 
       曾经出现过dumpfile模式仅读取一个pcap包, 瞬间就退出了, 导致此处死循环的问题!!
	*/
	while(sapp_global_val->individual_volatile->current_state < SAPP_STATE_PROCESSING){
		sapp_usleep(100);
	}

	update_packet_io_status_sw = 1;
	
	while(SAPP_STATE_PROCESSING == sapp_global_val->individual_volatile->current_state || SAPP_STATE_READY_TO_EXIT == sapp_global_val->individual_volatile->current_state)
	{
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
			sapp_mem_stat_output();
			sapp_watch_dog();
		}

		sapp_fuzzy_latency_update();
		
		ABBR_CURRENT_TIME_MS = sapp_get_current_time_in_ms();
		
		sapp_usleep(10);
	}
	
	return NULL;
}

int sapp_timer_destroy(sapp_timer_handle h)
{
	sapp_timer_handle_inner_t *inner_h = (sapp_timer_handle_inner_t *)h;

	if(NULL == inner_h){
		return ST_RET_ERROR;
	}

	MESA_ATOMIC_SET(inner_h->running, 0);
	sapp_usleep(100);
	pthread_join(inner_h->effective_thread_pid, NULL);

	//free 内存在 global_sapp_timer_destroy() 实现
	//free(h);

	return ST_RET_SUCC;
}

void global_sapp_timer_destroy(void)
{
	int i;
	sapp_timer_handle_inner_t *inner_h;
	
	for(i = 0; i < g_iThreadNum; i++){
		inner_h = (sapp_timer_handle_inner_t *)ABBR_SAPP_TIMER_HANDLE[i];
		event_base_free(inner_h->libev_base);
		free(inner_h);
	}

	inner_h = sapp_global_val->individual_fixed.sapp_standalone_timer;	
	event_base_free(inner_h->libev_base);
	free(inner_h);	
}


#ifdef __cplusplus
}
#endif


