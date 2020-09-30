#include "sapp_api.h"
#include "sapp_private_api.h"
#include "public/sapp_timer.h"
#include "support/event2/event.h"

#ifdef __cplusplus
extern "C" {
#endif

sapp_timer_handle sapp_get_platform_standalone_timer(void);
static void *sapp_standalone_timer_check_timeout(void *arg);

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
		usleep(1000);
	}
	
	while(MESA_ATOMIC_READ(inner_h->running)){
		event_base_loop(inner_h->libev_base, 0);
		usleep(100);
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
		inner_h->effective_thread_pid = sapp_global_val->individual_fixed.pkt_process_tid[i];
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
		pthread_detach(stand_alone_pid);
		inner_h->effective_thread_pid = stand_alone_pid;
	}else{
		inner_h->effective_thread_pid = sapp_global_val->individual_fixed.pkt_process_tid[inner_h->effective_thread_index];
	}

	MESA_ATOMIC_SET(inner_h->running, 1);
	
	return 0;
}

int sapp_timer_destroy(sapp_timer_handle h)
{
	sapp_timer_handle_inner_t *inner_h = (sapp_timer_handle_inner_t *)h;


	if(__st_is_platform_timer(h)){
		return ST_RET_CANT_OP_PLATFORM_TIMER; /* 不允许外部调用者start 全局句柄 */
	}

	if(STO_EFFECTIVE_SCOPE_PKT_PROCESS_THREADS == inner_h->effective_mode){
		return ST_RET_CANT_OP_PLATFORM_TIMER; /* 不允许外部调用者start 全局句柄 */
	}

	MESA_ATOMIC_SET(inner_h->running, 0);
	pthread_cancel(inner_h->effective_thread_pid);

	///////to do, to be improved

	free(h);

	return ST_RET_SUCC;
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
    clock_gettime(CLOCK_MONOTONIC, &t);
    tms = (t.tv_sec)*1000 + (t.tv_nsec)/(1000*1000);

	return tms;
}


static void *sapp_standalone_timer_check_timeout(void *arg)
{
	sapp_timer_handle_inner_t *inner_h = (sapp_timer_handle_inner_t *)sapp_global_val->individual_fixed.sapp_standalone_timer;
	
	while(1){
		if(MESA_ATOMIC_READ(inner_h->running)){
			event_base_loop(inner_h->libev_base, EVLOOP_NONBLOCK);
		}	
		
		usleep(1);
	}

	return NULL;
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
		
		usleep(100);
	}
	
	return NULL;
}

#ifdef __cplusplus
}
#endif


