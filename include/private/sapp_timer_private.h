#ifndef _SAPP_TIMER_PRIVATE_H_
#define _SAPP_TIMER_PRIVATE_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

#include "support/MESA_atomic.h"
#include "sapp_timer.h"
#include "support/event2/event.h"
#include "support/event2/event_struct.h"

/* NOTE: the two effective scope options are conflict, can't use as same time */
enum st_ef_scope_t{
	STO_EFFECTIVE_SCOPE_STANDALONE_THREAD		= 1,
	STO_EFFECTIVE_SCOPE_PKT_PROCESS_THREADS		= 2,
};


/*
	NOTE:
		1.每个线程只有一个ev_base, 如果是包处理线程启用, 则是thread_cnt个, 可以和独立线程一起开启.
		2.add, new只能在event处理线程调用, 而且只在当前线程生效.
*/
typedef struct{
	volatile MESA_ATOMIC_T running;
	enum st_ef_scope_t effective_mode;
	struct event_base *libev_base;
	//struct event *libev_event[SAPP_MAX_THREADS+1];
	pthread_t effective_thread_pid;
	int effective_thread_index;

	//int thread_cnt; /* sapp平台实际并发线程数, 如果有stand_alone线程, 则固定存储于最后一个index, 即SAPP_TIMER_MAX_THREADS */	
}sapp_timer_handle_inner_t;

/* event需要使用set_opt设置各种参数, 用结构体将标准struct event封装, 存储相关参数 */
typedef struct{
	struct event *libev_event;
	sapp_timer_handle_inner_t *timer_handle;
	event_callback_fn libev_cb_fun;
	sapp_timer_cbfun_t *sapp_plug_cb_fun;
	void *user_arg;
	struct timeval tval;
	int callback_count; // to do
}sapp_timer_event_inner_t;

#ifdef __cplusplus
}
#endif

#endif

