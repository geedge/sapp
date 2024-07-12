#ifndef _SAPP_TIMER_PRIVATE_H_
#define _SAPP_TIMER_PRIVATE_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>
#include "support/MESA_atomic.h"
#include "sapp_timer.h"

/* NOTE: the two effective scope options are conflict, can't use as same time */
enum st_ef_scope_t{
	STO_EFFECTIVE_SCOPE_STANDALONE_THREAD		= 1,
	STO_EFFECTIVE_SCOPE_PKT_PROCESS_THREADS		= 2,
};

#ifdef LIBEVENT_ENABLED
#include "support/event2/event.h"
#endif


typedef struct{
	volatile MESA_ATOMIC_T running;
	enum st_ef_scope_t effective_mode;
	struct event_base *libev_base;
	//struct event *libev_event[SAPP_MAX_THREADS+1];
	pthread_t effective_thread_pid;
	int effective_thread_index;
	int event_cnt;
}sapp_timer_handle_inner_t;

typedef struct{
	sapp_timer_handle_inner_t *timer_handle;
#ifdef LIBEVENT_ENABLED	
	struct event *libev_event;
	event_callback_fn libev_cb_fun;
#endif
	sapp_timer_cbfun_t *sapp_plug_cb_fun;
	void *user_arg;
	struct timeval tval;
	int callback_count; // to do
}sapp_timer_event_inner_t;

#ifdef __cplusplus
}
#endif

#endif

