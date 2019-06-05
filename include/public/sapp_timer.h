#ifndef _SAPP_TIMER_H_
#define _SAPP_TIMER_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_limits.h"

#if 0


typedef enum{
	STO_EFFECTIVE_SCOPE, 	/* value type is int, refer to STO_EFFECTIVE_SCOPE_xxx */
	STO_PKT_PROCESS_THREAD_NUM, /* value type is int */
}sapp_timer_opt;

#endif

enum st_return_errno{
	ST_RET_SUCC = 0,
	ST_RET_ERROR = -1,
	ST_RET_CANT_OP_PLATFORM_TIMER = -2,
	ST_RET_INVALID_ARGS = -3, 
	ST_RET_NEED_MANDATORY_OPT = -4,
	ST_RET_DIFF_THREAD_CONTEXT = -5, 
};


typedef enum{
	STEO_EFFECTIVE_THREAD_ID, /* value type is int */
	STEO_TIMEOUT_VAL,		/* value type is struct timeval, refer to <linux/time.h> */
	STEO_CALLBACK_FUN,		/* value type is sapp_timer_cbfun_t*   */
	STEO_CALLBACK_FUN_ARG, 	/* value type is void*   */
	STEO_CALLBACK_COUNT,	/* value type is int */
}sapp_event_opt;

typedef void * sapp_timer_handle;
typedef void * sapp_timer_event;

/* NOTE: this timer is active in a standalone thread context, is single thread. */
sapp_timer_handle sapp_standalone_timer_new(void);

/* NOTE: this timer is active in sapp packet process threads context, is multithread. */
sapp_timer_handle sapp_get_platform_timer(int tid);

/*
	NOTE:
		In sapp platform packet process thread context, the pkt_process_thread_id is in region: [0, max_thread_num-1];
		In stand_alone thread context, the pkt_process_thread_id is -1;
*/
typedef void sapp_timer_cbfun_t(sapp_timer_handle h, sapp_timer_event ev, int pkt_process_thread_id, void *user_arg);

/*
	NOTE:
		If you want use sapp platform timer, must call sapp_get_platform_timer(), not sapp_timer_new().
		If you want a independent private timer, must call sapp_timer_new().
*/
sapp_timer_event sapp_timer_event_new(sapp_timer_handle h);

//int sapp_timer_set_opt(sapp_timer_handle h, sapp_timer_opt t_opt, void *t_value, int t_value_len);
int sapp_event_set_opt(sapp_timer_event ev, sapp_event_opt ev_opt, void *ev_value, int ev_value_len);


int sapp_timer_add(sapp_timer_handle h, sapp_timer_event ev);
int sapp_timer_del(sapp_timer_handle h, sapp_timer_event ev);
int sapp_timer_start(sapp_timer_handle h);
int sapp_timer_destroy(sapp_timer_handle h);

#ifdef __cplusplus
}
#endif


#endif
