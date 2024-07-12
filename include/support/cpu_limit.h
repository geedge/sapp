#ifndef _CPU_LIMIT_H_
#define _CPU_LIMIT_H_ 1

#ifdef __cplusplus
extern "C" {
#endif
typedef void * cpu_limit_handle;

typedef double (*cl_get_res_t)(cpu_limit_handle h, int thread_seq, void *user_arg);//thread_seq: [0,CL_OPT_THREAD_COUNT-1]
typedef double (*cl_get_factor_t)(cpu_limit_handle h, int thread_seq,void *user_arg);//thread_seq: [0,CL_OPT_THREAD_COUNT-1]
typedef void (*cl_destroy_cb_t)(cpu_limit_handle h, void *user_arg);

typedef enum{
	/* set options */
	CL_OPT_DEBUG_LOG_FILE_NAME, 
	CL_OPT_RES_TRIGGER_THRESHOLD,  
	CL_OPT_THREAD_COUNT, 
	CL_OPT_RES_SMOOTH_SCOPE,
	CL_OPT_STAT_INTERVAL, 
	CL_OPT_OBSERVE_TIME,
	CL_OPT_RES_GET_FUN, 
	CL_OPT_FACTOR_GET_FUN,
	CL_OPT_USER_ARG, 
	CL_OPT_DESTROY_CALLBCAK_FUN, 
	CL_OPT_FACTOR_DECREASE_RATIO, 
	CL_OPT_FACTOR_INCREASE_RATIO, 

	/* get options */
	CL_OPT_GLOBAL_BYPASS_STATE, 
}cpu_limit_opt;

cpu_limit_handle cpu_limit_create(void);

int cpu_limit_set_opt(cpu_limit_handle h, cpu_limit_opt opt, void *value, int value_len);
int cpu_limit_get_opt(cpu_limit_handle h, cpu_limit_opt opt, void *value, int *value_len);
int cpu_limit_start(cpu_limit_handle h);

int cpu_limit_can_i_do(cpu_limit_handle h, int thread_seq);

void cpu_limit_destroy(cpu_limit_handle h);

#ifdef __cplusplus
}
#endif

#endif