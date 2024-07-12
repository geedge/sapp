#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <linux/limits.h>
#include <sys/sysinfo.h>
#include "cpu_limit.h"

#ifdef __cplusplus
extern "C" {
#endif


#define DEBUG_PRINT  0
#if DEBUG_PRINT
#define DPRINT(fmt, args...)    printf(fmt, ## args)
#else
#define DPRINT(fmt, args...)
#endif


#define MAX_THREAD_COUNT	(128)
#define CL_HISTORY_FACTOR_NUM (10)
#define CPUL_MAGIC_NUM		(0xCC12345678LU)

typedef enum{
	CL_LIMIT_STATE_PENDING = 0, 
	CL_LIMIT_STATE_OBSERVE,  
	CL_LIMIT_STATE_REDUCE,  
}cl_limit_state_t;

typedef enum{
	CL_STATE_INIT = 0, 
	CL_STATE_RUNNING = 1,  
	CL_STATE_TO_BE_DESTORY = 2,  
}cl_running_state_t;

static const double g_cpul_limit_min = 1.00;
static const double g_cpul_recovery_bypass_percent = 0.05; 

struct __cpul_mthread_stat{
	cl_limit_state_t op_state; 

	int recent_smooth_index; 
	double *recent_smooth_res_value; 
	double realtime_res_val;
	
	double last_time_factor_value;
	double actual_limit_factor_value; 

	double history_factor_value[CL_HISTORY_FACTOR_NUM]; 
	unsigned int history_factor_index;
	
	time_t last_abnormal_time;	

	time_t last_adjust_factor_time;

	volatile long long realtime_work_count;
	volatile long long realtime_bypass_count;

	volatile long long observe_work_count;
	volatile long long observe_bypass_count;

	volatile long long debug_factor_work_per_second;
	volatile long long debug_factor_bypass_per_second;
}__attribute__ ((aligned (64)));
typedef struct __cpul_mthread_stat cpul_mthread_stat_t;


typedef struct{
	long long header_magic; 
	volatile cl_running_state_t running_state;
	pthread_t thread_id;
	time_t last_debug_log_print_time;
	time_t global_last_abnormal_time;
	volatile int global_bypass_state;
	
	
	char *debug_log_filename; 
	double user_trigger_value;
	double factor_decrease_ratio;
	double factor_increase_ratio;
	//double user_recovery_value; 
	int recent_res_smooth_number; 
	int stat_interval; 
	int recovery_observe_time; 
	cl_get_res_t get_res_fun;
	cl_get_factor_t get_factor_fun;
	void *user_arg;
	cl_destroy_cb_t destroy_cb_fun;
	int thread_count; 
	time_t current_time; 
	long long last_analysis_time_ms;
	cpul_mthread_stat_t mthread_stat[MAX_THREAD_COUNT];
}cpu_limit_inner_t;


static void cl_get_res(cpu_limit_inner_t *h)
{
	double tmp_res_val, this_time_val;
	int tid, j;
	cpul_mthread_stat_t *this_stat;
	double tmp_smooth_sum_res = 0.0;

	for(tid = 0; tid < h->thread_count; tid++){
		tmp_res_val = h->get_res_fun(h, tid, h->user_arg);
		this_stat = &h->mthread_stat[tid];

		this_time_val = tmp_res_val;

		if(h->recent_res_smooth_number > 1){
			this_stat->recent_smooth_res_value[this_stat->recent_smooth_index] = this_time_val;
			this_stat->recent_smooth_index++;
			if(this_stat->recent_smooth_index >= h->recent_res_smooth_number){
				this_stat->recent_smooth_index = 0;
			}	
		
			for(j = 0, tmp_smooth_sum_res = 0; j < h->recent_res_smooth_number; j++){
				tmp_smooth_sum_res += this_stat->recent_smooth_res_value[j];
			}
			this_stat->realtime_res_val = tmp_smooth_sum_res/h->recent_res_smooth_number;
		}else{
			this_stat->realtime_res_val = this_time_val;
		}
	}
	
}

static void cl_get_factor(cpu_limit_inner_t *h)
{
	int i;
	cpul_mthread_stat_t *this_stat;

	for( i = 0; i < h->thread_count; i++){
		this_stat = &h->mthread_stat[i];
		
		//h->mthread_stat[i].last_time_factor_value = h->get_factor_fun(h, i, h->user_arg);
		this_stat->last_time_factor_value = this_stat->realtime_work_count + this_stat->realtime_bypass_count;	

		this_stat->history_factor_value[this_stat->history_factor_index++ % CL_HISTORY_FACTOR_NUM] = h->mthread_stat[i].last_time_factor_value;
	}
}

static inline void cl_update_limit_factor(cpu_limit_inner_t *h, cpul_mthread_stat_t *this_stat, double differ)
{
	if(this_stat->last_adjust_factor_time < h->current_time){
		this_stat->actual_limit_factor_value = this_stat->actual_limit_factor_value * differ;
		if(this_stat->actual_limit_factor_value < g_cpul_limit_min){
			this_stat->actual_limit_factor_value = g_cpul_limit_min;
		}
		//this_stat->actual_limit_factor_value = this_stat->actual_limit_factor_value + 1;//加法增大
		this_stat->last_adjust_factor_time = h->current_time;
	}
}

static inline double cl_get_history_max_factor(cpul_mthread_stat_t *this_stat)
{
	int i;
	double max_value = 0.0;

	for(i = 0; i < CL_HISTORY_FACTOR_NUM; i++){
		if(this_stat->history_factor_value[i] > max_value){
			max_value = this_stat->history_factor_value[i];
		}
	}

	return max_value;
}

static void cl_analysis_reduce_state(cpu_limit_inner_t *h, int tid, cpul_mthread_stat_t *this_stat)
{
	double history_factor_max_val;
	
	if(0 == this_stat->last_abnormal_time){
		history_factor_max_val = cl_get_history_max_factor(this_stat);
		this_stat->actual_limit_factor_value = history_factor_max_val * h->factor_decrease_ratio;
		this_stat->last_abnormal_time = h->current_time;
	}else{
		cl_update_limit_factor(h, this_stat, h->factor_decrease_ratio);
	}
	
	this_stat->op_state = CL_LIMIT_STATE_REDUCE;
	h->global_last_abnormal_time = h->current_time;

	DPRINT("### thread:%d cl_analysis(), res:%.2f, change to reduce state, CL limit factor:%.2f\n", tid, this_stat->realtime_res_val, this_stat->actual_limit_factor_value);			
}

static int cl_fast_recovery(cpu_limit_inner_t *h, cpul_mthread_stat_t *this_stat)
{
	int recovery = 0;

	if(this_stat->last_abnormal_time + h->recovery_observe_time >= h->current_time){//还未超时
		return 0;
	}
	
	if(this_stat->observe_work_count + this_stat->observe_bypass_count > 0){
		if(((double)this_stat->observe_bypass_count/(double)(this_stat->observe_work_count + this_stat->observe_bypass_count) < g_cpul_recovery_bypass_percent)
		 &&(this_stat->realtime_res_val < h->user_trigger_value*0.9)){
			recovery = 1;
		}
	}else{	 
		recovery = 1;
	}

	return recovery;
}

static void cl_analysis_observe_state(cpu_limit_inner_t *h, int tid, cpul_mthread_stat_t *this_stat)
{
	if(0 == this_stat->last_abnormal_time){
		this_stat->op_state = CL_LIMIT_STATE_PENDING; 	
		return;
	}

	if(cl_fast_recovery(h, this_stat)){ 
		this_stat->last_abnormal_time = 0;	
		this_stat->op_state = CL_LIMIT_STATE_PENDING; 	
		return;
	}

	if((this_stat->observe_work_count + this_stat->observe_bypass_count > 0)
	 && ((double)this_stat->observe_bypass_count/(double)(this_stat->observe_work_count + this_stat->observe_bypass_count) > g_cpul_recovery_bypass_percent)){
		this_stat->last_abnormal_time = h->current_time;				
	}

	if(this_stat->observe_work_count + this_stat->observe_bypass_count > this_stat->actual_limit_factor_value*0.9){
		cl_update_limit_factor(h, this_stat, h->factor_increase_ratio);	
	}
	this_stat->op_state = CL_LIMIT_STATE_OBSERVE;	

	return ;
}

#include "sapp_declaration.h"

static void cl_analysis(cpu_limit_inner_t *h)
{
	cpul_mthread_stat_t *this_stat;
	int tid;

	for(tid = 0; tid < h ->thread_count; tid++){
		this_stat = &h->mthread_stat[tid];
		
		if(this_stat->realtime_res_val >= h->user_trigger_value){//超最高限制阈值
			cl_analysis_reduce_state(h, tid, this_stat);
			if(this_stat->realtime_res_val >= 99.9)
			{
				sapp_process_latency_log(RLOG_LV_FATAL, "[cpu_limit] thread_index:%d usage:%.2f over 99.9%%, send SIGUSR2 to pthread_id:%llu, tid:%d", 
										tid, this_stat->realtime_res_val, sapp_global_val->individual_fixed.thread_obtain_id[tid],sapp_global_val->individual_fixed.thread_tid[tid]);
				if(MESA_handle_runtime_log_level_enabled(ABBR_PROCESS_LATENCY_LOG_HANDLE, RLOG_LV_INFO))
				{
					pthread_kill(sapp_global_val->individual_fixed.thread_obtain_id[tid], SIGUSR2);
				}
			}
		}else{
			cl_analysis_observe_state(h, tid, this_stat);
		}
	}

	return;
}

static const char *cl_op_state_ntop(cl_limit_state_t cl_op_state)
{
	const char *string_state;
	
	switch(cl_op_state){
		case CL_LIMIT_STATE_PENDING:
			string_state = "pending";
		break;

		case CL_LIMIT_STATE_OBSERVE:
			string_state = "observe";
		break;

		case CL_LIMIT_STATE_REDUCE:
			string_state = "reduce";
		break;
	}

	return string_state;
}


static char *cl_timet_to_str(time_t timet, char *time_str, int time_str_len)
{
    struct tm *now;

    if(NULL == time_str || time_str_len <= (int)strlen("YY-MM-DD HH:MM:SS"))
    {
        return (char *)"1970-01-01 error";
    }	

    now = localtime(&timet);
    strftime(time_str, time_str_len, "%Y-%m-%d %H:%M:%S", now);

    return time_str;
}

static void cl_debug_log(cpu_limit_inner_t *h)
{
	int tid;
	int thread_bypass_state = 0;
	FILE *fp;
	cpul_mthread_stat_t *this_stat;
	
	if(NULL == h->debug_log_filename){
		return;
	}

	if(h->last_debug_log_print_time >= h->current_time){
		return;
	}
	h->last_debug_log_print_time = h->current_time;

	fp = fopen(h->debug_log_filename, "w+");
	if(NULL == fp){
		return;
	}

	char cur_time_string[64];
	fprintf(fp, "%s\n", cl_timet_to_str(h->current_time, cur_time_string, sizeof(cur_time_string)));
	
	fprintf(fp, "User define bypass trigger threshod:%.2f%%\n", h->user_trigger_value);
	//fprintf(fp, "User define low recovery threshod:%.2f\n", h->user_recovery_value);
	fprintf(fp, "User define get res interval:%dms\n", h->stat_interval);
	if(h->global_last_abnormal_time != 0){	
		char abnormal_time_string[64];
		fprintf(fp, "lastest abnormal time:%s\n", cl_timet_to_str(h->global_last_abnormal_time, abnormal_time_string, sizeof(abnormal_time_string)));
	}
	fprintf(fp, "-------------------------------------------------------------------------------\n");

	fprintf(fp, "%9s %7s %9s %15s %18s CL_Limit(/%dms)\n", "Thread_ID", "State", "CPU_Usage", "Req_Factor(/s)","Bypass_Factor(/s)", h->stat_interval);
	for(tid = 0; tid < h ->thread_count; tid++){
		this_stat = &h->mthread_stat[tid];
		
		if(this_stat->op_state != CL_LIMIT_STATE_PENDING){
			thread_bypass_state++;
		}
		if(CL_LIMIT_STATE_PENDING == this_stat->op_state){
			fprintf(fp, "%9d %7s %9.2f %15lld %18lld %15s\n", tid, 
					cl_op_state_ntop(this_stat->op_state), 
					this_stat->realtime_res_val, 
					this_stat->debug_factor_work_per_second + this_stat->debug_factor_bypass_per_second,
					this_stat->debug_factor_bypass_per_second,
					"infinity");
		}else{
			fprintf(fp, "%9d %7s %9.2f %15lld %18lld %15.2f\n", tid, 
					cl_op_state_ntop(this_stat->op_state), 
					this_stat->realtime_res_val, 
					this_stat->debug_factor_work_per_second + this_stat->debug_factor_bypass_per_second,
					this_stat->debug_factor_bypass_per_second,
					this_stat->actual_limit_factor_value);
		}

		this_stat->debug_factor_work_per_second = 0;
		this_stat->debug_factor_bypass_per_second = 0;
	}
	fprintf(fp, "-------------------------------------------------------------------------------\n");
	
	if(0 == thread_bypass_state){
		h->global_bypass_state = 0;
	}else{
		h->global_bypass_state = 1;
	}

	fprintf(fp, "Global BYAPSS status: %s\n", (h->global_bypass_state > 0)?"YES":"NO");
	fclose(fp);

	h->last_debug_log_print_time = h->current_time;
}


static void cl_clear_counter(cpu_limit_inner_t *h)
{
	int i;
	for( i = 0; i < h->thread_count; i++){	
		h->mthread_stat[i].realtime_work_count = 0;
		h->mthread_stat[i].realtime_bypass_count = 0;
		h->mthread_stat[i].observe_work_count = 0;
		h->mthread_stat[i].observe_bypass_count = 0;			
	}

}

static inline long long _cl_get_current_time_in_ms(void)
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

extern int sapp_usleep(int usec);

static void *cl_bg_thread(void *_arg_h)
{
	cpu_limit_inner_t *h = (cpu_limit_inner_t *)_arg_h;
	long long cur_time_ms = 0;

	while(CL_STATE_RUNNING != h->running_state){
		h->current_time = time(NULL);
		sleep(1);
	}
	
	while(CL_STATE_RUNNING == h->running_state){
		cl_get_res(h);
		cl_get_factor(h);
		cl_analysis(h);
		cl_debug_log(h);
		cl_clear_counter(h);
		
		h->current_time = time(NULL);

		while(h->last_analysis_time_ms + h->stat_interval > cur_time_ms){
			sapp_usleep(10);
			cur_time_ms = _cl_get_current_time_in_ms();
		}
		h->last_analysis_time_ms = cur_time_ms;
	}
	
	return NULL;
}

int cpu_limit_set_opt(cpu_limit_handle _arg_h, cpu_limit_opt opt, void *value, int value_len)
{
	int ret = 0;
	cpu_limit_inner_t *h = (cpu_limit_inner_t *)_arg_h;

	if(NULL == _arg_h || NULL == value || value_len <= 0){
		return -1;
	}

	if(h->running_state != CL_STATE_INIT){
		return -1;
	}

	switch(opt){
		case CL_OPT_DEBUG_LOG_FILE_NAME:
		{
			int filename_len = strnlen((char *)value, PATH_MAX);
			h->debug_log_filename = (char *)calloc(1, filename_len+1);
			strncpy(h->debug_log_filename, value, filename_len);
		}
		break;
		
		case CL_OPT_RES_TRIGGER_THRESHOLD:
			h->user_trigger_value = *(double *)value;
		break;

		case CL_OPT_FACTOR_DECREASE_RATIO:
			h->factor_decrease_ratio = *(double *)value;
		break;

		case CL_OPT_FACTOR_INCREASE_RATIO:
			h->factor_increase_ratio = *(double *)value;
		break;
		
		case CL_OPT_THREAD_COUNT:
			h->thread_count = *(int *)value;
		break;

		case CL_OPT_RES_SMOOTH_SCOPE:
			h->recent_res_smooth_number = *(int *)value;
		break;

		case CL_OPT_STAT_INTERVAL:
			h->stat_interval = *(int *)value;
		break;

		case CL_OPT_OBSERVE_TIME:
			h->recovery_observe_time  = *(int *)value;
		break;
		

		case CL_OPT_RES_GET_FUN:
			h->get_res_fun = (cl_get_res_t )value;
		break;

#if 0
		case CL_OPT_RES_GET_TYPE:
			h->get_res_type = *(cpu_limit_get_value_type_t *)value;
		break;
#endif
		case CL_OPT_FACTOR_GET_FUN:
			h->get_factor_fun = (cl_get_factor_t )value;
		break;

#if 0
		case CL_OPT_FACTOR_GET_TYPE:
			h->get_factor_type = *(cpu_limit_get_value_type_t *)value;
		break;		
#endif
		case CL_OPT_USER_ARG:
			h->user_arg = (void *)value;
		break;

		case CL_OPT_DESTROY_CALLBCAK_FUN:
			h->destroy_cb_fun = (cl_destroy_cb_t )value;
		break;

		default:
			ret = -1;
		break;
	}

	return ret;
}

int cpu_limit_get_opt(cpu_limit_handle _arg_h, cpu_limit_opt opt, void *value, int *value_len)
{
	int ret = 0;

	cpu_limit_inner_t *h = (cpu_limit_inner_t *)_arg_h;

	if(NULL == _arg_h || NULL == value || NULL == value_len){
		return -1;
	}

    switch (opt)
    {
    case CL_OPT_GLOBAL_BYPASS_STATE: {
        if (h->running_state != CL_STATE_RUNNING)
        {
            return -1;
        }
        int *out_value = (int *)value;
        *out_value = h->global_bypass_state;
    }
    break;
    default:
        break;
    }

    return ret;
}

cpu_limit_handle cpu_limit_create(void)
{
	cpu_limit_inner_t *h = calloc(1, sizeof(cpu_limit_inner_t));

	h->header_magic = CPUL_MAGIC_NUM;
	h->stat_interval = 1000; //默认1秒
	h->recent_res_smooth_number = 1;
	h->thread_count = 1;
	h->running_state = CL_STATE_INIT;
	
	return h;
}

int cpu_limit_start(cpu_limit_handle _arg_h)
{
	cpu_limit_inner_t *h = (cpu_limit_inner_t *)_arg_h;
	int i;
	
	if(NULL == h->get_res_fun){
		return -1;
	}
	if(NULL == h->get_factor_fun){
		return -1;
	}	
	for(i = 0; i < h->thread_count; i++){
		h->mthread_stat[i].recent_smooth_res_value = (double *)calloc(h->recent_res_smooth_number, sizeof(double));
		h->mthread_stat[i].recent_smooth_index = 0;
	}
	pthread_create(&h->thread_id, NULL, cl_bg_thread, _arg_h);
	
	h->running_state = CL_STATE_RUNNING;
	
	return 0;
}

int cpu_limit_can_i_do(cpu_limit_handle _arg_h, int thread_seq)
{
	int can_i_do;
	cpu_limit_inner_t *h = (cpu_limit_inner_t *)_arg_h;
	cpul_mthread_stat_t *this_stat;

	this_stat = &h->mthread_stat[thread_seq];
	if(this_stat->op_state == CL_LIMIT_STATE_PENDING){
		can_i_do =  1;
	}else{
		if((double)this_stat->realtime_work_count > this_stat->actual_limit_factor_value){//超限制阈值
			can_i_do = 0;
		}else{
			can_i_do = 1;
		}
	}

	if(can_i_do){
		this_stat->realtime_work_count++;
		this_stat->observe_work_count++;
		this_stat->debug_factor_work_per_second++;		
	}else{
		this_stat->observe_bypass_count++;
		this_stat->realtime_bypass_count++;
		this_stat->debug_factor_bypass_per_second++;
	}

	return can_i_do;
}

void cpu_limit_destroy(cpu_limit_handle _arg_h)
{
	cpu_limit_inner_t *h = (cpu_limit_inner_t *)_arg_h;
	
	h->running_state = CL_STATE_TO_BE_DESTORY;
	pthread_join(h->thread_id, NULL);
	int i;
    for (i = 0; i < h->thread_count; i++)
    {
        free(h->mthread_stat[i].recent_smooth_res_value);
        h->mthread_stat[i].recent_smooth_index = 0;
    }
	if(h->debug_log_filename)
	{
		free(h->debug_log_filename);
	}

    if(h->destroy_cb_fun){
		h->destroy_cb_fun(_arg_h, h->user_arg);
	}

	//memset(h, 0xFE, sizeof(cpu_limit_inner_t));
	
	free(h);
	
	return;
}

#ifdef __cplusplus
}
#endif

