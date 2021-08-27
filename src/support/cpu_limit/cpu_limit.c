#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
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
#define DPRINT(fmt, args...)    /* Don't do anything in release builds */
#endif



#define MAX_THREAD_COUNT	(128)
#define CPUL_MAGIC_NUM		(0xCC12345678LU)

typedef enum{
	CL_LIMIT_STATE_PENDING = 0, //检测中, 悬而未决, 没超阈值, 无异常, 不干预外界操作
	CL_LIMIT_STATE_OBSERVE,  //曾经超标过, 观察等待期, 不修改actual_limit_factor_value, 但是也不允许外界操作超过actual_limit_factor_value
	CL_LIMIT_STATE_REDUCE,  //2:超量, 适当降低factor的值
}cl_limit_state_t;

typedef enum{
	CL_STATE_INIT = 0, //初始化阶段
	CL_STATE_RUNNING = 1,  //调用了start, 运行阶段
	CL_STATE_TO_BE_DESTORY = 2,  //2:准备释放所有资源
}cl_running_state_t;


static const double g_cpul_reduce_step = 0.999; /* 超阈值后, factor每次降低的频率 */
static const double g_cpul_raise_step = 1.001;  /* 观察期, factor每次升高的频率 */

static const double g_cpul_recovery_bypass_percent = 0.05; /* 观察期, bypass占比总数小于此值时, 认为可用恢复常态 */ 
static const int g_abnormal_observe_time = 60; //刚从异常态转为正常态, 为了避免抖动, 需要观察一段时间, 单位:秒


struct __cpul_mthread_stat{
	cl_limit_state_t op_state; 

	int recent_smooth_index; //平滑平均值数组下标
	double *recent_smooth_res_value; //默认是1, 即只看最近一次的实时值, 实际看用户设置
	double history_diff_res_value; //如果CL_OPT_RES_TYPE是RES_TYPE_DIFFERENCE, 通过这个数组存储最近两次的值

	double realtime_res_val;//最近一次的资源占用值, 综合计算出来的
	
	double last_time_factor_value;//最近一次用户操作的实际factor值, 比如pps, bps, link_new_create/pps等
	double actual_limit_factor_value; //本次资源限制值, 会随op_state变化

	//int abnormal_observe_time; //曾经超过阈值, 但已经恢复正常了, 观察等待期时间, 单位:秒
	
	/* 会随时间变化, 动态更新的变量, 支持多线程 */
	time_t last_abnormal_time; /* 最后一次异常状态的时间, 0表示从来没有出现过异常, last_abnormal_time==current_time, 说明当前时刻就处于异常状态 */	

	volatile long long realtime_work_count;   /* 实时外部应用请求cpu_limit_can_i_do()函数返回Yes, 即work的次数, 每隔 stat_interval 时间清零 */
	volatile long long realtime_bypass_count; /* 实时外部应用请求cpu_limit_can_i_do()函数返回No,  即bypass的次数, 每隔 stat_interval 时间清零 */

	volatile long long observe_work_count;   /* 观察期外部应用请求cpu_limit_can_i_do()函数返回Yes, 即work的次数 */
	volatile long long observe_bypass_count; /* 观察期外部应用请求cpu_limit_can_i_do()函数返回No,  即bypass的次数 */
}__attribute__ ((aligned (64)));
typedef struct __cpul_mthread_stat cpul_mthread_stat_t;



typedef struct{
	/* 内部私有变量 */
	long long header_magic; 
	volatile cl_running_state_t running_state;
	pthread_t thread_id;
	time_t last_debug_log_print_time;
	
	/* 用户定义的选项或参数, 启动后固定不变 */
	char *debug_log_filename; //是否开启本地debug日志
	double user_trigger_value;
	double user_recovery_value; //低于这个值, 立即恢复正常, 不再限制
	int recent_res_smooth_number;
	int stat_interval; //每次获取资源间隔时间, 单位ms
	cl_get_res_t get_res_fun;
	cl_get_factor_t get_factor_fun;
	//cpu_limit_get_value_type_t get_res_type;
	//cpu_limit_get_value_type_t get_factor_type;
	void *user_arg;
	cl_destroy_cb_t destroy_cb_fun;
	int thread_count; 
	time_t current_time; 
	cpul_mthread_stat_t mthread_stat[MAX_THREAD_COUNT];
}cpu_limit_inner_t;


static void cl_get_res(cpu_limit_inner_t *h)
{
	double tmp_res_val, this_time_val;
	int tid, j, last_time_diff_index;
	cpul_mthread_stat_t *this_stat;
	double tmp_smooth_sum_res = 0.0;

	for(tid = 0; tid < h->thread_count; tid++){
		tmp_res_val = h->get_res_fun(h, tid, h->user_arg);
		this_stat = &h->mthread_stat[tid];

		/* 获取当前时刻的res值, 可能是绝对值, 可能需要求两次的差值 */
		//if(RES_TYPE_DIFFERENCE == h->get_res_type)
		if(0){
			if(this_stat->history_diff_res_value > 0){
				this_time_val = tmp_res_val - this_stat->history_diff_res_value;
			}else{
				/* 首次获取, 因为历史记录为0, 避免差值变成了第一次绝对值, 第一次先返回0 */
				this_time_val = 0;
			}
			this_stat->history_diff_res_value = tmp_res_val;
		}else{
			this_time_val = tmp_res_val;
		}

		/* 根据情况是否需要平滑求平均值 */
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

	for( i = 0; i < h->thread_count; i++){
		//h->mthread_stat[i].last_time_factor_value = h->get_factor_fun(h, i, h->user_arg);
		h->mthread_stat[i].last_time_factor_value = h->mthread_stat[i].realtime_work_count;		
		h->mthread_stat[i].realtime_work_count = 0;
		h->mthread_stat[i].realtime_bypass_count = 0;
	}
}


static void cl_analysis(cpu_limit_inner_t *h)
{
	cpul_mthread_stat_t *this_stat;
	int tid;

	for(tid = 0; tid < h ->thread_count; tid++){
		this_stat = &h->mthread_stat[tid];
		
		if(this_stat->realtime_res_val >= h->user_trigger_value){//超最高限制阈值

			this_stat->last_abnormal_time = h->current_time;
			this_stat->op_state = CL_LIMIT_STATE_REDUCE;
			if(this_stat->last_time_factor_value > 1.0){
				this_stat->actual_limit_factor_value = this_stat->last_time_factor_value * g_cpul_reduce_step;
			}
DPRINT("### thread:%d cl_analysis(), res:%.2f, change to reduce state, CL limit factor:%.2f\n", tid, this_stat->realtime_res_val, this_stat->actual_limit_factor_value);			
		}else if(this_stat->realtime_res_val <= h->user_recovery_value){//小于恢复阈值
DPRINT("### thread:%d cl_analysis(), current res:%.2f < low threshold, change to pending state!\n", tid, this_stat->realtime_res_val);			
		
			this_stat->op_state = CL_LIMIT_STATE_PENDING; 
			this_stat->last_abnormal_time = 0;
			this_stat->observe_work_count = 0;
			this_stat->observe_bypass_count = 0;
		}else{
#if 0		
			/* 最简单的策略, KISS,   如果res没有超阈值, 缓慢地调高factor阈值, 使res在trigger线上下徘徊 */
			this_stat->actual_limit_factor_value = this_stat->last_time_factor_value * g_cpul_raise_step; 
			this_stat->op_state = CL_LIMIT_STATE_OBSERVE;
			printf("### debug: cl_analysis(), in  observe state, CL limit factor:%.2f\n", this_stat->actual_limit_factor_value);			
			
#else
			/* 在最高阈值和最低恢复阈值之间, 根据g_abnormal_observe_time时间决定 */
			if(this_stat->last_abnormal_time != 0){
				if(this_stat->last_abnormal_time + g_abnormal_observe_time < h->current_time){
					/* 已经超时, 判断最近一段时间的work和bypass结果 */
					if((double)this_stat->observe_bypass_count/(double)(this_stat->observe_work_count + this_stat->observe_bypass_count) >= g_cpul_recovery_bypass_percent){ 
						this_stat->op_state = CL_LIMIT_STATE_OBSERVE;
						this_stat->last_abnormal_time = h->current_time; /* 观察期还是有很多bypass, 认为还是异常状态, 重置last_abnormal_time */
						this_stat->observe_work_count = 0;
						this_stat->observe_bypass_count = 0;					
					}else{
						this_stat->op_state = CL_LIMIT_STATE_PENDING; 
						this_stat->last_abnormal_time = 0;				
						this_stat->observe_work_count = 0;
						this_stat->observe_bypass_count = 0;					
					}
				}else{
					/* 还未超时, 不论还有没有日志, 都保持最近一次的 actual_limit_factor_value, 
					   因为可能还有攻击, res_val降下来的原因是被自身bypass导致, 
					   不能轻易放宽条件,否则会频繁抖动 */
					this_stat->op_state = CL_LIMIT_STATE_OBSERVE;
					/* 因为CPU抖动, actual_limit_factor_value可能下降的比限制实际效果的值还要小, 如果一直保持不变,要丢包很长时间, 此处再缓慢的调高一些 */
					this_stat->actual_limit_factor_value++; 
DPRINT("### thread:%d cl_analysis(), in observe state, factor:%.2f\n", tid, this_stat->actual_limit_factor_value);							
				}
			}else{
				/* 可能是从启动以来就没啥事, 或者已经从异常态超时恢复, 保持CL_LIMIT_STATE_PENDING */
				this_stat->op_state = CL_LIMIT_STATE_PENDING; 
DPRINT("### thread:%d cl_analysis(), low < current < high, change to pending state\n", tid);					
			}
#endif			
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


/*
    convert time_t to time string like "YY-MM-DD HH:MM:SS".
*/
static char *cl_timet_to_str(time_t timet, char *time_str, int time_str_len)
{
    struct tm *now;

    if(NULL == time_str || time_str_len <= (int)strlen("YY-MM-DD HH:MM:SS"))
    {
        return (char *)"1970-01-01 error"; /* error! */
    }	

    now = localtime(&timet);
    strftime(time_str, time_str_len, "%Y-%m-%d %H:%M:%S", now);

    return time_str;
}

static void cl_debug_log(cpu_limit_inner_t *h)
{
	int tid;
	int global_bypass_state = 0;
	
	if(NULL == h->debug_log_filename){
		return;
	}

	if(h->last_debug_log_print_time + 1 > h->current_time){
		return;
	}

	FILE *fp;

	fp = fopen(h->debug_log_filename, "w+");
	if(NULL == fp){
		h->last_debug_log_print_time = h->current_time;
		return;
	}

	char time_string[64];
	fprintf(fp, "%s\n", cl_timet_to_str(h->current_time, time_string, sizeof(time_string)));

	fprintf(fp, "User define high trigger threshod:%.2f\n", h->user_trigger_value);
	fprintf(fp, "User define low recovery threshod:%.2f\n", h->user_recovery_value);
	fprintf(fp, "User define get res interval:%d ms\n", h->stat_interval);
	fprintf(fp, "-------------------------------------------\n");

	fprintf(fp, "%9s %7s %8s %10s %10s\n", "Thread_ID", "State", "Usr_RES", "Usr_Factor", "CL_Factor");
	for(tid = 0; tid < h ->thread_count; tid++){
		if(h->mthread_stat[tid].op_state != CL_LIMIT_STATE_PENDING){
			global_bypass_state = 1;
		}
		fprintf(fp, "%9d %7s %8.2f %10.2f %10.2f\n", tid, 
				cl_op_state_ntop(h->mthread_stat[tid].op_state), 
				h->mthread_stat[tid].realtime_res_val, 
				h->mthread_stat[tid].last_time_factor_value, h->mthread_stat[tid].actual_limit_factor_value);
	}

	fprintf(fp, "Global BYAPSS status: %s\n", (global_bypass_state > 0)?"YES":"NO");

	fclose(fp);

	h->last_debug_log_print_time = h->current_time;
}


/* 后台实时统计分析线程 */
static void *cl_bg_thread(void *_arg_h)
{
	cpu_limit_inner_t *h = (cpu_limit_inner_t *)_arg_h;
	int analysis_count = 0;

	while(CL_STATE_RUNNING != h->running_state){
		h->current_time = time(NULL);
		sleep(1);
	}
	
	while(CL_STATE_RUNNING == h->running_state){
		cl_get_res(h);
		cl_get_factor(h);

		/* 分析周期略微长于获取res和factor周期 */
		if(++analysis_count > 3){
			cl_analysis(h);
			analysis_count = 0;
		}

		cl_debug_log(h);
		
		h->current_time = time(NULL);
		usleep(h->stat_interval * 1000);
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

		case CL_OPT_RES_RECOVERY_THRESHOLD:
			h->user_recovery_value = *(double *)value;
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
		/* 在观察期和降低阈值期间, 也不一定就是固定返回0, 看最近的factor值 */
		if((double)this_stat->realtime_work_count > this_stat->actual_limit_factor_value){//超限制阈值
			can_i_do = 0;
		}else{
			can_i_do = 1;
		}
	}

	if(can_i_do){
		this_stat->realtime_work_count++;
		this_stat->observe_work_count++;
	}else{
		this_stat->observe_bypass_count++;
		this_stat->realtime_bypass_count++;
	}
	
	return can_i_do;
}

void cpu_limit_destroy(cpu_limit_handle _arg_h)
{
	cpu_limit_inner_t *h = (cpu_limit_inner_t *)_arg_h;
	
	h->running_state = CL_STATE_TO_BE_DESTORY;
	pthread_join(h->thread_id, NULL);
	
	if(h->destroy_cb_fun){
		h->destroy_cb_fun(_arg_h, h->user_arg);
	}

	memset(h, 0xFE, sizeof(cpu_limit_inner_t));
	
	free(h);
	
	return;
}

#ifdef __cplusplus
}
#endif



