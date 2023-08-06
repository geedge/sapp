/***********************************************************************************************************************
    本文件用于实现疑似ddos攻击时, 将某些流切换为bypass状态, 以忽略一小部分流的代价, 使大部分流还是能正常处理.
    暂时先放在sapp工程里, 尽量保持独立, 也不一定仅限于CPU, 也可以是内存, pps, bps, drop_pps等参数,
    以后可能作为一个独立的库存在.

    TODO:
        可以参考反馈控制PID算法 : 
            https://en.wikipedia.org/wiki/PID_controller
            http://brettbeauregard.com/blog/2011/04/improving-the-beginners-pid-introduction/
***********************************************************************************************************************/
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
#define CL_HISTORY_FACTOR_NUM (10)
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

static const double g_cpul_limit_min = 1.00; /* 测试时设了一个极低的res阈值, 无论怎么减factor, res都降不下来, 一直降到0为止, 导致无法恢复!! 先内置一个最低值 */
static const double g_cpul_recovery_bypass_percent = 0.05; /* 在观察期内, bypass占比总数小于此值时, 认为可恢复常态 */ 

struct __cpul_mthread_stat{
	cl_limit_state_t op_state; 

	int recent_smooth_index; //平滑平均值数组下标
	double *recent_smooth_res_value; //默认是1, 即只看最近一次的实时值, 实际看用户设置
	double realtime_res_val;//最近一次的资源占用值, 综合计算出来的
	
	double last_time_factor_value;//最近一次用户操作的实际factor值, 比如pps, bps, link_new_create/pps等
	double actual_limit_factor_value; //本次资源限制值, 会随op_state变化

	double history_factor_value[CL_HISTORY_FACTOR_NUM]; //最近N次用户操作的实际factor值, 用于res第一次超阈值后, 选个合适的actual_limit_factor_value
	unsigned int history_factor_index;
	//int abnormal_observe_time; //曾经超过阈值, 但已经恢复正常了, 观察等待期时间, 单位:秒
	
	/* 会随时间变化, 动态更新的变量, 支持多线程 */
	time_t last_abnormal_time; /* 最后一次异常状态的时间, 0表示从来没有出现过异常, last_abnormal_time==current_time, 说明当前时刻就处于异常状态 */	

	time_t last_adjust_factor_time;

	volatile long long realtime_work_count;   /* 实时外部应用请求cpu_limit_can_i_do()函数返回Yes, 即work的次数, 每隔 stat_interval 时间清零 */
	volatile long long realtime_bypass_count; /* 实时外部应用请求cpu_limit_can_i_do()函数返回No,  即bypass的次数, 每隔 stat_interval 时间清零 */

	volatile long long observe_work_count;   /* 观察期外部应用请求cpu_limit_can_i_do()函数返回Yes, 即work的次数 */
	volatile long long observe_bypass_count; /* 观察期外部应用请求cpu_limit_can_i_do()函数返回No,  即bypass的次数 */

	volatile long long debug_factor_work_per_second; /* stat_interval 单位是毫秒, 如果配置了太短的时间间隔统计pps, bps等参数, 误差太大, 所以此值每秒更新一次 */
	volatile long long debug_factor_bypass_per_second; /* stat_interval 单位是毫秒, 如果配置了太短的时间间隔统计pps, bps等参数, 误差太大, 所以此值每秒更新一次 */
}__attribute__ ((aligned (64)));
typedef struct __cpul_mthread_stat cpul_mthread_stat_t;


typedef struct{
	/* 内部私有变量 */
	long long header_magic; 
	volatile cl_running_state_t running_state;
	pthread_t thread_id;
	time_t last_debug_log_print_time;
	time_t global_last_abnormal_time;
	volatile int global_bypass_state;
	
	
	/* 用户定义的选项或参数, 启动后固定不变 */
	char *debug_log_filename; //是否开启本地debug日志
	double user_trigger_value;
	double factor_decrease_ratio; /* 超阈值后, factor每次降低的频率 */
	double factor_increase_ratio; /* 观察期, factor每次升高的频率 */
	/* 因为获取时间间隔太短, 经常有cpu占用率为0.0的情况,  所以不能加最低快速恢复阈值 */
	//double user_recovery_value; //低于这个值, 立即恢复正常, 不再限制
	int recent_res_smooth_number; 
	int stat_interval; //每次获取资源间隔时间, 单位ms
	int recovery_observe_time; 
	cl_get_res_t get_res_fun;
	cl_get_factor_t get_factor_fun; /* TODO: 要不要这个callbakc呢? 其实从 cpu_limit_can_i_do() 函数就能获取了 */
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
	cpul_mthread_stat_t *this_stat;

	for( i = 0; i < h->thread_count; i++){
		this_stat = &h->mthread_stat[i];
		
		//h->mthread_stat[i].last_time_factor_value = h->get_factor_fun(h, i, h->user_arg);
		this_stat->last_time_factor_value = this_stat->realtime_work_count + this_stat->realtime_bypass_count;	

		this_stat->history_factor_value[this_stat->history_factor_index++ % CL_HISTORY_FACTOR_NUM] = h->mthread_stat[i].last_time_factor_value;
	}
}

/* 连续超过阈值, 每次按之前限制的值倍数减少, 
   因为监控CPU周期可能比较短, 避免减的太快, 每秒操作一次 
*/
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

/*
	TODO: 使用最近N次的最大值, 还是平均值呢??
	      最大值可能太抖了, 
	      平均值可能比较小,
*/
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
		/*
			TODO: 此处如果之前流量很小, 瞬间忽然来了一大股流量, 导致actual_limit_factor_value很小,
			虽然bypass后cpu不会超阈值, 但是user factor被压制的太小了, 也不合实际!!

			设置一点静默时间, 首次发现超阈值后, 先观察几秒, 测试一个平均的actual_limit_factor_value.
		*/
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
		/* 测试时忽然停了流量, 计数全0时也要恢复 */
		recovery = 1;
	}

	return recovery;
}

static void cl_analysis_observe_state(cpu_limit_inner_t *h, int tid, cpul_mthread_stat_t *this_stat)
{
	if(0 == this_stat->last_abnormal_time){
		/* 可能是从启动以来就没啥事, 或者刚从异常态超时恢复, 保持CL_LIMIT_STATE_PENDING状态 */
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
		this_stat->last_abnormal_time = h->current_time; /* 观察期还是有很多bypass, 认为还是异常状态, 更新last_abnormal_time */				
	}

	/* 在线测试发现, 某些线程的流量巨小甚至为0, 此时还一直增加actual_limit_factor_value就没有意义了, 判断一下 */
	if(this_stat->observe_work_count + this_stat->observe_bypass_count > this_stat->actual_limit_factor_value*0.9){
		cl_update_limit_factor(h, this_stat, h->factor_increase_ratio); /* 每次升高一点点, 让user res在最高阈值附近小范围浮动 */	
	}
	this_stat->op_state = CL_LIMIT_STATE_OBSERVE;	

	return ;
}

static void cl_analysis(cpu_limit_inner_t *h)
{
	cpul_mthread_stat_t *this_stat;
	int tid;

	for(tid = 0; tid < h ->thread_count; tid++){
		this_stat = &h->mthread_stat[tid];
		
		if(this_stat->realtime_res_val >= h->user_trigger_value){//超最高限制阈值
			cl_analysis_reduce_state(h, tid, this_stat);
		}else{
			cl_analysis_observe_state(h, tid, this_stat); /* 可能是从没有过攻击, 可能是刚从攻击状态bypass之后恢复过来 */
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
					"infinity"/*无限制*/);
		}else{
			fprintf(fp, "%9d %7s %9.2f %15lld %18lld %15.2f\n", tid, 
					cl_op_state_ntop(this_stat->op_state), 
					this_stat->realtime_res_val, 
					this_stat->debug_factor_work_per_second + this_stat->debug_factor_bypass_per_second,
					this_stat->debug_factor_bypass_per_second,
					this_stat->actual_limit_factor_value);
		}

		this_stat->debug_factor_work_per_second = 0; /* 每秒更新一次 */
		this_stat->debug_factor_bypass_per_second = 0; /* 每秒更新一次 */
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

/* 后台实时统计分析线程, 不占用sapp IO线程的时间片 */
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

		/* 
		   get和analysis都结束后,    此处为啥不能直接休眠等一会? 即usleep(h->stat_interval * 1000) ?
           因为以上函数自身耗时可能就很长, 再usleep()那么长时间, 真正usleep的时间肯定比预期的长, 就不准了.
		*/
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

