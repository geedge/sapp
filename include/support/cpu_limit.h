#ifndef _CPU_LIMIT_H_
#define _CPU_LIMIT_H_ 1

#ifdef __cplusplus
extern "C" {
#endif
typedef void * cpu_limit_handle;

typedef double (*cl_get_res_t)(cpu_limit_handle h, int thread_seq, void *user_arg);//thread_seq范围: [0,CL_OPT_THREAD_COUNT-1]
typedef double (*cl_get_factor_t)(cpu_limit_handle h, int thread_seq,void *user_arg);//thread_seq范围: [0,CL_OPT_THREAD_COUNT-1]
typedef void (*cl_destroy_cb_t)(cpu_limit_handle h, void *user_arg);

typedef enum{
	/* set options */
	CL_OPT_DEBUG_LOG_FILE_NAME, 
	CL_OPT_RES_TRIGGER_THRESHOLD,  //double, 把资源限制在某个数值内, 比如限速到1Mbps, CPU占用率最大60%, 等等
	CL_OPT_THREAD_COUNT, //int ,是否支持多线程模式, 线程数量, 默认是1, 
	CL_OPT_RES_SMOOTH_SCOPE, //int, 为了平滑资源占用统计, 避免抖动, 使用最近N次的平均值, 假如统计CPU占用率设成10, 即最近10次的CPU平均值. 如果无此选项, 默认是1
	CL_OPT_STAT_INTERVAL, //int ,获取当前资源占用时间间隔, 单位ms, 默认1000, 即1秒
	CL_OPT_OBSERVE_TIME, //int, 单位:秒, 为了避免抖动, 发现异常后, 即使降低到CL_OPT_RES_TRIGGER_THRESHOLD以下, 短时间内暂不恢复正常状态
	CL_OPT_RES_GET_FUN, // cl_get_res_t, 获取当前资源占用函数指针
	CL_OPT_FACTOR_GET_FUN, // 获取当前占用资源的操作因子数值, 比如pps, bps, new_link/s等,  函数指针
	CL_OPT_USER_ARG, //void *, 用户自定义字段
	CL_OPT_DESTROY_CALLBCAK_FUN, //释放资源callback, cl_destroy_cb_t
	CL_OPT_FACTOR_DECREASE_RATIO, //double, 超过res阈值后, 抑制factor的递减率
	CL_OPT_FACTOR_INCREASE_RATIO, //double, 抑制factor低于res阈值后, 缓慢恢复的增长率

	/* get options */
	CL_OPT_GLOBAL_BYPASS_STATE, //int, 全局bypass状态
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