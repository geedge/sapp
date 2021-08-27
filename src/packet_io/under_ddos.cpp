#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/sysinfo.h>
#include <pcap/pcap.h>
#include "cpu_limit.h"
#include "sapp_api.h"
#include "sapp_private_api.h"


#ifdef __cplusplus
extern "C" {
#endif


typedef enum
{
    TCK_USER = 0,
    TCK_NICE,
    TCK_SYSTEM,
    TCK_IDLE,
    TCK_IOWAIT,
    TCK_IRQ,
    TCK_SOFTIRQ,
    TCK_STEAL,
    TCK_GUEST,
    TCK_GUEST_NICE,
    NUM_TCK_TYPES
} cpu_tck_type;
/* https://www.linuxhowtos.org/System/procstat.htm */

typedef struct
{
    char name[16];
    uint64_t tcks[NUM_TCK_TYPES];
} cpu_tck_t;

typedef struct{
	unsigned long long last_create_stream_new_sum[MAX_THREAD_NUM];
	double last_time_cpu_total[MAX_THREAD_NUM];
	double last_time_cpu_idle[MAX_THREAD_NUM];
	cpu_tck_t all_cpu_usage[MAX_THREAD_NUM];
}under_sapp_user_args_t;


/* 
	获取cpu占用率是通过core_id参数, 通过线程index转换成core_id.
*/
int sapp_thread_index_to_core_id(int thread_seq)
{
	int i;
    cpu_set_t current_cpu_mask;
	
	CPU_ZERO(&current_cpu_mask);
	
	if(pthread_getaffinity_np(pthread_self(), sizeof(cpu_set_t), &current_cpu_mask) < 0){
		printf("pid:%ld is not set affinity\n", pthread_self());
		return -1;
	}
	
	int tot_cpu_core = get_nprocs();
	
	for(i = 1; i <= tot_cpu_core; i++){
		if(CPU_ISSET(i, &current_cpu_mask)){
			break;
		}
	}
	
	return i;

}



static inline uint64_t calc_total_ticks(cpu_tck_t *stat)
{
    uint64_t total = 0;
    int i;
    for(i = 0; i < NUM_TCK_TYPES; i++)
        total += stat->tcks[i];
    return total;
}


static void read_cpu_usage_from_proc(cpu_tck_t *per_cpu_core_stat, int max_cpu_num)
{
    FILE *stat_fp = fopen("/proc/stat", "r");

    int i = 0;
    char no_use_string[NAME_MAX];

	if(NULL == stat_fp){
		memset(per_cpu_core_stat, 0, sizeof(cpu_tck_t)*max_cpu_num);
		return;
	}

	/* 第一行是系统整体cpu占用率, 然后是每个CPU核心的 */
    fscanf(stat_fp, "%s \n", no_use_string);

    for(i = 0; i < max_cpu_num; i++)
	{
        fscanf(
            stat_fp,
            "%s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
            per_cpu_core_stat[i].name,
            &(per_cpu_core_stat[i].tcks[TCK_USER]),
            &(per_cpu_core_stat[i].tcks[TCK_NICE]),
            &(per_cpu_core_stat[i].tcks[TCK_SYSTEM]),
            &(per_cpu_core_stat[i].tcks[TCK_IDLE]),
            &(per_cpu_core_stat[i].tcks[TCK_IOWAIT]),
            &(per_cpu_core_stat[i].tcks[TCK_IRQ]),
            &(per_cpu_core_stat[i].tcks[TCK_SOFTIRQ]),
            &(per_cpu_core_stat[i].tcks[TCK_STEAL]),
            &(per_cpu_core_stat[i].tcks[TCK_GUEST]),
            &(per_cpu_core_stat[i].tcks[TCK_GUEST_NICE])
        );
    }

    fclose(stat_fp);
}


static double sapp_get_cpu_usage_cb(cpu_limit_handle h, int _thread_index, void *_void_user_arg)
{
	double cpu_usage;
	uint64_t this_total_tcks, this_idle_tcks;
	int cpu_core_id;
	int sys_actual_cpu_core_num = get_nprocs();
	under_sapp_user_args_t *ud_usr_arg = (under_sapp_user_args_t *)_void_user_arg;
	
	cpu_core_id = sapp_thread_index_to_core_id(_thread_index);

	/* 外部模块调用, thread_index是从0-N顺序依次调用,
	   仅在第一次从/proc/stat中获取, 后续的直接从内存里获取, 避免多次打开/proc/stat */
	if(0 == _thread_index){
		read_cpu_usage_from_proc(ud_usr_arg->all_cpu_usage, sys_actual_cpu_core_num);
	}
	
	this_total_tcks = calc_total_ticks(&ud_usr_arg->all_cpu_usage[cpu_core_id]);
	this_idle_tcks = ud_usr_arg->all_cpu_usage[cpu_core_id].tcks[TCK_IDLE];

	if(0 == ud_usr_arg->last_time_cpu_total[cpu_core_id]){
		/* 第一次为0, 为了避免误差, 此次不计算 */
		ud_usr_arg->last_time_cpu_total[cpu_core_id] = this_total_tcks;
		ud_usr_arg->last_time_cpu_idle[cpu_core_id] = this_idle_tcks;
		return 0.0;
	}

	/* 间隔一段时间, 连续两次used的差值除以两次总数的差值, 
	   不能直接用总数, 那是表示自机器加电启动以来cpu占用率的总平均值, 
	*/
	cpu_usage = 100.0 * ((this_total_tcks - this_idle_tcks)-(ud_usr_arg->last_time_cpu_total[cpu_core_id] - ud_usr_arg->last_time_cpu_idle[cpu_core_id]))/(this_total_tcks - ud_usr_arg->last_time_cpu_total[cpu_core_id]);
	ud_usr_arg->last_time_cpu_total[cpu_core_id] = this_total_tcks;
	ud_usr_arg->last_time_cpu_idle[cpu_core_id]  = this_idle_tcks;	

	return cpu_usage;

}

static double sapp_get_create_stream_rate_cb(cpu_limit_handle h, int thread_index,void *_void_user_arg)
{
	under_sapp_user_args_t *ud_usr_arg = (under_sapp_user_args_t *)_void_user_arg;
	unsigned long long cur_create_stream_sum;
	unsigned long long cur_create_stream_rate;

	/* TCP和UDP总计 */
	cur_create_stream_sum = sapp_global_val->mthread_volatile[thread_index]->sys_stat.count[SAPP_STAT_TCP_STREAM_NEW] + sapp_global_val->mthread_volatile[thread_index]->sys_stat.count[SAPP_STAT_UDP_STREAM_NEW];

	/* 第一次为0, 为了避免误差, 此次不计算 */
	if(0 == ud_usr_arg->last_create_stream_new_sum[thread_index]){
		ud_usr_arg->last_create_stream_new_sum[thread_index] = cur_create_stream_sum;
		return 0.0;
	}
	cur_create_stream_rate = cur_create_stream_sum-ud_usr_arg->last_create_stream_new_sum[thread_index];
	ud_usr_arg->last_create_stream_new_sum[thread_index] = cur_create_stream_sum;

	return (double)cur_create_stream_rate;
}


int packet_io_under_ddos_should_bypass(int thread_index)
{
	int ret;
	const sapp_under_ddos_config_t *p_ddos_cfg = &sapp_global_val->config.packet_io.under_ddos_config;

	if(0 == p_ddos_cfg->enabled){
		return 0;
	}

	ret = cpu_limit_can_i_do(sapp_global_val->individual_fixed.under_ddos_handle, thread_index);
	/* 返回值要取反 */
	return !ret;
}


void packet_io_under_ddos_run(void)
{
	const sapp_under_ddos_config_t *p_ddos_cfg = &sapp_global_val->config.packet_io.under_ddos_config;

	if(0 == p_ddos_cfg->enabled){
		return;
	}

	if(cpu_limit_start(sapp_global_val->individual_fixed.under_ddos_handle) < 0){
		sapp_runtime_log(RLOG_LV_FATAL, "cpu_limit_start() error !\n");
	}
}

int packet_io_under_ddos_init(void)
{
	sapp_under_ddos_config_t *p_ddos_cfg = &sapp_global_val->config.packet_io.under_ddos_config;
	cpu_limit_handle ud_handle;
	int iopt_value;
	
	if(0 == p_ddos_cfg->enabled){
		return 0;
	}

	if(sapp_global_val->config.cpu.bind_mask_array_num == 0){
		sapp_runtime_log(RLOG_LV_FATAL, "cpu_limit_create() error, must set [CPU]->bind_mask!\n");
		return -1;
	}

	ud_handle = cpu_limit_create();
	if(NULL == ud_handle){
		sapp_runtime_log(RLOG_LV_FATAL, "cpu_limit_create() error!\n");
		return -1;		
	}	

	cpu_limit_set_opt(ud_handle, CL_OPT_RES_TRIGGER_THRESHOLD, &p_ddos_cfg->bypass_trigger_cpu_usage, sizeof(double));
	cpu_limit_set_opt(ud_handle, CL_OPT_RES_RECOVERY_THRESHOLD, &p_ddos_cfg->recovery_cpu_usage, sizeof(double));	

	iopt_value = g_packet_io_thread_num;
	cpu_limit_set_opt(ud_handle, CL_OPT_THREAD_COUNT, &iopt_value, sizeof(int));

	cpu_limit_set_opt(ud_handle, CL_OPT_STAT_INTERVAL, &p_ddos_cfg->get_cpu_usage_interval, sizeof(int));

	cpu_limit_set_opt(ud_handle, CL_OPT_RES_SMOOTH_SCOPE, &p_ddos_cfg->smooth_avg_window, sizeof(int));
	
	cpu_limit_set_opt(ud_handle, CL_OPT_RES_GET_FUN, (void *)&sapp_get_cpu_usage_cb, sizeof(void *));	

	cpu_limit_set_opt(ud_handle, CL_OPT_FACTOR_GET_FUN, (void *)&sapp_get_create_stream_rate_cb, sizeof(void *));	

	under_sapp_user_args_t *ud_user_arg = (under_sapp_user_args_t *)calloc(1, sizeof(under_sapp_user_args_t));
	cpu_limit_set_opt(ud_handle, CL_OPT_USER_ARG, ud_user_arg, sizeof(void *));	

	cpu_limit_set_opt(ud_handle, CL_OPT_DEBUG_LOG_FILE_NAME, (void *)sapp_global_val->config.data_file_path.data_under_ddos_stat_log_absolute, strlen(sapp_global_val->config.data_file_path.data_under_ddos_stat_log_absolute));		

	sapp_global_val->individual_fixed.under_ddos_handle = ud_handle;

	return 0;
}

#ifdef __cplusplus
}
#endif


