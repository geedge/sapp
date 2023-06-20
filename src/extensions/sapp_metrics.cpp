#include "field_stat2.h"
#include "fieldstat.h"

#include "sapp_declaration.h"
#include "sapp_pkt_stat.h"

void sapp_fs2_update_count(int field_index, unsigned  long long value)
{
	if(sapp_global_val->individual_fixed.fs2_runtime.fs_metric_handle != NULL){
		FS_operate(sapp_global_val->individual_fixed.fs2_runtime.fs_metric_handle, 
					sapp_global_val->individual_fixed.fs2_runtime.fs_id_count_array[field_index], 
					0, FS_OP_SET,  (long long)value);
	}
}

void sapp_fs2_update_length(int field_index, unsigned  long long value)
{
	if(sapp_global_val->individual_fixed.fs2_runtime.fs_metric_handle != NULL){
		FS_operate(sapp_global_val->individual_fixed.fs2_runtime.fs_metric_handle, 
					sapp_global_val->individual_fixed.fs2_runtime.fs_id_length_array[field_index],  
					0, FS_OP_SET,  (long long)value);
	}
}


void sapp_fs2_set_latency(int thead_seq, long long time_cost)
{
    if(sapp_global_val->individual_fixed.fs2_runtime.fs_metric_handle != NULL){
        FS_operate(sapp_global_val->individual_fixed.fs2_runtime.fs_metric_handle, 
        		   sapp_global_val->individual_fixed.fs2_runtime.fs_latency_id_array[thead_seq], 
        		   0, FS_OP_SET, time_cost);
    }
}


void sapp_fs2_set_plug_entry_latency(int entry_id, long long time_cost)
{
	if(unlikely(entry_id < 0 || entry_id >= SAPP_MAX_PLUG_ENTRY_NUM)){
		return;
	}
    if(sapp_global_val->individual_fixed.fs2_runtime.fs_metric_handle != NULL){
        FS_operate(sapp_global_val->individual_fixed.fs2_runtime.fs_metric_handle, 
        		   sapp_global_val->individual_fixed.fs2_runtime.fs_latency_plug_entrg_id_array[entry_id], 
        		   0, FS_OP_SET, time_cost);
    }
}

/*
	模糊计算包处理延时, 不用每个包都调用一次FS_operate(),
	由sapp timer线程每隔一段时间调用sapp_fuzzy_latency_update(), 更新filed_stat2计数.
*/
extern "C" void sapp_fs2_fuzzy_latency_update_per_thread(int thead_seq, long long time_cost)
{
	sapp_fuzzy_latency_stat_t *this_thread_stat = &sapp_global_val->mthread_volatile[thead_seq]->fuzzy_pkt_latency_stat_per_thread;

	if(time_cost < this_thread_stat->min_time_cost){
		this_thread_stat->min_time_cost = time_cost;
	}

	if(time_cost > this_thread_stat->max_time_cost){
		this_thread_stat->max_time_cost = time_cost;
	}
	
	this_thread_stat->time_cost_sum += time_cost;
	this_thread_stat->stat_count++;
}

extern "C" void sapp_fs2_fuzzy_latency_update_per_entry(int thead_seq, int entry_id, long long time_cost)
{
	sapp_fuzzy_latency_stat_t *this_thread_stat;
	if(unlikely(entry_id < 0 || entry_id >= SAPP_MAX_PLUG_ENTRY_NUM)){
		return;
	}	

	this_thread_stat = &sapp_global_val->mthread_volatile[thead_seq]->fuzzy_pkt_latency_stat_per_entry_per_thread[entry_id];

	if(time_cost < this_thread_stat->min_time_cost){
		this_thread_stat->min_time_cost = time_cost;
	}

	if(time_cost > this_thread_stat->max_time_cost){
		this_thread_stat->max_time_cost = time_cost;
	}
	
	this_thread_stat->time_cost_sum += time_cost;
	this_thread_stat->stat_count++;

}


/*
	由sapp timer独立线程调用, 每隔一段时间, 将积累的包处理延时数据刷新给field_stat2.
*/
void sapp_fuzzy_latency_update(void)
{
	int tid, entry_id, this_stat_count;
	long long min_latency, max_latency;
	double avg_latency;
	sapp_fuzzy_latency_stat_t *this_thread_stat, *this_entry_stat;
	
	for(tid = 0; tid < g_packet_io_thread_num; tid++){
		this_thread_stat = &sapp_global_val->mthread_volatile[tid]->fuzzy_pkt_latency_stat_per_thread;
		avg_latency = (double)this_thread_stat->time_cost_sum/(double)this_thread_stat->stat_count;
		min_latency = this_thread_stat->min_time_cost;
		max_latency = this_thread_stat->max_time_cost;
		this_stat_count = this_thread_stat->stat_count;

		if(this_stat_count > 0){
			memset(this_thread_stat, 0, sizeof(sapp_fuzzy_latency_stat_t));
			this_thread_stat->min_time_cost = 999999999; /* 要记录最小值, 初始化要设成最大值 */

			/* 每次更新三个值, 最大,最小和平均值 */
			sapp_fs2_set_latency(tid, min_latency);
			sapp_fs2_set_latency(tid, max_latency);
			sapp_fs2_set_latency(tid, (long long)avg_latency);
		}
		
		for(entry_id = 1; entry_id < g_plug_global_entry_index; entry_id++){
			this_entry_stat = &sapp_global_val->mthread_volatile[tid]->fuzzy_pkt_latency_stat_per_entry_per_thread[entry_id];
			avg_latency = (double)this_entry_stat->time_cost_sum/(double)this_entry_stat->stat_count;
			min_latency = this_entry_stat->min_time_cost;
			max_latency = this_entry_stat->max_time_cost;
			this_stat_count = this_entry_stat->stat_count;
			if(this_stat_count > 0){
				memset(this_entry_stat, 0, sizeof(sapp_fuzzy_latency_stat_t));
				this_entry_stat->min_time_cost = 999999999; /* 要记录最小值, 初始化要设成最大值 */
				
				sapp_fs2_set_latency(tid, min_latency);
				sapp_fs2_set_latency(tid, max_latency);
				sapp_fs2_set_plug_entry_latency(entry_id, (long long)avg_latency);
			}
		}
	}
}

/************************ C++ compiler **************************************/
static int sapp_fs2_init(sapp_global_t *global_paramters)
{
	void *fs2_handle=NULL;
	int fs2_opt;
	sapp_gval_individual_fixed_fs2_t *p_fs2_rt = &global_paramters->individual_fixed.fs2_runtime;
	sapp_config_profiling_metric_t *p_fs2_para = &global_paramters->config.profiling.fs2;
	int fs2_local_enabled = 0;
	int fs2_prometheus_enabled = 0;

	if(strlen(p_fs2_para->local_file) > 0)
	{
		fs2_local_enabled = 1;
	}
	if(strlen(p_fs2_para->prometheus_service_uri) > 0 && p_fs2_para->prometheus_service_port > 0)
	{
		fs2_prometheus_enabled = 1;
	}	

	p_fs2_rt->fs_metric_handle = FS_create_handle();
	if(NULL == p_fs2_rt->fs_metric_handle){
		sapp_log(RLOG_LV_FATAL, 30, 30, "FS_create_handle() error: %s!\n", strerror(errno));
		return -1;
	}
	fs2_handle = p_fs2_rt->fs_metric_handle;
	if(fs2_prometheus_enabled){
		FS_library_set_prometheus_port((unsigned short)p_fs2_para->prometheus_service_port);
		FS_library_set_prometheus_url_path(p_fs2_para->prometheus_service_uri);
		if(FS_library_init() < 0){
			sapp_log(RLOG_LV_FATAL, 30, 30, "FS_library_init() error, port:%d, url:%s\n", 
					p_fs2_para->prometheus_service_port,
					p_fs2_para->prometheus_service_uri);
			return -1;			
		}
		fs2_opt = 1;
		FS_set_para(fs2_handle, OUTPUT_PROMETHEUS, &fs2_opt, sizeof(int));
	}

	FS_set_para(fs2_handle, STAT_CYCLE, &p_fs2_para->refresh_interval_s, sizeof(int));

	fs2_opt = 1; /* 1:Rewrite ,2: Append.  */
	FS_set_para(fs2_handle, PRINT_MODE, &fs2_opt, sizeof(int));

	fs2_opt = 1;
	FS_set_para(fs2_handle, PRINT_TRIGGER, &fs2_opt, sizeof(int));

	fs2_opt = 1;
    FS_set_para(fs2_handle, NOT_SEND_METRIC_TO_SERVER, &fs2_opt, sizeof(int));

	if (fs2_local_enabled)
	{
		FS_set_para(fs2_handle, OUTPUT_DEVICE, ABBR_FS2_LOG_DATA_FILE, strlen(ABBR_FS2_LOG_DATA_FILE) + 1);
	}
	else
	{
		sapp_log(RLOG_LV_INFO, 10, 10, "profiling.log.local.enabled is 0, not save local stat log file.\n");
		FS_set_para(fs2_handle, OUTPUT_DEVICE, "/dev/null", strlen("/dev/null") + 1);
	}
	FS_set_para(fs2_handle, APP_NAME, sapp_global_val->config.system.instance_name, strlen(sapp_global_val->config.system.instance_name)+1);


	p_fs2_rt->fs_id_count_array[SAPP_STAT_RCV_LINE] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Line_Pkt");
	p_fs2_rt->fs_id_length_array[SAPP_STAT_RCV_LINE] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Line_Bit");
	
	p_fs2_rt->fs_id_count_array[SAPP_STAT_RCV_ETHERNET] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Eth_Pkt");
	p_fs2_rt->fs_id_length_array[SAPP_STAT_RCV_ETHERNET] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Eth_Bit");

	if((DEPOLYMENT_MODE_INLINE == sapp_global_val->config.packet_io.depolyment_mode_bin)
	 || (DEPOLYMENT_MODE_TRANSPARENT == sapp_global_val->config.packet_io.depolyment_mode_bin)){
		p_fs2_rt->fs_id_count_array[SAPP_STAT_ETH_INBOUND] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Pkt_Inbound");
		p_fs2_rt->fs_id_length_array[SAPP_STAT_ETH_INBOUND] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Bit_Inbound");	 
		p_fs2_rt->fs_id_count_array[SAPP_STAT_ETH_OUTBOUND] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Pkt_Outbound");
		p_fs2_rt->fs_id_length_array[SAPP_STAT_ETH_OUTBOUND] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Bit_Outbound");			
	}

	p_fs2_rt->fs_id_count_array[SAPP_STAT_RCV_UNKNOWN] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Unknown_Pkt");
	p_fs2_rt->fs_id_length_array[SAPP_STAT_RCV_UNKNOWN] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Unknown_Bit");

	p_fs2_rt->fs_id_count_array[SAPP_STAT_SND_ERROR] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Snd_Err_Pkt");
	//pfs_para->fs_id_length_array[SAPP_STAT_SND_ERROR] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Snd_Err_Bit");	 

	p_fs2_rt->fs_id_count_array[SAPP_STAT_RCV_IPV4] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Ipv4_Pkt");
	p_fs2_rt->fs_id_length_array[SAPP_STAT_RCV_IPV4] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Ipv4_Bit");

	p_fs2_rt->fs_id_count_array[SAPP_STAT_RCV_IPV6] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Ipv6_Pkt");
	p_fs2_rt->fs_id_length_array[SAPP_STAT_RCV_IPV6] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Ipv6_Bit");

	p_fs2_rt->fs_id_count_array[SAPP_STAT_RCV_TCP] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Tcp_Pkt");
	p_fs2_rt->fs_id_length_array[SAPP_STAT_RCV_TCP] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Tcp_Bit");
	p_fs2_rt->fs_id_count_array[SAPP_STAT_RCV_DUP_TCP] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Dup_Tcp_Pkt");
	p_fs2_rt->fs_id_length_array[SAPP_STAT_RCV_DUP_TCP] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Dup_Tcp_Bit");
    p_fs2_rt->fs_id_length_array[SAPP_STAT_TCP_LOST_PKT] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Tcp_Lost_Bit");	
	p_fs2_rt->fs_id_count_array[SAPP_STAT_TCP_LOST_PKT_STREAM_NUM] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Tcp_Lost_STM");	

	p_fs2_rt->fs_id_count_array[SAPP_STAT_DUP_IDENTIFY_ERR] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Dup_Key_Err"); /* dup重复包识别添加key错误计数 */	

    p_fs2_rt->fs_id_count_array[SAPP_STAT_TCP_CLOSE_BY_TIMEOUT] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Tcp_Close_byT");	
	p_fs2_rt->fs_id_count_array[SAPP_STAT_TCP_CLOSE_BY_KICKOUT] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Tcp_Close_byK");	
	
	p_fs2_rt->fs_id_count_array[SAPP_STAT_RCV_UDP] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Udp_Pkt");
	p_fs2_rt->fs_id_length_array[SAPP_STAT_RCV_UDP] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Udp_Bit");
	p_fs2_rt->fs_id_count_array[SAPP_STAT_RCV_DUP_UDP] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Dup_Udp_Pkt");
	p_fs2_rt->fs_id_length_array[SAPP_STAT_RCV_DUP_UDP] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Dup_Udp_Bit");

    p_fs2_rt->fs_id_count_array[SAPP_STAT_UDP_CLOSE_BY_TIMEOUT] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Udp_Close_byT");	
	p_fs2_rt->fs_id_count_array[SAPP_STAT_UDP_CLOSE_BY_KICKOUT] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Udp_Close_byK");	

	p_fs2_rt->fs_id_count_array[SAPP_STAT_TCP_STREAM_NEW] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Tcp_Link_New");
	p_fs2_rt->fs_id_count_array[SAPP_STAT_TCP_STREAM_DEL] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Tcp_Link_Del");
	p_fs2_rt->fs_id_count_array[SAPP_STAT_TCP_STREAM_DATA] = FS_register(fs2_handle, FS_STYLE_STATUS, FS_CALC_CURRENT, "Tcp_Concurrent");

	p_fs2_rt->fs_id_count_array[SAPP_STAT_UDP_STREAM_NEW] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Udp_Link_New");
	p_fs2_rt->fs_id_count_array[SAPP_STAT_UDP_STREAM_DEL] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Udp_Link_Del");
	p_fs2_rt->fs_id_count_array[SAPP_STAT_UDP_STREAM_MORE] = FS_register(fs2_handle, FS_STYLE_STATUS, FS_CALC_CURRENT, "Udp_Concurrent");
	

    p_fs2_rt->fs_id_count_array[SAPP_STAT_TCP_STREAM_DOUBLE] = FS_register(fs2_handle, FS_STYLE_STATUS,FS_CALC_CURRENT, "Tcp_Link_Double");
    p_fs2_rt->fs_id_count_array[SAPP_STAT_TCP_STREAM_C2S] = FS_register(fs2_handle,FS_STYLE_STATUS, FS_CALC_CURRENT, "Tcp_Link_C2S");
    p_fs2_rt->fs_id_count_array[SAPP_STAT_TCP_STREAM_S2C] = FS_register(fs2_handle,FS_STYLE_STATUS, FS_CALC_CURRENT, "Tcp_Link_S2C");

    p_fs2_rt->fs_id_count_array[SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE] = FS_register(fs2_handle, FS_STYLE_STATUS,FS_CALC_CURRENT, "Tcp_Link_Double_ALL");
    p_fs2_rt->fs_id_count_array[SAPP_STAT_TCP_STREAM_TOTAL_C2S] = FS_register(fs2_handle,FS_STYLE_STATUS, FS_CALC_CURRENT, "Tcp_Link_C2S_ALL");
    p_fs2_rt->fs_id_count_array[SAPP_STAT_TCP_STREAM_TOTAL_S2C] = FS_register(fs2_handle,FS_STYLE_STATUS, FS_CALC_CURRENT, "Tcp_Link_S2C_ALL");
 

    p_fs2_rt->fs_id_count_array[SAPP_STAT_UDP_STREAM_DOUBLE] = FS_register(fs2_handle, FS_STYLE_STATUS,FS_CALC_CURRENT, "Udp_Link_Double");
    p_fs2_rt->fs_id_count_array[SAPP_STAT_UDP_STREAM_C2S] = FS_register(fs2_handle,FS_STYLE_STATUS, FS_CALC_CURRENT, "Udp_Link_C2S");
    p_fs2_rt->fs_id_count_array[SAPP_STAT_UDP_STREAM_S2C] = FS_register(fs2_handle,FS_STYLE_STATUS, FS_CALC_CURRENT, "Udp_Link_S2C");

    p_fs2_rt->fs_id_count_array[SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE] = FS_register(fs2_handle, FS_STYLE_STATUS,FS_CALC_CURRENT, "Udp_Link_Double_ALL");
    p_fs2_rt->fs_id_count_array[SAPP_STAT_UDP_STREAM_TOTAL_C2S] = FS_register(fs2_handle,FS_STYLE_STATUS, FS_CALC_CURRENT, "Udp_Link_C2S_ALL");
    p_fs2_rt->fs_id_count_array[SAPP_STAT_UDP_STREAM_TOTAL_S2C] = FS_register(fs2_handle,FS_STYLE_STATUS, FS_CALC_CURRENT, "Udp_Link_S2C_ALL");


    p_fs2_rt->fs_id_count_array[SAPP_STAT_SND_TCP_RST] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Send_Tcp_Rst");
	p_fs2_rt->fs_id_count_array[SAPP_STAT_SND_TCP_SYNACK] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Send_Tcp_S/A");
	p_fs2_rt->fs_id_count_array[SAPP_STAT_SND_UDP] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Send_Udp");

	p_fs2_rt->fs_id_count_array[SAPP_STAT_GLOBAL_BYPASS] = FS_register(fs2_handle,FS_STYLE_STATUS, FS_CALC_CURRENT, "DDOS_Bypass");

	p_fs2_rt->fs_id_count_array[SAPP_STAT_TCP_BYPASS_STREAM] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Tcp_Bypass_STM");	
	p_fs2_rt->fs_id_count_array[SAPP_STAT_TCP_BYPASS_PKTS] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Tcp_Bypass_Pkt");
	p_fs2_rt->fs_id_length_array[SAPP_STAT_TCP_BYPASS_BYTES] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Tcp_Bypass_Bit");

	p_fs2_rt->fs_id_count_array[SAPP_STAT_UDP_BYPASS_STREAM] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Udp_Bypass_STM");	
	p_fs2_rt->fs_id_count_array[SAPP_STAT_UDP_BYPASS_PKTS] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Udp_Bypass_Pkt");
	p_fs2_rt->fs_id_length_array[SAPP_STAT_UDP_BYPASS_BYTES] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Udp_Bypass_Bit");

	p_fs2_rt->fs_id_count_array[SAPP_STAT_TCP_OFFLOAD_STREAM] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Tcp_Offload_STM");	
	p_fs2_rt->fs_id_count_array[SAPP_STAT_TCP_OFFLOAD_PKTS] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Tcp_Offload_Pkt");
	p_fs2_rt->fs_id_length_array[SAPP_STAT_TCP_OFFLOAD_BYTES] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Tcp_Offload_Bit");

	p_fs2_rt->fs_id_count_array[SAPP_STAT_UDP_OFFLOAD_STREAM] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Udp_Offload_STM");	
	p_fs2_rt->fs_id_count_array[SAPP_STAT_UDP_OFFLOAD_PKTS] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Udp_Offload_Pkt");
	p_fs2_rt->fs_id_length_array[SAPP_STAT_UDP_OFFLOAD_BYTES] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Udp_Offload_Bit");

	if (unlikely(g_timestamp_record_sw))
	{
		for (int i = 0; i < g_packet_io_thread_num; i++)
		{
			char histogram_name[16];
			sprintf(histogram_name, "TD_ns(tid_%d)", i);
			p_fs2_rt->fs_latency_id_array[i] = FS_register_histogram(fs2_handle,	 // Field Stat句柄
																	 FS_CALC_SPEED,	 // 输出累计值或瞬时值
																	 histogram_name, // 统计项名称，字符串
																	 1,				 // 可追踪的最小值
																	 1000000,		 // 可追踪的最大值
																	 2);			 // 精度，即小数点后几位，范围1~4
			FS_set_para(fs2_handle, NOT_SEND_METRIC_TO_SERVER, &p_fs2_rt->fs_latency_id_array[i], sizeof(int));
		}

		/* 0保留给sapp内置插件, index从1开始 */
		for (int i = 1; i < g_plug_global_entry_index; i++)
		{
			p_fs2_rt->fs_latency_plug_entrg_id_array[i] = FS_register_histogram(p_fs2_rt->fs_metric_handle,				// Field Stat句柄
																				FS_CALC_SPEED,							// 输出累计值或瞬时值
																				g_plug_global_entry[i].plug_entry_name, // 统计项名称，字符串
																				1,										// 可追踪的最小值
																				1000000,								// 可追踪的最大值
																				2);										// 精度，即小数点后几位，范围1~4
			if (p_fs2_rt->fs_latency_plug_entrg_id_array[i] < 0)
			{
				sapp_runtime_log(RLOG_LV_FATAL, "FS_register_histogram() error, plug name:%s", g_plug_global_entry[i].plug_entry_name);
				return -1;
			}
		}
	}
	FS_start(fs2_handle);
	
	return 0;
}

static void sapp_fs2_destroy(sapp_global_t *global_paramters)
{
	sapp_config_profiling_metric_t *p_fs2_para = &global_paramters->config.profiling.fs2;
	sapp_gval_individual_fixed_fs2_t *p_fs2_rt = &global_paramters->individual_fixed.fs2_runtime;
	if (strlen(p_fs2_para->prometheus_service_uri) > 0 && p_fs2_para->prometheus_service_port > 0)
	{
		FS_library_destroy();
	}

	if (p_fs2_rt->fs_metric_handle)
	{
		FS_stop(&p_fs2_rt->fs_metric_handle);
	}
}


void sapp_fs3_metric_set(int metric_idx, int metric_idy, long long value)
{
	sapp_gval_individual_fixed_fs3_t *fs3_rt = &sapp_global_val->individual_fixed.fs3_runtime;
	if(fs3_rt->fs_metric_handle!=NULL)
	{
		fieldstat_value_set(fs3_rt->fs_metric_handle, 
								fs3_rt->metrics_ids[metric_idx][metric_idy], 
								value);
	}
	return;
}

void sapp_fs3_metric_incrby(int column_idx, int column_idy,long long value)
{
	sapp_gval_individual_fixed_fs3_t *fs3_rt = &sapp_global_val->individual_fixed.fs3_runtime;
	if(fs3_rt->fs_metric_handle!=NULL)
	{
		fieldstat_value_incrby(fs3_rt->fs_metric_handle, 
								fs3_rt->metrics_ids[column_idx][column_idy], 
								value);
	}
	return;
}

static int sapp_fs3_init(sapp_global_t *global_paramters)
{
	sapp_config_profiling_metric_t *fs3_para = &global_paramters->config.profiling.fs3;
	sapp_gval_individual_fixed_fs3_t *fs3_rt = &global_paramters->individual_fixed.fs3_runtime;

	fs3_rt->fs_metric_handle = fieldstat_instance_new(sapp_global_val->config.system.instance_name);
	if(fs3_rt->fs_metric_handle == NULL)
	{
		return -1;
	}
	struct fieldstat_instance *fs3_handle = fs3_rt->fs_metric_handle;
	fieldstat_set_output_interval(fs3_handle, fs3_para->refresh_interval_s * 1000);
	if(strlen(fs3_para->local_file) > 0)
	{
		fieldstat_set_local_output(fs3_handle, ABBR_FS3_LOG_DATA_FILE, "default");
	}
	if(strlen(fs3_para->prometheus_service_uri) > 0 && fs3_para->prometheus_service_port > 0)
	{
		fieldstat_global_enable_prometheus_endpoint(fs3_para->prometheus_service_port, fs3_para->prometheus_service_uri);
		fieldstat_enable_prometheus_output(fs3_handle);
	}	


	fs3_rt->metrics_ids[0][SAPP_STAT_RCV_LINE] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Line_Pkt", 
								NULL, 0);
	fs3_rt->metrics_ids[1][SAPP_STAT_RCV_LINE] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Line_Bit", 
								NULL, 0);								

	fs3_rt->metrics_ids[0][SAPP_STAT_RCV_ETHERNET] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Eth_Pkt", 
								NULL, 0);
	fs3_rt->metrics_ids[1][SAPP_STAT_RCV_ETHERNET] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Eth_Bit", 
								NULL, 0);		

	fs3_rt->metrics_ids[0][SAPP_STAT_ETH_INBOUND] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Pkt_Inbound", 
								NULL, 0);
	fs3_rt->metrics_ids[1][SAPP_STAT_ETH_INBOUND] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Bit_Inbound", 
								NULL, 0);	
	fs3_rt->metrics_ids[0][SAPP_STAT_ETH_INBOUND] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Pkt_Outbound", 
								NULL, 0);
	fs3_rt->metrics_ids[1][SAPP_STAT_RCV_ETHERNET] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Bit_Outbound", 
								NULL, 0);	


	fs3_rt->metrics_ids[0][SAPP_STAT_RCV_UNKNOWN] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Unknown_Pkt", 
								NULL, 0);
	fs3_rt->metrics_ids[1][SAPP_STAT_RCV_UNKNOWN] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Unknown_Bit", 
								NULL, 0);	

	fs3_rt->metrics_ids[0][SAPP_STAT_SND_ERROR] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Snd_Err_Pkt", 
								NULL, 0);

	fs3_rt->metrics_ids[0][SAPP_STAT_RCV_IPV4] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Ipv4_Pkt", 
								NULL, 0);
	fs3_rt->metrics_ids[1][SAPP_STAT_RCV_IPV4] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Ipv4_Bit", 
								NULL, 0);	

	fs3_rt->metrics_ids[0][SAPP_STAT_RCV_IPV6] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Ipv6_Pkt", 
								NULL, 0);
	fs3_rt->metrics_ids[1][SAPP_STAT_RCV_IPV6] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Ipv6_Bit", 
								NULL, 0);	

	fs3_rt->metrics_ids[0][SAPP_STAT_RCV_TCP] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Tcp_Pkt", 
								NULL, 0);
	fs3_rt->metrics_ids[1][SAPP_STAT_RCV_TCP] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Tcp_Bit", 
								NULL, 0);	

	fs3_rt->metrics_ids[0][SAPP_STAT_RCV_DUP_TCP] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Dup_Tcp_Pkt", 
								NULL, 0);
	fs3_rt->metrics_ids[1][SAPP_STAT_RCV_DUP_TCP] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Dup_Tcp_Bit", 
								NULL, 0);	

	fs3_rt->metrics_ids[0][SAPP_STAT_TCP_LOST_PKT_STREAM_NUM] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Tcp_Lost_STM", 
								NULL, 0);
	fs3_rt->metrics_ids[1][SAPP_STAT_TCP_LOST_PKT] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Tcp_Lost_Bit", 
								NULL, 0);	

	fs3_rt->metrics_ids[0][SAPP_STAT_DUP_IDENTIFY_ERR] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Dup_Key_Err", 
								NULL, 0);

	fs3_rt->metrics_ids[0][SAPP_STAT_TCP_CLOSE_BY_TIMEOUT] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Tcp_Close_byT", 
								NULL, 0);
	fs3_rt->metrics_ids[0][SAPP_STAT_TCP_CLOSE_BY_KICKOUT] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Tcp_Close_byK", 
								NULL, 0);								

	fs3_rt->metrics_ids[0][SAPP_STAT_RCV_UDP] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Udp_Pkt", 
								NULL, 0);
	fs3_rt->metrics_ids[1][SAPP_STAT_RCV_UDP] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Udp_Bit", 
								NULL, 0);		
	fs3_rt->metrics_ids[0][SAPP_STAT_RCV_DUP_UDP] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Dup_Udp_Pkt", 
								NULL, 0);
	fs3_rt->metrics_ids[1][SAPP_STAT_RCV_DUP_UDP] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Dup_Udp_Bit", 
								NULL, 0);									

	fs3_rt->metrics_ids[0][SAPP_STAT_UDP_CLOSE_BY_TIMEOUT] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Udp_Close_byT", 
								NULL, 0);
	fs3_rt->metrics_ids[0][SAPP_STAT_UDP_CLOSE_BY_KICKOUT] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Udp_Close_byK", 
								NULL, 0);		

	fs3_rt->metrics_ids[0][SAPP_STAT_TCP_STREAM_NEW] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Tcp_Link_New", 
								NULL, 0);
	fs3_rt->metrics_ids[0][SAPP_STAT_TCP_STREAM_DEL] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Tcp_Link_Del", 
								NULL, 0);	

	fs3_rt->metrics_ids[0][SAPP_STAT_TCP_STREAM_DATA] = fieldstat_register(fs3_handle, FIELD_TYPE_GAUGE, "Tcp_Concurrent", 
								NULL, 0);									

	fs3_rt->metrics_ids[0][SAPP_STAT_UDP_STREAM_NEW] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Udp_Link_New", 
								NULL, 0);
	fs3_rt->metrics_ids[0][SAPP_STAT_UDP_STREAM_DEL] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Udp_Link_Del", 
								NULL, 0);	

	fs3_rt->metrics_ids[0][SAPP_STAT_UDP_STREAM_MORE] = fieldstat_register(fs3_handle, FIELD_TYPE_GAUGE, "Udp_Concurrent", 
								NULL, 0);	


	fs3_rt->metrics_ids[0][SAPP_STAT_TCP_STREAM_DOUBLE] = fieldstat_register(fs3_handle, FIELD_TYPE_GAUGE, "Tcp_Link_Double", 
								NULL, 0);	
	fs3_rt->metrics_ids[0][SAPP_STAT_TCP_STREAM_C2S] = fieldstat_register(fs3_handle, FIELD_TYPE_GAUGE, "Tcp_Link_C2S", 
								NULL, 0);	
	fs3_rt->metrics_ids[0][SAPP_STAT_TCP_STREAM_C2S] = fieldstat_register(fs3_handle, FIELD_TYPE_GAUGE, "Tcp_Link_S2C", 
								NULL, 0);									

	fs3_rt->metrics_ids[0][SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE] = fieldstat_register(fs3_handle, FIELD_TYPE_GAUGE, "Tcp_Link_Double_ALL", 
								NULL, 0);	
	fs3_rt->metrics_ids[0][SAPP_STAT_TCP_STREAM_TOTAL_C2S] = fieldstat_register(fs3_handle, FIELD_TYPE_GAUGE, "Tcp_Link_C2S_ALL", 
								NULL, 0);	
	fs3_rt->metrics_ids[0][SAPP_STAT_TCP_STREAM_TOTAL_S2C] = fieldstat_register(fs3_handle, FIELD_TYPE_GAUGE, "Tcp_Link_S2C_ALL", 
								NULL, 0);	

	fs3_rt->metrics_ids[0][SAPP_STAT_UDP_STREAM_DOUBLE] = fieldstat_register(fs3_handle, FIELD_TYPE_GAUGE, "Udp_Link_Double", 
								NULL, 0);	
	fs3_rt->metrics_ids[0][SAPP_STAT_UDP_STREAM_C2S] = fieldstat_register(fs3_handle, FIELD_TYPE_GAUGE, "Udp_Link_C2S", 
								NULL, 0);	
	fs3_rt->metrics_ids[0][SAPP_STAT_UDP_STREAM_S2C] = fieldstat_register(fs3_handle, FIELD_TYPE_GAUGE, "Udp_Link_S2C", 
								NULL, 0);									

	fs3_rt->metrics_ids[0][SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE] = fieldstat_register(fs3_handle, FIELD_TYPE_GAUGE, "Udp_Link_Double_ALL", 
								NULL, 0);	
	fs3_rt->metrics_ids[0][SAPP_STAT_UDP_STREAM_TOTAL_C2S] = fieldstat_register(fs3_handle, FIELD_TYPE_GAUGE, "Udp_Link_C2S_ALL", 
								NULL, 0);	
	fs3_rt->metrics_ids[0][SAPP_STAT_UDP_STREAM_TOTAL_S2C] = fieldstat_register(fs3_handle, FIELD_TYPE_GAUGE, "Udp_Link_S2C_ALL", 
								NULL, 0);	

	fs3_rt->metrics_ids[0][SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE] = fieldstat_register(fs3_handle, FIELD_TYPE_GAUGE, "Udp_Link_Double_ALL", 
								NULL, 0);	
	fs3_rt->metrics_ids[0][SAPP_STAT_UDP_STREAM_TOTAL_C2S] = fieldstat_register(fs3_handle, FIELD_TYPE_GAUGE, "Udp_Link_C2S_ALL", 
								NULL, 0);	
	fs3_rt->metrics_ids[0][SAPP_STAT_UDP_STREAM_TOTAL_S2C] = fieldstat_register(fs3_handle, FIELD_TYPE_GAUGE, "Udp_Link_S2C_ALL", 
								NULL, 0);		
	
	fs3_rt->metrics_ids[0][SAPP_STAT_SND_TCP_RST] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Send_Tcp_Rst", 
								NULL, 0);	
	fs3_rt->metrics_ids[0][SAPP_STAT_SND_TCP_SYNACK] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Send_Tcp_S/A", 
								NULL, 0);	
	fs3_rt->metrics_ids[0][SAPP_STAT_SND_UDP] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Send_Udp", 
								NULL, 0);		
								
	
	fs3_rt->metrics_ids[0][SAPP_STAT_GLOBAL_BYPASS] = fieldstat_register(fs3_handle, FIELD_TYPE_GAUGE, "DDOS_Bypass", 
								NULL, 0);	

	fs3_rt->metrics_ids[0][SAPP_STAT_TCP_BYPASS_STREAM] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Tcp_Bypass_STM", 
								NULL, 0);	
	fs3_rt->metrics_ids[0][SAPP_STAT_TCP_BYPASS_PKTS] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Tcp_Bypass_Pkt", 
								NULL, 0);	
	fs3_rt->metrics_ids[1][SAPP_STAT_TCP_BYPASS_BYTES] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Tcp_Bypass_Bit", 
								NULL, 0);								

	fs3_rt->metrics_ids[0][SAPP_STAT_UDP_BYPASS_STREAM] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Udp_Bypass_STM", 
								NULL, 0);	
	fs3_rt->metrics_ids[0][SAPP_STAT_UDP_BYPASS_PKTS] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Udp_Bypass_Pkt", 
								NULL, 0);	
	fs3_rt->metrics_ids[1][SAPP_STAT_UDP_BYPASS_BYTES] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Udp_Bypass_Bit", 
								NULL, 0);	

	fs3_rt->metrics_ids[0][SAPP_STAT_TCP_OFFLOAD_STREAM] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Tcp_Offload_STM", 
								NULL, 0);	
	fs3_rt->metrics_ids[0][SAPP_STAT_TCP_OFFLOAD_PKTS] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Tcp_Offload_Pkt", 
								NULL, 0);	
	fs3_rt->metrics_ids[1][SAPP_STAT_TCP_OFFLOAD_BYTES] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Tcp_Offload_Bit", 
								NULL, 0);	

	fs3_rt->metrics_ids[0][SAPP_STAT_UDP_OFFLOAD_STREAM] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Udp_Offload_STM", 
								NULL, 0);	
	fs3_rt->metrics_ids[0][SAPP_STAT_UDP_OFFLOAD_PKTS] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Udp_Offload_Pkt", 
								NULL, 0);	
	fs3_rt->metrics_ids[1][SAPP_STAT_UDP_OFFLOAD_BYTES] = fieldstat_register(fs3_handle, FIELD_TYPE_COUNTER, "Udp_Offload_Bit", 
								NULL, 0);	
	// TODO: histogram for process lanency							
	fieldstat_instance_start(fs3_handle);
	return 0;
}

static void sapp_fs3_destroy(sapp_global_t *global_paramters)
{
	sapp_gval_individual_fixed_fs3_t *fs3_rt = &global_paramters->individual_fixed.fs3_runtime;
	if(fs3_rt->fs_metric_handle != NULL)
	{
		fieldstat_instance_free(fs3_rt->fs_metric_handle);
	}
	fs3_rt->fs_metric_handle=NULL;
	return;
}


int sapp_metric_init(void)
{
	int ret = 0;
	if( sapp_global_val->config.profiling.fs2.enabled == 1)
	{
		sapp_fs2_init(sapp_global_val);
	}
	if( sapp_global_val->config.profiling.fs3.enabled == 1)
	{
		sapp_fs3_init(sapp_global_val);
	}
	
	return ret;
}

void sapp_metric_destroy(void)
{
	
	if( sapp_global_val->config.profiling.fs2.enabled == 1)
	{
		sapp_fs2_destroy(sapp_global_val);
	}
	if( sapp_global_val->config.profiling.fs3.enabled == 1)
	{
		sapp_fs3_destroy(sapp_global_val);
	}
}
