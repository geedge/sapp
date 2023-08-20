#include "breakpad_mini.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"
#include "support/tomlc99_wrap.h"
#include "field_stat2.h"
#include "sapp_declaration.h"

extern int g_overlay_layer_set[__ADDR_TYPE_MAX][SAPP_SUPPORT_LAYER_NUM_MAX];  

/*
	说明:
		_sapp_toml_sample_file_image数组, _sapp_toml_sample_file_image_len变量是靠命令xxd -i 自动生成的, 
		保存在动态创建的文件sapp.toml.hex.array.c里,
		此文件无需加入git仓库.
*/
extern const unsigned char _sapp_toml_sample_file_image[];
extern const int _sapp_toml_sample_file_image_len;

#define SAPP_CFG_OBSOLETE_FLAG  99999999
typedef struct __sapp_config_check{
	int global_id;
	int depend_id; /* 1:必须的参数, 不依赖其他参数, 也不能缺失;  0:可选的, 可以没有, 不影响sapp主体功能; >=1000:悬而未决的, 取决于其他配置参数是否开启, 比如transparent模式必须配置packet_io.external.interface */
	int err_log_level; /* 10,20,30, 错误日志等级 */
	const char *section;
	const char *cfg_key;
	const char *depend_cfg_value; /* 仅当depend_id>1000时有效, 表示依赖参数的值符合预先定义时, 才检查当前参数是否合法, 比如mirro模式下根本不需要检查 packet_io.external.interface */
	int (*cfg_value_check_fun)(const struct __sapp_config_check *sapp_cfg_check_attr, int this_cfg_id, int depend_cfg_id, const char *cfg_value, const void *range_array, int array_num);
	char *cfg_value; /* NULL is not found */
	const void *expect_range_array; /* 用于检测参数值的可选范围数组, 根据类型的不同可以是int *, 或者是char **类型 */
	int expect_array_num;
}sapp_config_check_t;


typedef struct{
	int array_num;
	int *integer_range_array;
	char **string_range_array;
}sapp_config_ckeck_range_t;

static const char *sapp_cfg_get_value_from_attr_by_id(const sapp_config_check_t *sapp_cfg_check_attr,int cfg_global_id);
static const char *sapp_cfg_get_value_from_attr_by_section_key(const sapp_config_check_t *sapp_cfg_check_attr, const char *section, const char *key);
static int cfg_value_check_inject_mode(const sapp_config_check_t *sapp_cfg_check_attr,int this_cfg_id,int depend_cfg_id, const char *raw_cfg_value, const void *expect_range_array, int array_num);

static int g_interger_range_array[65536]; /* 一个int型的数组, 数值下标和数值一样, 即 g_interger_range_array[0]=0, g_interger_range_array[1]=1, 用于判断数值参数范围合法性 */


static int cfg_value_check_integer_range(const sapp_config_check_t *sapp_cfg_check_attr,int this_cfg_id,int depend_cfg_id, const char *raw_cfg_value, const void *expect_range_array, int array_num)
{
	int i;
	int raw_int_value;
	const int *integer_array;
	
	if(NULL == raw_cfg_value){
		return -1;
	}
	
	raw_int_value = atoi(raw_cfg_value);
	integer_array = (int *)expect_range_array;	

	for(i = 0; i < array_num; i++){
		if(integer_array[i] == raw_int_value){
			return 0;
		}
	}

	return -1;
}

static int cfg_value_check_string_range(const sapp_config_check_t *sapp_cfg_check_attr,int this_cfg_id,int depend_cfg_id, const char *raw_cfg_value, const void *expect_range_array, int array_num)
{
	int i;
	char **string_array;

	if(NULL == raw_cfg_value){
		return -1;
	}

	string_array = (char **)expect_range_array;

	for(i = 0; i < array_num; i++){
		if((strncmp(string_array[i], raw_cfg_value, strlen(raw_cfg_value)) == 0)
		 &&(strncmp(string_array[i], raw_cfg_value, strlen(string_array[i])) == 0)){
			return 0;
		}
	}

	return -1;
}

static int cfg_value_check_string_non_null(const sapp_config_check_t *sapp_cfg_check_attr,int this_cfg_id,int depend_cfg_id, const char *raw_cfg_value, const void *expect_range_array, int array_num)
{
	if(NULL == raw_cfg_value){
		return -1;
	}

	return 0;
}


static int cfg_value_check_worker_threads(const sapp_config_check_t *sapp_cfg_check_attr,int this_cfg_id,int depend_cfg_id, const char *raw_cfg_value, const void *expect_range_array, int array_num)
{
	int cfg_value_int;

	if(NULL == raw_cfg_value){
		return -1;
	}
	cfg_value_int = atoi(raw_cfg_value);

	int cur_sys_cpu_num = get_nprocs();
	if(cfg_value_int <= 0 || cur_sys_cpu_num < cfg_value_int){
		//printf("\033[33m[Warning]sapp.toml->CPU.worker_threads=%d more than current available processors:%d\033[0m\n", sapp_global_val->config.cpu.worker_threads, cur_sys_cpu_num);		
		//sapp_runtime_log(RLOG_LV_INFO, "[Warning]sapp.toml->CPU.worker_threads=%d more than current available processors:%d", sapp_global_val->config.cpu.worker_threads, cur_sys_cpu_num); 	
		return -1;
	}

	return 0;
}

static int cfg_value_check_bind_mask(const sapp_config_check_t *sapp_cfg_check_attr,int this_cfg_id,int depend_cfg_id, const char *raw_cfg_value, const void *expect_range_array, int array_num)
{
	int bind_mask_array_num = SAPP_MAX_THREADS;
	long bind_mask_array[SAPP_MAX_THREADS];
	int ret;

	/* 暂时没有直接解析raw_cfg_value的函数, 此处再读取一遍配置文件 */
	ret = tomlc99_wrap_load_long_array(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"CPU", (char *)"bind_mask", bind_mask_array, &bind_mask_array_num);
	if(ret < 0){
		unsigned int load_profile_array[SAPP_MAX_THREADS];
		/* 带范围的配置, 如1-10,10-20等参数使用MESA_load_profile_uint_range解析, 此时要用字符串模式!!! */
		ret = MESA_load_profile_uint_range(
			ABBR_CFG_FILE_MAIN_ENTRY, (char *)"CPU", (char *)"bind_mask",
			SAPP_MAX_THREADS, (unsigned int *)load_profile_array);
		if(ret > 0){
			bind_mask_array_num = ret;
		}else{
			return -1;
		}
	}

	if(0 == bind_mask_array_num){
		return 0; /* 允许空数组, 即不绑定CPU,不算错误 */
	}

	const char *raw_cfg_worker_threads_value = sapp_cfg_get_value_from_attr_by_id(sapp_cfg_check_attr, depend_cfg_id);
	if(NULL == raw_cfg_worker_threads_value){
		return -1;
	}

	const char *raw_cfg_send_only_threads_value = sapp_cfg_get_value_from_attr_by_section_key(sapp_cfg_check_attr, "CPU", "send_only_threads_max");
	if(NULL == raw_cfg_send_only_threads_value){
		return -1;
	}
	
	int cfg_worker_threads_num = atoi(raw_cfg_worker_threads_value);
	int cfg_send_only_threads_num = atoi(raw_cfg_send_only_threads_value);
	
	if(bind_mask_array_num != cfg_worker_threads_num + cfg_send_only_threads_num){
		sapp_log(RLOG_LV_FATAL,1,1, "sapp.toml->CPU->bind_mask value is not match sapp.toml->CPU->worker_threads + CPU->send_only_threads_max!\n");
		return -1;
	}

	return 0;
}


static int cfg_value_check_stream_id_base_time(const sapp_config_check_t *sapp_cfg_check_attr,int this_cfg_id,int depend_cfg_id, const char *raw_cfg_value, const void *expect_range_array, int array_num)
{
	struct tm local_tm;
	
	if(NULL == raw_cfg_value || strlen(raw_cfg_value) == 0){
		return 0; /* 可以为NULL,不算错误 */
	}
	
	if(strptime(raw_cfg_value, "%Y-%m-%d %H:%M:%S", &local_tm) == NULL){
		sapp_log(RLOG_LV_FATAL,1,1,"sapp.toml->STREAM->stream_id_base_time error, the pattern must like '1970-01-01 01:01:01'!\n");
		return -1;
	}
	
	if(mktime(&local_tm) > time(NULL)){
		sapp_log(RLOG_LV_FATAL,1,1,"sapp.toml->STREAM.stream_id_base_time value error, is after current system time!\n");
		return -1;
	}

	return 0;
}


static const char *cfg_chk_value_overlay_mode[2] = {"none", "vxlan"};
static const char *cfg_chk_value_pcap_capture_direction[3] = {"in", "out", "inout"};
static const char *cfg_chk_value_inject_pkt_mode[4] = {"sys_route", "vxlan_by_inline_device", "raw_ethernet_single_gateway", "raw_ethernet_multi_gateway"};
static const char *cfg_chk_value_deployment_mode[4] = {"mirror", "inline", "transparent", "dumpfile"};
static const char *cfg_chk_value_interface_type[2] = {"pcap", "marsio"};
static const char *cfg_chk_value_pkt_dump_mode[2] = {"storage", "udp_socket"};
static const char *cfg_chk_value_pcap_distmode[2] = {"inner_tuple2", "outer_tuple2"};


static const sapp_config_check_t g_sapp_cfg_check_attr[] = 
{
	{1000,0,RLOG_LV_INFO,"SYSTEM",	"instance_name",	NULL,NULL, NULL, NULL, 0},
	
	{2001,1,RLOG_LV_FATAL,"CPU",		"worker_threads",	NULL,cfg_value_check_worker_threads, NULL, NULL, 0},
	{2002,0,RLOG_LV_DEBUG, "CPU",		"send_only_threads_max",	NULL,NULL, NULL, NULL, 0},
	{2003,2001,RLOG_LV_FATAL,"CPU",	"bind_mask",	"",cfg_value_check_bind_mask, NULL, NULL, 0},

	{3001,0, RLOG_LV_INFO,"MEM",		"dictator_enable",	NULL,cfg_value_check_integer_range, NULL, g_interger_range_array, 2}, /* 只能是0或1, 所以就用前2个元素 */

	{4000,0,RLOG_LV_DEBUG,"PACKET_IO", NULL,	NULL, NULL,NULL, NULL, 0},
	
	{4101,1,RLOG_LV_INFO,"overlay_tunnel_definition",	"l2_l3_tunnel_support",	NULL,cfg_value_check_integer_range, NULL, g_interger_range_array, 2},
	{4102,4101,RLOG_LV_INFO,"overlay_tunnel_definition",	"overlay_mode",	"1",cfg_value_check_string_range, NULL, cfg_chk_value_overlay_mode, 2},
	
	{4201,0,RLOG_LV_INFO,"packet_io.feature",	"inbound_route_dir",	NULL,cfg_value_check_integer_range, NULL, g_interger_range_array, 2},
	{4202,0,RLOG_LV_DEBUG,"packet_io.feature",	"BSD_packet_filter",	NULL,NULL, NULL, NULL, 0},
	{4203,0,RLOG_LV_DEBUG,"packet_io.feature",	"pcap_capture_direction",	NULL,cfg_value_check_string_range, NULL, cfg_chk_value_pcap_capture_direction, 3},
	{4204,4301,RLOG_LV_INFO,"packet_io.feature",	"inject_pkt_mode",	"mirror",cfg_value_check_string_range, NULL, cfg_chk_value_inject_pkt_mode, 4},
	{4205,4204,RLOG_LV_INFO,"packet_io.feature",	"inject_mode_inline_device_sport",	"vxlan_by_inline_device",cfg_value_check_inject_mode, NULL, g_interger_range_array, 65535},
	{4206,4204,RLOG_LV_INFO,"packet_io.feature",	"inject_mode_single_gateway_device",	"raw_ethernet_single_gateway",cfg_value_check_inject_mode, NULL, NULL, 0},
	{4207,4204,RLOG_LV_INFO,"packet_io.feature",	"inject_mode_single_gateway_src_mac",	"raw_ethernet_single_gateway",cfg_value_check_inject_mode, NULL, NULL, 0},
	{4208,4204,RLOG_LV_INFO,"packet_io.feature",	"inject_mode_single_gateway_dst_mac",	"raw_ethernet_single_gateway",cfg_value_check_inject_mode, NULL, NULL, 0},
	{4209,0,RLOG_LV_DEBUG,"packet_io.feature",	"monitor_thread_enabled",	NULL, cfg_value_check_integer_range, NULL, g_interger_range_array, 65535},
	{4210,0,RLOG_LV_DEBUG,"packet_io.feature",	"extract_linkdir_from_mac_in_mirror_mode",	NULL, NULL, NULL, NULL, 0},
	{4211,0,RLOG_LV_DEBUG,"packet_io.feature",	"pcap_distmode",	NULL,cfg_value_check_string_range, NULL, cfg_chk_value_pcap_distmode, 2},

	{4301,1,RLOG_LV_FATAL,"packet_io.deployment",	"mode",	NULL,cfg_value_check_string_range, NULL, cfg_chk_value_deployment_mode, 3},
	{4302,1,RLOG_LV_FATAL,"packet_io.internal.interface",	"type",	NULL,cfg_value_check_string_range, NULL, cfg_chk_value_interface_type, 2},
	{4303,1,RLOG_LV_FATAL,"packet_io.internal.interface",	"name",	NULL,cfg_value_check_string_non_null, NULL, NULL, 0},
	{4304,4301,RLOG_LV_FATAL,"packet_io.external.interface",	"type",	"transparent",cfg_value_check_string_range, NULL, cfg_chk_value_interface_type, 2},
	{4305,4301,RLOG_LV_FATAL,"packet_io.external.interface",	"name",	"transparent",cfg_value_check_string_non_null, NULL, NULL, 0},
	{4306,0,RLOG_LV_DEBUG,"packet_io.polling",	"enabled",	NULL,cfg_value_check_integer_range, NULL, g_interger_range_array, 2},
	{4307,0,RLOG_LV_DEBUG,"packet_io.polling",	"polling_priority",	NULL,cfg_value_check_integer_range, NULL, g_interger_range_array, 100},

	{4401,0,RLOG_LV_DEBUG,"PROTOCOL_FEATURE",	"ipv6_decapsulation_enabled",	NULL,NULL, NULL, NULL, 0},
	{4402,0,RLOG_LV_DEBUG,"PROTOCOL_FEATURE",	"ipv6_send_packet_enabled",	NULL,NULL, NULL, NULL, 0},
	{4403,0,RLOG_LV_DEBUG,"PROTOCOL_FEATURE",	"tcp_drop_pure_ack_pkt",	NULL,NULL, NULL, NULL, 0},
	{4404,0,RLOG_LV_DEBUG,"PROTOCOL_FEATURE",	"tcp_syn_option_parse_enabled",	NULL,NULL, NULL, NULL, 0},
	{4405,0,RLOG_LV_DEBUG,"PROTOCOL_FEATURE",	"skip_not_ip_layer_over_eth",	NULL,NULL, NULL, NULL, 0},
	{4406,0,RLOG_LV_DEBUG,"PROTOCOL_FEATURE",	"ipv6_decapsulation_enabled",	NULL,NULL, NULL, NULL, 0},
	{4407,0,RLOG_LV_DEBUG,"PROTOCOL_FEATURE",	"skip_gtp_S_PN_E_field_for_inject",	NULL,NULL, NULL, NULL, 0},

	{4501,0,RLOG_LV_INFO,"dup_pkt.traffic.original",	"original_ipv4_tcp_enabled",	NULL,NULL, NULL, NULL, 0},
	{4502,0,RLOG_LV_INFO,"dup_pkt.traffic.original",	"original_ipv4_udp_enabled",	NULL,NULL, NULL, NULL, 0},
	{4503,0,RLOG_LV_INFO,"dup_pkt.traffic.inject",	"inject_all_enabled",	NULL,NULL, NULL, NULL, 0},
	{4504,0,RLOG_LV_INFO,"dup_pkt.parameters",	"bloom_capacity",	NULL,NULL, NULL, NULL, 0},
	{4505,0,RLOG_LV_INFO,"dup_pkt.parameters",	"bloom_error_rate",	NULL,NULL, NULL, NULL, 0},
	{4506,0,RLOG_LV_INFO,"dup_pkt.parameters",	"bloom_timeout",	NULL,NULL, NULL, NULL, 0},

	{4600,0,RLOG_LV_DEBUG,"packet_io.under_ddos", NULL,	NULL, NULL,NULL, NULL, 0},
	{4601,0,RLOG_LV_INFO,"packet_io.under_ddos",	"stream_bypass_enabled",	NULL,cfg_value_check_integer_range, NULL, g_interger_range_array, 2},
	{4602,4601,RLOG_LV_INFO,"packet_io.under_ddos",	"get_cpu_usage_interval",	"1",NULL, NULL, NULL, 0},
	{4603,4601,RLOG_LV_INFO,"packet_io.under_ddos",	"smooth_avg_window",	"1",NULL, NULL, NULL, 0},
	{4604,4601,RLOG_LV_INFO,"packet_io.under_ddos",	"bypass_trigger_cpu_usage",	"1",cfg_value_check_integer_range, NULL, g_interger_range_array, 99},
	{4605,4601,RLOG_LV_INFO,"packet_io.under_ddos",	"decrease_ratio","1",NULL, NULL, NULL, 0},
	{4606,4601,RLOG_LV_INFO,"packet_io.under_ddos",	"increase_ratio","1",NULL, NULL, NULL, 0},
	{4607,4601,RLOG_LV_INFO,"packet_io.under_ddos",	"recovery_observe_time","1",NULL, NULL, NULL, 0},

	{5001,0,RLOG_LV_INFO,"STREAM",	"stream_id_base_time",	NULL,cfg_value_check_stream_id_base_time, NULL, NULL, 0},
	
	{5101,1,RLOG_LV_FATAL,"stream.tcp",	"max",	NULL,NULL, NULL, NULL, 0},
	{5102,1,RLOG_LV_FATAL,"stream.tcp",	"timeout",	NULL,cfg_value_check_integer_range, NULL, g_interger_range_array, 65535},
	{5103,1,RLOG_LV_FATAL,"stream.tcp",	"syn_mandatory",	NULL,cfg_value_check_integer_range, NULL, g_interger_range_array, 2},
	{5104,1,RLOG_LV_FATAL,"stream.tcp",	"reorder_pkt_max",	NULL,cfg_value_check_integer_range, NULL, g_interger_range_array, 65535},
	{5105,0,RLOG_LV_INFO,"stream.tcp",	"analyse_option_enabled",	NULL,NULL, NULL, NULL, 0},
	{5106,0,RLOG_LV_INFO,"stream.tcp",	"tuple4_reuse_time_interval",	NULL,NULL, NULL, NULL, 0},
	{5107,0,RLOG_LV_INFO,"stream.tcp",	"meaningful_statistics_minimum_pkt",	NULL,NULL, NULL, NULL, 0},
	{5108,0,RLOG_LV_INFO,"stream.tcp",	"meaningful_statistics_minimum_byte",	NULL,NULL, NULL, NULL, 0},

	{5201,0,RLOG_LV_INFO,"stream.tcp.inject",	"link_mss",	NULL,NULL, NULL, NULL, 0},
	{5202,0,RLOG_LV_INFO,"stream.tcp.inject.rst",	"auto_remedy",	NULL,NULL, NULL, NULL, 0},
	{5203,0,RLOG_LV_INFO,"stream.tcp.inject.rst",	"number",	NULL,cfg_value_check_integer_range, NULL, g_interger_range_array, 10},
	{5204,0,RLOG_LV_INFO,"stream.tcp.inject.rst",	"signature_enabled",	NULL,NULL, NULL, NULL, 0},
	{5205,5204,RLOG_LV_INFO,"stream.tcp.inject.rst",	"signature_seed1",	"1",NULL, NULL, NULL, 0},
	{5206,5204,RLOG_LV_INFO,"stream.tcp.inject.rst",	"signature_seed2",	"1",NULL, NULL, NULL, 0},
	{5207,5202,RLOG_LV_INFO,"stream.tcp.inject.rst",	"remedy_kill_tcp_by_inline_device",	"1",NULL, NULL, NULL, 0},

	{5301,1,RLOG_LV_FATAL,"stream.udp",	"max",	NULL, NULL, NULL, NULL, 0},
	{5302,1,RLOG_LV_FATAL,"stream.udp",	"timeout",	NULL,cfg_value_check_integer_range, NULL, g_interger_range_array, 65535},
	{5303,0,RLOG_LV_INFO,"stream.udp",	"meaningful_statistics_minimum_pkt",	NULL,NULL, NULL, NULL, 0},
	{5304,0,RLOG_LV_INFO,"stream.udp",	"meaningful_statistics_minimum_byte",	NULL,NULL, NULL, NULL, 0},

	{6000,0,RLOG_LV_DEBUG,"PROFILING",	NULL,NULL,	NULL, NULL, NULL, 0},
	{6101,0,RLOG_LV_DEBUG,"profiling.pkt_latency",	"enabled",	NULL,NULL, NULL, NULL, 0},
	{6102,0,RLOG_LV_DEBUG,"profiling.pkt_latency",	"threshold",	"1",NULL, NULL, NULL, 0},
	{6103,0,RLOG_LV_DEBUG,"profiling.pkt_latency",	"accurate_enable",	NULL,NULL, NULL, NULL, 0},

	{6201,0,RLOG_LV_DEBUG,"profiling.sanity_check",	"raw_pkt_broken_enabled",	NULL,NULL, NULL, NULL, 0},
	{6202,0,RLOG_LV_DEBUG,"profiling.sanity_check",	"symbol_conflict_enabled",	NULL,NULL, NULL, NULL, 0},

	{6301,1,RLOG_LV_FATAL,"profiling.log",	"level",	NULL,NULL, NULL, NULL, 0},
	{6302,0,RLOG_LV_INFO,"profiling.log",	"interval",	NULL,NULL, NULL, NULL, 0},
	
	{6401,0,RLOG_LV_INFO,"profiling.log.local",	"enabled",	NULL, NULL, NULL, 0, 0},
	{6402,0,RLOG_LV_INFO,"profiling.log.local",	"file_truncate_enabled",	NULL, NULL, NULL, 0, 0},

	{6501,0,RLOG_LV_INFO,"profiling.log.remote",	"enabled",	NULL,NULL, NULL, NULL, 0},
	{6502,6501,RLOG_LV_INFO,"profiling.log.remote",	"server_ip",	"1",NULL, NULL, NULL, 0},
	{6503,6501,RLOG_LV_INFO,"profiling.log.remote",	"server_port",	"1",cfg_value_check_integer_range, NULL, g_interger_range_array, 65535},

	{6601,0,RLOG_LV_INFO,"profiling.log.remote.field_stat2",	"metric_type",	NULL,NULL, NULL, NULL, 0},
	{6602,0,RLOG_LV_INFO,"profiling.log.remote.field_stat2",	"app_name",	NULL, NULL, NULL, NULL, 0},
	
	{6701,0,RLOG_LV_INFO,"profiling.log.prometheus",	"prometheus_enabled",	NULL, NULL, NULL, NULL, 0},
	{6702,6701,RLOG_LV_INFO,"profiling.log.prometheus",	"prometheus_port",	"1",cfg_value_check_integer_range, NULL, g_interger_range_array, 65535},
	{6703,6701,RLOG_LV_INFO,"profiling.log.prometheus",	"prometheus_url_path",	"1",NULL, NULL, NULL, 0},

	{7000,0,RLOG_LV_DEBUG,"TOOLS",	NULL, NULL,	NULL, NULL, NULL, 0},
	
	{7101,0,RLOG_LV_FATAL,"tools.pkt_dump",	"enabled",	NULL, NULL, NULL, NULL, 0},
	{7102,7101,RLOG_LV_FATAL,"tools.pkt_dump",	"mode",	"1", cfg_value_check_string_range, NULL, cfg_chk_value_pkt_dump_mode, 2},
	{7103,0,RLOG_LV_DEBUG,"tools.pkt_dump",	"BSD_packet_filter",	NULL, NULL, NULL, NULL, 0},

	{7201,0,RLOG_LV_DEBUG,"tools.pkt_dump.threads",	"all_threads_enabled",	NULL, NULL, NULL, NULL, 0},
	{7202,0,RLOG_LV_DEBUG,"tools.pkt_dump.threads",	"dump_thread_id",	NULL, NULL, NULL, NULL, 0},

	{7301,7102,RLOG_LV_FATAL,"tools.pkt_dump.udp",	"command_port",	"udp_socket", cfg_value_check_integer_range, NULL, g_interger_range_array, 65535},
	{7302,7102,RLOG_LV_DEBUG,"tools.pkt_dump.udp",	"pkt_dump_ratio",	"udp_socket",NULL, NULL, NULL, 0},
	
	{7401,7102,RLOG_LV_FATAL,"tools.pkt_dump.storage",	"path",	"storage",NULL, NULL, NULL, 0},
	{7402,7102,RLOG_LV_INFO,"tools.pkt_dump.storage",	"file_size_max_per_thread",	"storage",NULL, NULL, NULL, 0},

	{8001,0,RLOG_LV_DEBUG,"BREAKPAD",	"disable_coredump",	NULL,NULL, NULL, NULL, 0},
	{8002,0,RLOG_LV_DEBUG,"BREAKPAD",	"enable_breakpad",	NULL,NULL, NULL, NULL, 0},
	{8003,8002,RLOG_LV_DEBUG,"BREAKPAD",	"breakpad_minidump_dir",	"1",NULL, NULL, NULL, 0},
	{8004,0,RLOG_LV_DEBUG,"BREAKPAD",	"enable_breakpad_upload",	NULL,NULL, NULL, NULL, 0},
	{8005,8004,RLOG_LV_DEBUG,"BREAKPAD",	"breakpad_upload_url",	"1",NULL, NULL, NULL, 0},
	{8006,8004,RLOG_LV_DEBUG,"BREAKPAD","breakpad_upload_tools", "1",NULL, NULL, NULL, 0},

	{9001,1,RLOG_LV_FATAL,"SECONDARY_CONFIG_LINK",	"cfg_file_sapp_log",	NULL,NULL, NULL, NULL, 0},
	{9002,1,RLOG_LV_FATAL,"SECONDARY_CONFIG_LINK",	"cfg_file_plug_list",	NULL,NULL, NULL, NULL, 0},
	{9003,0,RLOG_LV_DEBUG, "SECONDARY_CONFIG_LINK",	"cfg_file_project_list",	NULL,NULL, NULL, NULL, 0},
	{9004,1,RLOG_LV_FATAL,"SECONDARY_CONFIG_LINK",	"cfg_file_entrylist",	NULL,NULL, NULL, NULL, 0},
	{9005,0,RLOG_LV_DEBUG, "SECONDARY_CONFIG_LINK",	"cfg_file_send_raw_pkt",	NULL,NULL, NULL, NULL, 0},
	{9006,4301,RLOG_LV_FATAL,"SECONDARY_CONFIG_LINK",	"cfg_file_vxlan_sport_map",	"inline",NULL, NULL, NULL, 0},
	{9007,4301,RLOG_LV_FATAL,"SECONDARY_CONFIG_LINK",	"cfg_file_inline_device",	"inline",NULL, NULL, NULL, 0},
	{9008,0,RLOG_LV_DEBUG, "SECONDARY_CONFIG_LINK",	"cfg_file_necessary_plug_list",	NULL,NULL, NULL, NULL, 0},
	{9009,0,RLOG_LV_DEBUG, "SECONDARY_CONFIG_LINK",	"cfg_file_stream_compare_layer",	NULL,NULL, NULL, NULL, 0},
	{9010,4301,RLOG_LV_FATAL,"SECONDARY_CONFIG_LINK",	"cfg_file_vlan_flipping",	"inline",NULL, NULL, NULL, 0},
	{9011,0,RLOG_LV_DEBUG, "SECONDARY_CONFIG_LINK",	"cfg_file_asymmetric_addr_layer",	NULL,NULL, NULL, NULL, 0},
	{9012,0,RLOG_LV_DEBUG, "SECONDARY_CONFIG_LINK",	"cfg_file_well_known_port",	NULL,NULL, NULL, NULL, 0},

	{9101,1,RLOG_LV_INFO,"SECONDARY_DATA_LINK",	"data_file_sysinfo_log",	NULL,NULL, NULL, NULL, 0},
	{9102,6501,RLOG_LV_DEBUG, "SECONDARY_DATA_LINK",	"data_file_field_stat_log",	"1",NULL, NULL, NULL, 0},
	{9103,4301,RLOG_LV_DEBUG, "SECONDARY_DATA_LINK",	"data_file_inline_keepalive_log",	"inline",NULL, NULL, NULL, 0},
	{9104,0,RLOG_LV_DEBUG, "SECONDARY_DATA_LINK",	"data_file_load_plugin_stat_log",	NULL,NULL, NULL, NULL, 0},
	{9105,0,RLOG_LV_DEBUG, "SECONDARY_DATA_LINK",	"data_file_under_ddos_stat_log",	NULL,NULL, NULL, NULL, 0},
	{9106,0,RLOG_LV_DEBUG, "SECONDARY_DATA_LINK",	"data_file_memory_stat_log",	NULL,NULL, NULL, NULL, 0},

	{9201,0,RLOG_LV_INFO, "LIBRARY_LINK",	"marsio_library_path",	NULL,NULL, NULL, NULL, 0},

	/******************************************************************************************************************/
	/*********** 以下是历史上曾经出现过的配置, 也不算错误,也不算不支持,输出告警信息表示被废弃掉了 *********************/
	/******************************************************************************************************************/
	{SAPP_CFG_OBSOLETE_FLAG,0,RLOG_LV_INFO,"overlay_tunnel_definition","stream_compare_layer_cfg_file",NULL, NULL, NULL,NULL, 0},
	{SAPP_CFG_OBSOLETE_FLAG,0,RLOG_LV_INFO,"overlay_tunnel_definition","vlan_flipping_cfg_file",NULL, NULL, NULL,NULL, 0},
	{SAPP_CFG_OBSOLETE_FLAG,0,RLOG_LV_INFO,"overlay_tunnel_definition","asymmetric_presence_layer_cfg_file",NULL, NULL, NULL,NULL, 0},
	{SAPP_CFG_OBSOLETE_FLAG,0,RLOG_LV_INFO,"overlay_tunnel_definition","asymmetric_addr_layer_cfg_file",NULL, NULL, NULL,NULL, 0},
	{SAPP_CFG_OBSOLETE_FLAG,0,RLOG_LV_INFO,"overlay_tunnel_definition","prune_inject_layer_cfg_file",NULL, NULL, NULL,NULL, 0},
	{SAPP_CFG_OBSOLETE_FLAG,0,RLOG_LV_INFO,"PROTOCOL_FEATURE","treat_vlan_as_mac_in_mac",NULL, NULL, NULL,NULL, 0},
	{SAPP_CFG_OBSOLETE_FLAG,0,RLOG_LV_INFO,"PROTOCOL_FEATURE","reverse_ethernet_addr",NULL, NULL, NULL,NULL, 0},

	{SAPP_CFG_OBSOLETE_FLAG,0,RLOG_LV_INFO,"DUPLICATE_PKT","duplicate_pkt_distinguish",NULL, NULL, NULL,NULL, 0},
	{SAPP_CFG_OBSOLETE_FLAG,0,RLOG_LV_INFO,"DUPLICATE_PKT","bloom_capacity",NULL, NULL, NULL,NULL, 0},
	{SAPP_CFG_OBSOLETE_FLAG,0,RLOG_LV_INFO,"DUPLICATE_PKT","bloom_error_rate",NULL, NULL, NULL,NULL, 0},
	{SAPP_CFG_OBSOLETE_FLAG,0,RLOG_LV_INFO,"DUPLICATE_PKT","bloom_timeout",NULL, NULL, NULL,NULL, 0},

	{SAPP_CFG_OBSOLETE_FLAG,0,RLOG_LV_INFO,"profiling.log.local","log_file_name",NULL, NULL, NULL,NULL, 0},
	{SAPP_CFG_OBSOLETE_FLAG,0,RLOG_LV_INFO,"profiling.log.local","log_conf_name",NULL, NULL, NULL,NULL, 0},

	{SAPP_CFG_OBSOLETE_FLAG,0,RLOG_LV_INFO,"SPECIAL_CONFIG_LINK","project_list_path",NULL, NULL, NULL,NULL, 0},
	{SAPP_CFG_OBSOLETE_FLAG,0,RLOG_LV_INFO,"SPECIAL_CONFIG_LINK","plugin_path",NULL, NULL, NULL,NULL, 0},
	{SAPP_CFG_OBSOLETE_FLAG,0,RLOG_LV_INFO,"SPECIAL_CONFIG_LINK","entrylist_path",NULL, NULL, NULL,NULL, 0},
	{SAPP_CFG_OBSOLETE_FLAG,0,RLOG_LV_INFO,"SPECIAL_CONFIG_LINK","send_raw_pkt_path",NULL, NULL, NULL,NULL, 0},
	{SAPP_CFG_OBSOLETE_FLAG,0,RLOG_LV_INFO,"SPECIAL_CONFIG_LINK","vxlan_sport_service_map_path",NULL, NULL, NULL,NULL, 0},

	{SAPP_CFG_OBSOLETE_FLAG,0,RLOG_LV_INFO,"tools.pkt_dump","pkt_dump_total_size",NULL, NULL, NULL,NULL, 0},
	{SAPP_CFG_OBSOLETE_FLAG,0,RLOG_LV_INFO,"tools.pkt_dump","pkt_dump_file_max_size",NULL, NULL, NULL,NULL, 0},

	{-1,-1,RLOG_LV_DEBUG,NULL,NULL,NULL, NULL, NULL,NULL, 0}
};



static int cfg_get_index_by_cfg_id(int expect_cfg_id)
{
	int i;

	for(i = 0; g_sapp_cfg_check_attr[i].global_id != -1; i++){
		if(g_sapp_cfg_check_attr[i].global_id == expect_cfg_id){
			return i;
		}
	}

	return -1;
}


static int cfg_get_index_by_depend_id(int expect_depend_id)
{
	int i;

	for(i = 0; g_sapp_cfg_check_attr[i].global_id != -1; i++){
		if(g_sapp_cfg_check_attr[i].global_id == expect_depend_id){
			return i;
		}
	}

	return -1;
}

static int cfg_get_index_by_key_name(const char *keyname)
{
	int i;

	for(i = 0; g_sapp_cfg_check_attr[i].global_id != -1; i++){
		if((g_sapp_cfg_check_attr[i].cfg_key != NULL)
		&&(strncasecmp(g_sapp_cfg_check_attr[i].cfg_key, keyname, strlen(g_sapp_cfg_check_attr[i].cfg_key)) == 0)
		&&(strncasecmp(g_sapp_cfg_check_attr[i].cfg_key, keyname, strlen(keyname)) == 0)){
			return i;
		}
	}

	return -1;
}


static int cfg_value_check_inject_mode(const sapp_config_check_t *sapp_cfg_check_attr,int this_cfg_id,int depend_cfg_id, const char *raw_cfg_value, const void *expect_range_array, int array_num)
{
	int depend_cfg_index;
	const char *depend_cfg_value;
	int this_cfg_index, expect_cfg_index;

	this_cfg_index = cfg_get_index_by_cfg_id(this_cfg_id);
	depend_cfg_index = cfg_get_index_by_depend_id(depend_cfg_id);
	depend_cfg_value = sapp_cfg_check_attr[depend_cfg_index].cfg_value;

	/* raw_cfg_value可能是NULL, 此时应该先判断depend_cfg_value, 这个是依赖配置, 不太可能是空 */

	if(strncasecmp(depend_cfg_value, "vxlan_by_inline_device", strlen("vxlan_by_inline_device")) == 0){
		expect_cfg_index = cfg_get_index_by_key_name("inject_mode_inline_device_sport");
		if((NULL == sapp_cfg_check_attr[expect_cfg_index].cfg_value ) && (this_cfg_index == expect_cfg_index)){
			sapp_log(RLOG_LV_FATAL,1,1,"sapp.toml->inject_pkt_mode value is 'vxlan_by_inline_device', but not found '%s'!\n", "inject_mode_inline_device_sport");
			return -1;
		}
	}

	if(strncasecmp(depend_cfg_value, "raw_ethernet_single_gateway", strlen("raw_ethernet_single_gateway")) == 0){
		expect_cfg_index = cfg_get_index_by_key_name("inject_mode_single_gateway_device");
		if((NULL == sapp_cfg_check_attr[expect_cfg_index].cfg_value ) && (this_cfg_index == expect_cfg_index)){
			sapp_log(RLOG_LV_FATAL,1,1,"sapp.toml->inject_pkt_mode value is 'raw_ethernet_single_gateway', but not found '%s'!\n", "inject_mode_single_gateway_device");
			return -1;
		}

		expect_cfg_index = cfg_get_index_by_key_name("inject_mode_single_gateway_src_mac");
		if((NULL == sapp_cfg_check_attr[expect_cfg_index].cfg_value ) && (this_cfg_index == expect_cfg_index)){
			sapp_log(RLOG_LV_FATAL,1,1,"sapp.toml->inject_pkt_mode value is 'raw_ethernet_single_gateway', but not found '%s'!\n", "inject_mode_single_gateway_src_mac");
			return -1;
		}

		expect_cfg_index = cfg_get_index_by_key_name("inject_mode_single_gateway_dst_mac");
		if((NULL == sapp_cfg_check_attr[expect_cfg_index].cfg_value ) && (this_cfg_index == expect_cfg_index)){
			sapp_log(RLOG_LV_FATAL,1,1,"sapp.toml->inject_pkt_mode value is 'raw_ethernet_single_gateway', but not found '%s'!\n", "inject_mode_single_gateway_dst_mac");
			return -1;
		}		
	}	

	return 0;
}

static const char *sapp_cfg_get_value_from_attr_by_id(const sapp_config_check_t *sapp_cfg_check_attr,int cfg_global_id)
{
	int i;

	for(i = 0; sapp_cfg_check_attr[i].global_id != -1; i++){
		if(sapp_cfg_check_attr[i].global_id == cfg_global_id){
			return sapp_cfg_check_attr[i].cfg_value;
		}
	}	

	return NULL;
}

static const char *sapp_cfg_get_value_from_attr_by_section_key(const sapp_config_check_t *sapp_cfg_check_attr, const char *section, const char *key)
{
	int i;

	for(i = 0; sapp_cfg_check_attr[i].global_id != -1; i++){
		if((strncmp(sapp_cfg_check_attr[i].section,section, strlen(sapp_cfg_check_attr[i].section)) == 0)
		 &&(strncmp(sapp_cfg_check_attr[i].section,section, strlen(section)) == 0)
		 &&(strncmp(sapp_cfg_check_attr[i].cfg_key,key, strlen(sapp_cfg_check_attr[i].cfg_key)) == 0)
		 &&(strncmp(sapp_cfg_check_attr[i].cfg_key,key, strlen(key)) == 0)){
			return sapp_cfg_check_attr[i].cfg_value;
		}
	}	

	return NULL;

}

static void special_usage(void)
{
	sapp_printf_colorful(RLOG_LV_FATAL,"open %s error!\n", ABBR_CFG_FILE_MAIN_ENTRY);
	sapp_printf_colorful(RLOG_LV_FATAL,"This is sapp version4.2, use sapp.toml instead of main.conf!\n");
	sapp_printf_colorful(RLOG_LV_FATAL,"You should run ./sapp -e to generate sapp.toml!\n");
}

static inline int is_file_exist(const char *filename)
{
	struct stat fstat;
	int fres, ret=0;

	fres = stat(filename, &fstat);
	if(fres < 0){
		if(ENOENT == errno){
			ret = 0;
		}
	}else{
		ret = 1;
	}

	return ret;
}

static void update_overlay_vxlan_layer_set(void);

/* 对于相同类型的配置, 命令行参数优先, 覆盖sapp.toml中的配置 */
void sapp_cla_override_cfg_file(void)
{
	char *cmd_args;
	sapp_config_t *pconfig = &sapp_global_val->config;

	if (sapp_get_cla_raw("coredump", &cmd_args) >= 0){ 
		breakpad_segv_generate();
	}
	
	if (sapp_get_cla_raw("dumpfile", &cmd_args) >= 0)
	{ /* dumpfile模式自动覆盖interface配置 */
		strncpy(pconfig->packet_io.deployment_mode_str, "dumpfile", NAME_MAX);
		pconfig->packet_io.deployment_mode_bin = DEPLOYMENT_MODE_MIRROR;
		sapp_global_val->individual_fixed.deployment_mode_private = NET_CONN_PARALLEL;
		strncpy(pconfig->packet_io.internal.interface.type_str, "pcap", NAME_MAX);
		pconfig->packet_io.internal.interface.type_bin = CAP_MODEL_PCAP_DUMPFILE;
		if(OVERLAY_MODE_VXLAN == pconfig->packet_io.packet_io_tunnel.overlay_mode_bin)
		{
			update_overlay_vxlan_layer_set();
		}
	}

	if (sapp_get_cla_raw("dumpfile-file", &cmd_args) >= 0)
	{
		strncpy(sapp_global_val->config.packet_io.pcap_dumpfile_name, cmd_args, NAME_MAX);
	}

		return;
	}

void sapp_generate_example_config(const char *cfg_file_name, const char *sapp_version)
{
	FILE *fp;
	struct stat file_stat;
	int ret;

	ret = stat(cfg_file_name, &file_stat);
	if((ret >= 0) || (errno != ENOENT) || S_ISREG(file_stat.st_mode)){
		sapp_printf_colorful(RLOG_LV_FATAL,"file '%s' already exist!\n", cfg_file_name);
		return;
	}

	fp = fopen(cfg_file_name, "w+");
	if(NULL == fp){
		sapp_printf_colorful(RLOG_LV_FATAL,"open %s error, %s!\n", cfg_file_name, strerror(errno));
		return;
	}

	fprintf(fp, "# This sample configure file is generate by sapp.%s\n", sapp_version);
	fwrite(_sapp_toml_sample_file_image, _sapp_toml_sample_file_image_len, 1, fp);

	fclose(fp);

	printf("\033[32mThe example config file saved to '%s',\033[0m\n", cfg_file_name);
	printf("\033[32mYou should change some parameters to suit the current system environment!\033[0m\n");
}

static int pkt_dump_thread_id_convert(void)
{
	sapp_config_tools_pktdump_t *pdump;
	int i, index;
	
	pdump = &sapp_global_val->config.tools.pkt_dump;

	if(pdump->dump_all_thread_enabled != 0){
		memset(pdump->dump_thread_id_mask, 1, sizeof(pdump->dump_thread_id_mask));
		pdump->dump_thread_id_array_num = sapp_global_val->config.cpu.worker_threads;
		return 0;
	}

	memset(pdump->dump_thread_id_mask, 0, sizeof(pdump->dump_thread_id_mask));

	for(i = 0; i < pdump->dump_thread_id_array_num; i++){
		index = pdump->dump_thread_id_array[i];
		if(index >= SAPP_MAX_THREADS){
			sapp_log(RLOG_LV_FATAL,1,1,"sapp.toml->PKT_DUMP->dump_thread_id value more than max CPU core number!\n");
			return -1;
		}else{
			pdump->dump_thread_id_mask[index] = 1;
		}
	}

	return 0;
}

/*
	C_router_vlan_id  I_router_vlan_id mac_flipping_enable
*/
static int parse_vlan_flipping_map_config(void)
{
	FILE *fp;
	char line_cont[MAX_INPUT];
	sapp_vlan_flipping_map_t *vlan_map = sapp_global_val->config.packet_io.packet_io_tunnel.vlan_flipping_map_array;
	int vlan_map_num = 0;
	int i, ret;
	unsigned long long c_router_vlan_id, i_router_vlan_id, mac_flip_enable;

	fp = fopen(ABBR_VLAN_FLIPPING_CONF_FILE, "r");
	if(NULL == fp){
		sapp_log(RLOG_LV_INFO, ~0, ~0, "[warning]can't open vlan_flipping_cfg_file:%s", ABBR_VLAN_FLIPPING_CONF_FILE);
		/* 向前兼容, 如果文件不存在, 不算错误 */
		return 0;
	}

	while(fgets(line_cont, MAX_INPUT, fp)){
		if('#' == line_cont[0] || ' ' == line_cont[0] || '\r' == line_cont[0] || '\n' == line_cont[0]){
			continue;
		}

		c_router_vlan_id = 4097;
		i_router_vlan_id = 4097;
		mac_flip_enable = 0;
		ret = sscanf(line_cont, "%llu %llu %llu", &c_router_vlan_id, &i_router_vlan_id, &mac_flip_enable);
		if(ret != 3){
			sapp_log(RLOG_LV_FATAL,1,1,"parse vlan_flipping_cfg_file:%s, line:%s error!", ABBR_VLAN_FLIPPING_CONF_FILE, line_cont);
			fclose(fp);
			return -1;
		}
		if(c_router_vlan_id>= 4096 || i_router_vlan_id >= 4096){
			sapp_log(RLOG_LV_FATAL,1,1, "parse vlan_flipping_cfg_file:%s line:%s  error, vlan id must in range[1,4095]!", ABBR_VLAN_FLIPPING_CONF_FILE, line_cont);
			fclose(fp);
			return -1;			
		}
		vlan_map[c_router_vlan_id].this_vlan_route_location = 'C';
		vlan_map[c_router_vlan_id].mac_flipping_enable = mac_flip_enable;
		vlan_map[c_router_vlan_id].couple_vlan_id = i_router_vlan_id;
		
		vlan_map[i_router_vlan_id].this_vlan_route_location = 'I';
		vlan_map[i_router_vlan_id].mac_flipping_enable = mac_flip_enable;
		vlan_map[i_router_vlan_id].couple_vlan_id = c_router_vlan_id;

		vlan_map_num++;
	}

	sapp_global_val->config.packet_io.packet_io_tunnel.vlan_flipping_map_num = vlan_map_num;

	if(0 == vlan_map_num){
		sapp_runtime_log(RLOG_LV_INFO, "parse vlan_flipping_cfg_file, no valid config!");
	}else{
		for(i = 0; i < MAX_VLAN_FLIPPING_MAP_NUM; i++){
			if(vlan_map[i].couple_vlan_id > 0){
				sapp_runtime_log(RLOG_LV_DEBUG, "vlan_flipping_cfg_file %d: vlan_id:%u, couple_vlan_id:%u, mac_flipping_enable:%d", 
							i, i, vlan_map[i].couple_vlan_id, vlan_map[i].mac_flipping_enable);
			}
		}
	}

	fclose(fp);
	return 0;
}


static int embed_layer_t_pton(char *config_val, embed_layer_t *result)
{
	enum addr_type_t addrtype;
	int  j, layer_index;
	const char *delim = "[] ";
	char *save_ptr;
	const char *layer_type_string;
	const char *layer_index_string;

	layer_type_string = strtok_r(config_val, delim, &save_ptr);
	layer_index_string = strtok_r(NULL, delim, &save_ptr);

	if(NULL == layer_type_string || NULL == layer_index_string ){
		return -1;
	}
	
	addrtype = addr_type_abbreviation_pton(layer_type_string);
	if(__ADDR_TYPE_MAX == addrtype){
		return -1;
	}

	memset(result, 0, sizeof(embed_layer_t));

	if('*' == layer_index_string[0]){
		for(j = 0; j < SAPP_SUPPORT_LAYER_NUM_MAX; j++){
			result->layer_type_index[addrtype][j] = 1;
		}
	}else{
		layer_index = atoi(layer_index_string);
		if(layer_index < 0 || layer_index >= (int)SAPP_SUPPORT_LAYER_NUM_MAX-1){
			return -1;
		}

		result->layer_type_index[addrtype][layer_index] = 1;
	}

	return 0;
}

/*
	return value pattern: 
	    addr_type_name[layer_index]
*/
static const char *embed_layer_t_ntop(const embed_layer_t *layer_st, char *result, int res_max_len)
{
	char addrtype_name_str[NAME_MAX] = {};
	char layer_index_str[NAME_MAX] = {};
	char one_layer_index_str[NAME_MAX];
	int i, j;

	memset(result, 0, res_max_len);
	
	for(i = __ADDR_TYPE_INIT + 1; i < __ADDR_TYPE_MAX; i++){
		for(j = 0; j < SAPP_SUPPORT_LAYER_NUM_MAX; j++){
			if(layer_st->layer_type_index[i][j] != 0){
				sprintf(addrtype_name_str, "%s", addr_type_abbreviation_ntop((enum addr_type_t)i));
				goto bingo;
			}
		}
	}

bingo:
	if(i==__ADDR_TYPE_MAX)i=i-1;
	for(j = 0; j < SAPP_SUPPORT_LAYER_NUM_MAX; j++){
		if(layer_st->layer_type_index[i][j] != 0){
			sprintf(one_layer_index_str, "%d,", j);
			strcat(layer_index_str, one_layer_index_str);
		}
	}	

	snprintf(result, res_max_len, "%s[%s]", addrtype_name_str, layer_index_str);
	
	return result;
}

static int update_asymmetric_layer_info(embed_layer_t *global_array, embed_layer_t *new_config)
{
	int type_index, layer_index;

	for(type_index = 0; type_index < __ADDR_TYPE_MAX; type_index++){
		for(layer_index = 0; layer_index < SAPP_SUPPORT_LAYER_NUM_MAX; layer_index++){
			if(new_config->layer_type_index[type_index][layer_index] != 0){
				global_array->layer_type_index[type_index][layer_index] = 1;
			}
		}
	}

	return 0;
}

static int update_asymmetric_presence_layer(enum addr_type_t addrtype, embed_layer_t *under_layer, embed_layer_t *upper_layer)
{
	g_asymmetric_presence_layer_set[addrtype].is_asymmetric_layer = 1;

	update_asymmetric_layer_info(&g_asymmetric_presence_layer_set[addrtype].under_layer, under_layer);
	update_asymmetric_layer_info(&g_asymmetric_presence_layer_set[addrtype].upper_layer, upper_layer);

	return 0;
}

/* 
    #pattern: asymmetric_layer_name[layer index]
    ethernet[1]
    mpls[*]
*/
static int parse_asymmetric_addr_layer_config(void)
{
	int i, j, ret;
	FILE *fp;
	char line_cont[MAX_INPUT];
	embed_layer_t embed_layer;

	memset(&g_asymmetric_addr_layer_set, 0, sizeof(g_asymmetric_addr_layer_set));
	
	fp = fopen(ABBR_ASYM_LAYER_ADDR_CONF_FILE, "r");
	if(NULL == fp){
 		sapp_log(RLOG_LV_INFO, ~0, ~0, "[Warning]can't open asymmetric_addr_layer_cfg_file:%s", ABBR_ASYM_LAYER_ADDR_CONF_FILE);
		/* 向前兼容, 如果文件不存在, 不算错误 */
		return 0; 
	}

	while(fgets(line_cont, MAX_INPUT, fp)){
		if('#' == line_cont[0] || ' ' == line_cont[0] || '\r' == line_cont[0] || '\n' == line_cont[0]){
			continue;
		}
		memset(&embed_layer, 0, sizeof(embed_layer));
		ret = embed_layer_t_pton(line_cont, &embed_layer);
		if(ret < 0){
			sapp_log(RLOG_LV_FATAL, ~0, ~0, "parse cfg_file:%s error, inlavid:%s", ABBR_ASYM_LAYER_ADDR_CONF_FILE, line_cont); 
			fclose(fp);
			return -1;
		}

		update_asymmetric_layer_info(&g_asymmetric_addr_layer_set, &embed_layer);
	}

	char one_layer_index_str[NAME_MAX];
	char debug_layer_index_str[NAME_MAX];
	
	for(i = __ADDR_TYPE_INIT + 1; i < __ADDR_TYPE_MAX; i++){
		memset(debug_layer_index_str, 0, sizeof(debug_layer_index_str));
		for(j = 0; j < SAPP_SUPPORT_LAYER_NUM_MAX; j++){
			if(g_asymmetric_addr_layer_set.layer_type_index[i][j] != 0){
				sprintf(one_layer_index_str, "%d,", j);
				strcat(debug_layer_index_str, one_layer_index_str);
			}
		}
	}

	fclose(fp);
	return 0;
}



static int set_default_stream_compare_layer(embed_layer_t *stream_compare_layer_set)
{
	int i;

	for(i = 0; i < SAPP_SUPPORT_LAYER_NUM_MAX; i++){
		stream_compare_layer_set->layer_type_index[ADDR_TYPE_IPV4][i] = 1;
		stream_compare_layer_set->layer_type_index[ADDR_TYPE_IPV6][i] = 1;
		stream_compare_layer_set->layer_type_index[__ADDR_TYPE_IP_PAIR_V4][i] = 1;
		stream_compare_layer_set->layer_type_index[__ADDR_TYPE_IP_PAIR_V6][i] = 1;
		stream_compare_layer_set->layer_type_index[ADDR_TYPE_TCP][i] = 1;
		stream_compare_layer_set->layer_type_index[ADDR_TYPE_UDP][i] = 1;
	}
	
	return 0;
}

/* 
    #pattern: stream_compare_layer_name[layer index]
	vlan[1]
    mpls[*]
*/
static int parse_stream_compare_layer_config(void)
{
	int i, j, ret;
	FILE *fp;
	char line_cont[MAX_INPUT];
	embed_layer_t embed_layer;

	memset(&g_stream_compare_layer_set, 0, sizeof(g_stream_compare_layer_set));

	set_default_stream_compare_layer(&g_stream_compare_layer_set);
	
	fp = fopen(ABBR_STREAM_CMP_LAYER_CONF_FILE, "r");
	if(NULL == fp){
		sapp_log(RLOG_LV_INFO, ~0, ~0, "[Warning]can't open stream compare layer cfg_file:%s", ABBR_STREAM_CMP_LAYER_CONF_FILE);
		/* 向前兼容, 如果文件不存在, 不算错误 */
		return 0; 
	}

	while(fgets(line_cont, MAX_INPUT, fp)){
		if('#' == line_cont[0] || ' ' == line_cont[0] || '\r' == line_cont[0] || '\n' == line_cont[0]){
			continue;
		}
		memset(&embed_layer, 0, sizeof(embed_layer));
		ret = embed_layer_t_pton(line_cont, &embed_layer);
		if(ret < 0){
			sapp_log(RLOG_LV_FATAL, ~0, ~0, "parse stream compare layer cfg_file:%s error, inlavid:%s", ABBR_STREAM_CMP_LAYER_CONF_FILE, line_cont); 
			goto fun_exit;
		}

		update_asymmetric_layer_info(&g_stream_compare_layer_set, &embed_layer);
	}

	char one_layer_index_str[NAME_MAX];
	char debug_layer_index_str[NAME_MAX];
	
	for(i = __ADDR_TYPE_INIT + 1; i < __ADDR_TYPE_MAX; i++){
		memset(debug_layer_index_str, 0, sizeof(debug_layer_index_str));
		for(j = 0; j < SAPP_SUPPORT_LAYER_NUM_MAX; j++){
			if(g_stream_compare_layer_set.layer_type_index[i][j] != 0){
				sprintf(one_layer_index_str, "%d,", j);
				strcat(debug_layer_index_str, one_layer_index_str);
			}
		}
		sapp_runtime_log(RLOG_LV_DEBUG, "stream_compare_layer: %s:%s", 
						addr_type_abbreviation_ntop((enum addr_type_t)i), debug_layer_index_str);
	}

fun_exit:
	fclose(fp);
	
	return 0;
}

static void update_overlay_vxlan_layer_set(void)
{
	g_overlay_layer_set[ADDR_TYPE_MAC][0] = 1;	
	g_overlay_layer_set[ADDR_TYPE_IPV4][1] = 1;	
	g_overlay_layer_set[__ADDR_TYPE_IP_PAIR_V4][1] = 1;	
	g_overlay_layer_set[ADDR_TYPE_UDP][1] = 1;	/* IP和udp合并算为一层, 所以此处还是用1 */
	g_overlay_layer_set[ADDR_TYPE_VXLAN][2] = 1;	
}

static void update_well_known_port_array(int last_section_proto, unsigned short *port_array, int port_array_num)
{
	if(IPPROTO_TCP == last_section_proto){
		sapp_global_val->config.stream.tcp.well_known_ports_array = port_array;
		sapp_global_val->config.stream.tcp.well_known_ports_array_num = port_array_num;
	}else if(IPPROTO_UDP == last_section_proto){
		sapp_global_val->config.stream.udp.well_known_ports_array = port_array;
		sapp_global_val->config.stream.udp.well_known_ports_array_num = port_array_num;
	}else{
		sapp_log(RLOG_LV_FATAL, ~0, ~0, "parse cfg_file:%s error, onlye support TCP or UDP", ABBR_WELL_KNOWN_PORT_CONF_FILE); 
	}
}

/* 
    #pattern: 
    [TCP]
		some ports here
    [UDP]
		some ports here
*/
static int parse_well_known_port_config(void)
{
	FILE *fp;
	char line_buf[256];
	int last_section_proto = -1; /* 段落标识: TCP or UDP */
	unsigned short *port_array = NULL;
	int port_array_num = 0;
	int tmpnum;
	int i;

	fp = fopen(ABBR_WELL_KNOWN_PORT_CONF_FILE, "r");
	if(NULL == fp){
		return 0; /* 没有此文件, 不算错误 */
	}

	while(fgets(line_buf, sizeof(line_buf), fp)){
		if('#' == line_buf[0] || '\n' == line_buf[0]){
			continue;
		}
		sapp_memmove_for_blank_table(line_buf, sizeof(line_buf));
		del_last_rn(line_buf, sizeof(line_buf));

		if('[' == line_buf[0]){ /* [] 一个段落的起始 */
			if(port_array != NULL){
				/* 上一个段落刚结束 */
				update_well_known_port_array(last_section_proto, port_array, port_array_num);
				port_array = NULL; 
				port_array_num = 0;
			}

			if(strncasecmp("[TCP]", line_buf, strlen("TCP")) == 0){
				last_section_proto = IPPROTO_TCP;
			}else if(strncasecmp("[UDP]", line_buf, strlen("UDP")) == 0){
				last_section_proto = IPPROTO_UDP;	
			}else{
				sapp_log(RLOG_LV_FATAL, ~0, ~0, "parse cfg_file:%s error, onlye support TCP or UDP", ABBR_WELL_KNOWN_PORT_CONF_FILE); 
				return -1;
			}
			continue;
		}
		
		tmpnum = atoi(line_buf);
		if(tmpnum <=0 || tmpnum > 65535){
			sapp_log(RLOG_LV_FATAL, ~0, ~0, "parse cfg_file:%s error, port value invalid:%s", ABBR_WELL_KNOWN_PORT_CONF_FILE, line_buf); 
			return -1;			
		}

		port_array = (unsigned short *)sapp_mem_realloc(SAPP_MEM_FIX_GLOBAL_VAL, MEM_STAT_GLOBAL_THREAD_ID,port_array, sizeof(short)*(port_array_num+1));
		port_array[port_array_num] = (unsigned short)tmpnum;
		port_array_num++;
	}

	if(port_array != NULL){
		update_well_known_port_array(last_section_proto, port_array, port_array_num);
		port_array = 0; 
		port_array_num = 0;
	}

	if(sapp_global_val->config.stream.tcp.well_known_ports_array){
		for(i = 0; i < sapp_global_val->config.stream.tcp.well_known_ports_array_num; i++){
			sapp_runtime_log(RLOG_LV_INFO, "these TCP ports are considered as server: %u", sapp_global_val->config.stream.tcp.well_known_ports_array[i]);
		}
	}

	if(sapp_global_val->config.stream.udp.well_known_ports_array){
		for(i = 0; i < sapp_global_val->config.stream.udp.well_known_ports_array_num; i++){
			sapp_runtime_log(RLOG_LV_INFO, "these UDP ports are considered as server: %u", sapp_global_val->config.stream.udp.well_known_ports_array[i]);
		}
	}

	fclose(fp);

	return 0;
}

/*
	example: ether[4]:0
*/
static int parse_extract_linkdir_from_mac_cfg(void)
{
	sapp_config_t *pconfig;
	int ret;
	int byte_index = 0xFFFFFFFF, bit_index = 0xFFFFFFFF;
	
	pconfig = &sapp_global_val->config;
	
	if(pconfig->packet_io.deployment_mode_bin != DEPLOYMENT_MODE_MIRROR){
		pconfig->packet_io.extract_linkdir_from_mac_enabled = 0;
		return 0;
	}

	if(strnlen(pconfig->packet_io.extract_linkdir_from_mac_sntax_raw_string, 12) <= 0){
		pconfig->packet_io.extract_linkdir_from_mac_enabled = 0;
		return 0;
	}

	ret = sscanf(pconfig->packet_io.extract_linkdir_from_mac_sntax_raw_string, "ether[%d]:%d", &byte_index, &bit_index);
	if(ret != 2){
		return -1;
	}

	if(byte_index < 0 || byte_index > 11){
		return -1;
	}

	if(bit_index < 0 || bit_index > 7){
		return -1;
	}	

	pconfig->packet_io.extract_linkdir_from_mac_byte_index = byte_index;
	pconfig->packet_io.extract_linkdir_from_mac_bit_value = (1<<bit_index);
	pconfig->packet_io.extract_linkdir_from_mac_enabled = 1;
	
	return 0;
}

/* 配置格式转换, 如字符串类型转为int类型,便于程序处理 */
static int config_expression_convert(void)
{
	sapp_config_t *pconfig;
	const char *tmp_str;
	int ret;
	
	pconfig = &sapp_global_val->config;

	if(pconfig->cpu.bind_mask_array_num > 0){
		sapp_global_val->config.cpu.bind_mask = tomlc99_long_array_combination(pconfig->cpu.bind_mask_array, pconfig->cpu.bind_mask_array_num);
	}

	if(pconfig->stream.tcp.syn_mandatory != 0){
		sapp_global_val->individual_fixed.create_stream_mode = TCP_CTEAT_LINK_BYSYN;
	}else{
		sapp_global_val->individual_fixed.create_stream_mode = TCP_CTEAT_LINK_BYSYN | TCP_CTEAT_LINK_BYDATA;
	}

	/******************************  PACKET_IO  *******************************/

	/*
		net_connection_mode:
			0: don't send packet, only capture;
			1: parallel mode with single card;
			2: serial mode with two card;
			3: logic serial mode with G device.
	*/	
	tmp_str = pconfig->packet_io.deployment_mode_str;
	if(strncasecmp(tmp_str, "mirror", strlen("mirror")) == 0){
		pconfig->packet_io.deployment_mode_bin = DEPLOYMENT_MODE_MIRROR;
		sapp_global_val->individual_fixed.deployment_mode_private = NET_CONN_PARALLEL;
	}else if(strncasecmp(tmp_str, "dumpfile", strlen("dumpfile")) == 0){
		pconfig->packet_io.deployment_mode_bin = DEPLOYMENT_MODE_MIRROR;
		sapp_global_val->individual_fixed.deployment_mode_private = NET_CONN_PARALLEL;
	}else if(strncasecmp(tmp_str, "inline", strlen("inline")) == 0){
		pconfig->packet_io.deployment_mode_bin = DEPLOYMENT_MODE_INLINE;
		sapp_global_val->individual_fixed.deployment_mode_private = NET_CONN_SERIAL_GDEV;
	}else if(strncasecmp(tmp_str, "transparent", strlen("transparent")) == 0){
		pconfig->packet_io.deployment_mode_bin = DEPLOYMENT_MODE_TRANSPARENT;
		sapp_global_val->individual_fixed.deployment_mode_private = NET_CONN_SERIAL_2CARD;
	}else{
		sapp_log(RLOG_LV_FATAL, ~0, ~0, "sapp.toml->PACKET_IO.deployment.mode error, only support:%s!", "[mirror, inline, transparent]");
		return -1;
	}

	tmp_str = pconfig->packet_io.packet_io_tunnel.overlay_mode_string;
	if(strncasecmp(tmp_str, "none", strlen("none")) == 0){
		pconfig->packet_io.packet_io_tunnel.overlay_mode_bin = OVERLAY_MODE_NONE;
	}else if(strncasecmp(tmp_str, "vxlan", strlen("vxlan")) == 0){
		pconfig->packet_io.packet_io_tunnel.overlay_mode_bin = OVERLAY_MODE_VXLAN;
	}
	else if(strncasecmp(tmp_str, "nf", strlen("nf")) == 0){
		pconfig->packet_io.packet_io_tunnel.overlay_mode_bin = OVERLAY_MODE_NF;
	}else{
		sapp_log(RLOG_LV_FATAL, ~0, ~0, "sapp.toml->overlay_mode error, unsupport : %s", tmp_str); 
		return -1;
	}

	if((pconfig->packet_io.deployment_mode_bin == DEPLOYMENT_MODE_INLINE)
	&& (OVERLAY_MODE_VXLAN == pconfig->packet_io.packet_io_tunnel.overlay_mode_bin)){
		update_overlay_vxlan_layer_set();
	}

	ret = parse_vlan_flipping_map_config();
	if(ret < 0){
		sapp_log(RLOG_LV_FATAL, ~0, ~0, "%s parse error", ABBR_VLAN_FLIPPING_CONF_FILE); 
		return- 1;
	}

	ret = parse_asymmetric_addr_layer_config();
	if(ret < 0){
		sapp_log(RLOG_LV_FATAL, ~0, ~0, "%s parse error", ABBR_ASYM_LAYER_ADDR_CONF_FILE); 
		return- 1;
	}

	ret = parse_stream_compare_layer_config();
	if(ret < 0){
		sapp_log(RLOG_LV_FATAL, ~0, ~0, "%s parse error", ABBR_STREAM_CMP_LAYER_CONF_FILE); 
		return- 1;
	}	
	
	ret = parse_well_known_port_config();
	if(ret < 0){
		sapp_log(RLOG_LV_FATAL, ~0, ~0, "%s parse error", ABBR_WELL_KNOWN_PORT_CONF_FILE); 
		return- 1;
	}	

	//todo, parse prune inject cfg file

	
	tmp_str = pconfig->packet_io.internal.interface.type_str;
	if(strncasecmp(tmp_str, "pcap", strlen("pcap")) == 0){
		pconfig->packet_io.internal.interface.type_bin = CAP_MODEL_PCAP_ONLINE;
	}else if(strncasecmp(tmp_str, "pag", strlen("pag")) == 0){
		pconfig->packet_io.internal.interface.type_bin = CAP_MODEL_PAG;
	}else if(strncasecmp(tmp_str, "marsio", strlen("marsio")) == 0){
		pconfig->packet_io.internal.interface.type_bin = CAP_MODEL_MARSIOV4;
	}else if(strncasecmp(tmp_str, "tun", strlen("tun")) == 0){
		pconfig->packet_io.internal.interface.type_bin = CAP_MODEL_TUN;
	}else{
		sapp_log(RLOG_LV_FATAL, ~0, ~0, "sapp.toml->type error, unsupport : %s", tmp_str); 
		return -1;
	}

	if(strncasecmp("sys_route", pconfig->packet_io.inject_pkt_mode_string, strlen("sys_route")) == 0){
		pconfig->packet_io.inject_pkt_mode = SEND_PKT_MODE_STACK_3_LAYER;
	}else if(strncasecmp("vxlan_by_inline_device", pconfig->packet_io.inject_pkt_mode_string, strlen("vxlan_by_inline_device")) == 0){
		pconfig->packet_io.inject_pkt_mode = SEND_PKT_MODE_GDEV;
	}else if(strncasecmp("raw_ethernet_single_gateway", pconfig->packet_io.inject_pkt_mode_string, strlen("raw_ethernet_single_gateway")) == 0){
		pconfig->packet_io.inject_pkt_mode = SEND_PKT_MODE_STACK_2_LAYER_1_ROUTE;
	}else if(strncasecmp("raw_ethernet_multi_gateway", pconfig->packet_io.inject_pkt_mode_string, strlen("raw_ethernet_multi_gateway")) == 0){
		pconfig->packet_io.inject_pkt_mode = SEND_PKT_MODE_STACK_2_LAYER_MUTI_ROUTE;
	}else if(strncasecmp("default", pconfig->packet_io.inject_pkt_mode_string, strlen("default")) == 0){
		pconfig->packet_io.inject_pkt_mode = SEND_PKT_MODE_DEFAULT;
	}
	else{
	  	sapp_log(RLOG_LV_FATAL, ~0, ~0, "sapp.toml->PACKET_IO.inject_pkt_mode set error, only support:%s!", "[default, sys_route, vxlan_by_inline_device, raw_ethernet_single_gateway, raw_ethernet_multi_gateway]");
		return -1;
	}

	if(strncasecmp(pconfig->packet_io.inject_pkt_mode_string, "raw_ethernet_single_gateway", strlen("raw_ethernet_single_gateway")) == 0){
		if(MESA_mac_pton(pconfig->packet_io.inject_mode_single_gateway_dst_mac_string, ':', pconfig->packet_io.inject_mode_single_gateway_dst_mac) < 0){
			sapp_log(RLOG_LV_FATAL, ~0, ~0, "sapp.toml->[packet_io.feature]->inject_mode_single_gateway_dst_mac error: %s", pconfig->packet_io.inject_mode_single_gateway_dst_mac_string);
			return -1;	
		}

		if(MESA_get_dev_mac(pconfig->packet_io.inject_mode_single_gateway_device, (unsigned char *)pconfig->packet_io.inject_mode_single_gateway_src_mac) < 0){
			sapp_runtime_log(RLOG_LV_INFO, "[Warning]can't get sapp.toml->[packet_io.feature]->inject_mode_single_gateway_device: '%s' mac address", pconfig->packet_io.inject_mode_single_gateway_device);
			
			tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.feature", (char *)"inject_mode_single_gateway_src_mac", pconfig->packet_io.inject_mode_single_gateway_src_mac_string, sizeof(pconfig->packet_io.inject_mode_single_gateway_src_mac_string), "$");
			if('$' == pconfig->packet_io.inject_mode_single_gateway_src_mac_string[0]){
				sapp_log(RLOG_LV_FATAL, ~0, ~0, "can't get local device '%s' mac address, and no valid inject_mode_single_gateway_src_mac", pconfig->packet_io.inject_mode_single_gateway_device);
				return -1;
			}
			if(MESA_mac_pton(pconfig->packet_io.inject_mode_single_gateway_src_mac_string, ':', pconfig->packet_io.inject_mode_single_gateway_src_mac) < 0){
				sapp_log(RLOG_LV_FATAL, ~0, ~0, "sapp.toml->[packet_io.feature]->inject_mode_single_gateway_src_mac error: %s", pconfig->packet_io.inject_mode_single_gateway_src_mac_string);
				return -1;	
			}			
		}
	}

	tmp_str = pconfig->packet_io.external.interface.type_str;
	if(strncasecmp(tmp_str, "pcap", strlen("pcap")) == 0){
		pconfig->packet_io.external.interface.type_bin = CAP_MODEL_PCAP_ONLINE;
	}else if(strncasecmp(tmp_str, "pag", strlen("pag")) == 0){
		pconfig->packet_io.external.interface.type_bin = CAP_MODEL_PAG;
	}else if(strncasecmp(tmp_str, "marsio", strlen("marsio")) == 0){
		pconfig->packet_io.external.interface.type_bin = CAP_MODEL_MARSIOV4;
	}else if(strncasecmp(tmp_str, "tun", strlen("tun")) == 0){
		pconfig->packet_io.external.interface.type_bin = CAP_MODEL_TUN;
	}

	if(parse_extract_linkdir_from_mac_cfg() < 0){
	    sapp_log(RLOG_LV_FATAL, ~0, ~0, "sapp.toml->extract_linkdir_from_mac_in_mirror_mode format error, must like 'ether[4]:0'");
		return -1;		
	}

	/******************************  STREAM  *******************************/
	struct tm ttm = {};
	if(sapp_global_val->config.stream.stream_id_base_time_str[0] == '\0'){
		sapp_log(20, ~0, ~0, "[Warning]sapp.toml->STREAM.stream_id_base_time is not set, use '1970-01-01 00:00:00' as default!");
		sapp_global_val->config.stream.stream_id_base_time_t = 0;
	}else{
		if(strptime(sapp_global_val->config.stream.stream_id_base_time_str, "%Y-%m-%d %H:%M:%S", &ttm) == NULL){
		  	sapp_log(RLOG_LV_FATAL, ~0, ~0, "sapp.toml->STREAM.stream_id_base_time format error, must like '1970-01-01 01:02:03'");
			return -1;
		}
		if(mktime(&ttm) > time(NULL)){
		  	sapp_log(RLOG_LV_FATAL, ~0, ~0, "sapp.toml->STREAM.stream_id_base_time value error, is after current system time!");
			return -1;
		}
		if(time(NULL) - mktime(&ttm) > 268435456L){
		  	sapp_log(RLOG_LV_FATAL, ~0, ~0, "sapp.toml->STREAM.stream_id_base_time value error, sapp stream id support max time range is 8.5 year!");
			return -1;
		}
		sapp_global_val->config.stream.stream_id_base_time_t = mktime(&ttm);
	}

	/******************************  TOOLS   *******************************/
	if(pconfig->tools.pkt_dump.enabled != 0){
		if(strncasecmp(pconfig->tools.pkt_dump.mode_str, "storage" ,strlen("storage")) == 0){
			pconfig->tools.pkt_dump.mode_bin = PKT_DUMP_LOCAL_FILE;
		}else if(strncasecmp(pconfig->tools.pkt_dump.mode_str, "udp_socket" ,strlen("udp_socket")) == 0){
			pconfig->tools.pkt_dump.mode_bin = PKT_DUMP_UDP_SOCKET;
		}else{
			sapp_log(RLOG_LV_FATAL, ~0, ~0, "TOOLS.PKT_DUMP.mode only support [storage, udp_socket]!");
			return -1;
		}
	}

	if(pkt_dump_thread_id_convert() < 0){
		return -1;
	}

	return 0;
}

/*
	1: yes, go on!
	0: no,  exit.
*/
static int get_user_intention(void)
{
	char input_buf[MAX_INPUT];
	
	while(fgets(input_buf, sizeof(input_buf), stdin)){
		if(strncasecmp(input_buf, "y", 1) == 0){
			return 1;
		}else if(strncasecmp(input_buf, "n", 1) == 0){
			return 0;
		}else{
			sapp_log(30, ~0, ~0, "Please input 'y' or 'n' : "); 
			continue;
		}
	}

	return 1;
}


static inline void old_config_file_detect(const char *old_filename, const char *new_filename)
{
	if(is_file_exist(old_filename)){
		sapp_log(RLOG_LV_FATAL, ~0, ~0, "This is sapp v4.0, detect obsolete config file:\"%s\"! please use \"%s\" instead!", old_filename, new_filename);
		if(is_file_exist(new_filename)){
			sapp_log(RLOG_LV_FATAL, ~0, ~0, "You already have new config file:\"%s\", you must rename or delete obsolete file:\"%s\"!", new_filename, old_filename); 
			//sapp_log(30, ~0, ~0, "Are you sure you are using new config file? 'y' or 'n':");
			//if(0 == get_user_intention()){
				exit(1);
			//}			
		}else{
			//sapp_log(30, ~0, ~0, "Do you want to continue running, the sapp behavior is unpredictable! 'y' or 'n' : "); 
			//if(0 == get_user_intention()){
				sapp_log(30, ~0, ~0, "You should run ./sapp --sample-config to generate sapp.toml!");
				exit(1);
			//}
		}
	}
}


/*
	配置文件合法性、相关性检查.

	TODO: 与参数检测引擎 g_sapp_cfg_check_attr[] 待合并, 某些参数检测功能是重复的!!!
	
	return value:
		 0: succ;
		-1: error, must exit!
*/
static int config_sanity_check(void)
{
	int cur_cpu_num;
	const char *tmp_str;
	sapp_config_t *pconfig = &sapp_global_val->config;

	struct streaminfo_private phony_stream_pr;

	phony_stream_pr.layer_index = 0xF;
	assert(SAPP_SUPPORT_LAYER_NUM_MAX == phony_stream_pr.layer_index); /* 用于判断无意中修改了layer_index或SAPP_SUPPORT_LAYER_NUM_MAX, 两个变量不一致的情况 */
	if(SAPP_SUPPORT_LAYER_NUM_MAX != phony_stream_pr.layer_index){
		sapp_log(RLOG_LV_FATAL, ~0, ~0, "SAPP_SUPPORT_LAYER_NUM_MAX is:%d, but streaminfo_private->layer_index max is:%d", SAPP_SUPPORT_LAYER_NUM_MAX, phony_stream_pr.layer_index); 
		return -1;
	}

	/*******************************  CPU  ********************************/
	cur_cpu_num = get_nprocs();
	if(cur_cpu_num < pconfig->cpu.worker_threads){	
		sapp_log(20, 0, ~0, "[Warning]sapp.toml->CPU.worker_threads=%d more than current available processors:%d", sapp_global_val->config.cpu.worker_threads, cur_cpu_num); 	
		sleep(1);
	}

	if(sapp_global_val->config.cpu.send_only_threads_max_num > INDEPENDENT_SEND_QUEUE_MAX_NUM){
		sapp_log(RLOG_LV_FATAL, ~0, ~0, "send_only_threads_max is:%d, but max support value is:%d", sapp_global_val->config.cpu.send_only_threads_max_num, INDEPENDENT_SEND_QUEUE_MAX_NUM); 
		return -1;		
	}

	if(sapp_global_val->config.cpu.worker_threads + sapp_global_val->config.cpu.send_only_threads_max_num > INDEPENDENT_SEND_QUEUE_MAX_NUM){
		sapp_log(RLOG_LV_FATAL, ~0, ~0, "RLOG_LV_FATALsend_only_threads_max + worker_threads is:%d, but max support send queue is:%d", 
				sapp_global_val->config.cpu.send_only_threads_max_num + sapp_global_val->config.cpu.worker_threads, 
				INDEPENDENT_SEND_QUEUE_MAX_NUM); 
		return -1;		
	}	

	if(pconfig->cpu.bind_mask_array_num > 0){ 
		if(pconfig->cpu.worker_threads + pconfig->cpu.send_only_threads_max_num != pconfig->cpu.bind_mask_array_num){
			sapp_log(RLOG_LV_FATAL, ~0, ~0,"sapp.toml->CPU->bind_mask value is not match etc/sapp.toml->CPU->worker_threads + CPU->send_only_threads_max!\n");
			sapp_log(RLOG_LV_FATAL, ~0, ~0,"for example, worker_threads=4, send_only_threads_max=4, bind_mask should be [1,2,3,4,5,6,7,8]\n");
			return -1;
		}

		int i;
		int tot_cpu_core_num = get_nprocs();
		for(i = 0; i < pconfig->cpu.bind_mask_array_num; i++){
			if(pconfig->cpu.bind_mask_array[i] > tot_cpu_core_num-1){
				printf("\033[41mbind_mask[%d]=%ld, bigger than total cpu core number:%d!\033[0m\n", i, pconfig->cpu.bind_mask_array[i], tot_cpu_core_num);
				return -1;
			}
		}
	}

	/*******************************  STREAM  ******************************/
	if(pconfig->stream.tcp.inject.auto_remedy != 0){
		if(pconfig->stream.tcp.inject.rst_num <= 0 || pconfig->stream.tcp.inject.rst_num >= 10){
			sapp_log(RLOG_LV_FATAL, ~0, ~0, "sapp.toml->stream.tcp.inject.rst.number=%d, is Illegal!", pconfig->stream.tcp.inject.rst_num);
			return -1;
		}
	}

	/*******************************  Packet IO  ******************************/
	
	tmp_str = pconfig->packet_io.deployment_mode_str;
	if((strncasecmp(tmp_str, "mirror", strlen("mirror")) != 0)
	  &&(strncasecmp(tmp_str, "inline", strlen("inline")) != 0)
	  &&(strncasecmp(tmp_str, "transparent", strlen("transparent")) != 0)
	  &&(strncasecmp(tmp_str, "dumpfile", strlen("dumpfile")) != 0)){
	  	sapp_log(RLOG_LV_FATAL, ~0, ~0, "sapp.toml->PACKET_IO.deployment.mode error, only support:%s!\n", "[mirror, inline, transparent, dumpfile]");
		return -1;
	}

	if(strncasecmp(tmp_str, "transparent", strlen("transparent")) == 0){
		if((pconfig->packet_io.internal.interface.name[0] == '\0')
		 || (strlen(pconfig->packet_io.internal.interface.name) == 0)
		 ||(pconfig->packet_io.internal.interface.type_str[0] == '\0')
		 || (strlen(pconfig->packet_io.internal.interface.type_str) == 0)){
			sapp_log(RLOG_LV_FATAL, ~0, ~0, "deployment_mode is transparent, must set internal interface parameters!");
			return -1;
		}
		if((pconfig->packet_io.external.interface.name[0] == '\0')
		 || (strlen(pconfig->packet_io.external.interface.name) == 0)
		 ||(pconfig->packet_io.external.interface.type_str[0] == '\0')
		 || (strlen(pconfig->packet_io.external.interface.type_str) == 0)){
			sapp_log(RLOG_LV_FATAL, ~0, ~0, "deployment_mode is transparent, must set external interface parameters!");
			return -1;
		}

		if(strncasecmp(pconfig->packet_io.internal.interface.type_str,
					   pconfig->packet_io.external.interface.type_str,
					   strlen(pconfig->packet_io.internal.interface.type_str)) != 0){
			sapp_log(RLOG_LV_FATAL, ~0, ~0, "int transparent, internal and external interface type must be the same!");
			return -1;
		}
	}

	if(pconfig->packet_io.under_ddos_config.enabled){
		if(pconfig->packet_io.under_ddos_config.bypass_trigger_cpu_usage < 1.0
		|| pconfig->packet_io.under_ddos_config.bypass_trigger_cpu_usage >= 100.0){
			sapp_log(RLOG_LV_FATAL, ~0, ~0, "[packet_io.under_ddos]->bypass_trigger_cpu_usage invalid!");
			return -1;		
		}

		if(pconfig->packet_io.under_ddos_config.factor_decrease_ratio >= 1.0000){
			sapp_log(RLOG_LV_FATAL, ~0, ~0, "[packet_io.under_ddos]->factor_decrease_ratio invalid, must smaller than 1.0!");
			return -1;					
		}
		if(pconfig->packet_io.under_ddos_config.factor_increase_ratio <= 1.0000){
			sapp_log(RLOG_LV_FATAL, ~0, ~0, "[packet_io.under_ddos]->factor_increase_ratio invalid, must bigger than 1.0!");
			return -1;					
		}		
	}

	/*******************************  PKT_DUMP  ******************************/
	if(pconfig->tools.pkt_dump.enabled != 0){
		if(pconfig->tools.pkt_dump.dump_thread_id_array_num > pconfig->cpu.worker_threads){
			sapp_log(RLOG_LV_FATAL, ~0, ~0, "TOOLS.PKT_DUMP.dump_thread_id_array items more than CPU.worker_threads!");
			return -1;
		}

		if((strncasecmp(pconfig->tools.pkt_dump.mode_str, "storage" ,strlen("storage")) != 0)
	     && (strncasecmp(pconfig->tools.pkt_dump.mode_str, "udp_socket" ,strlen("udp_socket")) != 0)){
			sapp_log(RLOG_LV_FATAL, ~0, ~0, "TOOLS.PKT_DUMP.mode only support [storage, udp_socket]!");
			return -1;
		}

		if(strncasecmp(pconfig->tools.pkt_dump.mode_str, "udp_socket" ,strlen("udp_socket")) == 0){
			if(pconfig->tools.pkt_dump.command_port ==0 || pconfig->tools.pkt_dump.command_port > 65535){
				sapp_log(RLOG_LV_FATAL, ~0, ~0, "TOOLS.PKT_DUMP.command_port: %u invalid!", pconfig->tools.pkt_dump.command_port);
				return -1;
			}
		}	
	}

	old_config_file_detect("./conf/main.conf", "./etc/sapp.toml");


	return 0;
}



/*
	支持读写分离模式, 更新各种配置文件路径, 本地数据文件路径.
*/
int sapp_get_secondary_file_path(void)
{
	char str_tmp[ARG_MAX];
	sapp_config_t *pconfig = &sapp_global_val->config;

	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"profiling.metric.fs2", (char *)"local_file", pconfig->profiling.fs2.local_file, NAME_MAX, "");
	if (strlen(pconfig->profiling.fs2.local_file) > 0)
	{
		if (pconfig->data_file_path.data_sapp_fs2_log_relative)
		{
			SAPP_GLOBAL_FREE(pconfig->data_file_path.data_sapp_fs2_log_relative);
		}
		pconfig->data_file_path.data_sapp_fs2_log_relative = sapp_strdup(pconfig->profiling.fs2.local_file);
	}

	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"profiling.metric.fs3", (char *)"local_file", pconfig->profiling.fs3.local_file, NAME_MAX, "");
	if (strlen(pconfig->profiling.fs3.local_file) > 0)
	{
		if (pconfig->data_file_path.data_sapp_fs3_log_relative)
		{
			SAPP_GLOBAL_FREE(pconfig->data_file_path.data_sapp_fs3_log_relative);
		}
		pconfig->data_file_path.data_sapp_fs3_log_relative = sapp_strdup(pconfig->profiling.fs3.local_file);
	}

	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"profiling.process_latency", (char *)"local_file", pconfig->profiling.process_latency_local_file, NAME_MAX, "");
	if (strlen(pconfig->profiling.process_latency_local_file) > 0)
	{
		if (pconfig->data_file_path.data_sapp_fs2_process_latency_relative)
		{
			SAPP_GLOBAL_FREE(pconfig->data_file_path.data_sapp_fs2_process_latency_relative);
		}
		pconfig->data_file_path.data_sapp_fs2_process_latency_relative = sapp_strdup(pconfig->profiling.process_latency_local_file);
	}

	/*************************** SECONDARY_CONFIG_LINK *************************/
	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"SECONDARY_CONFIG_LINK", (char *)"cfg_file_sapp_log", str_tmp, ARG_MAX, "etc/sapp_log.conf");
	if(str_tmp[0] != '\0'){
		if(pconfig->cfg_file_path.cfg_sapp_log_relative){
			SAPP_GLOBAL_FREE(pconfig->cfg_file_path.cfg_sapp_log_relative);
		}
		pconfig->cfg_file_path.cfg_sapp_log_relative = sapp_strdup(str_tmp);
	}

	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"SECONDARY_CONFIG_LINK", (char *)"cfg_file_plug_list", str_tmp, ARG_MAX, "plug/conflist.inf");
	if(str_tmp[0] != '\0'){
		if(pconfig->cfg_file_path.cfg_plug_list_relative){
			SAPP_GLOBAL_FREE(pconfig->cfg_file_path.cfg_plug_list_relative);
		}	
		pconfig->cfg_file_path.cfg_plug_list_relative = sapp_strdup(str_tmp);
	}

	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"SECONDARY_CONFIG_LINK", (char *)"cfg_file_project_list", str_tmp, ARG_MAX, "etc/project_list.conf");
	if(str_tmp[0] != '\0'){
		if(pconfig->cfg_file_path.cfg_project_list_relative){
			SAPP_GLOBAL_FREE(pconfig->cfg_file_path.cfg_project_list_relative);
		}		
		pconfig->cfg_file_path.cfg_project_list_relative = sapp_strdup(str_tmp);
	}
	
	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"SECONDARY_CONFIG_LINK", (char *)"cfg_file_entrylist", str_tmp, ARG_MAX, "etc/entrylist.conf");
	if(str_tmp[0] != '\0'){
		if(pconfig->cfg_file_path.cfg_entry_list_relative){
			SAPP_GLOBAL_FREE(pconfig->cfg_file_path.cfg_entry_list_relative);
		}		
		pconfig->cfg_file_path.cfg_entry_list_relative = sapp_strdup(str_tmp);
	}
	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"SECONDARY_CONFIG_LINK", (char *)"cfg_file_send_raw_pkt", str_tmp, ARG_MAX, "etc/send_raw_pkt.conf");
	if(str_tmp[0] != '\0'){
		if(pconfig->cfg_file_path.cfg_file_send_raw_pkt_relative){
			SAPP_GLOBAL_FREE(pconfig->cfg_file_path.cfg_file_send_raw_pkt_relative);
		}		
		pconfig->cfg_file_path.cfg_file_send_raw_pkt_relative = sapp_strdup(str_tmp);
	}
	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"SECONDARY_CONFIG_LINK", (char *)"cfg_file_vxlan_sport_map", str_tmp, ARG_MAX, "etc/vxlan_sport_service_map.conf");
	if(str_tmp[0] != '\0'){
		if(pconfig->cfg_file_path.cfg_file_vxlan_sport_map_relative){
			SAPP_GLOBAL_FREE(pconfig->cfg_file_path.cfg_file_vxlan_sport_map_relative);
		}		
		pconfig->cfg_file_path.cfg_file_vxlan_sport_map_relative = sapp_strdup(str_tmp);
	}
	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"SECONDARY_CONFIG_LINK", (char *)"cfg_file_inline_device", str_tmp, ARG_MAX, "etc/gdev.conf");
	if(str_tmp[0] != '\0'){
		if(pconfig->cfg_file_path.cfg_file_inline_dev_relative){
			SAPP_GLOBAL_FREE(pconfig->cfg_file_path.cfg_file_inline_dev_relative);
		}		
		pconfig->cfg_file_path.cfg_file_inline_dev_relative = sapp_strdup(str_tmp);
	}
	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"SECONDARY_CONFIG_LINK", (char *)"cfg_file_necessary_plug_list", str_tmp, ARG_MAX, "etc/necessary_plug_list.conf");
	if(str_tmp[0] != '\0'){
		if(pconfig->cfg_file_path.cfg_file_necessary_plug_relative){
			SAPP_GLOBAL_FREE(pconfig->cfg_file_path.cfg_file_necessary_plug_relative);
		}		
		pconfig->cfg_file_path.cfg_file_necessary_plug_relative = sapp_strdup(str_tmp);
	}
	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"SECONDARY_CONFIG_LINK", (char *)"cfg_file_stream_compare_layer", str_tmp, ARG_MAX, "etc/stream_compare_layer.conf");
	if(str_tmp[0] != '\0'){
		if(pconfig->cfg_file_path.cfg_file_stream_compare_layer_relative){
			SAPP_GLOBAL_FREE(pconfig->cfg_file_path.cfg_file_stream_compare_layer_relative);
		}		
		pconfig->cfg_file_path.cfg_file_stream_compare_layer_relative = sapp_strdup(str_tmp);
	}
	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"SECONDARY_CONFIG_LINK", (char *)"cfg_file_vlan_flipping", str_tmp, ARG_MAX, "etc/vlan_flipping_map.conf");
	if(str_tmp[0] != '\0'){
		if(pconfig->cfg_file_path.cfg_file_vlan_flipping_relative){
			SAPP_GLOBAL_FREE(pconfig->cfg_file_path.cfg_file_vlan_flipping_relative);
		}		
		pconfig->cfg_file_path.cfg_file_vlan_flipping_relative = sapp_strdup(str_tmp);
	}
	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"SECONDARY_CONFIG_LINK", (char *)"cfg_file_asymmetric_addr_layer", str_tmp, ARG_MAX, "etc/asymmetric_addr_layer.conf");
	if(str_tmp[0] != '\0'){
		if(pconfig->cfg_file_path.cfg_file_asymmetric_addr_layer_relative){
			SAPP_GLOBAL_FREE(pconfig->cfg_file_path.cfg_file_asymmetric_addr_layer_relative);
		}			
		pconfig->cfg_file_path.cfg_file_asymmetric_addr_layer_relative = sapp_strdup(str_tmp);
	}

	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"SECONDARY_CONFIG_LINK", (char *)"cfg_file_well_known_port", str_tmp, ARG_MAX, "etc/well_known_port.conf");
	if(str_tmp[0] != '\0'){
		if(pconfig->cfg_file_path.cfg_file_well_known_port_relative){
			SAPP_GLOBAL_FREE(pconfig->cfg_file_path.cfg_file_well_known_port_relative);
		}			
		pconfig->cfg_file_path.cfg_file_well_known_port_relative = sapp_strdup(str_tmp);
	}	

	/*************************** SECONDARY_DATA_LINK *************************/
	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"SECONDARY_DATA_LINK", (char *)"data_file_sysinfo_log", str_tmp, ARG_MAX, "sysinfo.log");
	if(str_tmp[0] != '\0'){
		if(pconfig->data_file_path.data_sapp_sysinfo_log_relative){
			SAPP_GLOBAL_FREE(pconfig->data_file_path.data_sapp_sysinfo_log_relative);
		}		
		pconfig->data_file_path.data_sapp_sysinfo_log_relative = sapp_strdup(str_tmp);
	}

	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"SECONDARY_DATA_LINK", (char *)"data_file_inline_keepalive_log", str_tmp, ARG_MAX, "gdev_keeplive_status.log");
	if(str_tmp[0] != '\0'){
		if(pconfig->data_file_path.data_inline_keepalive_log_relative){
			SAPP_GLOBAL_FREE(pconfig->data_file_path.data_inline_keepalive_log_relative);
		}		
		pconfig->data_file_path.data_inline_keepalive_log_relative = sapp_strdup(str_tmp);
	}

	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"SECONDARY_DATA_LINK", (char *)"data_file_load_plugin_stat_log", str_tmp, ARG_MAX, "load_plugin_stat.log");
	if(str_tmp[0] != '\0'){
		if(pconfig->data_file_path.data_load_plugin_stat_log_relative){
			SAPP_GLOBAL_FREE(pconfig->data_file_path.data_load_plugin_stat_log_relative);
		}
		pconfig->data_file_path.data_load_plugin_stat_log_relative = sapp_strdup(str_tmp);
	}

	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"SECONDARY_DATA_LINK", (char *)"data_file_under_ddos_stat_log", str_tmp, ARG_MAX, "under_ddos_stat.log");
	if(str_tmp[0] != '\0'){
		if(pconfig->data_file_path.data_under_ddos_stat_log_relative){
			SAPP_GLOBAL_FREE(pconfig->data_file_path.data_under_ddos_stat_log_relative);
		}
		pconfig->data_file_path.data_under_ddos_stat_log_relative = sapp_strdup(str_tmp);
	}

	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"SECONDARY_DATA_LINK", (char *)"data_file_memory_stat_log", str_tmp, ARG_MAX, "memory_used_stat.log");
	if(str_tmp[0] != '\0'){
		if(pconfig->data_file_path.data_memory_stat_log_relative){
			SAPP_GLOBAL_FREE(pconfig->data_file_path.data_memory_stat_log_relative);
		}
		pconfig->data_file_path.data_memory_stat_log_relative = sapp_strdup(str_tmp);
	}
	

	return 0;
}


/* 读取配置文件sapp.toml, 本函数只Load, 不做解析和错误处理 */
int sapp_parse_config(void)
{
	int ret;
	int tmp_int;
	sapp_config_t *pconfig;
	char str_tmp[ARG_MAX];
	
	if(0 == is_file_exist(ABBR_CFG_FILE_MAIN_ENTRY)){
		special_usage();
		exit(1);
	}

	sapp_printf("sapp use main config file: %s\n", ABBR_CFG_FILE_MAIN_ENTRY);
	sapp_runtime_log(RLOG_LV_INFO, "sapp use main config file: %s", ABBR_CFG_FILE_MAIN_ENTRY);
	
	pconfig = &sapp_global_val->config;


	/*******************************  SYSTEM *********************************/
	ret = tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"SYSTEM", (char *)"instance_name", pconfig->system.instance_name, NAME_MAX, "sapp_v4.2");
	if(TOMLC99_RET_PATTERN_ERROR == ret){
		/* 首次解析判断如果是PATTERN_ERROR, 说明toml格式有问题, 不再继续解析 */
		sapp_log(30, ~0, ~0, "parse config file %s error!", ABBR_CFG_FILE_MAIN_ENTRY);
		exit(1);
	}

	/*******************************  PROFILING.LOG ***************************/
	MESA_handle_runtime_log_creation(ABBR_SAPP_LOG_CONF_FILE);

	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"profiling.log", (char *)"sapp_log_category", pconfig->profiling.log.sapp_log_category, NAME_MAX, "sapp_runtime_log");
	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"profiling.log", (char *)"sapp_plugin_log_category", pconfig->profiling.log.sapp_plugin_log_category, NAME_MAX, "sapp_plugin_log");
	
	sapp_global_val->individual_fixed.log_handle = MESA_create_runtime_log_handle(sapp_global_val->config.profiling.log.sapp_log_category, RLOG_LV_FATAL);
	sapp_global_val->individual_fixed.plugin_log_handle = MESA_create_runtime_log_handle(sapp_global_val->config.profiling.log.sapp_plugin_log_category, RLOG_LV_INFO);


	/*******************************  CPU *********************************/
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"CPU", (char *)"worker_threads", (int *)&pconfig->cpu.worker_threads, 1);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"CPU", (char *)"send_only_threads_max", (int *)&pconfig->cpu.send_only_threads_max_num, 0);

	pconfig->cpu.bind_mask_array_num = SAPP_MAX_THREADS;

	tomlc99_wrap_load_long_array(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"CPU", (char *)"bind_mask", pconfig->cpu.bind_mask_array, &pconfig->cpu.bind_mask_array_num);

	/* 带范围的配置, 如1-10,10-20等参数使用MESA_load_profile_uint_range解析, 此时要用字符串模式!!! */
	int tmp_bind_mask[SAPP_MAX_THREADS] = {};
	ret = MESA_load_profile_uint_range(
		ABBR_CFG_FILE_MAIN_ENTRY, (char *)"CPU", (char *)"bind_mask",
		SAPP_MAX_THREADS, (unsigned int *)tmp_bind_mask);
	if(ret > 0)
	{
		pconfig->cpu.bind_mask_array_num = ret;
		for (int i = 0; i < ret; i++)
		{
			pconfig->cpu.bind_mask_array[i] = (long)tmp_bind_mask[i];
		}
	}


	
	/*******************************  PACKET_IO ******************************/

	/*******************************  packet_io.overlay_tunnel_definition ******************************/
	
	//tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"overlay_tunnel_definition", (char *)"l2_l3_tunnel_support", &pconfig->packet_io.packet_io_tunnel.l2_l3_tunnel_support, 1);
	pconfig->packet_io.packet_io_tunnel.l2_l3_tunnel_support=1;

	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"overlay_tunnel_definition", (char *)"overlay_mode", pconfig->packet_io.packet_io_tunnel.overlay_mode_string, NAME_MAX, "none");

	/*******************************  packet_io.feature ******************************/
	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.feature", (char *)"BSD_packet_filter", str_tmp, NAME_MAX, "");
	if(str_tmp[0] != '\0'){
		pconfig->packet_io.input_bpf_filter = sapp_strdup(str_tmp);
	}
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.feature", (char *)"inbound_route_dir", &pconfig->packet_io.inbound_route_dir, 0);
	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.feature", (char *)"pcap_capture_direction", pconfig->packet_io.pcap_capture_direction, NAME_MAX, "in");
	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.feature", (char *)"inject_pkt_mode", pconfig->packet_io.inject_pkt_mode_string, NAME_MAX, "sys_route");
	if(strncasecmp(pconfig->packet_io.inject_pkt_mode_string, "raw_ethernet_single_gateway", strlen("raw_ethernet_single_gateway")) == 0){
		tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.feature", (char *)"inject_mode_single_gateway_device", pconfig->packet_io.inject_mode_single_gateway_device, NAME_MAX, "lo");
		tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.feature", (char *)"inject_mode_single_gateway_dst_mac", pconfig->packet_io.inject_mode_single_gateway_dst_mac_string, sizeof(pconfig->packet_io.inject_mode_single_gateway_dst_mac_string), "$");
	}
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.feature", (char *)"inject_pkt_prepend_segment_id", &pconfig->packet_io.inject_pkt_prepend_segment_id, 0);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.feature", (char *)"inject_mode_inline_device_sport", &tmp_int, 54789);
	if(tmp_int <= 0 || tmp_int > 65535){
		sapp_log(30, ~0, ~0, "config parse error! invalid value of 'packet_io.feature.inject_mode_inline_device_sport %d'", tmp_int);
		return -1;
	}else{
		pconfig->packet_io.inject_mode_inline_device_sport = tmp_int;
	}
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.feature", (char *)"monitor_thread_enabled", &pconfig->packet_io.monitor_thread_enabled, 1);
	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.feature", (char *)"extract_linkdir_from_mac_in_mirror_mode", pconfig->packet_io.extract_linkdir_from_mac_sntax_raw_string, sizeof(pconfig->packet_io.extract_linkdir_from_mac_sntax_raw_string), "");
	
	MESA_load_profile_short_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.feature", (char *)"dlclose_all_plug_enabled", &pconfig->packet_io.dlclose_all_plug_enabled, 1);
	MESA_load_profile_short_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.feature", (char *)"destroy_all_plug_enabled", &pconfig->packet_io.destroy_all_plug_enabled, 1);
	MESA_load_profile_short_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.polling", (char *)"infinite_loop_enabled", &pconfig->packet_io.infinite_loop_enabled, 0);

	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.deployment", (char *)"mode", pconfig->packet_io.deployment_mode_str, NAME_MAX, "inline");
	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.internal.interface", (char *)"type", pconfig->packet_io.internal.interface.type_str, NAME_MAX, "pcap");
	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.internal.interface", (char *)"name", pconfig->packet_io.internal.interface.name, NAME_MAX, "lo");
	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.external.interface", (char *)"type", pconfig->packet_io.external.interface.type_str, NAME_MAX, "");
	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.external.interface", (char *)"name", pconfig->packet_io.external.interface.name, NAME_MAX, "");
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.polling", (char *)"enabled", &pconfig->packet_io.polling_enabled, 1);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.polling", (char *)"polling_priority", &pconfig->packet_io.polling_priority, 100);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.polling", (char *)"work_percent", &pconfig->packet_io.work_percent, 90);
	

	/**  duplicate packet config **/
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"dup_pkt.traffic.original", (char *)"original_ipv4_tcp_enabled", &pconfig->packet_io.dup_pkt_para.dup_pkt_distinguish_ipv4_tcp, 0);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"dup_pkt.traffic.original", (char *)"original_ipv4_udp_enabled", &pconfig->packet_io.dup_pkt_para.dup_pkt_distinguish_ipv4_udp, 0);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"dup_pkt.traffic.inject", (char *)"inject_all_enabled", &pconfig->packet_io.dup_pkt_para.dup_pkt_distinguish_all_inject, 0);
	
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"dup_pkt.parameter", (char *)"bloom_capacity", &pconfig->packet_io.dup_pkt_para.bloom_capacity, 1000000);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"dup_pkt.parameter", (char *)"bloom_timeout", &pconfig->packet_io.dup_pkt_para.bloom_timeout, 10);
	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"dup_pkt.parameter", (char *)"bloom_error_rate", str_tmp, sizeof(str_tmp), "0.00001");
	pconfig->packet_io.dup_pkt_para.bloom_error_rate = strtod(str_tmp, NULL);

	/*******************************  packet_io.under_ddos ******************************/
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.under_ddos", (char *)"stream_bypass_enabled", &pconfig->packet_io.under_ddos_config.enabled, 0); //向前兼容, 默认不开启
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.under_ddos", (char *)"get_cpu_usage_interval", &pconfig->packet_io.under_ddos_config.get_cpu_usage_interval, 50);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.under_ddos", (char *)"smooth_avg_window", &pconfig->packet_io.under_ddos_config.smooth_avg_window, 3);

	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.under_ddos", (char *)"bypass_trigger_cpu_usage", &tmp_int, 90);
	pconfig->packet_io.under_ddos_config.bypass_trigger_cpu_usage = (double)tmp_int;

	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.under_ddos", (char *)"decrease_ratio", str_tmp, sizeof(str_tmp), "0.99");
	pconfig->packet_io.under_ddos_config.factor_decrease_ratio = strtod(str_tmp, NULL);

	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.under_ddos", (char *)"increase_ratio", str_tmp, sizeof(str_tmp), "1.001");
	pconfig->packet_io.under_ddos_config.factor_increase_ratio = strtod(str_tmp, NULL);
	
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"packet_io.under_ddos", (char *)"recovery_observe_time", &pconfig->packet_io.under_ddos_config.recovery_observe_time, 60);

	/*******************************  STREAM ******************************/
	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"STREAM", (char *)"stream_id_base_time", pconfig->stream.stream_id_base_time_str, 32, "");

	/*******************************  STREAM.TCP ******************************/
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"stream.tcp", (char *)"max", (int *)&pconfig->stream.tcp.max, 50000);

	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"stream.tcp", (char *)"timeout", (int *)&pconfig->stream.tcp.timeout, 180);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"stream.tcp", (char *)"syn_mandatory", (int *)&pconfig->stream.tcp.syn_mandatory, 1);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"stream.tcp", (char *)"reorder_pkt_max", (int *)&pconfig->stream.tcp.reorder_pkt_max, 5);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"stream.tcp", (char *)"analyse_option_enabled", (int *)&pconfig->stream.tcp.analyse_option_enabled, 1);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"stream.tcp", (char *)"tuple4_reuse_time_interval", (int *)&pconfig->stream.tcp.tuple4_reuse_time_interval, 30);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"stream.tcp", (char *)"meaningful_statistics_minimum_pkt", (int *)&pconfig->stream.tcp.meaningful_statistics_minimum_pkt, 3);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"stream.tcp", (char *)"meaningful_statistics_minimum_byte", (int *)&pconfig->stream.tcp.meaningful_statistics_minimum_byte, 5);
	
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"stream.tcp", (char *)"closing_timeout", (int *)&pconfig->stream.tcp.closing_timeout, 30);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"stream.tcp", (char *)"opening_timeout", (int *)&pconfig->stream.tcp.opening_timeout, 10);
	
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"stream.tcp.inject", (char *)"link_mss", (int *)&pconfig->stream.tcp.inject.link_mss, 1460);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"stream.tcp.inject.rst", (char *)"auto_remedy", (int *)&pconfig->stream.tcp.inject.auto_remedy, 0);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"stream.tcp.inject.rst", (char *)"signature_enabled", (int *)&pconfig->stream.tcp.inject.rst_signature_enable, 1);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"stream.tcp.inject.rst", (char *)"signature_seed1", (int *)&pconfig->stream.tcp.inject.rst_signature_seed1, 65535);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"stream.tcp.inject.rst", (char *)"signature_seed2", (int *)&pconfig->stream.tcp.inject.rst_signature_seed2, 13);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"stream.tcp.inject.rst", (char *)"number", (int *)&pconfig->stream.tcp.inject.rst_num, 3);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"stream.tcp.inject.rst", (char *)"remedy_kill_tcp_by_inline_device", &pconfig->stream.tcp.inject.remedy_kill_tcp_by_inline_device, 0);


	/*******************************  STREAM.UDP ******************************/
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"stream.udp", (char *)"max", (int *)&pconfig->stream.udp.max, 5000);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"stream.udp", (char *)"timeout", (int *)&pconfig->stream.udp.timeout, 60);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"stream.udp", (char *)"meaningful_statistics_minimum_pkt", (int *)&pconfig->stream.udp.meaningful_statistics_minimum_pkt, 3);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"stream.udp", (char *)"meaningful_statistics_minimum_byte", (int *)&pconfig->stream.udp.meaningful_statistics_minimum_byte, 5);
	


	/*******************************  PROFILING.metric.fs2 **********************/
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"profiling.metric.fs2", (char *)"enabled", (int *)&pconfig->profiling.fs2.enabled, 0);
	if(pconfig->profiling.fs2.enabled)
	{
		tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"profiling.metric.fs2", (char *)"prometheus_port", (int *)&pconfig->profiling.fs2.prometheus_service_port, 0);
		tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"profiling.metric.fs2", (char *)"refresh_interval_s", (int *)&pconfig->profiling.fs2.refresh_interval_s, 2);
		tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"profiling.metric.fs2", (char *)"prometheus_url_path", pconfig->profiling.fs2.prometheus_service_uri, NAME_MAX, "");
		tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"profiling.metric.fs2", (char *)"app_name", pconfig->profiling.fs2.app_name, NAME_MAX, "sapp4");

	}
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"profiling.metric.fs3", (char *)"enabled", (int *)&pconfig->profiling.fs3.enabled, 0);
	/*******************************  PROFILING.metric.fs3 **********************/
	if(pconfig->profiling.fs3.enabled)
	{
		tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"profiling.metric.fs3", (char *)"prometheus_port", (int *)&pconfig->profiling.fs3.prometheus_service_port, 0);
		tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"profiling.metric.fs3", (char *)"refresh_interval_s", (int *)&pconfig->profiling.fs3.refresh_interval_s, 2);
		tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"profiling.metric.fs3", (char *)"prometheus_url_path", pconfig->profiling.fs3.prometheus_service_uri, NAME_MAX, "");
		tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"profiling.metric.fs3", (char *)"app_name", pconfig->profiling.fs3.app_name, NAME_MAX, "sapp4");
	}

	/*******************************  PROFILING.process_latency ******************************/
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"profiling.process_latency", (char *)"histogram_enabled", (int *)&pconfig->profiling.histogram_enabled, 0);
	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"profiling.process_latency", (char *)"log_category", pconfig->profiling.process_latency_log_category, NAME_MAX, "sapp_process_latency_log");

	sapp_global_val->individual_fixed.process_latency_log_handle = MESA_create_runtime_log_handle(sapp_global_val->config.profiling.process_latency_log_category, sapp_global_val->config.profiling.histogram_enabled);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"profiling.process_latency", (char *)"threshold_us", (int *)&pconfig->profiling.process_latency_threshold_in_us, 1000);
	if (pconfig->profiling.process_latency_threshold_in_us <= 0)
	{
		sapp_log(30, ~0, ~0, "config parse error! invalid value of 'profiling.pkt_latency->threshold_us', valid range is [1,99999999]");
		return -1;
	}
	if (pconfig->profiling.process_latency_threshold_in_us >= 99999999)
	{
		sapp_log(30, ~0, ~0, "config parse error! invalid value of 'profiling.pkt_latency->threshold_us', valid range is [1,99999999], set to max value 9999!");
		pconfig->profiling.process_latency_threshold_in_us = 99999999;
	}

	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"profiling.process_latency", (char *)"clock_gettime_id", (int *)&pconfig->profiling.process_latency_clock_id, 6);
	if(pconfig->profiling.process_latency_clock_id < 0 || pconfig->profiling.process_latency_clock_id > 6)
	{
		sapp_log(30, ~0, ~0, "config parse error! invalid value of 'profiling.pkt_latency->clock_gettime_id', valid range is [0,6], set to default value 6!");
		pconfig->profiling.process_latency_clock_id=6;
	}

	/*******************************  PROFILING.sanity_check ******************************/
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"profiling.sanity_check", (char *)"raw_pkt_broken_enabled", (int *)&pconfig->profiling.sanity_check_raw_pkt_broken_enabled, 0);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"profiling.sanity_check", (char *)"symbol_conflict_enabled", (int *)&pconfig->profiling.sanity_check_symbol_conflict_enabled, 0);

	/************************  PROTOCOL_FEATURE **********************************/
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"PROTOCOL_FEATURE", (char *)"ipv6_decapsulation_enabled", (int *)&pconfig->protocol_feature.ipv6_decapsulation_enabled, 1);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"PROTOCOL_FEATURE", (char *)"ipv6_send_packet_enabled", (int *)&pconfig->protocol_feature.ipv6_send_packet_enabled, 1);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"PROTOCOL_FEATURE", (char *)"tcp_drop_pure_ack_pkt", (int *)&pconfig->protocol_feature.tcp_drop_pure_ack_pkt, 0);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"PROTOCOL_FEATURE", (char *)"tcp_syn_option_parse_enabled", (int *)&pconfig->protocol_feature.tcp_syn_option_parse_enabled, 1);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"PROTOCOL_FEATURE", (char *)"skip_not_ip_layer_over_eth", (int *)&pconfig->protocol_feature.skip_not_ip_layer_over_eth, 0);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"PROTOCOL_FEATURE", (char *)"reverse_ethernet_addr", (int *)&pconfig->protocol_feature.reverse_ethernet_addr_enabled, 1);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"PROTOCOL_FEATURE", (char *)"skip_gtp_S_PN_E_field_for_inject", (int *)&pconfig->protocol_feature.skip_gtp_S_PN_E_field_for_inject, 1);

	/*******************************  TOOLS **********************************/
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"tools.signal_handler", (char *)"signal", (int *)&pconfig->tools.signal_handler.signal, 0);

	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"tools.pkt_dump", (char *)"enabled", (int *)&pconfig->tools.pkt_dump.enabled, 0);
	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"tools.pkt_dump", (char *)"mode", pconfig->tools.pkt_dump.mode_str, NAME_MAX, "udp_socket");
	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"tools.pkt_dump", (char *)"BSD_packet_filter", str_tmp, ARG_MAX, "");
	if (str_tmp[0] != '\0')
	{
		pconfig->tools.pkt_dump.bpf_filter = sapp_strdup(str_tmp);
	}

	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"tools.pkt_dump.threads", (char *)"all_threads_enabled", &pconfig->tools.pkt_dump.dump_all_thread_enabled, 0);
	if(0 == pconfig->tools.pkt_dump.dump_all_thread_enabled){
		pconfig->tools.pkt_dump.dump_thread_id_array_num = SAPP_MAX_THREADS;
		tomlc99_wrap_load_int_array(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"tools.pkt_dump.threads", (char *)"dump_thread_id", pconfig->tools.pkt_dump.dump_thread_id_array, &pconfig->tools.pkt_dump.dump_thread_id_array_num);
	}
	
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"tools.pkt_dump.udp", (char *)"command_port", (int *)&pconfig->tools.pkt_dump.command_port, 0);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"tools.pkt_dump.udp", (char *)"pkt_dump_ratio", (int *)&pconfig->tools.pkt_dump.pkt_dump_ratio, 30);

	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"tools.pkt_dump.storage", (char *)"path", str_tmp, ARG_MAX, "/dev/shm/pkt_dump");
	pconfig->tools.pkt_dump.storge_path = sapp_strdup(str_tmp);
	tomlc99_wrap_load_int_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"tools.pkt_dump.storage", (char *)"file_size_max_per_thread", (int *)&pconfig->tools.pkt_dump.file_size_max_per_thread, 1000);

	tomlc99_wrap_load_string_def(ABBR_CFG_FILE_MAIN_ENTRY, (char *)"LIBRARY_LINK", (char *)"marsio_library_path", str_tmp, ARG_MAX, "/opt/mrzcpd/lib/libmarsio.so");
	pconfig->library_file_path.libmarsio_file_path = sapp_strdup(str_tmp);

	if(config_sanity_check() < 0){
		exit(1);
	}

	if(config_expression_convert() < 0){
		exit(1);
	}

	sapp_runtime_log(RLOG_LV_INFO, "config parse success!");
	
	return 0;
}

/*
	0: 不认识配置文件中的key-value;
	1: 识别并存储配置文件中的key-value;
	2: 包括某些已经被废弃的参数.
*/
static int sapp_config_check_update_option(sapp_config_check_t *local_cfg_check_attr, const char *section, const char *key, const char *value)
{
	int i;
	int section_max_len, key_max_len;
	int found_cfg = 0;
	
	for(i = 0; local_cfg_check_attr[i].global_id != -1; i++){
		if(NULL == local_cfg_check_attr[i].cfg_key){ /* [PACKET_IO], []DUPLICATE_PKT] 等配置只有个section, 但是没有key */
			continue;
		}
		section_max_len = SAPP_MAX(strlen(local_cfg_check_attr[i].section), strlen(section));
		key_max_len = SAPP_MAX(strlen(local_cfg_check_attr[i].cfg_key), strlen(key));
		if((strncmp(section, local_cfg_check_attr[i].section, section_max_len) == 0)
		&& (strncmp(key, local_cfg_check_attr[i].cfg_key, key_max_len) == 0)){
			if(SAPP_CFG_OBSOLETE_FLAG == local_cfg_check_attr[i].global_id){
				sapp_printf_colorful(RLOG_LV_INFO, "config: [%s] -> %s is obsolete!\n", section, key);
				return 2;
			}else{
				if(NULL == value){
					local_cfg_check_attr[i].cfg_value = sapp_strdup(""); /* 没有配置有意的值, 比如bpf过滤条件为空, 但是key是存在的, 也算配置找到了 */
				}else{
					local_cfg_check_attr[i].cfg_value = sapp_strdup(value);
				}
				found_cfg = 1;
			}
			break;
		}
	}

	return found_cfg;
}

extern void del_last_rn(char *data, int max_len);
extern int sapp_del_last_char(char *data, int max_len, char del_char);
extern char *sapp_memmove_for_blank_table(char *data, int max_len);


/*
	是否需要检查当前配置的合法性.
*/
static int cfg_value_need_be_check(const sapp_config_check_t *local_cfg_check_array, const sapp_config_check_t *this_cfg_check_attr)
{
	int depend_cfg_index;
	
	if(1 == this_cfg_check_attr->depend_id){
		return 1;
	}
	if(0 == this_cfg_check_attr->depend_id){ /* 可选的配置也检查 */
		return 1;
	}	

	if(this_cfg_check_attr->depend_id >= 1000){
		
		depend_cfg_index = cfg_get_index_by_depend_id(this_cfg_check_attr->depend_id);

		if((local_cfg_check_array[depend_cfg_index].cfg_value != NULL) 
		&& (strncasecmp(local_cfg_check_array[depend_cfg_index].cfg_value, this_cfg_check_attr->depend_cfg_value, strlen(this_cfg_check_attr->depend_cfg_value)) == 0)){
			return 1;
		}
	}

	return 0;
}

/*
	完全遍历一遍当前的sapp.toml, 检查是否有不认识的配置, 如果有说明:
	    1)sapp比sapp.toml的版本旧;
	    2)某些历史上的参数已经被废弃, 但是sapp.toml还存在;	

	此处不用prof_load而是自行用fgets逐行读取, 因为事先不知道要获取什么, 要把所有的行都遍历一遍.
*/
static int sapp_config_check_unsupport(sapp_config_check_t *local_cfg_check_attr)
{
	int ret, fun_ret = 0;
	char raw_config_line[1024];
	char config_line[1024];
	char section_string[128] = {};
	char *cfg_key;
	char *cfg_value;
	const char *kname_delim = "="; /* 参数的值只能用=分割, 否则会把key的值里的空格\t删除, 比如bpf filter */ 
	const char *section_delim = "[] \t";
	char *key_save_ptr, *section_save_ptr;
	FILE *fp;

	fp = fopen(ABBR_CFG_FILE_MAIN_ENTRY, "r");
	if(NULL == fp){
		sapp_printf_colorful(RLOG_LV_FATAL, "can't open file:%s\n", ABBR_CFG_FILE_MAIN_ENTRY);
		return RLOG_LV_FATAL;
	}

	while(fgets(raw_config_line, sizeof(raw_config_line), fp) != NULL){
		del_last_rn(raw_config_line, sizeof(raw_config_line));
		sapp_memmove_for_blank_table(raw_config_line, sizeof(raw_config_line));

		if('#' == raw_config_line[0]){
			continue;
		}
		if('\0' == raw_config_line[0]){ /* 纯空行 */
			continue;
		}		

		memcpy(config_line, raw_config_line, sizeof(raw_config_line));
		if('[' == raw_config_line[0]){ /* 以[开头表示是section段落开始 */
			char *pure_sesion_str = strtok_r(config_line, section_delim, &section_save_ptr);
			strncpy(section_string, pure_sesion_str, sizeof(section_string));
			while(strtok_r(NULL, section_delim, &section_save_ptr));
			continue;
		}

		cfg_key = strtok_r(config_line, kname_delim, &key_save_ptr);
		if(NULL == cfg_key){
			sapp_printf_colorful(RLOG_LV_FATAL, "invalid config line:%s\n", config_line);
			continue;
		}
		sapp_del_last_char(cfg_key, strlen(cfg_key), ' ');
		sapp_del_last_char(cfg_key, strlen(cfg_key), '\t');

		cfg_value = strtok_r(NULL, kname_delim, &key_save_ptr);
		if(NULL == cfg_value){
			sapp_printf_colorful(RLOG_LV_FATAL, "invalid config line:%s\n", config_line);
			continue;
		}

		sapp_memmove_for_blank_table(cfg_value, strlen(cfg_value));

		const char *kkvalue_delim = "\"'";  /* 参数的值可能被双引号保护了, 此时只能去掉引号但是不能再用空格\t分割了, 比如bpf_filter */
		char *pure_cfg_value_save_ptr;
		char *pure_cfg_value = strtok_r(cfg_value, kkvalue_delim, &pure_cfg_value_save_ptr);
		ret = sapp_config_check_update_option(local_cfg_check_attr, section_string, cfg_key, pure_cfg_value);
		if(ret <= 0){
			sapp_printf_colorful(RLOG_LV_FATAL, "unsupport config: [%s] -> %s\n", section_string, raw_config_line);
			fun_ret = SAPP_MAX(fun_ret, RLOG_LV_FATAL);
		}else if(2 == ret){
			fun_ret = SAPP_MAX(fun_ret, RLOG_LV_INFO);
		}

		while(strtok_r(NULL, kname_delim, &key_save_ptr));
	}

	return fun_ret;
}

/*
	把所有已知的参数从sapp.toml里读取一遍, 检查是否有不存在的配置, 如果有:
	    1)sapp比sapp.toml的版本新;
*/
static int sapp_config_check_missing(sapp_config_check_t *local_cfg_check_attr)
{
	int ret1, ret2, ret3, i;
	char cfg_value[1024];
	int array_num, cfg_array[1024];
	int fun_ret = 0;
	
	for(i = 0; local_cfg_check_attr[i].global_id != -1; i++){
		if(NULL == local_cfg_check_attr[i].cfg_key){ /* [PACKET_IO], []DUPLICATE_PKT] 等配置只有个section, 仅作为段落标识, 但是没有key */
			continue;
		}	
		if(SAPP_CFG_OBSOLETE_FLAG == local_cfg_check_attr[i].global_id){ /* 已经废弃的配置, 不用于检查missing */
			continue;
		}			
		if(cfg_value_need_be_check(local_cfg_check_attr, &local_cfg_check_attr[i]) == 0){
			continue;
		}
		ret1 = MESA_load_profile_string_nodef(ABBR_CFG_FILE_MAIN_ENTRY, local_cfg_check_attr[i].section, local_cfg_check_attr[i].cfg_key, cfg_value, sizeof(cfg_value));
		if(ret1 < 0){
			/* 用profile接口读取不到有可能是toml格式的数组, 再用toml数组尝试解析一下 */
			array_num = 1024;
			ret2 = tomlc99_wrap_load_int_array(ABBR_CFG_FILE_MAIN_ENTRY, local_cfg_check_attr[i].section, (char *)local_cfg_check_attr[i].cfg_key, cfg_array, &array_num);
			if(ret2 < 0){
				/* 使用toml数组也没有读取到配置, 检查是否依赖其他配置项 */
				if((local_cfg_check_attr[i].depend_id != 0) && (local_cfg_check_attr[i].cfg_value_check_fun != NULL)){
					ret3 = local_cfg_check_attr[i].cfg_value_check_fun(local_cfg_check_attr, local_cfg_check_attr[i].global_id, local_cfg_check_attr[i].depend_id, 
																 local_cfg_check_attr[i].cfg_value, local_cfg_check_attr[i].expect_range_array, local_cfg_check_attr[i].expect_array_num);
					if(ret3 != 0){
						fun_ret = SAPP_MAX(local_cfg_check_attr[i].err_log_level, fun_ret); 
						sapp_printf_colorful(fun_ret, "missing sapp.toml config: [%s] -> %s\n", local_cfg_check_attr[i].section, local_cfg_check_attr[i].cfg_key);
						/* 注意: 此处不要break, 检查所有的配置文件参数 */
					}
				}else{
					fun_ret = SAPP_MAX(local_cfg_check_attr[i].err_log_level, fun_ret);
					sapp_printf_colorful(fun_ret, "missing sapp.toml config: [%s] -> %s\n", local_cfg_check_attr[i].section, local_cfg_check_attr[i].cfg_key);
					
					/* 注意: 此处不要break, 检查所有的配置文件参数 */
				}
			}
		}
	}
	
	return fun_ret;
}


static int sapp_config_check_missing_and_unsupport(sapp_config_check_t *local_cfg_check_attr)
{
	int ret;

	/* 注意:   check_unsupport放在前面, 因为还有个附加作用, 就是把所有配置的值读取到全局变量: g_sapp_cfg_check_attr 中*/
	ret = sapp_config_check_unsupport(local_cfg_check_attr);
	if(ret != 0){
		sapp_printf_colorful(ret, "maybe a typo, maybe some config is obsolete, or sapp is older than sapp.toml version!\n");
		return ret;
	}

	ret = sapp_config_check_missing(local_cfg_check_attr);
	if(ret != 0){
		sapp_printf_colorful(ret, "maybe a typo, or sapp is newer than sapp.toml version!\n");
		return ret;
	}

	return ret;
}

/*
	检查每个参数自身的合法性, 只是单纯看参数的值合不合法, 不做关联性检查.
*/
static int sapp_config_check_single_validity(sapp_config_check_t *local_cfg_check_attr)
{
	int i, ret, fun_ret = 0;

	for(i = 0; local_cfg_check_attr[i].global_id != -1; i++){
		if(cfg_value_need_be_check(local_cfg_check_attr, &local_cfg_check_attr[i]) == 0){
			continue;
		}
		
		if(local_cfg_check_attr[i].cfg_value_check_fun != NULL){
			ret = local_cfg_check_attr[i].cfg_value_check_fun(local_cfg_check_attr, local_cfg_check_attr[i].global_id, 
					local_cfg_check_attr[i].depend_id, local_cfg_check_attr[i].cfg_value, 
					local_cfg_check_attr[i].expect_range_array, local_cfg_check_attr[i].expect_array_num);
			if(ret != 0){
				fun_ret = SAPP_MAX(fun_ret, local_cfg_check_attr[i].err_log_level);
				sapp_printf_colorful(fun_ret, "check config: [%s]->%s error, invalid value:'%s'\n", 
						local_cfg_check_attr[i].section, local_cfg_check_attr[i].cfg_key, local_cfg_check_attr[i].cfg_value);
				return fun_ret;
			}
		}
	}

	return fun_ret;
}

/*
	多个从参数之间的关联性检查, 
	    比如拓扑为transparent模式, 必须开启packet_io.external.interface;
	    比如开启了prometheus_enabled, 必须有prometheus_port和prometheus_url_path;
*/
static int sapp_config_check_sanity(sapp_config_check_t *local_cfg_check_attr)
{
	/*
		TODO:
		
	*/
	return 0;
}


/*
	check_level:
		t1: 只检查支持的参数在不在, 是否有不支持的新参数;
		t2: 检查每个参数的值是否合法, 比如packet_io.mode 不是mirror, inline, tansparent等;
		t3: 不仅检查单个参数, 尽可能的检查所有参数的相关性依赖问题, 比如transparent模式没有配置external网卡;
*/
int sapp_config_check(void)
{
	int i, ret1, ret2, final_ret = 0;

	/* 全局变量中有固定不变的配置, 也有动态从配置文件读取的数据, 所以此处copy一份临时数据 */
	sapp_config_check_t *local_cfg_check_attr = (sapp_config_check_t *)sapp_mem_calloc(SAPP_MEM_FIX_GLOBAL_VAL, MEM_STAT_GLOBAL_THREAD_ID,sizeof(g_sapp_cfg_check_attr)); 
	memcpy(local_cfg_check_attr, g_sapp_cfg_check_attr, sizeof(g_sapp_cfg_check_attr));

	for(i = 0; i < (int)(sizeof(g_interger_range_array)/sizeof(int)); i++){
		g_interger_range_array[i] = i;
	}

	ret1 = sapp_config_check_missing_and_unsupport(local_cfg_check_attr);
	if(ret1 != 0){
		final_ret = SAPP_MAX(ret1, final_ret);
		goto done;			
	}

	ret2 = sapp_config_check_single_validity(local_cfg_check_attr);		
	if(ret2 != 0){
		final_ret = SAPP_MAX(ret2, final_ret);
		goto done;			
	}

	sapp_config_check_sanity(local_cfg_check_attr);
	final_ret = SAPP_MAX(ret2, final_ret);
done:

	if(final_ret != 0){
		//printf("\033[1;31;40msapp config check fail!\033[0m\n");
		sapp_printf_colorful(final_ret, "You should use './sapp -e filename' to generate the latest sample configuration file.\n");
	}else{
		printf("\033[32msapp config check success!\033[0m\n");
	}

	sapp_mem_free(SAPP_MEM_FIX_GLOBAL_VAL, MEM_STAT_GLOBAL_THREAD_ID,local_cfg_check_attr);

	return final_ret;
}



void sapp_log_handle_destroy(void)
{
	MESA_destroy_runtime_log_handle(sapp_global_val->individual_fixed.log_handle);
	sapp_global_val->individual_fixed.log_handle = NULL;

	MESA_destroy_runtime_log_handle(sapp_global_val->individual_fixed.plugin_log_handle);
	sapp_global_val->individual_fixed.plugin_log_handle = NULL;

	MESA_destroy_runtime_log_handle( sapp_global_val->individual_fixed.process_latency_log_handle);
	sapp_global_val->individual_fixed.process_latency_log_handle = NULL;
}


/* init breakpad_mini */
void sapp_init_breakpad_mini(void)
{
#ifdef GIT_VERSION
	//__attribute__((__used__)) const char *sapp_git_ver = GIT_VERSION;
	const char *sapp_git_ver = GIT_VERSION;
#else
	 const char * sapp_git_ver = "sapp_version_unkonw";
#endif
	struct breakpad_instance * g_breakpad = breakpad_init(ABBR_CFG_FILE_MAIN_ENTRY, "BREAKPAD", sapp_global_val->individual_fixed.log_handle,  sapp_git_ver);
	if(g_breakpad == NULL){exit(-1);}
	sapp_global_val->individual_fixed.breakpad = g_breakpad;
	return;
}

void sapp_segv_generate()
{
	breakpad_segv_generate();
}



#ifdef __cplusplus
}
#endif


