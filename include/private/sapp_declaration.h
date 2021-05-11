#ifndef _SAPP_DECLARATION_H_
#define _SAPP_DECLARATION_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_private_api.h"


/* 因嵌套层次太多, 使用简称描述 */
#define ABBR_SAPP_LOG_LEVEL 	sapp_global_val->config.profiling.log.level
#define ABBR_SAPP_LOG_HANDLE 	sapp_global_val->individual_fixed.log_handle
#define ABBR_SAPP_TIMER_HANDLE	sapp_global_val->individual_fixed.sapp_timer_handle
#define ABBR_SAPP_START_TIME 	sapp_global_val->individual_fixed.sapp_start_time
#define ABBR_CURRENT_TIME 		sapp_global_val->individual_volatile->current_time
#define ABBR_CURRENT_TIME_MS 	sapp_global_val->individual_volatile->current_time_ms
#define ABBR_INJECT_RST_NUM 	sapp_global_val->config.stream.tcp.inject.rst_num
#define ABBR_INJECT_RST_SIGN 	sapp_global_val->config.stream.tcp.inject.rst_signature_enable
#define ABBR_INTERFACE_TYPE		sapp_global_val->config.packet_io.internal.interface.type_bin

#define ABBR_CFG_FILE_MAIN_ENTRY  		sapp_global_val->config.cfg_file_path.cfg_main_entry_absolute
#define ABBR_SAPP_LOG_CONF_FILE  		sapp_global_val->config.cfg_file_path.cfg_sapp_log_absolute
#define ABBR_PROJECT_LIST_CONF_FILE  	sapp_global_val->config.cfg_file_path.cfg_project_list_absolute
#define ABBR_PLUG_ENTRY_LIST_CONF_FILE  sapp_global_val->config.cfg_file_path.cfg_entry_list_absolute
#define ABBR_SEND_RAW_PKT_CONF_FILE  	sapp_global_val->config.cfg_file_path.cfg_file_send_raw_pkt_absolute
#define ABBR_VXLAN_SPORT_MAP_CONF_FILE	sapp_global_val->config.cfg_file_path.cfg_file_vxlan_sport_map_absolute
#define ABBR_INLINE_DEV_CONF_FILE		sapp_global_val->config.cfg_file_path.cfg_file_inline_dev_absolute
#define ABBR_NECESSARY_PLUG_CONF_FILE	sapp_global_val->config.cfg_file_path.cfg_file_necessary_plug_absolute
#define ABBR_STREAM_CMP_LAYER_CONF_FILE	sapp_global_val->config.cfg_file_path.cfg_file_stream_compare_layer_absolute
#define ABBR_VLAN_FLIPPING_CONF_FILE	sapp_global_val->config.cfg_file_path.cfg_file_vlan_flipping_absolute
#define ABBR_ASYM_LAYER_ADDR_CONF_FILE	sapp_global_val->config.cfg_file_path.cfg_file_asymmetric_addr_layer_absolute


#define ABBR_SYSINFO_LOG_DATA_FILE		sapp_global_val->config.data_file_path.data_sapp_sysinfo_log_absolute
#define ABBR_FS2_LOG_DATA_FILE			sapp_global_val->config.data_file_path.data_sapp_fs2_log_absolute
#define ABBR_INLINE_KEEPALIVE_LOG_DATA_FILE  sapp_global_val->config.data_file_path.data_inline_keepalive_log_absolute


extern sapp_global_t *sapp_global_val;

/* 将之前分散的全局变量强制更新为新的全局变量 */
#define g_CurrentTime 			sapp_global_val->individual_volatile->current_time
#define g_sapp_log_handle		sapp_global_val->individual_fixed.log_handle
#define g_iThreadNum			sapp_global_val->config.cpu.worker_threads
#define g_packet_io_thread_num  sapp_global_val->config.cpu.worker_threads
#define max_udp_stream_num		sapp_global_val->config.stream.udp.max
#define max_tcp_stream_num		sapp_global_val->config.stream.tcp.max
#define create_link_mode		sapp_global_val->individual_fixed.create_stream_mode
#define g_iMaxRandVal			sapp_global_val->config.stream.tcp.inject.rst_signature_seed1
#define g_iRandKey				sapp_global_val->config.stream.tcp.inject.rst_signature_seed2
#define tcp_default_unorder		sapp_global_val->config.stream.tcp.reorder_pkt_max
#define tcp_creatlink_model		sapp_global_val->individual_fixed.create_stream_mode
#define link_default_nopkt_time	sapp_global_val->config.stream.tcp.timeout
#define udp_reset_time			sapp_global_val->config.stream.udp.timeout
#define g_topology_mode			sapp_global_val->individual_fixed.depolyment_mode_private
#define g_topology_mode_raw		sapp_global_val->config.packet_io.depolyment_mode_bin
#define g_packet_io_cap_mode 	sapp_global_val->config.packet_io.internal.interface.type_bin
#define g_packet_io_cap_level	sapp_global_val->individual_fixed.packet_io_cap_level
#define g_timestamp_record_sw	sapp_global_val->config.profiling.pkt_latency_enabled
#define g_discard_ack_sw		sapp_global_val->config.protocol_feature.tcp_drop_pure_ack_pkt
#define g_tcp_syn_option_parse_enabled	sapp_global_val->config.protocol_feature.tcp_syn_option_parse_enabled
#define g_ipv6_decapsulation_enabled  sapp_global_val->config.protocol_feature.ipv6_decapsulation_enabled
#define g_ipv6_send_packet_enabled    sapp_global_val->config.protocol_feature.ipv6_send_packet_enabled
#define G_SKIP_NOT_IP_LAYER 	sapp_global_val->config.protocol_feature.skip_not_ip_layer_over_eth
#define G_DICTATOR_SW			sapp_global_val->config.mem.dictator_enable

#define sapp_runtime_log(log_level, format, args...)  do{if(log_level>=ABBR_SAPP_LOG_LEVEL){MESA_handle_runtime_log(ABBR_SAPP_LOG_HANDLE, log_level, "sapp", format, ##args);}}while(0)

extern void sapp_log(int level, int print_sw, int file_sw, const char *format, ...);

int sapp_parse_cmd_args(int argc, char *argv[]);
int sapp_parse_config(void);
void sapp_init_breakpad_mini(void);
void sapp_segv_generate(void);
void sapp_generate_example_config(const char *filename);
void sapp_cla_override_cfg_file(void);
void sapp_global_val_sanity_check(void);
void *sapp_time_event_thread(void *arg);
void sapp_fs2_update_count(int field_index, unsigned  long long value);
void sapp_fs2_update_length(int field_index, unsigned  long long value);
void sapp_fs2_set_latency(int thead_seq, long long time_cost);
void sapp_gval_init(void);
struct mr_instance *sapp_get_marsio_instance(void);
int __sapp_timer_platform_init(void);
void __st_pkt_proc_context_check_timeout(int tid);
void __sapp_timer_platform_run(void);
void sapp_set_current_state(enum sapp_state_t st);
void line_protocol_update_metrics(void);
char *timet_to_str(time_t timet, char *time_str, int time_str_len);


extern volatile unsigned int  g_aiSysCounter[COUNTER_NUM]; /*newly modified   ---LiLei*/
extern const struct dl_io_lib_name g_dl_io_lib_info[__CAP_MODEL_MAX];
extern dl_io_fun_list_t dl_io_fun_list;

#ifdef __cplusplus
}
#endif


#endif

