#ifndef __GTEST_SAPP_FUN_H_
#define __GTEST_SAPP_FUN_H_ 1

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/limits.h>
#include <pcap/pcap.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include "MESA_jump_layer.h"

/*
	说明:
		为了方便测试sapp的某些功�?不得已引用了一些private级别的头文件,
		但是如果sapp的头文件更新�? 但此模块没同步更�? 导致结构体不一�? 可能会测试不通过.
*/

#include "sapp_limits.h"

#ifndef SAPP_SUPPORT_LAYER_NUM_MAX
#define SAPP_SUPPORT_LAYER_NUM_MAX (15)
#endif

#ifndef SAPP_MAX_PLUG_ENTRY_NUM
#define SAPP_MAX_PLUG_ENTRY_NUM (256)
#endif

#include "stream.h"
#include "packet_io.h"
#include "sapp_cla_private.h"
//#include "sapp_global_val.h"
#include "mesa_net.h"
#include "MESA_handle_logger.h"

#define GTEST_SAPP_COMM_MODE		(2) /* 1:unix domain socket;  2:udp socket */
#define UNIX_SOCKET_NAME  			"/tmp/gtest_sapp_unix_sd"
#define UDP_SERVER_BIND_PORT		(65432)

#define GTEST_SAPP_LOG_FILE			"./gtest_sapp.log" 

#define GTEST_HYBRID_STREAM_LOG_FILE	"./gtest_sapp_hybrid_stream.log"


#define GTEST_DEV_MTU				(2000)
#define GTEST_VXLAN_HDR_LEN			(8)

#define GTEST_SAPP_ERR					(0x0EEEEEEE) /* 检测错误返回�?*/
#define GTEST_SAPP_SUCC					(0x01234567) /* sapp插件检测正确返回�?*/
#define GTEST_INLINE_TO_SAPP_SUCC		(0x07654321) /* inline模式下TAP模拟外部设备检测正确返回�?*/
#define GTEST_TRANSPARENT_TO_SAPP_SUCC	(0x00ABCDEF) /* 双臂模式下TAP模拟外部设备检测正确返回�?*/
#define GTEST_FAKE_MARSIO_SUCC			(0x0FEFEFE0) /* fake marsio模式检测正确返回�?*/
#define GTEST_SAPP_ERR_SKIP				(0x534B4950U) /* 因sapp的内部结构体变化, 无法测试, 跳过此用例的返回�? 即字符SKIP的十六进�?*/
#define GTEST_RESULT_NONE				(0x4E4F4E45) /* "NONE"�?6进制, 不发送或者表示无任何意义的返回�?*/

#define BENCHMARK_PCAP_ROOT_DIR "../benchmark_pcap"

#define GINJECT_TEST_PAYLOAD "abcdefghijklmnopqrstuvwxyz-1234567890-!@#$%^&*()"

#define GTEST_TAP_UP_DEV_NAME	"tap_sapp_up"
#define GTEST_TAP_DOWN_DEV_NAME	"tap_sapp_down"


#define GTEST_INLINE_PROG_NAME 		"./inline_test_sapp_v4"
#define GTEST_TRANSPARENT_PROG_NAME "./transparent_test_sapp_v4"


#define SAPP_GTEST_LOG(level, module, fmt, args...)		do{MESA_handle_runtime_log(g_sapp_test_log_handle, level, module, fmt, ##args);}while(0)

/* 用于sapp插件上下文空�? 有可能是被fork之后调用sapp, 跟gtest_main函数不在同一个进程里 */
#define SAPP_PLUG_LOG(level, module, fmt, args...)		do{MESA_handle_runtime_log(g_sapp_plug_log_handle, level, module, fmt, ##args);}while(0)


extern void *g_sapp_test_log_handle;
extern void *g_sapp_plug_log_handle;
extern int g_slient_mode;

typedef struct{
	UINT32 C2S_all_pkt; /* All tcp packets, include SYN, ACK, FIN, RST, etc. */
	UINT32 C2S_data_pkt;	/* TCP reassemble packet, payload size more than zero, no retransmit packet */
	UINT32 S2C_all_pkt;
	UINT32 S2C_data_pkt;
	UINT64 C2S_all_byte;	/* All tcp packet's data size, include retransmit packet */
	UINT64 C2S_data_byte;	
	UINT64 S2C_all_byte;
	UINT64 S2C_data_byte;
	UINT64 C2S_lost_byte; /* TCP total lost bytes, cumulation */
	UINT64 S2C_lost_byte; /* TCP total lost bytes, cumulation */
}gtest_plug_stat_t;

#if 0
struct mesa_pppoe_session_hdr{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int ver:4;   
	unsigned int type:4;  
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int type:4; 
	unsigned int ver:4; 
#else
#error "Please check <endian.h>"
#endif
  	unsigned char code;
	unsigned short session_id;
	unsigned short len;
	unsigned short ppp_protocol; 
}__attribute__((packed, aligned(1)));



#define MPLS_LABEL_MASK	(0xFFFFF000)
#define MPLS_EXP_MASK		(0x00000E00)
#define MPLS_BLS_MASK	(0x00000100)
#define MPLS_TTL_MASK		(0x000000FF)
struct mesa_mpls_hdr{
#if __BYTE_ORDER == __LITTLE_ENDIAN 
	unsigned char mpls_label_low;
	unsigned char mpls_label_mid;
	unsigned char mpls_bls:1;	/* bottom of label stack */
	unsigned char mpls_exp:3;
	unsigned char mpls_label_high:4;
	unsigned char mpls_ttl;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned char mpls_ttl;
	unsigned char mpls_label_high:4;
	unsigned char mpls_exp:3;
	unsigned char mpls_bls:1;	/* bottom of label stack */
	unsigned short mpls_label_low;
#else
#error "Please check <endian.h>"
#endif
};

struct mesa_vlan_hdr{
	unsigned short pri_cfi_id;
	unsigned short type;
};
#endif

enum gtest_inject_type{
	GINJECT_TYPE_IPV4 = 0x10,
	GINJECT_TYPE_IPV6 = 0x20,
	GINJECT_TYPE_TCP  = 0x40,
	GINJECT_TYPE_UDP  = 0x80,
	GINJECT_TCP_PAYLOAD = GINJECT_TYPE_TCP|0x01,
	GINJECT_TCP_RST 	= GINJECT_TYPE_TCP|0x02,
	GINJECT_TCP_SYNACK = GINJECT_TYPE_TCP|0x03,
	GINJECT_UDP_PAYLOAD = GINJECT_TYPE_UDP|0x01,
};

/* 用于指定哪些pcap�? 对应哪些检测函�?*/
typedef struct {
	const char *pcap_file_md5;
	unsigned int default_check_result;
	void (*pcap_callback)(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data);	
	const char *description;
}pcap_md5_tuple_t;

typedef struct {
	const char *pcap_file_md5;
	const char *keepalive_ip; /* inline 回流 保活ip */
	int inject_reverse; /* 注入包是否反�?*/
	int inject_pkt_trigger_threshold; /* inject超过几个包发送成功结�?*/ 
	unsigned int default_check_result;
	void (*pcap_callback)(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data);	
	const char *description;
}inline_mode_pcap_md5_tuple_t;


/********************************** common  ***********************************/
int gtest_file_md5sum(const char *filename, char *md5sum_result, int result_len);
int directory_md5_checksum(const char *dir_name, const char *expect_md5sum);
unsigned long gtest_get_file_length(const char *file_name);
int gtest_if_file_exist(const char *file_name);

int update_config_file(const char *filename, const char *param, const char *value);
int update_config_file_by_lastline(const char *filename, const char *lastline, const char *param, const char *value);
int update_config_file_by_lastNline(const char *filename, const char *lastline, int N, const char *param, const char *value);

void update_conflist_inf(const char *plug_inf_path);
void append_conflist_inf(const char *plug_inf_path);
void insert_into_conflist_inf(const char *module, const char *plug_inf_path);
int update_protocol_plugin_inf(const char *filepath, const char *plugname, const char *init_fun_name, 
    const char *get_plugid_fun, const char *flag_change_fun, const char *flagstate_fun, 
	const char *entry_name, const char *fun_name);
void set_default_asymmetric_addr_layer_conf(const char *);
void set_default_asymmetric_presence_layer_conf(const char *);
void set_default_stream_compare_layer_conf(const char *config_value);
void set_default_vlan_flipping_conf(const char *config_value);

int update_plugin_inf_with_options(const char *filepath, const char *plug_name, const char *init_fun_name, const char *destroy_fun, const char *entry_name, const char *fun_name);
int update_plugin_inf(const char *entry_name, const char *fun_name);
int append_plugin_inf(const char *entry_name, const char *fun_name);
void set_pcap_dumpfile(const char *filename);
int file_md5_checksum(const char *filename, const char *expect_md5sum);
void set_default_config(void);
int sendto_test_result(int res);
void gtest_sapp_sleep(int sleep_time, const char *tips);
int set_project_list_conf_default(void);
int append_project_list_conf(const char *name, const char *type);
int check_test_result(void);
int gtest_get_timeout_default_result();
void gtest_sig_handler(int signum);
int gtest_sapp_master_init(void);
void gtest_start_sapp_progress(const char *argv[]);
void gtest_start_inline_env_progress(const char *prog_name, const char *pcap_filename, int timeout);
void gtest_start_transparent_env_progress(const char *prog_name, const char *pcap_filename);
int get_file_md5sum(const char *filename, char *md5sum_result);
ssize_t recv_with_timeout(int sockfd, void *buf, size_t len, int time_ms);
char *gtest_timet_to_str(time_t timet, char *time_str, int time_str_len);
int gtest_set_timeout_default_result(int res_value);
int pcap_replay_route_dir(const void *raw_eth_data);

void call_libsapp_devel_with_args(int argc, const char *argv[]);
void start_run_stop_libsapp(int sleep_seconds);

int gtest_set_libsapp_devel_result(int res_value);
int gtest_get_libsapp_devel_result(void);
int ifconfig_device_up(const char *interface_name);
void call_libsapp_devel_for_dumpfile_topspeed(void);
void call_libsapp_devel_for_dumpfile_timestamp(void);
void call_libsapp_devel_online_mode(void);
void gtest_exec_printf(const char *fmt, ...);
void gtest_plug_printf(const char *fmt, ...);


extern "C" void sapp_printf(const char *fmt, ...); /* 在插件的上下文调�?*/
extern "C" int gtest_sapp_slave_init(void);
/*********************************** tcp **************************************/
void tcp_simple_run(void);
void tcpall_simple_run(void);
void tcp_oos_run(void);
void tcp_oos_lost_pkt_run(void);
void tcp_timeout_reset_run(void);
void tcp_deduce_flow_stat_run(void);
void tcp_call_order_check_run(void);
void tcp_call_order_for_reset_check_run(void);
int tcp_plug_has_high_priority(void);
void tcp_tuple4_reuse_with_fin_run(void);
void tcpall_tuple4_reuse_with_fin_run(void);
void tcp_tuple4_reuse_no_close_run(void);
void tcp_overlap_run(void);
void tcp_retransmit_run(void);


void MESA_rst_tcp_test_v4_run(void);
void MESA_kill_tcp_test_v4_run(void);
void MESA_rst_tcp_test_v6_run(void);
void MESA_rst_tcp_with_vlan_single_c2s_run(void);
void MESA_rst_tcp_with_vlan_pppoe_run(void);
void MESA_rst_tcp_with_mpls_1vs2_run(void);
void MESA_rst_tcp_with_mpls_0vs2_run(void);
void MESA_rst_tcp_with_mpls_single_c2s_run(void);
void MESA_rst_tcp_with_vpls_run(void);
void MESA_rst_tcp_with_double_vlan_run(void);
void MESA_rst_tcp_with_8021ad_qinq_run(void);
void MESA_rst_tcp_mpls_vlan_mpls_c2s_run(void);
void tcp_plug_killother_run(void);
void MESA_inject_tcp_payload_test_v4_run(void);
void sapp_inject_tcp_payload_test_v4_run(void);
void MESA_inject_udp_mpls_vlan_mpls_s2c_run(void);
void sapp_inject_tcp_mpls_vlan_mpls_asymmetric_double_run(void);
void MESA_rst_tcp_reverse_ethernet_run(void);
void sapp_inject_l2tp_double_dir_run(void);
void sapp_inject_l2tp_ppp_compress_double_dir_run(void);
void sapp_inject_4over6_layer_run(void);
void sapp_inject_4over6_exclude_layer_run(void);
void sapp_inject_6over4_layer_run(void);
void sapp_inject_6over4_exclude_layer_run(void);


void sapp_inject_gtp_single_reverse_asymmetric_run(void);
void sapp_inject_gtp_single_reverse_not_asymmetric_run(void);
void sapp_inject_gtp_seq_single_reverse_not_asymmetric_run(void);
void sapp_inject_gtp_double_dir_run(void);
void sapp_inject_gtp_payload_double_dir_run(void);
void sapp_inject_gtp_raw_ip_pkt_double_dir_run(void);
void MESA_rst_tcp_pure_ipv4_with_fake_mpls_run(void);
void tcp_lost_pkt_run(void);
void tcp_lost_pkt_manual_run(void);
void tcp_raw_entry_run(void);
void tcp_dumpfile_list_run(void);
void tcp_dup_pkt_identify_run(void);
void tcp_dropstream_and_unorder_run(void);
void tcp_well_known_port_run_v4(void);
void tcp_not_use_well_known_port_run_v4(void);
void tcp_well_known_port_run_v6(void);
void tcp_first_unorder_rawpkt_run(void);
void gtp_with_seq_no_ext_tcp_run(void);
void gtp_with_seq_and_ext_tcp_run(void);
void gtp_without_seq_and_ext_tcp_run(void);

void tcpall_offload_givestate_entry_run(void);
void tcpall_offload_givestate_and_giveme_entry_run(void);

void tcp_offload_givestate_entry_run(void);
void tcp_offload_givestate_and_giveme_entry_run(void);


/*********************************** udp **************************************/
void udp_simple_run(void);
void udp_link_c2s_1pkt_run(void);
void udp_link_c2s_10pkt_run(void);
void udp_link_s2c_1pkt_run(void);
void udp_link_s2c_10pkt_run(void);
void udp_dup_pkt_identify_run(void);
void cheat_l2tp_dup_dns_run(void);
void cheat_gtp_dup_dns_run(void);
void udp_well_known_port_run_v4(void);
void udp_well_known_port_run_v6(void);
void udp_tuple4_reuse_test(void);
void udp_givestate_entry_offload_run(void);
void udp__givestate_and_giveme_entry_offload_run(void);


/*********************************** ipv4 **************************************/
void ipv4_frag_assemble_simple_run(void);
void ipv4_frag_assemble_checksum_run(void);
void ipv4_frag_assemble_oos_run(void);
void ipv4_frag_udp_assemble_run(void);


/*********************************** ipv6 **************************************/
void ipv6_frag_assemble_simple_run(void);
void ipv6_frag_assemble_oos_run(void);
void ipv6_frag_udp_assemble_run(void);

/****************************** stream_control.h API **************************/
void control_max_unorder_run(void);
void control_tcp_need_ack_run(void);
void control_takeover_run(void);
void control_timeout_run(void);
void control_tcp_isn_c2s_run(void);
void control_tcp_isn_s2c_run(void);
void control_tcp_option_run(void);
void control_tunnel_type_6over4_run(void);
void control_tunnel_type_gre_run(void);
void control_tunnel_type_teredo_run(void);
void control_tunnel_type_l2tp_run(void);
void control_tunnel_type_pptp_run(void);
void control_tunnel_type_gtp_run(void);
void control_stream_and_traffic_run(void);
void control_get_root_dir_run(void);

void global_stream_id_run(void);
void global_stream_id_tuple4_reuse_run(void);
void stream_creattime_tuple4_reuse_run(void);

void control_platform_opt_run(void);
void control_get_tcp_streamid_run(void);
void control_get_udp_streamid_run(void);
void control_stream_create_timestamp_ms_run(void);
void control_up_layer_tunnel_gtp_run(void);
void control_up_layer_tunnel_l2tp_run(void);
void control_up_layer_tunnel_teredo_run(void);
void control_get_plug_pme_run(void);
void control_plug_necessary_run(void);
void control_plug_necessary_run_no_inf(void);
void control_plug_necessary_run_no_sofile(void);
void control_plug_dup_pkt_tcp_run(void);
void control_plug_dup_pkt_udp_run(void);
void find_streaminfo_v4_run(void);
void find_streaminfo_v6_run(void);
void find_streaminfo_diff_tunnel_v4_run(void);

void inline_get_tcp_flow_stat_run(void);
void inline_get_udp_flow_stat_run(void);
void control_fork_listen_port_run(void);
void toml_array_parse_run(void);
void get_linkdir_from_mac_run(void);
void get_linkdir_from_mac_run2(void);

void get_deployment_mode_mirror(void);
void get_deployment_mode_inline(void);
void get_deployment_mode_transparent(void);
void control_get_ip_ttl_run(void);
void control_get_tcp_rtt_run(void);
void control_get_tcp_rtt_c2s_run(void);
void control_get_tcp_rtt_s2c_run(void);
/****************************** tunnel **************************/
void teredo_unstandard_port_run(void);
void teredo_with_auth_hdr_run(void);
void gtp_identify_run(void);
void gtp_mpls_identify_run(void);
void gtp_diff_outer_tuple4_run(void);
void gtp_diff_outer_tuple4_track_gtp_teid_run(void);
void gtp_diff_outer_tuple4_track_gtp_teid_s2c_run(void);
void pptp_identify_run(void);
void l2tp_identify_run(void);
void l2tp_without_ppp_control_field_identify_run(void);

void teredo_identify_run(void);
void pptp_and_4over6_identify_run(void);
void t6over4_identify_run(void);
void tcp_same_tuple4_diff_mpls_one_stream_run(void);
void tcp_same_tuple4_diff_mpls_two_stream_run(void);
void mpls_asymmetric_1vs2_run(void);
void vlan_2layer_run(void);
void vlan_asymmetric_merge_run(void);

void pcap_no_mpls_tcp_run(void);
void l2tp_tunnel_pfather_iterate_run(void);
void pptp_tunnel_pfather_iterate_run(void);
void mpls_empty_run(void);
void l2tp_protocol_timeout_run(void);


/****************************** app state **************************/
void app_state_kill_follow_head_pending_run(void);
void app_state_kill_follow_head_pending_dropme_run(void);
void app_state_kill_follow_middle_pending_run(void);
void app_state_kill_follow_tail_pending_run(void);
void app_state_kill_follow_head_data_run(void);
void app_state_kill_follow_head_data_dropme_run(void);

void app_state_kill_follow_middle_data_run(void);
void app_state_kill_follow_tail_data_run(void);

void app_state_kill_other_head_pending_run(void);
void app_state_kill_other_middle_pending_run(void);
void app_state_kill_other_tail_pending_run(void);
void app_state_kill_other_tail_pending_dropme_run(void);

void app_state_kill_other_head_data_run(void);
void app_state_kill_other_middle_data_run(void);
void app_state_kill_other_tail_data_run(void);
void app_state_kill_follow_ip_entry_run(void);

/***************************** plug ctrl **************************/
void plug_ctrl_simple_run(void);
void plug_ctrl_flag_change_run(void);
void plug_ctrl_3state_pdc_run(void);
void plug_ctrl_2state_pd_dc_run(void);
void plug_ctrl_state_pd_d_dc_run(void);
void plug_ctrl_biz_dropme_in_pending_run(void);
void plug_ctrl_biz_dropme_in_data_run(void);
void plug_ctrl_biz_dropme_in_close_run(void);
void plug_ctrl_biz_giveme_in_close_run(void);
void special_plug_wire_graft_test(void);



/***************************** jump_layer **************************/

void jump_layer_eth_ipv4_tcp_run(void);
void jump_layer_eth_ipv4_udp_run(void);
void jump_layer_eth_ipv6_tcp_run(void);
void jump_layer_eth_ipv6_udp_run(void);
void jump_layer_eth_ipv4_pptp_ipv4_tcp_run(void);
void jump_layer_eth_ipv4_gtp_ipv4_tcp_run(void);
void jump_layer_eth_ip4_l2tp_ip4_tcp_run(void);
void jump_layer_eth_ip4_l2tp_ip4_udp_run(void);
void jump_layer_eth_ip4_l2tp_ppp_compress_ip4_udp_run(void);
void jump_layer_eth_ipv4_gre_ipv4_gre_ipv4_dns_run(void);
void jump_layer_eth_vlan_ip6_ip4_pptp_ip4_ip6_tcp_run(void);
void jump_layer_eth_ip4_udp_teredo_udp_ip6_udp_run(void);
void jump_layer_eth_ip4_udp_teredo_udp_ip6_tcp_run(void);
void jump_layer_eth_vlan_ip6_udp_gtpext_ip4_tcp_run(void);


/***************************** inline test **************************/
void inline_vxlan_header_run(void);
void inline_flow_forward_simple_run(void);
void inline_tcp_simple_run(void);
void inline_inject_rst_c2s_trigger_by_c2s_pkt_run(void);
void inline_inject_rst_s2c_trigger_by_s2c_pkt_run(void);
void inline_inject_rst_s2c_trigger_by_c2s_pkt_run(void);
void inline_inject_rst_c2s_trigger_by_s2c_pkt_run(void);
void inline_inject_payload_s2c_trigger_by_c2s_ipv6_run(void);

void inline_ip_plug_entry_not_call_run(void);
void inline_udp_plug_entry_not_call_run(void);
void inline_udp_plug_drop_entry_run(void);
void inline_layer_addr_ntop_run(void);
void inline_stream_addr_ntop_run(void);
void inline_stream_pfather_run(void);
void inline_plug_stat_run(void);
void inline_polling_timeout_tcp_run(void);
void inline_polling_timeout_tcpall_run(void);
void inline_polling_timeout_udp_run(void);
void inline_asymmetric_vxlan_addr_run(void);
void inline_cheat_dup_tcp_run(void);
void inline_dup_inject_ipv4_tcp_run(void);
void inline_dup_inject_ipv6_tcp_run(void);
void inline_dup_inject_ipv4_udp_run(void);
void inline_dup_inject_ipv6_udp_run(void);
void inline_ssdp_run(void);
void inline_nbns_run(void);
void inline_get_rawpkt_data_run(void);
void inline_raw_ip_frag_list_run(void);
void inline_vxlan_info_run(void);
void inline_grev0_inject_reverse_run(void);
void inline_inner_hdlc_run(void);
void inline_inject_rst_inner_hdlc_run(void);
void inline_inner_ppp_run(void);
void inline_inject_rst_inner_ppp_run(void);




/************************** transparent test ************************/

void transparent_network_env_init(void);
void transparent_arp_forward_run(void);
void transparent_tcp_simple_run(void);
void transparent_drop_and_rst_c2s_trigger_by_c2s_run(void);
void transparent_drop_and_rst_s2c_trigger_by_c2s_run(void);
void transparent_drop_and_inject_c2s_trigger_by_c2s_run(void);
void transparent_drop_and_inject_c2s_trigger_by_s2c_run(void);
void control_drop_current_tcp_pkt_run(void);
void control_drop_current_udp_pkt_run(void);


void project_simple_run(void);

void sapp_perf_test_run(void);
void stream_bridge_test_run(void);



void hybrid_pure_tcp_run(void);
void hybrid_pure_udp_run(void);
void hybrid_dataset_run(void);


void asymmetric_mpls_c2s_run(void);
void asymmetric_mpls_s2c_run(void);
void asymmetric_vlan_c2s_run(void);
void asymmetric_vlan_s2c_run(void);
void asymmetric_mpls_and_vlan_run(void);




void timer_simple_run(void);
int wait_for_sapp_running(void);
int tuntap_dev_create(char *dev, int flags);
pcap_t *pcap_dumpfile_init(const char *pcap_filename);


/****************************  common function   *************************************/
int check_ethernet_pkt_equal(const struct ethhdr *ethdr1, const struct ethhdr *ethdr2, int reverse);
int check_ip_pkt_equal(const struct ip *iphdr1, const struct ip *iphdr2, int reverse_dir, int check_length);
int check_ipv6_pkt_equal(const struct ip6_hdr *iphdr1, const struct ip6_hdr *iphdr2, int reverse_dir, int check_length);

int check_udp_pkt_equal(const struct udphdr *udphdr1, const struct udphdr *udphdr2, int reverse_dir, int check_length);
int check_tcp_pkt_equal(const struct mesa_tcp_hdr *raw_hdr, const struct mesa_tcp_hdr *snd_hdr, unsigned char flags,
				unsigned int seq_net_order, unsigned int ack_net_order, int reverse_dir);
int check_mpls_pkt_equal(const struct mesa_mpls_hdr *mhdr1, const struct mesa_mpls_hdr *mhdr2);

int sapp_set_mpls_addr(struct layer_addr_mpls *addr, const unsigned char *raw_mpls_pkt_data);
int expect_file_has_some_string(const char *filename, const char *expect_string);


/****************************  fake marsio	 *************************************/
void fake_marsio_vlan_flipping_run(void);
void fake_marsio_vlan_flipp_and_mac_flip_run(void);
void fake_marsio_vlan_flipp_and_symmetric_mpls0vs1_run(void);
void fake_marsio_vlan_flipp_and_symmetric_mpls1vs2_run(void);
void fake_marsio_vlan_mac_flipping_inject_run(int is_asymmetric);


/****************************  proxy *************************************/
void sapp_deal_proxy_run(void);
void sapp_deal_proxy_kill_tcp_run(void);


/****************************  pkt_dump *************************************/
int test_pkt_dump_run(void);


void append_entry_list(const char *entryname);
int check_sapp_version(void);

extern "C" int sendpacket_do_checksum(unsigned char *buf, int protocol, int len);

extern "C" int gtest_sapp_slave_init(void);
extern "C" int sapp_size_of_sapp_global(void);
extern "C" int sapp_size_of_streaminfo_private(void);
extern "C" int sapp_size_of_tcpdetail_private(void);
extern "C" int sapp_size_of_udpdetail_private(void);
extern "C" int sapp_size_of_raw_pkt_t(void);
extern "C" const void *MESA_net_jump_to_layer(const void *raw_data,  int raw_layer_type, int expect_layer_type);
extern const char *sapp_start_args[3];
extern const char *sapp_inline_start_args[2];
extern const char *sapp_transparent_start_args[2];
extern const char *sapp_online_start_args[2];
#endif

