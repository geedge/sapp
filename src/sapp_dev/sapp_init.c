#include "sapp_api.h"
#include "sapp_private_api.h"
#include "sapp_declaration.h"

/* Systemd */
#include <systemd/sd-daemon.h>

#ifdef __cplusplus
extern "C" {
#endif

//static int threadnum = 1;
static volatile long stream_num = 0;
//int g_iThreadNum = 1;
//time_t g_CurrentTime;//add by lqy 20070606
extern int sapp_args_v;
int ipv4_frag_init(int thread_count, unsigned int hash_size);
int ipv6_frag_init(int thread_count, unsigned hash_size);
int project_requirement_global_init(void);
int packet_io_set_cap_level(int cap_level);
int plugctrl_proc(void);
int runtime_log_init(char * file, int level);
int iknow_info_init(void);
extern void sesame_open_door(const char *lock_path, const char *lock_name);
/* (0:pag,1:pcap,2:dumpfile,3:pfring,4:DPDK,5:ppf,6:NPacket,7:qnf,8:N95,9:pcap-dumpfile-list, 10:topsec) */
//int cap_mode = 2;
//int top_mode = 0;
extern struct global_stream **G_MESA_GLOBAL_STREAM;
extern long long g_timedelay_threshold;
extern int g_use_MESA_sleep_sw;
extern int g_raw_pkt_broken_check;
extern int g_skip_ethernet_layer_sw;
//extern int g_kill_tcp_remedy_sw;
extern int g_encapsulate_with_ddp;
extern int g_encapsulate_with_L2E; /* ʹ��DDPЭ���װ��x27ԭʼIP�� */

extern int g_PollingFunNum;
extern int packet_io_set_ipv6_raw_socket_enable(int op_switch);
extern const char *stream_addr_list_ntop_outward(const struct streaminfo *pstream);
extern const char *stream_addr_list_ntop_inward(const struct streaminfo *pstream);
extern const struct streaminfo *stream_addr_list_pton_outward(const char *addr_list_str, int thread_index);
extern const struct streaminfo *stream_addr_list_pton_inward(const char *addr_list_str, int thread_index);
extern int cycle_pkt_dump_init(int argc, char *argv[]);
extern char udp_teredo_identify_entry(const struct streaminfo *pstream, const void *this_hdr, const void *raw_pkt, void **pme);
extern char udp_gtp_identify_entry(const struct streaminfo *pstream, const void *this_hdr, const void *raw_pkt, void **pme);
extern char udp_l2tp_identify_entry(const struct streaminfo *a_udp,void **pme, int thread_seq, const void *a_packet);
extern char isakmp_protocol_entry(const struct streaminfo *a_udp,  void **pme, int thread_seq,const void *ip_hdr);
extern int stream_register_udp_raw(SAPP_STREAM_FUN_T x);
extern int number_is_2powerN(uint n);
extern int symbol_check(void);
extern int timestamp_record_init(void);
extern  int sapp_global_val_init(void);
extern int sapp_assistant_init(void);
extern char gdev_keepalive_ip_entry(const struct streaminfo *pstream,unsigned char routedir,int thread_seq, const struct mesa_ip4_hdr *ipv4_hdr);
extern char gdev_keepalive_udp_entry(const struct streaminfo *a_udp,  void **pme, int thread_seq, const void *ip_hdr);

extern volatile unsigned long g_sapp_destory_env_running_state;
extern volatile unsigned long g_sapp_destory_env_done_state;

static void sapp_platform_finish_up(void)
{
	/* 
		�½��ļ���: ./sapp_status/
		
		�����ע��ɹ���project tag �б�, project_list.status, 
		name, type

		
		������в���ļ�����Ϣ, �����ǳɹ����ǲ��ɹ�, Ҫ��ÿ��cat | grep runtime.log
		plug_load.status, plug_name, plug_path, state(succ,fail)

		
		���sapp״̬Ǩ�Ʊ仯��ʱ���¼, sapp_state.staus:
		start_time  	state
		01:00:00		just_start
		01:00:01		platform_init
		01:01:01		plugctrl_init
		02:01:01		processing
	*/
	return;
}

extern int stream_register_overlay_ip(IPv4_CB_FUN_T x);
extern int stream_register_overlay_udp(STREAM_CB_FUN_T x);
extern int gdev_keepalive_plug_init(void);

int MESA_platform_init(int argc, char *argv[])
{
	int ipv6_switch = 0;
	char cap_filter[1024] = {};
	char gateway_mac[32] = {};
	int TcpAllEnable = 0;
	int load_plug_sw = 1;
	unsigned short udp_stream_timeout = 300;
	unsigned short link_timeout = 600;
	int int_tmp;

	sapp_set_current_state(SAPP_STATE_PLATFORM_INITING);

	ABBR_CURRENT_TIME = time(NULL);
	ABBR_SAPP_START_TIME = time(NULL);

	ipv4_frag_init(g_iThreadNum, 1024 * 512);
	ipv6_frag_init(g_iThreadNum, 1024 * 256);
	tcp_set_stream_num(sapp_global_val->config.stream.tcp.max_opening,max_tcp_stream_num,sapp_global_val->config.stream.tcp.max_discard);
	udp_set_stream_num(sapp_global_val->config.stream.udp.max_opening,sapp_global_val->config.stream.udp.max_pair,sapp_global_val->config.stream.udp.max);

	MESA_load_profile_int_def("conf/main.conf","Module", "timedelay_threshold", &int_tmp, 10000000);
	g_timedelay_threshold = (long long)int_tmp;
	
	MESA_load_profile_int_def("conf/main.conf","Module", "use_MESAsleep", &g_use_MESA_sleep_sw, 0);	

	MESA_load_profile_int_def("conf/main.conf","Module", "encapsulate_with_ddp", &g_encapsulate_with_ddp, 0);	
	if(g_encapsulate_with_ddp != 0){
		sapp_printf("\033[32m[Notice] '%s' is enable!\033[0m\n", "encapsulate_with_ddp");
		sleep(1);		
	}	

	MESA_load_profile_int_def("conf/main.conf","Module", "encapsulate_with_L2E", &g_encapsulate_with_L2E, 0);	
	if(g_encapsulate_with_L2E != 0){
		sapp_printf("\033[32m[Notice] '%s' is enable!\033[0m\n", "encapsulate_with_L2E");
		sleep(1);		
	}	

	if((g_encapsulate_with_ddp != 0) && (g_encapsulate_with_L2E != 0)){
		sapp_printf("\033[1;31;40m[Error]g_encapsulate_with_ddp is conflict with g_encapsulate_with_L2E, can't enable simultaneously at all!\033[0m\n");
		return -1;
	}
	
	if(packet_io_lib_load(ABBR_INTERFACE_TYPE) < 0){
		return -1;
	}

	packet_io_set_work_thread_num(g_packet_io_thread_num);

	packet_io_set_cap_mode(ABBR_INTERFACE_TYPE);

	/* 
		(0:pag,1:pcap,2:dumpfile,3:pfring,4:DPDK,5:ppf,6:NPacket,7:qnf,8:N95,9:pcap-dumpfile-list, 10:topsec) 
		11:ipfile, 12:marsio4, 13:agent_smith, 14:dpdk_vxlan, 15:marsio_vxlan, 16:pag_marsio.
	*/
	switch(ABBR_INTERFACE_TYPE){
		case CAP_MODEL_PAG:
		case CAP_MODEL_PAG_MARSIO:
#if USE_PAG_GET_FRAME		
			packet_io_set_cap_level(CAP_LEVEL_MAC);
#else			
			packet_io_set_cap_level(CAP_LEVEL_IPV4);	
#endif			
		break;
		
		case CAP_MODEL_PPF:
		case CAP_MODEL_TOPSEC:
		case CAP_MODEL_IPFILE:
		case CAP_MODEL_TUN:
			packet_io_set_cap_level(CAP_LEVEL_IPV4);
			break;
			
		case CAP_MODEL_PCAP_ONLINE:
		case CAP_MODEL_PCAP_DUMPFILE:
		case CAP_MODEL_AGENT_SMITH:
#if PCAP_CAP_FROM_IP
			packet_io_set_cap_level(CAP_LEVEL_IPV4);
			break;			
#endif

		case CAP_MODEL_PFRING:
		case CAP_MODEL_DPDK:
		case CAP_MODEL_NPACKET:
		case CAP_MODEL_PCAP_DUMPLIST:
		case CAP_MODEL_MARSIOV4:
		case CAP_MODEL_DPDK_VXLAN:
		case CAP_MODEL_MARSIOV4_VXLAN:
			packet_io_set_cap_level(CAP_LEVEL_MAC);
			break;
		default:
			printf("Invalid cap_mode:%d\n", ABBR_INTERFACE_TYPE);
			exit(1);
	}


	packet_io_set_capdev_parallel(sapp_global_val->config.packet_io.internal.interface.name);
	
	if(DEPLOYMENT_MODE_TRANSPARENT == g_topology_mode_raw){
		packet_io_set_capdev_serial(sapp_global_val->config.packet_io.internal.interface.name, 
									sapp_global_val->config.packet_io.external.interface.name);
	}	

	packet_io_set_topology_mode(sapp_global_val->config.packet_io.deployment_mode_bin);
	
	if(sapp_global_val->config.packet_io.input_bpf_filter != NULL){
		printf("\033[33m[Warning] pcap filter is '%s'.\033[0m\n", sapp_global_val->config.packet_io.input_bpf_filter);
		packet_io_set_capture_filter(sapp_global_val->config.packet_io.input_bpf_filter);
	}

	packet_io_set_cap_buf_queue(10000);

	MESA_load_profile_int_def("conf/main.conf", "Module", "signal_take_over_switch", &sapp_global_single.signal_take_over_sw, 0);
	MESA_load_profile_int_def("conf/main.conf", "Module", "ipentry_priority_over_ipfrag", &sapp_global_single.ipentry_priority_over_ipfrag, 0);
	//MESA_load_profile_int_def("conf/main.conf", "Module", "tuple4_reuse_time_interval", &sapp_global_single.tuple4_reuse_time_interval, 3);

	init_stream_manage(g_iThreadNum);	
	timestamp_record_init();

	/* timer must before packet_io and plug_proc() */

	__sapp_timer_platform_init();
	
#if 1
	if(cycle_pkt_dump_init(argc , argv) < 0){
		return -1;
	}
#else
	int __pkt_dump_switch = 0;
	MESA_load_profile_int_def((char *)"conf/main.conf", (char *)"pkt_dump", (char *)"pkt_dump_switch", &__pkt_dump_switch, 0);
	if(__pkt_dump_switch != 0){
		printf("\n\033[33m[Warning] pkt_dump enable, but the platform is compiled without debug feature.\033[0m\n");
		printf("\033[33mIf you want pkt_dump function, please recompile platform use 'make debug=0'.\033[0m\n");
		printf("\033[33mOtherwise, please close 'pkt_dump_switch', or ignore this message.\033[0m\n");
		usleep(10000);
	}
#endif

	MESA_load_profile_int_def((char *)"conf/main.conf", (char *)"Module", (char *)"raw_pkt_broken_check", &g_raw_pkt_broken_check, 0);
	MESA_load_profile_int_def((char *)"conf/main.conf", (char *)"Module", (char *)"skip_ethernet_layer", &g_skip_ethernet_layer_sw, 0);
	//MESA_load_profile_int_def((char *)"conf/main.conf", (char *)"Module", (char *)"reverse_ethernet_addr", &g_reverse_ethernet_addr_sw, 0);


	/* ƽ̨���ù̶������Ĳ�� */
	stream_register_udp_raw(udp_teredo_identify_entry);
	//stream_register_udp_raw(udp_gtp_identify_entry);
	stream_register_udp(udp_l2tp_identify_entry);

	/* 2020-12-23 lijia add, vxlan���������� */
	if(DEPLOYMENT_MODE_INLINE == sapp_global_val->config.packet_io.deployment_mode_bin){
		stream_register_overlay_ip((IPv4_CB_FUN_T)gdev_keepalive_ip_entry);
		stream_register_overlay_udp(gdev_keepalive_udp_entry);

		if(gdev_keepalive_plug_init() < 0){
			printf("\033[1;31;40m[Error]gdev_keepalive_plug_init() error!\033[0m\n");
			return -1;
		}
	}

	MESA_load_profile_int_def((char *)"conf/main.conf", (char *)"Module", (char *)"symbol_conflict_check", &int_tmp,0);
	if(int_tmp != 0){
		/* NOTE: ���������һ��Ҫ��plugctrl_proc(), �����в������֮��, Ĭ�Ͽ��� */
		symbol_check(); /* 2016-01-13 Lijia add, ���ȫ�ַ�������ͻ */
	}
	sapp_global_val_sanity_check();

	if(g_PollingFunNum != 0){
		printf("\n\033[33m[Warning]There are %d plugs on [POLLING] entry, this will increase latency of packet process!\033[0m\n", g_PollingFunNum);
		usleep(10000);
	}

	MESA_load_profile_int_def((char *)"conf/main.conf", (char *)"Module", (char *)"send_tcp_offload", &sapp_global_single.cfg_send_tcp_offload_sw, 0);

	sapp_set_current_state(SAPP_STATE_PLATFORM_INITED);
	
	/* 2017-02-24 lijia modify,
		NOTE:
		�ȳ�ʼ�����, ����ڲ����ܻ����pthread_create��̬�����߳�,
		������, ��DPDKģʽ��, dpdk��ʼ���׶ξͻ�󶨵�ǰ�̵߳�ĳCPU����,
		��ô������pthread_create���߳�Ĭ�ϼ̳������Ϊ,
		����, �ȳ�ʼ���߳��ٳ�ʼ��packet_io.
	*/
	/*
		2019-04-11, marsio�Ѿ�����������, �ٻָ����ȵ���packet_io_init(), �����plugctrl().
	*/

	/*
		2020-09-15, ���packet_io_init�ȵ���, �����Ѿ����հ�����, 
		���ǲ�����ܻ�û��ʼ�����, sapp����������ʼ�հ�, ������������, �������л��������˻ᵼ�¶���,
		�ĳ��ȵ���plugctrl(), �����packet_io_init().
	*/


	sapp_set_current_state(SAPP_STATE_PKT_IO_INITING);

	if(packet_io_init(argc, argv) < 0){
		return -1;
	}

	sapp_independent_thread_init(); /* Ҫ���ڲ����ʼ��֮ǰ, �����ʼ��ʱ������ independent_thread ���������߳� */

	sapp_dup_pkt_init();

	/* 2021-07-05, sapp_assistant_init()�ƶ���plugctrl_proc()֮��, Ҫ���Ѽ��ز������entry���б� */
	if(sapp_metric_init() < 0){
		return -1;
	}

	sapp_set_current_state(SAPP_STATE_PLUG_INITING);	
	plugctrl_proc();

	if(sapp_metric_start() < 0){
		return -1;
	}

	sapp_platform_finish_up(); /* ֧�ֶ�̬project tagע��, ���������в����ʼ����ɺ����, ��һЩƽ̨��ʼ���׶ε���β���� */
	sapp_set_current_state(SAPP_STATE_PLUG_INITED);

	sapp_set_current_state(SAPP_STATE_PKT_IO_INITED);

	sapp_runtime_log(RLOG_LV_DEBUG, "sapp platform init success");

	return 0;	
}

/* ��鱾�����Ƿ�ͨ��SYSTEMD���� */
static int check_is_started_by_notify()
{
	char *notify_socket = getenv("NOTIFY_SOCKET");
	return notify_socket == NULL ? 0 : 1;
}

void MESA_platform_run(void)
{
	/* 
		ʹ��atexit()ע��ĺ���, ������ע�ắ���෴, ���Ծ������Ӻ�atexit()ע��λ��,
		�������г�ʼ�����֮��, packet_io_run()֮ǰ��

		������sapp_gval_destroy()֮��, ȫ�ֱ���sapp_global_val����free��, �˴���ʱ��һ��.
	*/

	__sapp_timer_platform_run();
	
	packet_io_run();

	sapp_set_current_state(SAPP_STATE_PROCESSING);
	/* 
	   If sapp is started by systemd with notify, then tell the systemd sapp is ready.
     */
	if (check_is_started_by_notify()){
		sd_notify(0, "READY=1");
		sleep(1);
	}

}

#ifdef __cplusplus
}
#endif


