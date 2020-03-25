#include "sapp_api.h"
#include "sapp_private_api.h"


#ifdef __cplusplus
extern "C" {
#endif

//static int threadnum = 1;
static volatile long stream_num = 0;
//int g_iThreadNum = 1;
//time_t g_CurrentTime;//add by lqy 20070606
volatile unsigned long long g_SysInputInfo[MAX_THREAD_NUM][COUNTER_NUM];
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
extern int G_DICTATOR_SW;
extern struct global_stream **G_MESA_GLOBAL_STREAM;
//static int __times = 0;
//int g_timestamp_record_sw = 0;
extern long long g_timedelay_threshold;
extern int g_use_MESA_sleep_sw;
extern int g_raw_pkt_broken_check;
extern int g_skip_ethernet_layer_sw;
int g_reverse_ethernet_addr_sw;
//extern int g_kill_tcp_remedy_sw;
extern int g_encapsulate_with_ddp;
extern int g_encapsulate_with_L2E; /* 使用DDP协议封装的x27原始IP包 */
extern int G_DICTATOR_SW;
extern int g_PollingFunNum;
extern int packet_io_set_ipv6_raw_socket_enable(int op_switch);
extern const char *stream_addr_list_ntop_outward(const struct streaminfo *pstream);
extern const char *stream_addr_list_ntop_inward(const struct streaminfo *pstream);
extern const struct streaminfo *stream_addr_list_pton_outward(const char *addr_list_str, int thread_index);
extern const struct streaminfo *stream_addr_list_pton_inward(const char *addr_list_str, int thread_index);
extern int cycle_pkt_dump_init(int argc, char *argv[]);
extern char udp_teredo_identify_entry(const struct streaminfo *pstream, const void *this_hdr, const void *raw_pkt, void **pme);
extern char udp_gtp_identify_entry(const struct streaminfo *pstream, const void *this_hdr, const void *raw_pkt, void **pme);

extern char isakmp_protocol_entry(const struct streaminfo *a_udp,  void **pme, int thread_seq,const void *ip_hdr);
extern int stream_register_udp_raw(SAPP_STREAM_FUN_T x);
extern int number_is_2powerN(uint n);
extern int symbol_check(void);
extern int timestamp_record_init(void);
extern  int sapp_global_val_init(void);
extern int sapp_assistant_init(void);

static void forbid_call_exit_in_running_state(void)
{
	if(g_packet_io_cap_mode != CAP_MODEL_PCAP_DUMPFILE){
		printf("\033[41mCall exit() in running state is forbidden!!\033[0m\n");
		abort();
	}
}

/* 2016-09-22 lijia add, dictator在第一次被调用时有初始化代码, 防止多线程重入冲突, 平台先调用一次 */
static void sapp_dictator_init(void)
{
#if USE_MEMPOOL
	void *tmp;
	if(G_DICTATOR_SW){
		tmp =  __wrap_malloc(1);
		assert(tmp != NULL);
		__wrap_free(tmp);

		tmp = malloc(1);
		assert(tmp != NULL);
		free(tmp);
	}else{
		printf("\033[33m[Warning]dictator is not enable, please check 'conf/main.conf -> dictator_switch'.\033[0m\n");
	}
#else
	printf("\033[33m[Warning]sapp is compiled without dictator.\033[0m\n");
#endif	
}

int MESA_platform_init(int argc, char *argv[])
{
	int queue_max_num, ipv6_switch = 0;
	char pcap_dev1[128], pcap_dev2[128], snd_dev[128]; 
	char cap_filter[1024] = {};
	char gateway_mac[32] = {};
	//int create_link_mode;
	int TcpAllEnable = 0;
	//pthread_t gettimeThread;
	int maxrandval, randkeyval;
	int load_plug_sw = 1;
	unsigned short udp_stream_timeout = 300, max_unorder_num;
	unsigned short link_timeout = 600;
	int int_tmp;

	sapp_set_current_state(SAPP_STATE_PLATFORM_INITING);

	ABBR_CURRENT_TIME = time(NULL);
	ABBR_SAPP_START_TIME = time(NULL);

	/* 2016-09-22 lijia add, dictator在第一次被调用时有初始化代码, 防止多线程重入冲突, 平台先调用一次, 先要读取配置文件开关 */
	MESA_load_profile_int_def("conf/main.conf","Module", "dictator_switch", &G_DICTATOR_SW, 1);	
	sapp_dictator_init();

	//MESA_load_profile_int_def((char *)"conf/main.conf", (char *)"ShowStatInfo", (char *)"platform_log_level", &g_sapp_log_level, 10);
	//g_sapp_log_handle = MESA_create_runtime_log_handle("./log/runtimelog", g_sapp_log_level);
	//if(NULL == g_sapp_log_handle)
	//{
		//printf("MESA_create_runtime_log_handle() error!\n");
		//return -1;
	//}
	
	//if(MESA_load_profile_int_def("conf/main.conf", "Module", "capdatamodlel", &cap_mode, 2) < 0){
		//printf("read conf 'capdatamodlel' error!\n");
		//exit(1);
	//}

	//if(MESA_load_profile_int_def("conf/main.conf", "Module", "threadnum", &threadnum, 1) < 0){
		//printf("read conf 'threadnum' error!\n");
		//exit(1);
	//}	
	//g_iThreadNum = threadnum;

	//MESA_load_profile_int_def("conf/main.conf","Module", "MaxUdpStreams",&max_udp_stream_num , 65536);
#if HIGH_PERF
	//if(number_is_2powerN(max_udp_stream_num) == 0){
		//printf("\033[41m in high-mode '%s' must be power of 2! such as 32768,65536,131072...\033[0m\n", "MaxUdpStreams");
		//exit(1);		
	//}
#endif

	//MESA_load_profile_int_def("conf/main.conf","Module", "MaxTcpStreams",&max_tcp_stream_num, 65536);
#if HIGH_PERF
	//if(number_is_2powerN(max_tcp_stream_num) == 0){
		//printf("\033[41m in high-mode '%s' must be power of 2! such as 32768,65536,131072...\033[0m\n", "MaxTcpStreams");
		//exit(1);		
	//}
#endif

  	//MESA_load_profile_int_def("conf/main.conf","Module", "CreatLinkMode", &create_link_mode, TCP_CTEAT_LINK_BYSYN);
  	
	MESA_load_profile_int_def("conf/main.conf","Module", "TcpAllEnable", &TcpAllEnable, 1);
	tcp_set_support_tcpall_model(TcpAllEnable);

#if (0 == HIGH_PERF)
	//MESA_load_profile_int_def("conf/main.conf","Module", "discard_ack",&g_discard_ack_sw, 0);
#else
	//g_discard_ack_sw = 1;
	//printf("\033[33m in high-perf mode, 'discard_ack' is auto enable!\n");
#endif
	//MESA_load_profile_int_def("conf/main.conf","Module", "kill_tcp_remedy",&g_kill_tcp_remedy_sw, 0);
	
	//MESA_load_profile_int_def("conf/main.conf","Module", "maxrandval", &maxrandval, 65535);
	//set_rst_max_rnd_val(maxrandval);
	//MESA_load_profile_int_def("conf/main.conf","Module", "randkeyval", &randkeyval, 13);
  	//set_rst_rand_key(randkeyval);

	//MESA_load_profile_int_def("conf/main.conf","Module", "kill_tcp_rst_pkt_num", &sapp_global_single.cfg_kill_tcp_rst_num, 3);
	//if(sapp_global_single.cfg_kill_tcp_rst_num <= 0 || sapp_global_single.cfg_kill_tcp_rst_num > 3){
		//printf("\033[41mWarning! '%s' is %d, invalid, must in range [0,3], set it to 1!\033[0m\n", "kill_tcp_rst_pkt_num");
		//sleep(1);	
	//}
	
	//MESA_load_profile_int_def("conf/main.conf","Module", "kill_tcp_rst_signature", &sapp_global_single.cfg_kill_tcp_rst_signature,1);

	ipv4_frag_init(g_iThreadNum, 1024 * 512);
	//MESA_load_profile_int_def("conf/main.conf","Module", "IPv6_module_enable", &ipv6_switch, 1);
	//packet_io_set_ipv6_module_enable(1);
	//MESA_load_profile_int_def("conf/main.conf","Module", "IPv6_raw_socket", &ipv6_switch, 0); /* 为了便于部署, 此项默认关闭 */
	//packet_io_set_ipv6_raw_socket_enable(1);	
	ipv6_frag_init(g_iThreadNum, 1024 * 256);

	//tcp_set_creatlink_model(create_link_mode);
	//MESA_load_profile_short_def("conf/main.conf","Module", "MaxUnorderNum",(short *)&max_unorder_num, 5);
	//tcp_set_default_unorder_num(max_unorder_num);
	
	tcp_set_stream_num(max_tcp_stream_num*3,max_tcp_stream_num,max_tcp_stream_num*2);

	//MESA_load_profile_short_def("conf/main.conf","Module", "LinkTimeout", (short *)&link_timeout, 600);
	//stream_set_default_nopkt_time(link_timeout);
	
	//MESA_load_profile_short_def("conf/main.conf","Module", "UdpResetTime", (short *)&udp_stream_timeout, 300);
	//udp_set_stream_timeout(udp_stream_timeout);
	
	udp_set_stream_num(max_udp_stream_num*3,max_udp_stream_num,max_udp_stream_num*2);
#if 0
	MESA_load_profile_int_def("conf/main.conf","Module", "skip_not_ip_layer", &G_SKIP_NOT_IP_LAYER, 0);
	if(G_SKIP_NOT_IP_LAYER != 0){
		printf("\033[41mWarning!  '%s' is enable!\033[0m\n", "skip_not_ip_layer");
		sleep(1);		
	}
#endif

	//MESA_load_profile_int_def("conf/main.conf","Module", "timestamp_record", &g_timestamp_record_sw, 0);	
	MESA_load_profile_int_def("conf/main.conf","Module", "timedelay_threshold", &int_tmp, 10000000);
	g_timedelay_threshold = (long long)int_tmp;
	
	MESA_load_profile_int_def("conf/main.conf","Module", "use_MESAsleep", &g_use_MESA_sleep_sw, 0);	

	MESA_load_profile_int_def("conf/main.conf","Module", "encapsulate_with_ddp", &g_encapsulate_with_ddp, 0);	
	if(g_encapsulate_with_ddp != 0){
		printf("\033[32m[Notice] '%s' is enable!\033[0m\n", "encapsulate_with_ddp");
		sleep(1);		
	}	

	MESA_load_profile_int_def("conf/main.conf","Module", "encapsulate_with_L2E", &g_encapsulate_with_L2E, 0);	
	if(g_encapsulate_with_L2E != 0){
		printf("\033[32m[Notice] '%s' is enable!\033[0m\n", "encapsulate_with_L2E");
		sleep(1);		
	}	

	if((g_encapsulate_with_ddp != 0) && (g_encapsulate_with_L2E != 0)){
		printf("\033[1;31;40m[Error]g_encapsulate_with_ddp is conflict with g_encapsulate_with_L2E, can't enable simultaneously at all!\033[0m\n");
		return -1;
	}
	
#if (0 == SAPP_AS_TARGET_SO) /* 做为.so模式, 无需dlopen相关io.so */
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

	//if(MESA_load_profile_string_def("conf/main.conf", "Module", "pcapdevice", pcap_dev1, 128, "eth0") < 0){
		//printf("read conf 'pcapdevice' error!\n");
		//exit(1);
	//}
	packet_io_set_capdev_parallel(sapp_global_val->config.packet_io.internal.interface.name);
	
	if(DEPOLYMENT_MODE_TRANSPARENT == g_topology_mode_raw){
		//if(MESA_load_profile_string_def("conf/main.conf", "Module", "pcapdevice2", pcap_dev2, 128, "eth1")  < 0){
			//printf("read main.conf  'pcapdevice2' error!\n");
			//exit(1);
		//}
		packet_io_set_capdev_serial(sapp_global_val->config.packet_io.internal.interface.name, 
									sapp_global_val->config.packet_io.external.interface.name);
	}	

	//if(MESA_load_profile_int_def("conf/main.conf", "Module", "net_connection_mode", &top_mode, 1) < 0){
		//printf("read conf 'net_connection_mode' error!\n");
		//exit(1);
	//}
	packet_io_set_topology_mode(sapp_global_val->config.packet_io.depolyment_mode_bin);
	
	//if(MESA_load_profile_string_def("conf/main.conf", "Module", "pcapfilter", cap_filter, 1024, "") < 0){
		//printf("read conf 'pcapfilter' error!\n");
		//exit(1);
	//}
	
	if(sapp_global_val->config.packet_io.input_bpf_filter != NULL){
		printf("\033[33m[Warning] pcap filter is '%s'.\033[0m\n", sapp_global_val->config.packet_io.input_bpf_filter);
		packet_io_set_capture_filter(sapp_global_val->config.packet_io.input_bpf_filter);
	}

	//if(MESA_load_profile_int_def("conf/main.conf", "Module", "queue_max_num", &queue_max_num, 2000) < 0){
		//printf("read conf  'queue_max_num' error!\n");
		//exit(1);
	//}
	packet_io_set_cap_buf_queue(10000);
	
	//if(MESA_load_profile_string_nodef("conf/main.conf", "Module", "gateway_mac", gateway_mac, 32) < 0){
		//printf("read conf  'gateway_mac' error!\n");
	//}
	//packet_io_set_gateway_mac(gateway_mac); /*读取配置文件 */

	//if(MESA_load_profile_string_nodef("conf/main.conf", "Module", "senddevice", snd_dev, 128) < 0){
		//printf("read conf  'senddevice' error!\n");
		//exit(1);
	//}	
	//packet_io_set_send_dev(snd_dev);

	MESA_load_profile_int_def("conf/main.conf", "Module", "signal_take_over_switch", &sapp_global_single.signal_take_over_sw, 0);
	MESA_load_profile_int_def("conf/main.conf", "Module", "ipentry_priority_over_ipfrag", &sapp_global_single.ipentry_priority_over_ipfrag, 0);
	MESA_load_profile_int_def("conf/main.conf", "Module", "tuple4_reuse_time_interval", &sapp_global_single.tuple4_reuse_time_interval, 3);
#endif

	init_stream_manage(g_iThreadNum);	

#if 0
	MESA_load_profile_int_def("conf/main.conf", "Module", "iknow_switch", &int_tmp, 1);
	if(int_tmp != 0){
		iknow_info_init();
	}
#endif
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
	MESA_load_profile_int_def((char *)"conf/main.conf", (char *)"Module", (char *)"reverse_ethernet_addr", &g_reverse_ethernet_addr_sw, 0);


	/* 平台内置固定开启的插件 */
	stream_register_udp_raw(udp_teredo_identify_entry);
	stream_register_udp_raw(udp_gtp_identify_entry);

	MESA_load_profile_int_def((char *)"conf/main.conf", (char *)"Module", (char *)"kill_tcp_with_gdev", &sapp_global_single.kill_tcp_with_gdev, 0);
	if(sapp_global_single.kill_tcp_with_gdev != 0){
		if(gdev_block_init() < 0){
			printf("\n\033[33m[Warning]gdev_block_init error!\033[0m\n");
		}
	}

	MESA_load_profile_int_def((char *)"conf/main.conf", (char *)"Module", (char *)"symbol_conflict_check", &int_tmp,
			0);
	if(int_tmp != 0){
		/* NOTE: 符号名检测一定要在plugctrl_proc(), 即所有插件加载之后, 默认开启 */
		symbol_check(); /* 2016-01-13 Lijia add, 检查全局符号名冲突 */
	}
	sapp_global_val_sanity_check();

	if(g_PollingFunNum != 0){
		printf("\n\033[33m[Warning]There are %d plugs on [POLLING] entry, this will increase latency of packet process!\033[0m\n", g_PollingFunNum);
		usleep(10000);
	}

	MESA_load_profile_int_def((char *)"conf/main.conf", (char *)"Module", (char *)"create_mpls_anyway",  &sapp_global_single.create_mpls_anyway, 0);
	MESA_load_profile_int_def((char *)"conf/main.conf", (char *)"Module", (char *)"send_fake_pkt_mode",  &sapp_global_single.send_fake_pkt_mode, 0);
	MESA_load_profile_int_def((char *)"conf/main.conf", (char *)"Module", (char *)"send_fake_pkt_gdev_sport",  &sapp_global_single.send_fake_pkt_gdev_sport, 15);
	
	sapp_assistant_init();

	MESA_load_profile_int_def((char *)"conf/main.conf", (char *)"Module", (char *)"send_tcp_offload", &sapp_global_single.cfg_send_tcp_offload_sw, 0);
	MESA_load_profile_int_def((char *)"conf/main.conf", (char *)"Module", (char *)"treat_vlan_as_mac_in_mac", &sapp_global_single.treat_vlan_as_mac_in_mac_sw, 0);
	if(sapp_global_single.treat_vlan_as_mac_in_mac_sw){
		printf("\n\033[33m[Warning]'treat_vlan_as_mac_in_mac' is enable, vlan packet will be treat as MAC_IN_MAC!\033[0m\n");
		usleep(10000);
	}
	sapp_set_current_state(SAPP_STATE_PLATFORM_INITED);
	
	/* 2017-02-24 lijia modify,
		NOTE:
		先初始化插件, 插件内部可能会调用pthread_create动态创建线程,
		问题是, 在DPDK模式下, dpdk初始化阶段就会绑定当前线程到某CPU核心,
		那么后续的pthread_create的线程默认继承这个行为,
		所以, 先初始化线程再初始化packet_io.
	*/
	/*
		2019-04-11, marsio已经无上述问题, 再恢复成先调用packet_io_init(), 后调用plugctrl().
	*/
	sapp_set_current_state(SAPP_STATE_PKT_IO_INITING);
#if (0 == SAPP_AS_TARGET_SO) /* 做为.so模式, 无需初始化packet_io */	
	if(packet_io_init(argc, argv) < 0){
		return -1;
	}
#endif	
	sapp_set_current_state(SAPP_STATE_PKT_IO_INITED);

	sapp_set_current_state(SAPP_STATE_PLUG_INITING);
	plugctrl_proc();
	sapp_set_current_state(SAPP_STATE_PLUG_INITED);
	
	return 0;	
}


void MESA_platform_run(void)
{
	/* 
		使用atexit()注册的函数, 调用与注册函数相反, 所以尽可能延后atexit()注册位置,
		放在所有初始化完成之后, packet_io_run()之前。
	*/
	atexit(forbid_call_exit_in_running_state);

	__sapp_timer_platform_run();
	
	packet_io_run();

	sapp_set_current_state(SAPP_STATE_PROCESSING);

#if (0 == SAPP_AS_TARGET_SO)	
	while(1){
		pause();
	}
#endif	

}

#ifdef __cplusplus
}
#endif


