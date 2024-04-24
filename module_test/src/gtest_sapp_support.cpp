#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include "stream.h"
#include <sys/types.h>			/* See NOTES */
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include "gtest_sapp_fun.h"


#include <gtest/gtest.h>

void control_max_unorder_run(void)
{
	set_default_config();
#if SAPP_V3
	update_config_file("conf/main.conf", "MaxUnorderNum", "3"); /* 全局最大乱序数小于实际乱序的包间隔, 会导致认为是丢包 */
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "reorder_pkt_max", "3");
#else 
	abort();
#endif

	update_plugin_inf("TCP", "ctrl_max_unorder_tcp_entry");
	///append_plugin_inf("TCP_ALL", "ctrl_max_unorder_tcpall_entry");
	
	set_pcap_dumpfile("tcp/set_opt_max_unorder.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "d0271a097dcb8213ae7091a3fcd608e3"),0);
	
	 
	call_libsapp_devel_with_args(2, sapp_start_args);
}

void control_tcp_need_ack_run(void)
{
	set_default_config();
	update_plugin_inf("TCP", "ctrl_tcp_need_ack_entry");
	
	set_pcap_dumpfile("tcp/tcp_need_ack.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "d8ac2a79be31652d87ef13646f8bd996"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}

void control_takeover_run(void)
{
	set_default_config();
	
	update_plugin_inf("TCP", "ctrl_takeover_plundered_entry");
	append_plugin_inf("TCP_ALL", "ctrl_takeover_exclusive_entry");
	
	set_pcap_dumpfile("tcp/tcp_simple.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);
	
	 
	call_libsapp_devel_with_args(2, sapp_start_args);
}


void control_timeout_run(void)
{
	const char *sapp_argv[4];

	sapp_argv[0] = (char *)"./sapp ";
	sapp_argv[1] = (char *)"--dumpfile";
	sapp_argv[2] = (char *)"--dumpfile-speed=timestamp";
	sapp_argv[3] = NULL;
	

	set_default_config();
#if SAPP_V3
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
	update_config_file("conf/main.conf", "LinkTimeout", "0");  
	update_config_file("conf/main.conf", "UdpResetTime", "0");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "timeout", "5");	
#else
	abort();
#endif
	update_plugin_inf("TCP", "ctrl_tcp_timeout_entry");
	
	set_pcap_dumpfile("tcp/tcp_timeout_reset.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "9e8c65901915a0535d210e3766030b9e"),0);

	printf("test for timer, set --dumpfile-speed=timestamp please wait for a monment......\n");
	
	call_libsapp_devel_with_args(3, sapp_argv);
}


void control_tcp_isn_c2s_run(void)
{
	set_default_config();
#if SAPP_V3
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "1");
#else
	abort();
#endif
	update_plugin_inf("TCP", "ctrl_tcp_isn_c2s_entry");
	
	set_pcap_dumpfile("tcp/tcp_isn_c2s_single.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "a5d0d96ee6f44f729d79aeac5cc2fee0"),0);
	
	 
	call_libsapp_devel_with_args(2, sapp_start_args);
}


void control_tcp_isn_s2c_run(void)
{
	set_default_config();
	
#if SAPP_V3
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "1");
#else
	abort();
#endif

	update_plugin_inf("TCP", "ctrl_tcp_isn_s2c_entry");
	
	set_pcap_dumpfile("tcp/tcp_isn_s2c_single.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "b0fca0034b52ff3eefcba99d723b778d"),0);
	
	 
	call_libsapp_devel_with_args(2, sapp_start_args);
}

void control_tcp_option_run(void)
{
	set_default_config();

#if SAPP_V3
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
	update_config_file("conf/main.conf", "analyse_tcp_option", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "1");
#else
	abort();
#endif

	update_plugin_inf("TCP", "ctrl_tcp_option_entry");
	
	set_pcap_dumpfile("tcp/tcp_option.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "d4f541562c15f27c22b205de126f0a5f"),0);
	
	 
	call_libsapp_devel_with_args(2, sapp_start_args);
}

void control_tunnel_type_6over4_run(void)
{
	set_default_config();
	
	update_plugin_inf("TCP", "ctrl_tunnel_6over4_entry");
	
	set_pcap_dumpfile("6over4/ipv6_over_ipv4.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "5b512b3321164a73446bdd54f7d20057"),0);
	
	 
	call_libsapp_devel_with_args(2, sapp_start_args);
}

void control_tunnel_type_gre_run(void)
{
	set_default_config();
	
	update_plugin_inf("UDP", "ctrl_tunnel_gre_entry");
	
	set_pcap_dumpfile("gre/gre_dns.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "9242d1b85676308cee9b56e6a5fea3f4"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}

void control_tunnel_type_teredo_run(void)
{
	set_default_config();
	
	update_plugin_inf("TCP", "ctrl_tunnel_teredo_entry");
	
	set_pcap_dumpfile("teredo/teredo_http.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "b87935d6a063bf715d0c364ba9c65c19"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}

void control_tunnel_type_l2tp_run(void)
{
	set_default_config();

	/* l2tp识别目前需要挂载l2tp_protocol插件 */
	insert_into_conflist_inf("protocol", "./plug/protocol/l2tp_protocol_plug/l2tp_protocol_plug.inf");
	
	update_plugin_inf("TCP", "ctrl_tunnel_l2tp_entry");
	
	set_pcap_dumpfile("l2tp/l2tp_http.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "3862724016e0464569e6720ccc46d368"),0);

	call_libsapp_devel_with_args(2, sapp_start_args);
}

void control_tunnel_type_pptp_run(void)
{
	set_default_config();
	
	update_plugin_inf("TCP", "ctrl_tunnel_pptp_entry");
	
	set_pcap_dumpfile("pptp/pptp_http.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "4eb6fb78d78a4acdb2438949f28a7992"),0);

	call_libsapp_devel_with_args(2, sapp_start_args);
}

void control_tunnel_type_gtp_run(void)
{
	set_default_config();
	
#if SAPP_V3	
	update_config_file("conf/main.conf", "CreatLinkMode", "3"); /* gtp_simple.pcap没有syn包 */
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
#else
	abort();
#endif
	update_plugin_inf("TCP", "ctrl_tunnel_gtp_entry");
	set_pcap_dumpfile("gtp/gtp_simple.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "e10707dedef0680effc4dadeb333b275"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}

/* 测试sapp_get_platform_opt()接口相关功能 */
void control_stream_and_traffic_run(void)
{
	set_default_config();
#if SAPP_V3
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
	update_config_file("conf/main.conf", "LinkTimeout", "0");  
	update_config_file("conf/main.conf", "UdpResetTime", "0");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "1");
	update_config_file("etc/sapp.toml", "timeout", "0");
	update_config_file("etc/sapp.toml", "timeout", "0");	
#else
	abort();
#endif
	update_plugin_inf("TCP_ALL", "ctrl_tcp_stream_and_traffic_entry");
	
	set_pcap_dumpfile("tcp/tcp_simple.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}

void project_simple_run(void)
{
	set_default_config();

	/* 更新gtest.inf */
	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "project_test_init", NULL, "TCP", "project_customer_entry");	
	append_plugin_inf("TCP_ALL", "project_producer_entry");
	
#if SAPP_V3	
	update_config_file("conf/main.conf", "CreatLinkMode", "3");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
#else
	abort();
#endif
	set_project_list_conf_default();
	append_project_list_conf("project_test", "int");
	
	set_pcap_dumpfile("tcp/tcp_simple.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}

#if 0 //用bridge接口代替
void project_nodify_run(void)
{
	set_default_config();

	/* 更新gtest.inf */
	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "project_test_init", NULL, "TCP", "project_customer_entry");	

	/* project_producer_notify_entry 注册到TCP_ALL, 保证要先于TCP插件调用, 先插入project值 */	
	append_plugin_inf("TCP_ALL", "project_producer_notify_entry");

	/* 复用sapp_appstate测试用例的插件目录, 用来测试project nofity功能 */
	update_plugin_inf_with_options("./plug/business/gtest_sapp_appstate_1", "notify1", "project_nofity_custom1_init", NULL, "TCP", "project_customer_entry1");
	update_plugin_inf_with_options("./plug/business/gtest_sapp_appstate_2", "notify2", "project_nofity_custom2_init", NULL, "TCP", "project_customer_entry2");

	append_conflist_inf("./plug/business/gtest_sapp_appstate_1/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp_appstate_2/gtest_sapp.inf"); 
	
#if SAPP_V3	
	update_config_file("conf/main.conf", "CreatLinkMode", "3");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
#else
	abort();
#endif

	set_project_list_conf_default();
	append_project_list_conf("project_test", "int");
	
	set_pcap_dumpfile("tcp/tcp_simple.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);

	system("cp ./plug/business/gtest_sapp/libgtest_sapp.so ./plug/business/gtest_sapp_appstate_1/");
	system("cp ./plug/business/gtest_sapp/libgtest_sapp.so ./plug/business/gtest_sapp_appstate_2/");
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}
#endif



#if SAPP_V4
#include "sapp_timer.h"
void timer_simple_run(void)
{
	set_default_config();
	
	set_project_list_conf_default();
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "timeout", "0");
	update_config_file_by_lastline("etc/sapp.toml", "packet_io.polling","enabled", "1");
	update_config_file_by_lastline("etc/sapp.toml", "polling_priority","enabled", "1");
	update_plugin_inf("TCP_ALL", "timer_tcpall_entry");

	/* 
		构造一个pcap包, 使其间隔非常长, 使用--dumpfile-speed=timestamp参数,保证平台长时间不退出!
		如果是pcap_online模式捕获lo卡,非常可能没有数据,导致插件不会被调用.
	*/
	set_pcap_dumpfile("for_gtest_only/timer/timer_tcp_test.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "7bfc59d66bb44f76603cd6cedfd19091"),0);

	printf("test for timer, set --dumpfile-speed=timestamp please wait for a monment......\n");
	
	gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);

	char *_local_sapp_start_args[] = {(char *)"./sapp", (char *)"-d", (char *)"-p", (char *)"timestamp", (char *)"-n", (char *)NULL};
	int ret = libsapp_setup_env(5, _local_sapp_start_args);
	if(ret < 0){
		printf("call libsapp_setup_env() fail");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return;
	}
	while(sapp_get_current_state() != SAPP_STATE_PROCESSING){
		usleep(10);
	}
	/* 注意: 此处需要额外独立sleep() 10秒以上!! */
	sleep(12);
	
	libsapp_destroy_env();
}


void global_stream_id_run(void)
{
	set_default_config();
	set_project_list_conf_default();

	update_config_file("etc/sapp.toml", "worker_threads", "3");
	update_config_file("etc/sapp.toml", "bind_mask", "[]");
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "timeout", "0");
	update_config_file("etc/sapp.toml", "stream_id_base_time", "\"2018-08-08 08:08:08\"");

	update_plugin_inf("TCP_ALL", "global_stream_id_tcpall_entry");

	set_pcap_dumpfile("tcp/tcp_simple.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


void global_stream_id_tuple4_reuse_run(void)
{
	const char *reuse_argv[4];

	reuse_argv[0] = (char *)"./sapp";
	reuse_argv[1] = (char *)"--dumpfile";
	reuse_argv[2] = (char *)"--dumpfile-speed=timestamp";
	reuse_argv[3] = NULL;
	

	set_default_config();
	set_project_list_conf_default();

	update_config_file("etc/sapp.toml", "worker_threads", "1");
	update_config_file("etc/sapp.toml", "bind_mask", "[]");
	update_config_file("etc/sapp.toml", "syn_mandatory", "1");
	update_config_file("etc/sapp.toml", "timeout", "0");
	update_config_file("etc/sapp.toml", "tuple4_reuse_time_interval", "10");
	update_config_file("etc/sapp.toml", "stream_id_base_time", "\"2018-08-08 08:08:08\"");

	update_plugin_inf("TCP_ALL", "global_stream_id_tuple4_reuse_tcpall_entry");

	set_pcap_dumpfile("tcp/tcp_tuple4_reuse.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "4a7f3337a2039de8a91b7186e9a71c62"),0);

	printf("test for tuple4 reuse, set --dumpfile-speed=timestamp please wait for a monment......\n");
	
	call_libsapp_devel_with_args(3, reuse_argv);
}

/*
	测试四元组重用后, 流的创建时间是否更新.
*/
void stream_creattime_tuple4_reuse_run(void)
{
	const char *reuse_argv[4];

	reuse_argv[0] = (char *)"./sapp";
	reuse_argv[1] = (char *)"--dumpfile";
	reuse_argv[2] = (char *)"--dumpfile-speed=timestamp";
	reuse_argv[3] = NULL;
	

	set_default_config();
	set_project_list_conf_default();

	update_config_file("etc/sapp.toml", "worker_threads", "1");
	update_config_file("etc/sapp.toml", "bind_mask", "[]");
	update_config_file("etc/sapp.toml", "syn_mandatory", "1");
	update_config_file("etc/sapp.toml", "timeout", "0");
	update_config_file("etc/sapp.toml", "tuple4_reuse_time_interval", "10");
	update_config_file("etc/sapp.toml", "stream_id_base_time", "\"2018-08-08 08:08:08\"");

	update_plugin_inf("TCP_ALL", "stream_creatime_tuple4_reuse_tcpall_entry");

	set_pcap_dumpfile("tcp/tcp_tuple4_reuse.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "4a7f3337a2039de8a91b7186e9a71c62"),0);

	printf("test for tuple4 reuse, set --dumpfile-speed=timestamp please wait for a monment......\n");
	
	call_libsapp_devel_with_args(3, reuse_argv);
}


void control_get_tcp_streamid_run(void)
{
	set_default_config();
	
	update_plugin_inf("TCP", "global_stream_id_check_entry");
	
	set_pcap_dumpfile("tcp/tcp_simple.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}

void control_get_udp_streamid_run(void)
{
	set_default_config();
	
	update_plugin_inf("UDP", "global_stream_id_check_entry");
	
	set_pcap_dumpfile("udp/udp_simple.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "328951b2b04af765e6a0a7fe34ee29ad"),0);

	call_libsapp_devel_with_args(2, sapp_start_args);	
}


#endif


void control_platform_opt_run(void)
{
	set_default_config();

	/* 更新gtest.inf, 此处主要是更新test_get_platform_opt_init()函数, 插件其实无所谓, 随便加个tcp插件 */
	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "test_get_platform_opt_init", NULL, "TCP", "tcp_simple");

	set_pcap_dumpfile("tcp/tcp_simple.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);

	call_libsapp_devel_with_args(2, sapp_start_args);	
}


void control_stream_create_timestamp_ms_run(void)
{
	const char *argv[4];

	argv[0] = (char *)"./sapp ";
	argv[1] = (char *)"--dumpfile";
	argv[2] = (char *)"--dumpfile-speed=timestamp";
	argv[3] = NULL;
	
	set_default_config();
	set_project_list_conf_default();
	
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "timeout", "0");
	update_config_file_by_lastline("etc/sapp.toml", "packet_io.polling","enabled", "1");
	update_plugin_inf("TCP_ALL", "stream_createtime_ms_tcpall_entry");

	/* 
		构造一个pcap包, 使其间隔非常长, 使用--dumpfile-speed=timestamp参数,保证平台长时间不退出!
		如果是pcap_online模式捕获lo卡,非常可能没有数据,导致插件不会被调用.
	*/
	set_pcap_dumpfile("tcp/tcp_simple.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);

	printf("test for stream_create_timestamp_ms, set --dumpfile-speed=timestamp please wait for a monment......\n");
	
	call_libsapp_devel_with_args(3, argv);

}


/* 测试获取当前层上层承载的隧道, 与底层隧道不同 */
void control_up_layer_tunnel_gtp_run(void)
{
	set_default_config();

	/* gtp_dns.pcap有几个重复数据包, 得关闭重复包检测功能 */
	update_config_file("etc/sapp.toml", "original_ipv4_udp_enabled", "0");
	update_config_file("etc/sapp.toml", "inject_all_enabled", "0");

	update_plugin_inf("UDP", "up_layer_tunnel_gtp_entry");
	append_plugin_inf("TCP", "void_entry");
	set_pcap_dumpfile("gtp/gtp_dns.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "f978cc37ac9e49150eb30cd574013936"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);	
}


/* 测试获取当前层上层承载的隧道, 与底层隧道不同 */
void control_up_layer_tunnel_l2tp_run(void)
{
	set_default_config();

	/* l2tp识别目前需要挂载l2tp_protocol插件 */
	insert_into_conflist_inf("protocol", "./plug/protocol/l2tp_protocol_plug/l2tp_protocol_plug.inf");

	update_plugin_inf("UDP", "up_layer_tunnel_l2tp_entry");
	append_plugin_inf("UDP", "void_entry");
	set_pcap_dumpfile("l2tp/l2tp_dns.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "037494d45acf0e58d24911ea7a8b652d"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);	
}


/* 测试获取当前层上层承载的隧道, 与底层隧道不同 */
void control_up_layer_tunnel_teredo_run(void)
{
	set_default_config();

	update_plugin_inf("UDP", "up_layer_tunnel_teredo_entry");
	append_plugin_inf("UDP", "void_entry");
	set_pcap_dumpfile("teredo/teredo_udp.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "bd67ab7f4c40a8470f39f2bb423237c8"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


/* 测试插件的pme */
void control_get_plug_pme_run(void)
{
	set_default_config();

	update_plugin_inf("TCP", "void_entry"); /* 此插件主要用于调用 gtest_sapp_slave_init, entry函数啥也不干 */

	update_plugin_inf_with_options("./plug/business/gtest_get_plug_pme1", "get_plug_pme1", "get_plug_pme_init", NULL, "TCP_ALL", "get_plug_pme_tcpall_entry");
	update_plugin_inf_with_options("./plug/business/gtest_get_plug_pme2", "get_plug_pme2", "get_plug_pme_init", NULL, "TCP", "get_plug_pme_tcp_entry");

	/* 需要注意: 
		sapp加载business插件是dlopen + RTLD_LOCAL本地模式, 并不是-l靠系统自动加载的, 
		两个不同插件的入口函数名称虽然一样, 但内存地址实际是不一样的!! 
		所以需要加载到platform层.	
	*/
	update_plugin_inf_with_options("./plug/platform/gtest_get_plug_pme3", "get_plug_pme3", "get_plug_pme_init", NULL, "UDP", "get_plug_pme_udp_entry1");
	update_plugin_inf_with_options("./plug/platform/gtest_get_plug_pme4", "get_plug_pme4", "get_plug_pme_init", NULL, "UDP", "get_plug_pme_udp_entry2");

	append_conflist_inf("./plug/business/gtest_get_plug_pme1/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_get_plug_pme2/gtest_sapp.inf"); 
	append_conflist_inf("./plug/platform/gtest_get_plug_pme3/gtest_sapp.inf"); 
	append_conflist_inf("./plug/platform/gtest_get_plug_pme4/gtest_sapp.inf"); 
	
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");

	set_pcap_dumpfile("for_gtest_only/control/get_plug_pme.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "ef63b52cfedd492bb17a78c627ca1bc6"),0);

	system("cp ./plug/business/gtest_sapp/libgtest_sapp.so ./plug/business/gtest_get_plug_pme1/");
	system("cp ./plug/business/gtest_sapp/libgtest_sapp.so ./plug/business/gtest_get_plug_pme2/");
	system("cp ./plug/business/gtest_sapp/libgtest_sapp.so ./plug/platform/gtest_get_plug_pme3/");
	system("cp ./plug/business/gtest_sapp/libgtest_sapp.so ./plug/platform/gtest_get_plug_pme4/");
	
	call_libsapp_devel_with_args(2, sapp_start_args);	
}


/* 测试必要插件的初始化, 插件.inf和.so都存在, init()函数返回错误 */
void control_plug_necessary_run(void)
{
	set_default_config();
	
	/* 默认结果是成功, 除非插件发送错误结果 */
	gtest_set_timeout_default_result(GTEST_SAPP_SUCC);

	update_plugin_inf_with_options("./plug/business/necessary", "plug_necessary", "plug_necessary_init", NULL, "TCP", "plug_necessary_not_call_entry");
	update_plugin_inf_with_options("./plug/business/indifferent", "plug_indifferent", "plug_indifferent_init", NULL, "TCP", "plug_indifferent_not_call_entry");

	append_conflist_inf("./plug/business/necessary/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/indifferent/gtest_sapp.inf"); 
	
	system("cp -f ./plug/business/gtest_sapp/libgtest_sapp.so ./plug/business/necessary/");
	system("cp -f ./plug/business/gtest_sapp/libgtest_sapp.so ./plug/business/indifferent/");
	
	set_pcap_dumpfile("tcp/tcp_simple.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);

	system("echo ./plug/business/necessary/gtest_sapp.inf > ./etc/necessary_plug_list.conf");

	call_libsapp_devel_with_args(2, sapp_start_args);
}

/* 测试必要插件的初始化,但是插件.inf不存在, 读取插件.so路径, 函数符号名等会出现错误 */
void control_plug_necessary_run_no_inf(void)
{
	set_default_config();

	/* 默认结果是成功, 除非插件发送错误结果 */
	gtest_set_timeout_default_result(GTEST_SAPP_SUCC);

	update_plugin_inf_with_options("./plug/business/necessary", "plug_necessary", "plug_necessary_init", NULL, "TCP", "plug_necessary_not_call_entry");
	update_plugin_inf_with_options("./plug/business/indifferent", "plug_indifferent", "plug_indifferent_init", NULL, "TCP", "plug_indifferent_not_call_entry");

	append_conflist_inf("./plug/business/necessary/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/indifferent/gtest_sapp.inf"); 
	
	system("rm -f ./plug/business/necessary/gtest_sapp.inf"); /* 故意删除necessary的.inf文件 */
	
	set_pcap_dumpfile("tcp/tcp_simple.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);

	system("echo ./plug/business/necessary/gtest_sapp.inf > ./etc/necessary_plug_list.conf");

	call_libsapp_devel_with_args(2, sapp_start_args);
}


/* 测试必要插件的初始化,插件.inf存在, 但是.so不存在, dlopen会出现错误 */
void control_plug_necessary_run_no_sofile(void)
{
	set_default_config();

	/* 默认结果是成功, 除非插件发送错误结果 */
	gtest_set_timeout_default_result(GTEST_SAPP_SUCC);

	update_plugin_inf_with_options("./plug/business/necessary", "plug_necessary", "plug_necessary_init", NULL, "TCP", "plug_necessary_not_call_entry");
	update_plugin_inf_with_options("./plug/business/indifferent", "plug_indifferent", "plug_indifferent_init", NULL, "TCP", "plug_indifferent_not_call_entry");

	append_conflist_inf("./plug/business/necessary/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/indifferent/gtest_sapp.inf"); 
	
	system("rm -f ./plug/business/necessary/libgtest_sapp.so"); /* 故意删除necessary的.so文件 */
	system("cp -f ./plug/business/gtest_sapp/libgtest_sapp.so ./plug/business/indifferent/");
	
	set_pcap_dumpfile("tcp/tcp_simple.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);

	system("echo ./plug/business/necessary/gtest_sapp.inf > ./etc/necessary_plug_list.conf");

	call_libsapp_devel_with_args(2, sapp_start_args);
}


/* 测试插件获取重复流量状态, tcp包 */
void control_plug_dup_pkt_tcp_run(void)
{
	set_default_config();

	update_config_file("etc/sapp.toml", "original_ipv4_tcp_enabled", "1");
	update_config_file("etc/sapp.toml", "bloom_capacity", "1000000");
	update_config_file("etc/sapp.toml", "bloom_error_rate", "0.00001");
	update_config_file("etc/sapp.toml", "bloom_timeout", "10");
	
	update_plugin_inf("TCP", "get_duplicate_pkt_stat_entry");
	
	set_pcap_dumpfile("for_gtest_only/duplicate_packet/tcp_no_syn_dup.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "a56bfea74cd5168e9e3cbf1e2c5c17fb"),0);

	call_libsapp_devel_with_args(2, sapp_start_args);	
	
}


/* 测试插件获取重复流量状态, udp包 */
void control_plug_dup_pkt_udp_run(void)
{
	set_default_config();

	update_config_file("etc/sapp.toml", "original_ipv4_udp_enabled", "1");
	update_config_file("etc/sapp.toml", "bloom_capacity", "1000000");
	update_config_file("etc/sapp.toml", "bloom_error_rate", "0.00001");
	update_config_file("etc/sapp.toml", "bloom_timeout", "10");
	
	update_plugin_inf("UDP", "get_duplicate_pkt_stat_entry");
	
	set_pcap_dumpfile("for_gtest_only/duplicate_packet/udp_dup.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "d3641c8f301e78006d7cdb199538e73b"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);	
}

/*
	通过命令行参数-c修改配置文件根目录, -D修改数据文件根目录后的测试.
*/
void control_get_root_dir_run(void)
{
	const char *sapp_change_root_dir_args[10];

	sapp_change_root_dir_args[0] = (char *)"./sapp ";
	sapp_change_root_dir_args[1] = (char *)"-d";
	sapp_change_root_dir_args[2] = (char *)"-D";
	sapp_change_root_dir_args[3] = (char *)"/tmp/sapp_change_root_dir_test/data";
	sapp_change_root_dir_args[4] = (char *)"-c";
	sapp_change_root_dir_args[5] = (char *)"/tmp/sapp_change_root_dir_test/config/sapp/etc/sapp.toml";
	sapp_change_root_dir_args[6] = (char *)"-C";
	sapp_change_root_dir_args[7] = (char *)"/tmp/sapp_change_root_dir_test/config";	
	sapp_change_root_dir_args[8] = NULL;

	system("mkdir -p /tmp/sapp_change_root_dir_test/data");
	system("mkdir -p /tmp/sapp_change_root_dir_test/config");
	system("mkdir -p /tmp/sapp_change_root_dir_test/config/sapp");
	system("mkdir -p /tmp/sapp_change_root_dir_test/config/sapp/etc");
	system("mkdir -p /tmp/sapp_change_root_dir_test/config/etc");
	system("mkdir -p /tmp/sapp_change_root_dir_test/config/plug");

	system("rm -f /tmp/sapp_change_root_dir_test/data/sysinfo.log");

	set_default_config();

	update_config_file("./etc/sapp.toml", "dumpfile_sleep_time_before_exit", "0");

	/* 因为配置文件路径里包括'/', 会和sed命令冲突, 需要使用二次转义, 
       第一次用两个连续的\\, 表示真实的'\',
       第二次转义后其实变成了\x2F, 对于sed来说表示真实的'/'
	*/
	update_config_file("./etc/sapp.toml", "cfg_file_sapp_log", "\\x22\\x2Ftmp\\x2Fsapp_change_root_dir_test\\x2Fconfig\\x2Fetc\\x2Fsapp_log.conf\\x22");
	update_config_file("./etc/sapp.toml", "cfg_file_plug_list", "\\x22\\x2Ftmp\\x2Fsapp_change_root_dir_test\\x2Fconfig\\x2Fplug\\x2Fconflist.inf\\x22");

	update_config_file("./etc/sapp.toml", "data_file_sysinfo_log", "\\x22\\x2Ftmp\\x2Fsapp_change_root_dir_test\\x2Fdata\\x2Fsysinfo.log\\x22");

	
	update_plugin_inf("TCP", "ctrl_get_root_dir_entry");

	
	/* 等修改完默认参数后, 再将其copy到指定测试目录下 */
	system("cp -f ./etc/sapp.toml /tmp/sapp_change_root_dir_test/config/sapp/etc/sapp.toml");
	system("cp -f ./plug/conflist.inf /tmp/sapp_change_root_dir_test/config/plug/conflist.inf");
	
	set_pcap_dumpfile("tcp/tcp_simple.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"), 0);
	
	call_libsapp_devel_with_args(8, sapp_change_root_dir_args);	

	/* 执行完后再检查一下数据目录是否有sysinfo.log, 是否日志里的数据符合预期 */
	ASSERT_EQ(expect_file_has_some_string("/tmp/sapp_change_root_dir_test/data/sysinfo.log", "17.75K"), 0);
	ASSERT_EQ(expect_file_has_some_string("/tmp/sapp_change_root_dir_test/data/sysinfo.log", "16.82K"), 0);
	ASSERT_EQ(expect_file_has_some_string("/tmp/sapp_change_root_dir_test/data/sysinfo.log", "13674"), 0);
}


/*
	测试stream bridge接口功能
*/
void stream_bridge_test_run(void)
{
	set_default_config();
	
	/* 至少需要三个插件测试bridge功能, 创建两个新插件目录 */
	system("mkdir -p ./plug/business/gtest_sapp_1");
	system("mkdir -p ./plug/business/gtest_sapp_2");
	system("cp ./plug/business/gtest_sapp/libgtest_sapp.so ./plug/business/gtest_sapp_1/");
	system("cp ./plug/business/gtest_sapp/libgtest_sapp.so ./plug/business/gtest_sapp_2/");

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "tcp_bridge_producer_init", NULL, "TCP", "tcp_bridge_producer_entry");
	update_plugin_inf_with_options("./plug/business/gtest_sapp_1", "gtest1", "tcp_bridge_customer1_init", NULL, "TCP", "tcp_bridge_customer1_entry");
	update_plugin_inf_with_options("./plug/business/gtest_sapp_2", "gtest2", "tcp_bridge_customer2_init", NULL, "TCP", "tcp_bridge_customer2_entry");
	
	/* 更新插件conflist, 第一次使用update, 后续使用append */
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf");
	append_conflist_inf("./plug/business/gtest_sapp_1/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp_2/gtest_sapp.inf"); 

	set_pcap_dumpfile("tcp/tcp_simple.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);	
}


/*
	插件通过四元组找到streaminfo测试,

	通过读取一堆pcap包, 从中精确找到一个流.
*/
void find_streaminfo_v4_run(void)
{
	const char *sapp_hybrid_file_list_args[4];

	sapp_hybrid_file_list_args[0] = (char *)"./sapp ";
	sapp_hybrid_file_list_args[1] = (char *)"--dumpfile-list";
	sapp_hybrid_file_list_args[2] = (char *)"ls ../benchmark_pcap/for_gtest_only/hybrid_pcap/*.pcap";
	sapp_hybrid_file_list_args[3] = NULL;
	
	set_default_config();
	
	update_config_file("etc/sapp.toml", "worker_threads", "4"); /* 把线程数设多一些, 测试在不同线程里polling查找功能 */
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "reorder_pkt_max", "100");
	update_config_file("etc/sapp.toml", "timeout", "0");
	// update_config_file("etc/sapp.toml", "monitor_thread_enabled", "1");

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "gtest_sapp_slave_init", NULL, "TCP_ALL", "void_entry");
	append_plugin_inf("UDP", "void_entry");
	append_plugin_inf("POLLING", "polling_find_streaminfo_entry_v4");

	ASSERT_EQ(directory_md5_checksum("../benchmark_pcap/for_gtest_only/hybrid_pcap/", "da53135d294c280e391ce5879a307cc4"),0);
	
	call_libsapp_devel_with_args(3, sapp_hybrid_file_list_args);	
}


void find_streaminfo_v6_run(void)
{
	const char *sapp_hybrid_file_list_args[4];

	sapp_hybrid_file_list_args[0] = (char *)"./sapp ";
	sapp_hybrid_file_list_args[1] = (char *)"--dumpfile-list";
	sapp_hybrid_file_list_args[2] = (char *)"ls ../benchmark_pcap/for_gtest_only/ipv6/*.pcap";
	sapp_hybrid_file_list_args[3] = NULL;
	
	set_default_config();
	
	update_config_file("etc/sapp.toml", "worker_threads", "6"); /* 把线程数设多一些, 测试在不同线程里polling查找功能 */
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "reorder_pkt_max", "100");
	update_config_file("etc/sapp.toml", "timeout", "0");
	update_config_file("etc/sapp.toml", "dumpfile_sleep_time_before_exit", "0");

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "gtest_sapp_slave_init", NULL, "TCP_ALL", "void_entry");
	append_plugin_inf("UDP", "void_entry");
	append_plugin_inf("POLLING", "polling_find_streaminfo_entry_v6");

	ASSERT_EQ(directory_md5_checksum("../benchmark_pcap/for_gtest_only/ipv6/", "c20353018c27c30fb61edcd5a1a9665b"),0);
	
	call_libsapp_devel_with_args(3, sapp_hybrid_file_list_args);	
}


/*
	内层四元组一样, 但外层不一样的四元组地址查询.
*/
void find_streaminfo_diff_tunnel_v4_run(void)
{	
	const char *find_streaminfo_argv[4];

	find_streaminfo_argv[0] = (char *)"./sapp";
	find_streaminfo_argv[1] = (char *)"--dumpfile";
	find_streaminfo_argv[2] = (char *)"--dumpfile-speed=timestamp";
	find_streaminfo_argv[3] = NULL;


	set_default_config();
	
	update_config_file("etc/sapp.toml", "worker_threads", "1");  
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "reorder_pkt_max", "100");
	update_config_file("etc/sapp.toml", "timeout", "0");
	update_config_file("etc/sapp.toml", "monitor_thread_enabled", "0");

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "gtest_sapp_slave_init", NULL, "TCP_ALL", "void_entry");
	append_plugin_inf("UDP", "void_entry");
	append_plugin_inf("POLLING", "polling_find_diff_tunnel_streaminfo_entry_v4");

	set_pcap_dumpfile("for_gtest_only/control/same_inner_diff_outer_tuple4.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "a2d2d954be5f135751aba51717eafe60"),0);

	call_libsapp_devel_with_args(3, find_streaminfo_argv);	
}


/*
	程序崩溃后breakpad会fork一个新进程，收集崩溃现场，并上传到服务器，
	此过程会继承sapp监听的所有socket，如果minidump上传时间比较长，	
	会导致sapp再重启时会发现端口还在被minidump占用，而无法及时启动。
	此用例用于验证sapp的socket和占用端口是否能被及时关闭.
*/
void control_fork_listen_port_run(void)
{
	const char *sapp_timestamp_argv[4];

	sapp_timestamp_argv[0] = (char *)"./sapp ";
	sapp_timestamp_argv[1] = (char *)"--dumpfile";
	sapp_timestamp_argv[2] = (char *)"--dumpfile-speed=timestamp";
	sapp_timestamp_argv[3] = NULL;
	
	FILE *result_fp;
	char result[1024] = {};
	const char *check_listen_cmd = "netstat -antp | grep sapp| grep LISTEN | grep 12345"; 
	
	set_default_config();

	gtest_set_timeout_default_result(GTEST_SAPP_ERR);

	update_config_file_by_lastline("etc/sapp.toml", "tools.pkt_dump", "enabled", "1"); 
	update_config_file_by_lastNline("etc/sapp.toml", "tools.pkt_dump", 2, "mode", "udp_socket");
	update_config_file_by_lastNline("etc/sapp.toml", "tools.pkt_dump", 3, "mode", "udp_socket");
	update_config_file("etc/sapp.toml", "command_port", "12345"); 
	update_config_file("etc/sapp.toml", "monitor_thread_enabled", "0"); 
	update_plugin_inf("TCP", "fork_listen_port_tcp_plug");
	
	set_pcap_dumpfile("tcp/tcp_simple.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);	
	
	call_libsapp_devel_with_args(3, sapp_timestamp_argv);	

	/*************** 执行到此处, 父sapp进程已经退出, fork出来的sapp子进程可能刚刚启动, 检查一下12345是否还被占用 *****************/

	sleep(1);

	result_fp = popen(check_listen_cmd, "r"); /* 父进程退出后, fork出来的子进程不应该再监听任何端口了!! */
	if(NULL == result_fp){
		printf("\033[1;31;40mfork_listen_port error, popen cmd %s fail\033[0m\n", check_listen_cmd);
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
		return;
	}

	fgets(result, sizeof(result), result_fp);
	
	if(strlen(result) == 0){ /* netstat命令无结果, 是正确的 */
		printf("\033[32mfork_listen_port test success!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);
	}else{
		printf("\033[1;31;40mfork_listen_port check error, some port is opened:\n%s\n\033[0m\n", result);
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
	}	

	fclose(result_fp);

	system("killall -9 sapp"); /* 把sapp插件fork的子进程杀掉 */
}


void toml_array_parse_run(void)
{
	set_default_config();
	
	update_plugin_inf("TCP", "toml_array_parse_plug");
	
	set_pcap_dumpfile("tcp/tcp_simple.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);
	
	//call_libsapp_devel_with_args(2, sapp_start_args);	
	call_libsapp_devel_for_dumpfile_topspeed();
}


void get_linkdir_from_mac_run(void)
{
	set_default_config();
	/* 
		16进制 字符
		0x22   "
		0x2F   /
	*/	
	update_config_file("etc/sapp.toml", "extract_linkdir_from_mac_in_mirror_mode", "\\x22ether[4]:0\\x22");  
	update_plugin_inf("TCP_ALL", "get_linkdir_from_mac_tcpall_entry0");
	
	set_pcap_dumpfile("for_gtest_only/linkinfo/get_linkdir_from_mac_0.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "9f3f4bc66b4393b99042988f7a4be4b3"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);	
}

void get_linkdir_from_mac_run2(void)
{
	set_default_config();

	/* 
		16进制 字符
		0x22   "
		0x2F   /
	*/	
	update_config_file("etc/sapp.toml", "extract_linkdir_from_mac_in_mirror_mode", "\\x22ether[4]:0\\x22");  
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_plugin_inf("TCP_ALL", "get_linkdir_from_mac_tcpall_entry1");
	
	set_pcap_dumpfile("for_gtest_only/linkinfo/get_linkdir_from_mac_1.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "626820eaf50d623a7f1de1df85209bd5"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);	
}


void get_deployment_mode_mirror(void)
{
	set_default_config();
	update_plugin_inf("TCP", "get_deployment_mode_tcp_udp_entry");
	
	set_pcap_dumpfile("tcp/tcp_simple.pcap");  /* 随便找个包, 什么都行, 但是为了区别, 三个模式的包要不一样 */
	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);	
}


void get_deployment_mode_transparent(void)
{
	set_default_config();
	transparent_network_env_init();
	update_plugin_inf("POLLING", "get_deployment_mode_tcpall_entry");
	update_config_file_by_lastNline("etc/sapp.toml", "packet_io.internal.interface", 1, "name", "lo");
	update_config_file_by_lastNline("etc/sapp.toml", "packet_io.internal.interface", 2, "name", "lo");
	update_config_file_by_lastNline("etc/sapp.toml", "packet_io.external.interface", 1, "name", "lo");
	update_config_file_by_lastNline("etc/sapp.toml", "packet_io.external.interface", 2, "name", "lo");
	set_pcap_dumpfile("tcp/tcp_isn_c2s_single.pcap");  /* 随便找个包, 什么都行, 但是为了区别, 三个模式的包要不一样 */
	ASSERT_EQ(file_md5_checksum("dumpfile", "a5d0d96ee6f44f729d79aeac5cc2fee0"),0);
	call_libsapp_devel_with_args(1, sapp_transparent_start_args);	

}

void get_deployment_mode_inline(void)
{
	set_default_config();
	update_config_file("etc/sapp.toml", "l2_l3_tunnel_support", "1");
	update_config_file("etc/sapp.toml", "overlay_mode", "vxlan");
	update_config_file_by_lastline("etc/sapp.toml", "packet_io.deployment", "mode", "inline");
	update_config_file_by_lastNline("etc/sapp.toml", "packet_io.internal.interface", 1, "name", "lo");
	update_config_file_by_lastNline("etc/sapp.toml", "packet_io.internal.interface", 2, "name", "lo");
	update_config_file_by_lastNline("etc/sapp.toml", "packet_io.internal.interface", 1, "type", "pcap");  /* 此处用pcap模式测试, 不需要借助fake marsio */
	update_config_file_by_lastNline("etc/sapp.toml", "packet_io.internal.interface", 2, "type", "pcap");  /* 此处用pcap模式测试, 不需要借助fake marsio */
	update_config_file("etc/sapp.toml", "pcap_capture_direction", "\"in\"");
	set_default_asymmetric_presence_layer_conf("#"); /* vxlan inline模式下, asymmetric_presence_layer默认为空 */
	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "10.3.36.1");
	update_plugin_inf("POLLING", "get_deployment_mode_tcp_udp_entry"); 

	set_pcap_dumpfile("for_gtest_only/inline/tcp_flow_stat.pcap"); /* 随便找个包, 什么都行, 但是为了区别, 三个模式的包要不一样 */
	ASSERT_EQ(file_md5_checksum("dumpfile", "917fd6b8bc70e02812a036adf637479b"),0);

	call_libsapp_devel_with_args(1, sapp_inline_start_args);
}

void control_get_ip_ttl_run(void)
{
	set_default_config();
	
	update_plugin_inf("TCP_ALL", "get_ip_ttl_entry");
	append_plugin_inf("UDP", "get_ip_ttl_entry");
	
	set_pcap_dumpfile("for_gtest_only/control/get_ip_ttl_hybrid.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "434d6a566709f0f78c44c7f3cb7b934b"),0);
	call_libsapp_devel_for_dumpfile_topspeed();
}

void control_get_tcp_rtt_run(void)
{
	set_default_config();
	update_plugin_inf("TCP", "get_tcp_rtt_entry");
	
	set_pcap_dumpfile("for_gtest_only/tcp/tcp_rtt.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "1e06f7ed52405f9014bea2b117ecadff"),0);

	call_libsapp_devel_for_dumpfile_timestamp();
}

void control_get_tcp_rtt_c2s_run(void)
{
	set_default_config();
	update_plugin_inf("TCP", "get_tcp_rtt_err_entry");
	
	set_pcap_dumpfile("tcp/tcp_isn_c2s_single.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "a5d0d96ee6f44f729d79aeac5cc2fee0"),0);

	call_libsapp_devel_for_dumpfile_timestamp();
}

void control_get_tcp_rtt_s2c_run(void)
{
	set_default_config();
	update_plugin_inf("TCP", "get_tcp_rtt_err_entry");
	
	set_pcap_dumpfile("for_gtest_only/tcp/tcp_rtt_s2c.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "006277b38aa1f9a0d272b643b8a3b686"),0);

	call_libsapp_devel_for_dumpfile_timestamp();
}
