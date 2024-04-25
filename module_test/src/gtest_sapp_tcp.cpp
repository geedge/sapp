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


void tcpall_simple_run(void)
{
	set_default_config();
	update_plugin_inf("TCP_ALL", "tcpall_simple");

	set_pcap_dumpfile("tcp/tcp_simple.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}

void tcp_simple_run(void)
{
	set_default_config();
	update_plugin_inf("TCP", "tcp_simple");
	
	set_pcap_dumpfile("tcp/tcp_simple.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}


/* TCP乱序重组测试 */
void tcp_oos_run(void)
{
	set_default_config();
#if SAPP_V3	
	update_config_file("conf/main.conf", "MaxUnorderNum", "5");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "reorder_pkt_max", "5");
#else
	abort();
#endif
	update_plugin_inf("TCP", "tcp_oos_entry");
	
	set_pcap_dumpfile("tcp/tcp_out_of_order.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "975b0c020059c4a1aa9ae56c0926f17b"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}


/* TCP因乱�?? 且最大乱序数不合适导致丢包测�??*/
void tcp_oos_lost_pkt_run(void)
{
	set_default_config();
#if SAPP_V3	
	update_config_file("conf/main.conf", "MaxUnorderNum", "3"); /* 最大乱序数小于实际乱序的包间隔, 会导致认为是丢包 */
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "reorder_pkt_max", "3"); /* 最大乱序数小于实际乱序的包间隔, 会导致认为是丢包 */
#else
	abort();
#endif
	update_plugin_inf("TCP", "tcp_oos_lost_pkt_entry");
	
	set_pcap_dumpfile("tcp/tcp_out_of_order.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "975b0c020059c4a1aa9ae56c0926f17b"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}


void tcp_timeout_reset_run(void)
{
	set_default_config();

#if SAPP_V3	
	update_config_file("conf/main.conf", "dumpfile_speed", "timestamp");
	update_config_file("conf/main.conf", "LinkTimeout", "3");
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "timeout", "3");
	update_config_file("etc/sapp.toml", "syn_mandatory", "1");
#else
	abort();
#endif

	update_plugin_inf("TCP_ALL", "tcpall_pkt_stat");
	append_plugin_inf("TCP", "tcp_pkt_stat");
	append_plugin_inf("IP", "ip_entry_check_tcp_timeout");

	set_pcap_dumpfile("tcp/tcp_timeout_reset.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "9e8c65901915a0535d210e3766030b9e"),0);

	printf("test for timeout_reset, set --dumpfile-speed=timestamp please wait for a monment......\n");
		
	call_libsapp_devel_for_dumpfile_timestamp();
}


void tcp_deduce_flow_stat_run(void)
{
	set_default_config();
	set_project_list_conf_default();
	update_plugin_inf("TCP", "tcp_dedece_flow_stat");
	
	set_pcap_dumpfile("tcp/tcp_deduce_flow.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "cc9bf432209d1cc868bac3fc668c1e2d"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}


void tcp_call_order_check_run(void)
{
	set_default_config();
	set_project_list_conf_default();
	update_plugin_inf("TCP", "tcp_call_order_check");
	append_plugin_inf("TCP_ALL", "tcpall_call_order_check");

	set_pcap_dumpfile("tcp/tcp_simple.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}


void tcp_call_order_for_reset_check_run(void)
{
	set_default_config();
#if SAPP_V3		
	update_config_file("conf/main.conf", "LinkTimeout", "3");
	update_config_file("conf/main.conf", "CreatLinkMode", "3");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "timeout", "3");
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");	
#endif

	set_project_list_conf_default();
	
	update_plugin_inf("TCP", "tcp_call_order_for_reset_check");
	append_plugin_inf("TCP_ALL", "tcpall_call_order_for_reset_check");
		
	set_pcap_dumpfile("tcp/tcp_reset_call_order.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "8b8e378c37d3fbc36fc64ceb6a69aaa9"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}



static void tcp_plug_killother_env_init(void)
{
	set_default_config();

	/* 创建插件目录 */
	system("mkdir -p ./plug/business/gtest_sapp_droppkt_1");
	system("mkdir -p ./plug/business/gtest_sapp_droppkt_2");

	append_project_list_conf("droppkt_stat", "struct");

	update_plugin_inf_with_options("./plug/business/gtest_sapp_droppkt_1", "gtest_first", "tcp_plug_droppkt_first_init", NULL, "TCP", "tcp_plug_droppkt_first");
	update_plugin_inf_with_options("./plug/business/gtest_sapp_droppkt_2", "gtest_second", "tcp_plug_droppkt_second_init", NULL, "TCP", "tcp_plug_droppkt_second");

	update_conflist_inf("plug/business/gtest_sapp_droppkt_1/gtest_sapp.inf");
	append_conflist_inf("plug/business/gtest_sapp_droppkt_2/gtest_sapp.inf");

	set_pcap_dumpfile("tcp/tcp_simple.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);

	system("cp -f ./plug/business/gtest_sapp/libgtest_sapp.so ./plug/business/gtest_sapp_droppkt_1/");
	system("cp -f ./plug/business/gtest_sapp/libgtest_sapp.so ./plug/business/gtest_sapp_droppkt_2/");
}


/* 测试插件返回DROPPKT处理逻辑 */
void tcp_plug_killother_run(void)
{
	set_default_config();
	tcp_plug_killother_env_init();
	
	set_pcap_dumpfile("tcp/tcp_simple.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}

#if SAPP_V4 

void tcp_lost_pkt_run(void)
{
	set_default_config();
	update_config_file("etc/sapp.toml", "syn_mandatory", "1");
	
	update_plugin_inf("TCP", "tcp_lost_pkt_entry");
	append_plugin_inf("UDP", "tcp_lost_pkt_udp_entry");

	set_pcap_dumpfile("for_gtest_only/tcp/tcp_lost_pkt.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "9d8180519a40c595435f350b10662957"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}

/*
	人为构造的pcap丢包测试.
	真正的原始数据是:
		11111111111111111111111111111111111111111111111
		22222222222222222222222222222222222222222222222
		33333333333333333333333333333333333333333333333
		44444444444444444444444444444444444444444444444
		55555555555555555555555555555555555555555555555
	故意将第3个数据包删除, 测试丢包检测功�??
*/
void tcp_lost_pkt_manual_run(void)
{
	set_default_config();
	update_config_file("etc/sapp.toml", "syn_mandatory", "1");
	update_config_file("etc/sapp.toml", "reorder_on_closing", "1");
	update_plugin_inf("TCP", "tcp_lost_pkt_port55555_entry");

	set_pcap_dumpfile("for_gtest_only/tcp/tcp_lost_pkt_55555.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "758f3936c830a643b56f582383d24be0"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}

#endif


void tcp_raw_entry_run(void)
{
	set_default_config();
	update_plugin_inf("TCP_RAW", "tcp_raw_entry");
	
	set_pcap_dumpfile("tcp/tcp_simple.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}

/*
	读取一批pcap文件, 这些小pcap文件实际是通过editcap切割一个原始pcap文件而得�??
	目的是测�??f --dumpfile-list参数功能.
*/
void tcp_dumpfile_list_run(void)
{
	int ret;
	set_default_config();
	update_plugin_inf("TCP", "tcp_dumpfile_list_entry");
		
	gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);

	if(g_slient_mode){
		char *sapp_dumpfile_start_args[] = {(char *)"./sapp", (char *)"-s", (char *)"-d", (char *)"-n", (char *)"--dumpfile-list=find ../benchmark_pcap/for_gtest_only/tcp/dumpfile.list/ -name dumpfile.list_* | sort", (char *)NULL};
		ret = libsapp_setup_env(5, sapp_dumpfile_start_args);
	}else{
		char *sapp_dumpfile_start_args[] = {(char *)"./sapp", (char *)"-d", (char *)"-n", (char *)"--dumpfile-list=find ../benchmark_pcap/for_gtest_only/tcp/dumpfile.list/ -name dumpfile.list_* | sort", (char *)NULL};
		ret = libsapp_setup_env(4, sapp_dumpfile_start_args);
	}

	if(ret < 0){
		printf("call libsapp_setup_env() fail");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return;
	}
	while(sapp_get_current_state() != SAPP_STATE_READY_TO_EXIT){
		usleep(100);
	}
	libsapp_destroy_env();
}


void tcp_dup_pkt_positive_run(void)
{
	set_default_config();
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "original_ipv4_tcp_enabled", "1");
	update_config_file("etc/sapp.toml", "bloom_capacity", "1000000");
	update_config_file("etc/sapp.toml", "bloom_error_rate", "0.00001");
	update_config_file("etc/sapp.toml", "bloom_timeout", "10");
	/* tcp层的重复数据包不能在tcp入口测试,因为序号一样肯定被认为是重传而不调用插件,要挂载到TCP_ALL�?? 	    */
	update_plugin_inf("TCP_ALL", "tcpall_dup_pkt_positive_check");
	/* 此pcap包一共有9个包,前两个和后两个是人为制造的重复包, tcpall插件应该只收到7个包才是对的 */	
	set_pcap_dumpfile("for_gtest_only/duplicate_packet/tcp_no_syn_dup.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "a56bfea74cd5168e9e3cbf1e2c5c17fb"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}

void tcp_dup_pkt_negative_run(void)
{
	set_default_config();
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "original_ipv4_tcp_enabled", "0");
	update_config_file("etc/sapp.toml", "inject_all_enabled", "1");
	update_config_file("etc/sapp.toml", "bloom_capacity", "1000000");
	update_config_file("etc/sapp.toml", "bloom_error_rate", "0.00001");
	update_config_file("etc/sapp.toml", "bloom_timeout", "10");
	/* tcp层的重复数据包不能在tcp入口测试,因为序号一样肯定被认为是重传而不调用插件,要挂载到TCP_ALL�?? 	    */
	update_plugin_inf("TCP_ALL", "tcpall_dup_pkt_negative_check");
	/* 此pcap包一共有9个包,前两个和后两个是人为制造的重复包, 关闭重复包检查, tcpall插件应该全收到9个包才是对的 */	
	set_pcap_dumpfile("for_gtest_only/duplicate_packet/tcp_no_syn_dup.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "a56bfea74cd5168e9e3cbf1e2c5c17fb"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}

/*
	一个流有乱序包, 但是插件曾经调用过MSO_DROP_STREAM, 理论上什么情况都不应该再调用插件�??
*/
void tcp_dropstream_and_unorder_run(void)
{
	set_default_config();
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "reorder_pkt_max", "3");
	update_plugin_inf("TCP", "tcp_dropstream_and_unorder_entry");
	
	set_pcap_dumpfile("for_gtest_only/tcp/tcp_drop_stream_and_unorder.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "fe568321658ed650e5b280c98345d79a"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}

/*
	期待�??gtest_sapp_hybrid_stream.log 日志内容:
	
stream:192.168.36.103.57222>120.241.25.57.36688,c2s_pkt:5,c2s_byte:548,s2c_pkt:4,s2c_byte:20
stream:192.168.36.103.57235>120.241.25.15.36688,c2s_pkt:7,c2s_byte:424,s2c_pkt:5,s2c_byte:40
stream:192.168.36.103.57236>120.241.25.15.36688,c2s_pkt:9,c2s_byte:636,s2c_pkt:6,s2c_byte:60
stream:192.168.36.103.57241>120.241.25.15.36688,c2s_pkt:13,c2s_byte:1060,s2c_pkt:8,s2c_byte:100
stream:192.168.36.103.57264>120.241.25.15.36688,c2s_pkt:11,c2s_byte:848,s2c_pkt:7,s2c_byte:80
stream:192.168.36.103.57285>218.60.109.3.443,c2s_pkt:6,c2s_byte:597,s2c_pkt:9,s2c_byte:4687
stream:192.168.36.103.57288>182.61.128.177.443,c2s_pkt:6,c2s_byte:517,s2c_pkt:5,s2c_byte:4003
stream:192.168.36.103.57289>182.61.128.177.443,c2s_pkt:6,c2s_byte:517,s2c_pkt:5,s2c_byte:4003
stream:192.168.36.103.57290>182.61.128.177.443,c2s_pkt:6,c2s_byte:517,s2c_pkt:5,s2c_byte:4003
stream:192.168.36.103.57273>121.43.68.40.80,c2s_pkt:6,c2s_byte:433,s2c_pkt:4,s2c_byte:388
stream:192.168.36.103.57277>120.241.25.15.36688,c2s_pkt:11,c2s_byte:848,s2c_pkt:7,s2c_byte:80
stream:192.168.36.103.57295>120.52.148.41.443,c2s_pkt:10,c2s_byte:1989,s2c_pkt:11,s2c_byte:5070
stream:192.168.36.103.57299>120.52.148.41.443,c2s_pkt:8,c2s_byte:2138,s2c_pkt:6,s2c_byte:840
stream:192.168.36.103.57302>120.52.30.248.443,c2s_pkt:9,c2s_byte:2892,s2c_pkt:11,s2c_byte:4784
stream:192.168.36.103.57303>120.52.30.248.443,c2s_pkt:8,c2s_byte:3046,s2c_pkt:7,s2c_byte:459
stream:192.168.36.103.57217>125.94.242.80.20001,c2s_pkt:2,c2s_byte:1,s2c_pkt:2,s2c_byte:0
stream:192.168.36.103.57306>120.52.30.248.443,c2s_pkt:8,c2s_byte:2506,s2c_pkt:7,s2c_byte:459
stream:192.168.36.103.57304>120.241.25.15.36688,c2s_pkt:5,c2s_byte:212,s2c_pkt:4,s2c_byte:20
stream:192.168.36.103.57308>36.110.180.185.443,c2s_pkt:6,c2s_byte:597,s2c_pkt:9,s2c_byte:4653
stream:192.168.36.103.57309>120.52.30.248.443,c2s_pkt:10,c2s_byte:2943,s2c_pkt:11,s2c_byte:4784
stream:192.168.36.103.57310>120.241.25.15.36688,c2s_pkt:6,c2s_byte:212,s2c_pkt:4,s2c_byte:20
stream:192.168.36.103.57311>120.52.30.248.443,c2s_pkt:8,c2s_byte:3055,s2c_pkt:7,s2c_byte:459
stream:192.168.36.103.57312>120.52.30.248.443,c2s_pkt:8,c2s_byte:3055,s2c_pkt:7,s2c_byte:459
stream:192.168.36.103.57313>120.241.25.15.36688,c2s_pkt:5,c2s_byte:212,s2c_pkt:4,s2c_byte:20
stream:192.168.36.103.57314>120.241.25.15.36688,c2s_pkt:11,c2s_byte:848,s2c_pkt:7,s2c_byte:80
stream:192.168.36.103.57251>182.61.200.178.443,c2s_pkt:13,c2s_byte:4822,s2c_pkt:15,s2c_byte:2660
stream:192.168.36.103.57214>125.94.242.79.20001,c2s_pkt:3,c2s_byte:2,s2c_pkt:3,s2c_byte:0
stream:192.168.36.103.57323>120.241.25.15.36688,c2s_pkt:9,c2s_byte:636,s2c_pkt:6,s2c_byte:60
stream:192.168.36.103.57322>47.93.59.84.443,c2s_pkt:49,c2s_byte:4384,s2c_pkt:97,s2c_byte:63710
stream:192.168.36.103.57249>182.61.128.173.443,c2s_pkt:18,c2s_byte:7087,s2c_pkt:29,s2c_byte:19778
stream:192.168.36.103.57325>120.241.25.15.36688,c2s_pkt:5,c2s_byte:423,s2c_pkt:4,s2c_byte:20
stream:192.168.36.103.57324>47.93.59.84.443,c2s_pkt:15,c2s_byte:3360,s2c_pkt:15,s2c_byte:1863
stream:192.168.36.103.57245>182.61.128.164.443,c2s_pkt:39,c2s_byte:16954,s2c_pkt:96,s2c_byte:73223
stream:192.168.36.103.57262>182.61.128.187.443,c2s_pkt:18,c2s_byte:3328,s2c_pkt:33,s2c_byte:25259
stream:192.168.36.103.57248>182.61.128.163.443,c2s_pkt:30,c2s_byte:1650,s2c_pkt:122,s2c_byte:135305
stream:192.168.36.103.57326>120.241.25.15.36688,c2s_pkt:5,c2s_byte:212,s2c_pkt:4,s2c_byte:20
stream:192.168.36.103.57328>125.94.242.79.20001,c2s_pkt:7,c2s_byte:409,s2c_pkt:7,s2c_byte:349
stream:192.168.36.103.57283>106.120.182.36.80,c2s_pkt:8,c2s_byte:411,s2c_pkt:16,s2c_byte:17647
stream:192.168.36.103.57300>120.52.30.45.443,c2s_pkt:13,c2s_byte:1681,s2c_pkt:16,s2c_byte:5241
stream:192.168.36.103.57296>120.52.148.168.443,c2s_pkt:28,c2s_byte:3050,s2c_pkt:42,s2c_byte:31878
stream:192.168.36.103.57329>47.93.59.84.443,c2s_pkt:11,c2s_byte:1459,s2c_pkt:13,s2c_byte:819
stream:192.168.36.103.57298>211.144.24.231.443,c2s_pkt:19,c2s_byte:2547,s2c_pkt:18,s2c_byte:6667
stream:192.168.36.103.57330>121.51.73.101.80,c2s_pkt:5,c2s_byte:728,s2c_pkt:4,s2c_byte:1211
stream:192.168.36.103.57297>111.206.228.111.443,c2s_pkt:17,c2s_byte:2015,s2c_pkt:22,s2c_byte:11083
stream:192.168.36.103.57305>120.52.148.21.443,c2s_pkt:15,c2s_byte:2067,s2c_pkt:16,s2c_byte:5122
stream:192.168.36.103.57301>111.206.227.174.443,c2s_pkt:20,c2s_byte:1544,s2c_pkt:20,s2c_byte:6070
stream:192.168.36.103.57307>36.110.180.185.443,c2s_pkt:19,c2s_byte:5964,s2c_pkt:20,s2c_byte:5248
stream:192.168.36.103.57331>120.241.25.15.36688,c2s_pkt:7,c2s_byte:424,s2c_pkt:5,s2c_byte:40
stream:192.168.36.103.57339>120.241.25.15.36688,c2s_pkt:9,c2s_byte:636,s2c_pkt:6,s2c_byte:60
stream:192.168.36.103.57354>182.254.48.242.443,c2s_pkt:7,c2s_byte:610,s2c_pkt:10,s2c_byte:5213
stream:192.168.36.103.57352>182.254.48.242.443,c2s_pkt:6,c2s_byte:610,s2c_pkt:10,s2c_byte:5213
stream:192.168.36.103.57361>120.241.16.16.443,c2s_pkt:8,c2s_byte:1719,s2c_pkt:9,s2c_byte:4333
stream:192.168.36.103.57294>111.206.227.146.443,c2s_pkt:111,c2s_byte:84220,s2c_pkt:94,s2c_byte:27391
stream:192.168.36.103.57252>182.61.200.6.443,c2s_pkt:17,c2s_byte:4243,s2c_pkt:24,s2c_byte:5124
stream:192.168.36.103.57263>182.61.200.7.443,c2s_pkt:20,c2s_byte:8282,s2c_pkt:27,s2c_byte:5545
stream:192.168.36.103.57250>182.61.200.6.443,c2s_pkt:19,c2s_byte:7645,s2c_pkt:20,s2c_byte:1122
stream:192.168.36.103.57244>182.61.200.6.443,c2s_pkt:79,c2s_byte:41386,s2c_pkt:206,s2c_byte:196849
stream:192.168.36.103.57363>120.241.25.15.36688,c2s_pkt:5,c2s_byte:212,s2c_pkt:4,s2c_byte:20
stream:192.168.36.103.57364>120.241.25.15.36688,c2s_pkt:5,c2s_byte:212,s2c_pkt:4,s2c_byte:20
stream:192.168.36.103.57367>120.241.25.15.36688,c2s_pkt:5,c2s_byte:423,s2c_pkt:4,s2c_byte:20
stream:192.168.36.103.57374>125.94.242.79.20001,c2s_pkt:7,c2s_byte:409,s2c_pkt:7,s2c_byte:349
stream:192.168.36.103.57375>120.241.25.15.36688,c2s_pkt:5,c2s_byte:212,s2c_pkt:4,s2c_byte:20
stream:192.168.36.103.57261>182.61.128.166.443,c2s_pkt:35,c2s_byte:1843,s2c_pkt:168,s2c_byte:201488
stream:192.168.36.103.57376>120.241.25.15.36688,c2s_pkt:6,c2s_byte:456,s2c_pkt:5,s2c_byte:40
stream:192.168.36.103.57287>182.61.128.177.443,c2s_pkt:153,c2s_byte:8323,s2c_pkt:581,s2c_byte:593649
stream:192.168.36.103.57316>125.94.242.79.20001,c2s_pkt:18,c2s_byte:1629,s2c_pkt:20,s2c_byte:4148
stream:192.168.36.103.57281>218.60.109.3.443,c2s_pkt:20,c2s_byte:3328,s2c_pkt:62,s2c_byte:69502
stream:192.168.36.103.57279>43.254.24.18.80,c2s_pkt:8,c2s_byte:1230,s2c_pkt:6,s2c_byte:644
stream:192.168.36.103.57284>43.254.24.18.80,c2s_pkt:8,c2s_byte:535,s2c_pkt:6,s2c_byte:644
stream:192.168.36.103.57282>112.90.216.109.80,c2s_pkt:11,c2s_byte:2058,s2c_pkt:10,s2c_byte:2137
stream:192.168.36.103.57321>103.151.149.170.80,c2s_pkt:12,c2s_byte:413,s2c_pkt:36,s2c_byte:38843
stream:192.168.36.103.57320>103.151.149.75.80,c2s_pkt:19,c2s_byte:1235,s2c_pkt:58,s2c_byte:69057
stream:192.168.36.103.57332>203.205.254.157.80,c2s_pkt:7,c2s_byte:659,s2c_pkt:5,s2c_byte:367
stream:192.168.36.103.57267>112.90.216.109.80,c2s_pkt:252,c2s_byte:8449,s2c_pkt:574,s2c_byte:716517
stream:192.168.36.103.57270>112.90.216.109.80,c2s_pkt:117,c2s_byte:11175,s2c_pkt:291,s2c_byte:352963
stream:192.168.36.103.57272>112.90.216.109.80,c2s_pkt:98,c2s_byte:15798,s2c_pkt:249,s2c_byte:286088
stream:192.168.36.103.57269>112.90.216.109.80,c2s_pkt:1393,c2s_byte:8497,s2c_pkt:4043,s2c_byte:5372808
stream:192.168.36.103.57271>112.90.216.109.80,c2s_pkt:96,c2s_byte:15650,s2c_pkt:211,s2c_byte:240820
stream:192.168.36.103.57268>112.90.216.109.80,c2s_pkt:152,c2s_byte:16184,s2c_pkt:317,s2c_byte:370583
stream:192.168.36.103.57274>112.90.216.109.80,c2s_pkt:8,c2s_byte:786,s2c_pkt:7,s2c_byte:2470
stream:192.168.36.103.57276>112.90.216.109.80,c2s_pkt:10,c2s_byte:2092,s2c_pkt:7,s2c_byte:1282
stream:192.168.36.103.57280>43.254.24.18.443,c2s_pkt:11,c2s_byte:1378,s2c_pkt:14,s2c_byte:6433
stream:192.168.36.103.57359>113.108.92.147.443,c2s_pkt:13,c2s_byte:1504,s2c_pkt:15,s2c_byte:8858
stream:192.168.36.103.57350>14.22.5.244.443,c2s_pkt:10,c2s_byte:1406,s2c_pkt:14,s2c_byte:6913
stream:192.168.36.103.57348>183.3.226.30.443,c2s_pkt:12,c2s_byte:2190,s2c_pkt:11,s2c_byte:3859
stream:192.168.36.103.57362>183.3.226.92.443,c2s_pkt:11,c2s_byte:1649,s2c_pkt:11,s2c_byte:3985
stream:192.168.36.103.57357>121.51.23.161.443,c2s_pkt:12,c2s_byte:1922,s2c_pkt:13,s2c_byte:4829
stream:192.168.36.103.57347>14.22.9.212.443,c2s_pkt:11,c2s_byte:2074,s2c_pkt:10,s2c_byte:4460
stream:192.168.36.103.57360>139.199.134.168.443,c2s_pkt:12,c2s_byte:1480,s2c_pkt:14,s2c_byte:7638
stream:192.168.36.103.57342>175.27.8.138.443,c2s_pkt:7,c2s_byte:569,s2c_pkt:7,s2c_byte:187
stream:192.168.36.103.57337>175.27.8.138.443,c2s_pkt:19,c2s_byte:3299,s2c_pkt:42,s2c_byte:35049
stream:192.168.36.103.57344>175.27.8.138.443,c2s_pkt:9,c2s_byte:1444,s2c_pkt:12,s2c_byte:3678
stream:192.168.36.103.57343>175.27.8.138.443,c2s_pkt:9,c2s_byte:1441,s2c_pkt:11,s2c_byte:2235
stream:192.168.36.103.57278>112.90.216.109.443,c2s_pkt:20,c2s_byte:2170,s2c_pkt:28,s2c_byte:24050
stream:192.168.36.103.57378>47.93.59.84.443,c2s_pkt:11,c2s_byte:1459,s2c_pkt:12,s2c_byte:810
stream:192.168.36.103.52943>121.51.73.100.8080,c2s_pkt:4,c2s_byte:726,s2c_pkt:7,s2c_byte:2911
stream:192.168.36.103.51246>40.90.189.152.443,c2s_pkt:6,c2s_byte:309,s2c_pkt:3,s2c_byte:519
stream:192.168.36.103.57275>36.112.20.164.443,c2s_pkt:13,c2s_byte:2016,s2c_pkt:13,s2c_byte:8742
stream:192.168.36.103.57258>125.94.242.80.20001,c2s_pkt:13,c2s_byte:861,s2c_pkt:12,s2c_byte:973
stream:192.168.36.103.57259>125.94.242.80.20001,c2s_pkt:13,c2s_byte:861,s2c_pkt:12,s2c_byte:973
stream:192.168.36.103.57260>125.94.242.80.20001,c2s_pkt:17,c2s_byte:2031,s2c_pkt:18,s2c_byte:1709
stream:192.168.36.103.57254>125.94.242.80.20001,c2s_pkt:29,c2s_byte:2615,s2c_pkt:47,s2c_byte:34116
stream:192.168.36.103.57293>218.60.109.3.443,c2s_pkt:15,c2s_byte:1283,s2c_pkt:24,s2c_byte:13754
stream:192.168.36.103.52304>125.94.242.80.20001,c2s_pkt:6,c2s_byte:6,s2c_pkt:6,s2c_byte:0
stream:192.168.36.103.57286>218.60.109.3.443,c2s_pkt:125,c2s_byte:5054,s2c_pkt:526,s2c_byte:657873
stream:192.168.36.103.57266>125.94.242.80.20001,c2s_pkt:45,c2s_byte:12108,s2c_pkt:48,s2c_byte:8225
stream:192.168.36.103.57319>61.48.115.227.443,c2s_pkt:13,c2s_byte:1231,s2c_pkt:16,s2c_byte:5846
stream:192.168.36.103.57317>218.205.239.108.443,c2s_pkt:13,c2s_byte:1220,s2c_pkt:13,s2c_byte:3984
stream:192.168.36.103.57318>59.111.181.60.443,c2s_pkt:23,c2s_byte:3547,s2c_pkt:39,s2c_byte:29107
stream:192.168.36.103.57228>125.94.242.80.20001,c2s_pkt:66,c2s_byte:4938,s2c_pkt:74,s2c_byte:16487
stream:192.168.36.103.57230>125.94.242.80.20001,c2s_pkt:35,c2s_byte:2278,s2c_pkt:39,s2c_byte:8409
stream:192.168.36.103.57234>125.94.242.80.20001,c2s_pkt:56,c2s_byte:3967,s2c_pkt:67,s2c_byte:13041
stream:192.168.36.103.57232>125.94.242.80.20001,c2s_pkt:246,c2s_byte:19556,s2c_pkt:696,s2c_byte:738464
stream:192.168.36.103.57341>123.125.110.212.443,c2s_pkt:12,c2s_byte:1299,s2c_pkt:16,s2c_byte:5473
stream:192.168.36.103.57340>121.51.64.98.443,c2s_pkt:14,c2s_byte:1121,s2c_pkt:41,s2c_byte:37332
stream:192.168.36.103.57336>203.205.254.157.443,c2s_pkt:13,c2s_byte:1400,s2c_pkt:15,s2c_byte:7008
stream:192.168.36.103.57349>61.129.7.75.443,c2s_pkt:12,c2s_byte:1368,s2c_pkt:13,s2c_byte:4150
stream:192.168.36.103.57247>125.94.242.80.20001,c2s_pkt:25,c2s_byte:3483,s2c_pkt:30,s2c_byte:5272
stream:192.168.36.103.57351>182.254.57.118.443,c2s_pkt:151,c2s_byte:16500,s2c_pkt:156,s2c_byte:14205
stream:192.168.36.103.57353>182.254.48.242.443,c2s_pkt:18,c2s_byte:1302,s2c_pkt:30,s2c_byte:26045
stream:192.168.36.103.57355>123.125.46.172.443,c2s_pkt:12,c2s_byte:1176,s2c_pkt:15,s2c_byte:6433
stream:192.168.36.103.57356>121.51.42.248.443,c2s_pkt:12,c2s_byte:1269,s2c_pkt:17,s2c_byte:8871
stream:192.168.36.103.57368>123.57.35.217.22,c2s_pkt:401,c2s_byte:8770,s2c_pkt:261,s2c_byte:31829
stream:192.168.36.103.57345>182.254.60.249.443,c2s_pkt:49,c2s_byte:1842,s2c_pkt:144,s2c_byte:173981
stream:192.168.36.103.57338>182.254.48.49.443,c2s_pkt:111,c2s_byte:4370,s2c_pkt:332,s2c_byte:392665
stream:192.168.36.103.57358>113.96.232.215.443,c2s_pkt:40,c2s_byte:1585,s2c_pkt:164,s2c_byte:198594
stream:192.168.36.103.57346>1.31.173.39.443,c2s_pkt:71,c2s_byte:1605,s2c_pkt:352,s2c_byte:446329
stream:192.168.36.103.57240>125.94.242.80.20001,c2s_pkt:18,c2s_byte:2134,s2c_pkt:17,s2c_byte:2570
stream:192.168.36.103.57238>125.94.242.80.20001,c2s_pkt:21,c2s_byte:2639,s2c_pkt:20,s2c_byte:2772
stream:192.168.36.103.57243>125.94.242.80.20001,c2s_pkt:19,c2s_byte:2179,s2c_pkt:17,s2c_byte:1694
stream:192.168.36.103.57050>192.168.40.161.22,c2s_pkt:7,c2s_byte:181,s2c_pkt:10,s2c_byte:256
stream:192.168.36.103.52508>192.168.36.96.8009,c2s_pkt:80,c2s_byte:4680,s2c_pkt:80,s2c_byte:4680
	
*/
void hybrid_pure_tcp_run(void)
{
	set_default_config();

	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "reorder_pkt_max", "100");
	update_config_file("etc/sapp.toml", "timeout", "0");

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "gtest_sapp_slave_init", "hybrid_tcp_destroy", "TCP", "hybrid_stream_log_entry");

	/* hybrid混合包测试用例不开启重复流量检�??*/
	update_config_file("etc/sapp.toml", "inject_all_enabled", "0");
	update_config_file("etc/sapp.toml", "original_ipv4_tcp_enabled", "0");
	update_config_file("etc/sapp.toml", "original_ipv4_udp_enabled", "0");
	

	set_pcap_dumpfile("for_gtest_only/hybrid_pcap/hybrid_pure_tcp.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "59b3074249c623880f4d76e98d7fe1f7"),0);

	char cmd_buf[128];
	sprintf(cmd_buf, "> %s", GTEST_HYBRID_STREAM_LOG_FILE);
	system(cmd_buf);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}




/*
	单次读取一批pcap包测�?? 期待�??gtest_sapp_hybrid_stream.log:

stream:2001::192:168:40:134.37948>2001::192:168:40:133.22,c2s_pkt:60,c2s_byte:3937,s2c_pkt:41,s2c_byte:4813
stream:2a00:5e80:101:212d:504:7b1:2572:db22.37034>2606:f200:0:7:bad:f00d:d00d:1.80,c2s_pkt:5,c2s_byte:82,s2c_pkt:4,s2c_byte:381
stream:172.16.2.100.50072>10.0.6.229.80,c2s_pkt:6,c2s_byte:511,s2c_pkt:8,s2c_byte:5579
stream:2001:0:4137:9e76:2463:f227:88d7:dabe.63622>2001:252:0:2::2000.80,c2s_pkt:5,c2s_byte:469,s2c_pkt:4,s2c_byte:503
stream:10.58.121.62.52144>217.76.78.112.443,c2s_pkt:1,c2s_byte:0,s2c_pkt:1,s2c_byte:1400
stream:172.16.2.100.49250>10.0.6.229.80,c2s_pkt:22,c2s_byte:2961,s2c_pkt:22,s2c_byte:18802
stream:172.16.44.3.56461>173.194.72.18.443,c2s_pkt:32,c2s_byte:270,s2c_pkt:165,s2c_byte:202804
stream:122.112.114.73.20755>115.238.253.235.53,c2s_pkt:1,c2s_byte:44,s2c_pkt:0,s2c_byte:0
stream:10.166.20.10.2152>10.2.3.35.2152,c2s_pkt:1,c2s_byte:48,s2c_pkt:1,s2c_byte:1448
stream:172.16.0.254.1701>172.16.0.100.1701,c2s_pkt:22,c2s_byte:19970,s2c_pkt:22,s2c_byte:4201
stream:81.211.137.245.55560>81.211.155.24.8246,c2s_pkt:4,c2s_byte:110,s2c_pkt:6,s2c_byte:264
stream:109.6.1.72.1701>95.136.242.99.1701,c2s_pkt:4,c2s_byte:725,s2c_pkt:6,s2c_byte:582
stream:145.220.0.46.62944>192.168.10.144.3544,c2s_pkt:5,c2s_byte:815,s2c_pkt:5,s2c_byte:781


*/
void hybrid_dataset_run(void)
{
	const char *sapp_hybrid_file_list_args[4];

	sapp_hybrid_file_list_args[0] = (char *)"./sapp ";
	sapp_hybrid_file_list_args[1] = (char *)"--dumpfile-list";
	sapp_hybrid_file_list_args[2] = (char *)"ls ../benchmark_pcap/for_gtest_only/hybrid_pcap/dataset/*.pcap";
	sapp_hybrid_file_list_args[3] = NULL;
	
	set_default_config();

	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "reorder_pkt_max", "100");
	update_config_file("etc/sapp.toml", "timeout", "0");

	/* hybrid混合包测试用例不开启重复流量检�??*/
	update_config_file("etc/sapp.toml", "inject_all_enabled", "0");
	update_config_file("etc/sapp.toml", "original_ipv4_tcp_enabled", "0");
	update_config_file("etc/sapp.toml", "original_ipv4_udp_enabled", "0");

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "gtest_sapp_slave_init", "hybrid_all_dataset_destroy", "TCP", "hybrid_stream_log_entry");
	append_plugin_inf("UDP", "hybrid_stream_log_entry");

	char cmd_buf[128];
	sprintf(cmd_buf, "> %s", GTEST_HYBRID_STREAM_LOG_FILE);
	system(cmd_buf);

	ASSERT_EQ(directory_md5_checksum("../benchmark_pcap/for_gtest_only/hybrid_pcap/dataset/", "68c4cf4b739d9d96350aed7529bcefd1"),0);
	
	call_libsapp_devel_with_args(3, sapp_hybrid_file_list_args);
}


/*
	带fin包正常结束的tcp四元组重用测�?? 没有TCP_ALL插件.
*/
void tcp_tuple4_reuse_with_fin_run(void)
{
	set_default_config();

#if SAPP_V3	
	update_config_file("conf/main.conf", "dumpfile_speed", "timestamp");
	update_config_file("conf/main.conf", "LinkTimeout", "3");
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "timeout", "3");
	update_config_file("etc/sapp.toml", "syn_mandatory", "1");
	update_config_file("etc/sapp.toml", "tuple4_reuse_time_interval", "5");
#else
	abort();
#endif
	update_plugin_inf("TCP", "tcp_tuple4_reuse_with_fin_entry");

	set_pcap_dumpfile("tcp/tcp_tuple4_reuse.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "4a7f3337a2039de8a91b7186e9a71c62"),0);

	printf("test for timeout_reset, set --dumpfile-speed=timestamp please wait for a monment......\n");
		
	call_libsapp_devel_for_dumpfile_timestamp();
}

/*
	带fin包正常结束的tcp四元组重用测�?? 还加载了TCP_ALL插件, 此时第一个流结束不会真正free, 而是转到nouse链表.
*/
void tcpall_tuple4_reuse_with_fin_run(void)
{	
	set_default_config();

#if SAPP_V3	
	update_config_file("conf/main.conf", "dumpfile_speed", "timestamp");
	update_config_file("conf/main.conf", "LinkTimeout", "3");
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "timeout", "3");
	update_config_file("etc/sapp.toml", "syn_mandatory", "1");
	update_config_file("etc/sapp.toml", "tuple4_reuse_time_interval", "5");
#else
	abort();
#endif

	update_plugin_inf("TCP", "tcp_tuple4_reuse_with_fin_entry");
	append_plugin_inf("TCP_ALL", "void_entry");

	set_pcap_dumpfile("tcp/tcp_tuple4_reuse.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "4a7f3337a2039de8a91b7186e9a71c62"),0);

	printf("test for timeout_reset, set --dumpfile-speed=timestamp please wait for a monment......\n");
		
	call_libsapp_devel_for_dumpfile_timestamp();
}


/*
	没有正常结束的tcp四元组重用测�??
*/
void tcp_tuple4_reuse_no_close_run(void)
{
	set_default_config();

#if SAPP_V3	
	update_config_file("conf/main.conf", "dumpfile_speed", "timestamp");
	update_config_file("conf/main.conf", "LinkTimeout", "99");
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "timeout", "99"); /* 没有fin, 没有rst, 不能超时, 否则就没有意义了 */
	update_config_file("etc/sapp.toml", "syn_mandatory", "1");
	update_config_file("etc/sapp.toml", "tuple4_reuse_time_interval", "3");
#else
	abort();
#endif
	update_config_file_by_lastline("etc/sapp.toml", "packet_io.polling","enabled", "1");
	update_plugin_inf("TCP", "tcp_tuple4_reuse_no_close_entry");

	set_pcap_dumpfile("tcp/tcp_tuple4_reuse_5.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "4094ca41ca245c72987638e3c9fad8eb"),0);

	printf("test for timeout_reset, set --dumpfile-speed=timestamp please wait for a monment......\n");
		
	call_libsapp_devel_for_dumpfile_timestamp();
}


/*
	测试小端口是客户端的四元组创建流方向.
*/
void tcp_well_known_port_run_v4(void)
{
	set_default_config();
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_plugin_inf("TCP", "tcp_well_known_port_v4_entry");
	system("echo [TCP] > ./etc/well_known_port.conf");
	system("echo 8088  >> ./etc/well_known_port.conf");
	/* UDP的配置在这里其实没啥�?? 就是顺带测试一下解析配置文件的功能 */
	system("echo [UDP] >> ./etc/well_known_port.conf");
	system("echo 12345 >> ./etc/well_known_port.conf");
	system("echo 54321 >> ./etc/well_known_port.conf");
	system("echo \"### hahaha\" >> ./etc/well_known_port.conf");

	set_pcap_dumpfile("for_gtest_only/tcp/tcp_ipv4_small_sport.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "9824c97bbbdeca554b0f0365d7887ade"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}

/*
	测试小端口是客户端的四元组创建流方向,
	此包是带SYN标志�?? 理论上不应该受etc/well_known_port.conf影响, 故意将源端口33720设成服务�??
*/
void tcp_not_use_well_known_port_run_v4(void)
{
	set_default_config();
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_plugin_inf("TCP", "tcp_should_not_use_well_known_port_v4_entry");
	system("echo [TCP] > ./etc/well_known_port.conf");
	system("echo 33720 >> ./etc/well_known_port.conf");
	/* UDP的配置在这里其实没啥�?? 就是顺带测试一下解析配置文件的功能 */
	system("echo [UDP] >> ./etc/well_known_port.conf");
	system("echo 12345 >> ./etc/well_known_port.conf");
	system("echo 54321 >> ./etc/well_known_port.conf");
	system("echo \"### hahaha\" >> ./etc/well_known_port.conf");

	set_pcap_dumpfile("for_gtest_only/tcp/tcp_ipv4_small_sport_with_syn.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "390d79f1731474224b65f0b6ba009f20"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}


/*
	测试小端口是客户端的四元组创建流方向.
*/
void tcp_well_known_port_run_v6(void)
{
	set_default_config();
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_plugin_inf("TCP", "tcp_well_known_port_v6_entry");
	system("echo [TCP] > ./etc/well_known_port.conf");
	system("echo 55555 >> ./etc/well_known_port.conf");
	/* UDP的配置在这里其实没啥�?? 就是顺带测试一下解析配置文件的功能 */
	system("echo [UDP] >> ./etc/well_known_port.conf");
	system("echo 12345 >> ./etc/well_known_port.conf");
	system("echo 54321 >> ./etc/well_known_port.conf");
	system("echo \"### hahaha\" >> ./etc/well_known_port.conf");

	set_pcap_dumpfile("for_gtest_only/tcp/tcp_ipv6_small_sport.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "497b93563bd37cd0400446104d438397"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}

/*
	tcp重传包处�??
*/
void tcp_retransmit_run(void)
{
	set_default_config();
	update_config_file("etc/sapp.toml", "syn_mandatory", "1");
	update_plugin_inf("TCP", "tcp_retransmit_tcp_entry");
	append_plugin_inf("TCP_ALL", "tcp_retransmit_tcpall_entry");

	set_pcap_dumpfile("for_gtest_only/tcp/tcp_retransmit.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "844f36de5cd4f73716227a377ddd50a4"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}


/*
	测试tcp数据重叠功能, 
	流还原出来的结果应该是这样的, 没有555555, 和之前的4444是重叠的, 后面追加的overlap是新数据:
	
		11111111111111111111111111111111111111111111111
		22222222222222222222222222222222222222222222222
		33333333333333333333333333333333333333333333333
		44444444444444444444444444444444444444444444444
		overlap	

*/
void tcp_overlap_run(void)
{
	set_default_config();
	update_config_file("etc/sapp.toml", "syn_mandatory", "1");
	update_plugin_inf("TCP", "tcp_overlay_entry");

	set_pcap_dumpfile("for_gtest_only/tcp/tcp_overlap.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "543aa1a4c8005b0181a862fe98ca7a8f"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}

/*
	在没有TCP插件且第一个包就是乱序的情况下, 
	sapp在函数tcp_deal_unorder()�?? 会调用update_stream_list_raw_pkt_pointer(), 
	但是忘记恢复rawpkt指针就返回了, 导致后续再访问rawpkt其实是被free的乱序包中的rawpkt,
	如果有插件获取原始包选项, �??021-08-23之前是错误的! 
*/
void tcp_first_unorder_rawpkt_run(void)
{
	set_default_config();
	update_config_file("etc/sapp.toml", "reorder_pkt_max", "3");
	update_plugin_inf("TCP_ALL", "tcpall_first_unorder_pkt_entry");
	
	set_pcap_dumpfile("for_gtest_only/tcp/tcp_first_pkt_unorder.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "21e3b4362c4eb38446b433dce4fc9380"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}

/*
	gtp有序�?? 无扩展头�??
*/
void gtp_with_seq_no_ext_tcp_run(void)
{
	set_default_config();
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_plugin_inf("TCP", "gtp_with_seq_tcp_entry");
	
	set_pcap_dumpfile("gtp/gtp_with_seq.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "57f0b6c366f1045753fbeed3e988692b"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}

/*
	gtp无序�?? 但是有扩展头�??
*/
void gtp_without_seq_and_ext_tcp_run(void)
{
	set_default_config();
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_plugin_inf("TCP_ALL", "gtp_without_seq_and_ext_tcp_entry");
	
	set_pcap_dumpfile("for_gtest_only/gtp/gtp_with_extension_hdr_no_seq.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "81902db79f22bb3f4ed4559f6d7011db"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}


/*
	gtp有序号且有扩展头�??
*/
#if (0 == HIGH_PERF)	
void gtp_with_seq_and_ext_tcp_run(void)
{
	set_default_config();
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_plugin_inf("TCP_ALL", "gtp_with_seq_and_ext_tcp_entry");
	
	set_pcap_dumpfile("for_gtest_only/gtp/gtp_with_extension_hdr_and_seq.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "d51cebb81e70baaf9568f13af867f6c4"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}
#endif

void tcpall_offload_givestate_entry_run(void)
{
	set_default_config();
	update_plugin_inf("TCP_ALL", "tcpall_offload_1st_givestate_entry");

	set_pcap_dumpfile("tcp/tcp_simple.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}

void tcpall_offload_givestate_and_giveme_entry_run(void)
{
	set_default_config();
	update_plugin_inf("TCP_ALL", "tcpall_offload_1st_givestate_entry");
	update_plugin_inf("TCP_ALL", "tcpall_offload_2st_giveme_entry");
	
	set_pcap_dumpfile("tcp/tcp_simple.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}

void tcp_offload_givestate_entry_run(void)
{
	set_default_config();
	update_plugin_inf("TCP", "tcp_offload_1st_givestate_entry");

	set_pcap_dumpfile("tcp/tcp_simple.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}

void tcp_offload_givestate_and_giveme_entry_run(void)
{
	set_default_config();
	update_plugin_inf("TCP", "tcp_offload_1st_givestate_entry");
	update_plugin_inf("TCP", "tcp_offload_2st_giveme_entry");
	
	set_pcap_dumpfile("tcp/tcp_simple.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}

