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


int g_inline_test_timeout_s=5;

static void set_default_sapp_inline_env(void)
{
	set_default_config();
	update_config_file("etc/sapp.toml", "l2_l3_tunnel_support", "1");
	update_config_file("etc/sapp.toml", "overlay_mode", "vxlan");
	update_config_file_by_lastline("etc/sapp.toml", "packet_io.deployment", "mode", "inline");
	update_config_file_by_lastNline("etc/sapp.toml", "packet_io.internal.interface", 1, "name", GTEST_TAP_UP_DEV_NAME);
	update_config_file_by_lastNline("etc/sapp.toml", "packet_io.internal.interface", 2, "name", GTEST_TAP_UP_DEV_NAME);
	update_config_file_by_lastNline("etc/sapp.toml", "packet_io.internal.interface", 1, "type", "pcap");  /* 此处用pcap模式测试, 不需要借助fake marsio */
	update_config_file_by_lastNline("etc/sapp.toml", "packet_io.internal.interface", 2, "type", "pcap");  /* 此处用pcap模式测试, 不需要借助fake marsio */

	update_config_file("etc/sapp.toml", "pcap_capture_direction", "\"in\"");
	set_default_asymmetric_presence_layer_conf("#"); /* vxlan inline模式下, asymmetric_presence_layer默认为空 */
}

void start_run_stop_libsapp(int sleep_seconds)
{
	gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);

#if 0
	char *_local_sapp_start_args[] = {(char *)"./sapp", (char *)"-s", (char *)NULL};
	int ret = libsapp_setup_env(2, _local_sapp_start_args);
#else
	char *_local_sapp_start_args[] = {(char *)"./sapp",  (char *)NULL};
	int ret = libsapp_setup_env(1, _local_sapp_start_args);
#endif
	if(ret < 0){
		printf("call libsapp_setup_env() fail");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return;
	}
	while(sapp_get_current_state() <= SAPP_STATE_PROCESSING){
		usleep(100);
	}
	sleep(sleep_seconds);
	libsapp_destroy_env();
}


/* vxlan头部字段解析功能测试 */
void inline_vxlan_header_run(void)
{

	printf("--------------------------inline_vxlan_header_run start!\n");
	set_default_sapp_inline_env();

	set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nvxlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");

	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "10.3.36.1");
	update_plugin_inf("TCP_ALL", "inline_vxlan_header_parse_entry"); 
	set_pcap_dumpfile("for_gtest_only/inline/vxlan_header_simple.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "24fd87627aa8c240530982cdeb1b40ab"),0);
	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/inline/vxlan_header_simple.pcap", g_inline_test_timeout_s);
	
	start_run_stop_libsapp(5);
}


/* 串联模式基本回流回注测试 */
void inline_flow_forward_simple_run(void)
{
	set_default_sapp_inline_env();
	
	update_config_file_by_lastline("etc/sapp.toml", "packet_io.polling","enabled", "1");
	update_config_file("etc/sapp.toml", "timeout", "3");
	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "10.3.36.1");
	update_plugin_inf("TCP_ALL", "inline_tcpall_simple"); /* 基本回流,回注功能 */
	set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");
	
	set_pcap_dumpfile("for_gtest_only/inline/tcp_flow_forward_simple.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "2d930e391d57b8e4e930eec5a234aaba"),0);

	printf("inline_mode.simple, dependency polling timeout, please wait for a monment......\n");

	/* 插件inline_tcpall_simple需要超时淘汰, 此处时间长一些 */
	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/inline/tcp_flow_forward_simple.pcap", g_inline_test_timeout_s);
	
	start_run_stop_libsapp(5);
}

/* inline模式基本tcp流还原测试 */
void inline_tcp_simple_run(void)
{
	set_default_sapp_inline_env();
	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "10.3.36.1");
	update_plugin_inf("TCP", "inine_tcp_simple_plug"); 
	
	set_pcap_dumpfile("for_gtest_only/inline/tcp_flow_stat.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "917fd6b8bc70e02812a036adf637479b"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/inline/tcp_flow_stat.pcap", g_inline_test_timeout_s);
	
	start_run_stop_libsapp(5);
}



/* 串联模式注入RST包测试, 
	注入包方向: C2S
	触发包方向: C2S
*/
void inline_inject_rst_c2s_trigger_by_c2s_pkt_run(void)
{
	set_default_sapp_inline_env();
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "10.3.36.1");
	update_plugin_inf("TCP_ALL", "inline_rst_c2s_entry");

	set_pcap_dumpfile("for_gtest_only/inline/tcp_inject_rst_c2s.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "508e10b7af3ad4bac49868d9610d550b"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/inline/tcp_inject_rst_c2s.pcap", g_inline_test_timeout_s);

	gtest_start_sapp_progress(sapp_inline_start_args);
}


/* 串联模式注入RST包测试, 
	注入包方向: S2C
	触发包方向: S2C
*/
void inline_inject_rst_s2c_trigger_by_s2c_pkt_run(void)
{
	set_default_sapp_inline_env();
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "10.3.36.1");

	update_plugin_inf("TCP_ALL", "inline_rst_s2c_entry");

	set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");
	
	set_pcap_dumpfile("for_gtest_only/inline/tcp_inject_rst_s2c.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "a53c8674fbe467b86256b9911c66361f"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/inline/tcp_inject_rst_s2c.pcap", g_inline_test_timeout_s);
	
	gtest_start_sapp_progress(sapp_inline_start_args);
}


/* 串联模式注入RST包测试, 
	注入包方向: S2C
	触发包方向: C2S
*/
void inline_inject_rst_s2c_trigger_by_c2s_pkt_run(void)
{
	set_default_sapp_inline_env();
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "10.3.36.1");
	update_plugin_inf("TCP_ALL", "inline_rst_s2c_entry");

	/* 单向流反向发包不要开启非对称地址,否则肯定是错误的 */
 	set_default_asymmetric_addr_layer_conf("#\n");

	set_pcap_dumpfile("for_gtest_only/inline/tcp_inject_s2c_rst_trigger_by_c2s.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "8da13608354898e2af3f34547a0d54fa"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/inline/tcp_inject_s2c_rst_trigger_by_c2s.pcap",g_inline_test_timeout_s);
	
	gtest_start_sapp_progress(sapp_inline_start_args);
}

/* 串联模式注入RST包测试, 
	注入包方向: C2S
	触发包方向: S2C
*/
void inline_inject_rst_c2s_trigger_by_s2c_pkt_run(void)
{
	set_default_sapp_inline_env();
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "10.3.36.1");
	update_plugin_inf("TCP_ALL", "inline_rst_c2s_entry");

	/* 单向流反向发包不要开启非对称地址,否则肯定是错误的 */
 	set_default_asymmetric_addr_layer_conf("#\n");
	
	set_pcap_dumpfile("for_gtest_only/inline/tcp_inject_c2s_rst_trigger_by_s2c.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "25a94fb48a2cdb568a5561d60a2f72b3"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/inline/tcp_inject_c2s_rst_trigger_by_s2c.pcap",g_inline_test_timeout_s);
	
	gtest_start_sapp_progress(sapp_inline_start_args);
}

/* 串联模式注入带负载的包测试, 
	注入包方向: reverse
	触发包方向: C2S

	这个用例肯定是错误的, 怎么测试呢?
*/
#if 0
void inline_inject_payload_s2c_trigger_by_c2s_ipv6_run(void)
{
	set_default_sapp_inline_env();

	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "192.168.1.14");

	update_plugin_inf("TCP", "inline_inject_payload_reverse_entry");

	/* 单向流反向发包不要开启非对称地址,否则肯定是错误的 */
	set_default_asymmetric_addr_layer_conf("#\n");

	set_pcap_dumpfile("for_gtest_only/inline/tcp_inject_s2c_rst_trigger_by_c2s_ipv6.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "ff0aac8961b4cd660894304fd38d7d71"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/inline/tcp_inject_s2c_rst_trigger_by_c2s_ipv6.pcap",g_inline_test_timeout_s);
	
	start_run_stop_libsapp(5);
}
#endif


/*
	测试overlay层调用插件逻辑, vxlan层的ip不能调用普通插件.
*/
void inline_ip_plug_entry_not_call_run(void)
{
	set_default_sapp_inline_env();
	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "10.3.36.1");
	update_plugin_inf("IP", "vxlan_ip_plug_entry_not_call");
	set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");
	
	set_pcap_dumpfile("for_gtest_only/inline/ip_plug_entry_not_call.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "136ec31b723d689f0ee6bb6867193f39"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/inline/ip_plug_entry_not_call.pcap", g_inline_test_timeout_s);
	start_run_stop_libsapp(5);
}

/*
	测试overlay层调用插件逻辑, vxlan层的udp不能调用普通插件.
*/
void inline_udp_plug_entry_not_call_run(void)
{
	set_default_sapp_inline_env();

	update_config_file_by_lastline("etc/sapp.toml", "packet_io.polling","enabled", "1");
	update_config_file("etc/sapp.toml", "timeout", "3");

	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "192.168.1.10");
	update_plugin_inf("UDP", "vxlan_udp_plug_entry_not_call");
	set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");
	
	set_pcap_dumpfile("for_gtest_only/inline/udp_plug_not_call_entry.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "365675bc0fcb0ef839648c31419f107f"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/inline/udp_plug_not_call_entry.pcap",g_inline_test_timeout_s);
	
	start_run_stop_libsapp(5);
}

/*
	测试插件drop动作.
*/
void inline_udp_plug_drop_entry_run(void)
{
	set_default_sapp_inline_env();

	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "192.168.1.10");
	update_plugin_inf("UDP", "vxlan_udp_plug_drop_entry");
	set_pcap_dumpfile("for_gtest_only/inline/inline_drop_pkt.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "48126d760155589618c523050148475d"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/inline/inline_drop_pkt.pcap",g_inline_test_timeout_s);
	
	//start_run_stop_libsapp(5);
	gtest_start_sapp_progress(sapp_inline_start_args);
}


/*
	测试地址转换接口layer_addr_prefix_ntop().
*/
void inline_layer_addr_ntop_run(void)
{
	set_default_sapp_inline_env();

	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "10.3.36.1");
	update_plugin_inf("TCP_ALL", "inline_layer_addr_prefix_ntop_entry"); 
	set_pcap_dumpfile("for_gtest_only/inline/tcp_layer_addr_ntop.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "ff145f7e429c96abd783504da8c44a01"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/inline/tcp_layer_addr_ntop.pcap",g_inline_test_timeout_s);
	
	start_run_stop_libsapp(5);
}


/*
	测试地址转换接口stream_addr_ntop().
*/
void inline_stream_addr_ntop_run(void)
{
	set_default_sapp_inline_env();

	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "10.3.36.1");
	update_plugin_inf("TCP_ALL", "inline_stream_addr_ntop_entry"); 
	set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");
	
	set_pcap_dumpfile("for_gtest_only/inline/tcp_flow_forward_simple.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "2d930e391d57b8e4e930eec5a234aaba"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/inline/tcp_flow_forward_simple.pcap",g_inline_test_timeout_s);
	
	start_run_stop_libsapp(5);
}



/* 串联模式插件调用pfather链测试, 插件靠pfather遍历, 不能看到vxlan层的包 */
void inline_stream_pfather_run(void)
{
	set_default_sapp_inline_env();

	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "10.3.36.1");

	update_plugin_inf("TCP_ALL", "inline_stream_pfather_entry"); 

	set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");
	
	set_pcap_dumpfile("for_gtest_only/inline/tcp_flow_forward_simple.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "2d930e391d57b8e4e930eec5a234aaba"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/inline/tcp_flow_forward_simple.pcap", g_inline_test_timeout_s);
	
	start_run_stop_libsapp(5);
}


void inline_plug_stat_run(void)
{
	set_default_sapp_inline_env();
	update_config_file("etc/sapp.toml", "inbound_route_dir", "0");	
	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "10.3.36.1");
	update_plugin_inf("TCP", "inline_plug_stat_tcp_entry"); 
	set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");
	
	set_pcap_dumpfile("for_gtest_only/inline/inline_plug_stat.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "3153c45408e8b18b49ffda62b08e341e"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/inline/inline_plug_stat.pcap",g_inline_test_timeout_s);
	
	start_run_stop_libsapp(5);
}

/* 测试在无包的情况下, polling接口超时淘汰流,
   因为dumpfile模式会立即退出, 无法测试此种情况;
   inline模式不会自动退出,借用此模式测试超时.
*/
void inline_polling_timeout_tcp_run(void)
{
	set_default_sapp_inline_env();

	update_config_file_by_lastline("etc/sapp.toml", "packet_io.polling","enabled", "1");
#if SAPP_V3	
	update_config_file("conf/main.conf", "dumpfile_speed", "timestamp");
	update_config_file("conf/main.conf", "LinkTimeout", "3");
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "timeout", "3");
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
#else
	abort();
#endif

	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "10.3.36.1");
	update_plugin_inf("TCP", "inline_polling_timeout_entry");
	set_pcap_dumpfile("for_gtest_only/timer/polling_timeout.pcap");
	
	ASSERT_EQ(file_md5_checksum("dumpfile", "87f99936b70f415b81e665204a841ac3"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/timer/polling_timeout.pcap", g_inline_test_timeout_s);  
	
	start_run_stop_libsapp(5);
}


void inline_polling_timeout_tcpall_run(void)
{
	set_default_sapp_inline_env();
	update_config_file_by_lastline("etc/sapp.toml", "packet_io.polling","enabled", "1");

#if SAPP_V3	
	update_config_file("conf/main.conf", "dumpfile_speed", "timestamp");
	update_config_file("conf/main.conf", "LinkTimeout", "3");
	update_config_file("conf/main.conf", "CreatLinkMode", "3");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "timeout", "3");
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
#else
	abort();
#endif

	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "10.3.36.1");
	update_plugin_inf("TCP_ALL", "inline_polling_timeout_tcpall_entry");
	set_pcap_dumpfile("for_gtest_only/timer/polling_timeout.pcap");
	
	ASSERT_EQ(file_md5_checksum("dumpfile", "87f99936b70f415b81e665204a841ac3"),0);
	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/timer/polling_timeout.pcap", g_inline_test_timeout_s);  
	
	start_run_stop_libsapp(5);
}

void inline_polling_timeout_udp_run(void)
{
	set_default_sapp_inline_env();
	update_config_file_by_lastline("etc/sapp.toml", "packet_io.polling","enabled", "1");

#if SAPP_V3	
	update_config_file("conf/main.conf", "dumpfile_speed", "timestamp");
	update_config_file("conf/main.conf", "LinkTimeout", "3");
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "timeout", "3");
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
#else
	abort();
#endif

	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "192.168.1.10");
	update_plugin_inf("UDP", "inline_polling_timeout_entry"); //与TCP公用一个entry函数
	set_pcap_dumpfile("for_gtest_only/timer/polling_timeout_udp.pcap");
	
	ASSERT_EQ(file_md5_checksum("dumpfile", "a261999fac529d55b938b35c7d53b35d"),0);
	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/timer/polling_timeout_udp.pcap", g_inline_test_timeout_s); 
	
	start_run_stop_libsapp(5);
}

/*
	ATCA交换板发出的vxlan回流数据包, 两侧的vxlan udp端口是不一样的,
	测试此类情况处理是否正确.
*/
void inline_asymmetric_vxlan_addr_run(void)
{
	set_default_sapp_inline_env();

	update_config_file_by_lastline("etc/sapp.toml", "packet_io.polling","enabled", "1");
	update_config_file("etc/sapp.toml", "timeout", "3");
	
	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "10.3.36.1");
	update_plugin_inf("TCP_ALL", "inline_asymmetric_vxlan_addr_tcpall_entry"); 

	set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");

	/* 此pcap包的外层vxlan地址两侧端口不一样, 
        http get包的vxlan外层ip也不一样,
		inline模式下实际不能用于地址比较,特意构造此包用于自测试. 
	*/
	set_pcap_dumpfile("for_gtest_only/inline/inline_asymmetric_vxlan_addr.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "ba1aaa9eefc8e026509ce185369ee8c9"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/inline/inline_asymmetric_vxlan_addr.pcap", g_inline_test_timeout_s);
	
	start_run_stop_libsapp(5);
}


/* 串联模式重复包识别测试,
   其实在这个用例里没有重复包, 但是外层四元组, ip_id, udp_check都是0, 可能导致被识别成重复包, 而不继续处理上层tcp包.
*/
void inline_cheat_dup_tcp_run(void)
{
	set_default_sapp_inline_env();
	
	update_config_file_by_lastline("etc/sapp.toml", "packet_io.polling","enabled", "1");
	update_config_file("etc/sapp.toml", "timeout", "3"); /* inline模式必须靠polling结束超时的流 */
	update_config_file("etc/sapp.toml", "original_ipv4_tcp_enabled", "1");
	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "10.3.36.1");
	update_plugin_inf("TCP", "inline_cheat_dup_tcp_entry");  

	set_default_asymmetric_addr_layer_conf("vlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");

	set_pcap_dumpfile("for_gtest_only/duplicate_packet/inline_cheat_dup_tcp.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "0d8f03c71780c9c93e0702409484012b"),0);
	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/duplicate_packet/inline_cheat_dup_tcp.pcap", g_inline_test_timeout_s);
	
	start_run_stop_libsapp(5);
}


/*
	测试识别注入的重复包,
	1.每次从pcap回放包时都注入给sapp两次, 让sapp以为有重复流量;
	2.从sapp收到的数据包, 还原样注入给sapp, 模拟重复流量的情况, 但是应该默默的被转发而不能业务被插件收到.
*/
void inline_dup_inject_ipv4_tcp_run(void)
{
	set_default_sapp_inline_env();
	
	update_config_file_by_lastline("etc/sapp.toml", "packet_io.polling","enabled", "1");
	update_config_file("etc/sapp.toml", "timeout", "3"); /* inline模式必须靠polling结束超时的流 */
	update_config_file("etc/sapp.toml", "inject_all_enabled", "1");
	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "10.3.36.1");
	update_plugin_inf("TCP_ALL", "inline_dup_inject_tcpall_entry");  

	set_default_asymmetric_addr_layer_conf("vlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");

	set_pcap_dumpfile("for_gtest_only/duplicate_packet/ipv4_tcp_with_syn_dup_test.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "2808e7b99ed7680b22f370aa6621da2a"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/duplicate_packet/ipv4_tcp_with_syn_dup_test.pcap", g_inline_test_timeout_s);
	
	start_run_stop_libsapp(5);
}


/*
	IPv6的原始包重复流量识别已经关闭, 但是注入数据包必须要支持!
*/
void inline_dup_inject_ipv6_tcp_run(void)
{
	set_default_sapp_inline_env();
	update_config_file_by_lastline("etc/sapp.toml", "packet_io.polling","enabled", "1");
	update_config_file("etc/sapp.toml", "timeout", "3"); /* inline模式必须靠polling结束超时的流 */
	update_config_file("etc/sapp.toml", "inject_all_enabled", "1");
	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "10.3.36.1");

	update_plugin_inf("TCP_ALL", "inline_dup_inject_tcpall_entry");  
	set_default_asymmetric_addr_layer_conf("vlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");

	set_pcap_dumpfile("for_gtest_only/duplicate_packet/ipv6_tcp_with_syn_dup_test.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "8c66d7544a6c931d956c15249f401923"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/duplicate_packet/ipv6_tcp_with_syn_dup_test.pcap", g_inline_test_timeout_s);
	
	start_run_stop_libsapp(5);
}


/*
	测试识别注入的重复包,
	1.每次从pcap回放包时都注入给sapp两次, 让sapp以为有重复流量;
	2.从sapp收到的数据包, 还原样注入给sapp, 模拟重复流量的情况, 但是应该默默的被转发而不能业务被插件收到.
*/
void inline_dup_inject_ipv4_udp_run(void)
{
	set_default_sapp_inline_env();
	update_config_file_by_lastline("etc/sapp.toml", "packet_io.polling","enabled", "1");
	update_config_file("etc/sapp.toml", "timeout", "3"); /* inline模式必须靠polling结束超时的流 */
	update_config_file("etc/sapp.toml", "inject_all_enabled", "1");

	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "10.3.36.1");
	update_plugin_inf("UDP", "inline_dup_inject_udp_entry");  
	set_default_asymmetric_addr_layer_conf("vlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");

	set_pcap_dumpfile("for_gtest_only/duplicate_packet/ipv4_udp_dup_test.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "0f6dbdc4f65b98c7fd2e95c812b26d87"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/duplicate_packet/ipv4_udp_dup_test.pcap", g_inline_test_timeout_s);
	
	start_run_stop_libsapp(5);
}

/*
	IPv6的原始包重复流量识别已经关闭, 但是注入数据包必须要支持!
*/
void inline_dup_inject_ipv6_udp_run(void)
{
	set_default_sapp_inline_env();
	update_config_file_by_lastline("etc/sapp.toml", "packet_io.polling","enabled", "1");
	update_config_file("etc/sapp.toml", "timeout", "3"); /* inline模式必须靠polling结束超时的流 */
	update_config_file("etc/sapp.toml", "inject_all_enabled", "1");

	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "10.3.36.1");
	update_plugin_inf("UDP", "inline_dup_inject_udp_entry");  
	set_default_asymmetric_addr_layer_conf("vlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");

	set_pcap_dumpfile("for_gtest_only/duplicate_packet/ipv6_udp_dup_test.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "f109d211904245ea55a0ba8b92fd7233"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/duplicate_packet/ipv6_udp_dup_test.pcap", g_inline_test_timeout_s);
	start_run_stop_libsapp(5);
}


/* 从project tcp_flow_stat, udp_flow_stat 获取底层计数功能测试 */
void inline_get_tcp_flow_stat_run(void)
{
	set_default_sapp_inline_env();
	update_config_file("etc/sapp.toml", "timeout", "3"); /* inline模式必须靠polling结束超时的流 */
	set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");
	set_project_list_conf_default();
	/* TODO, 如果不挂载tcp插件, 统计flow->data_bytes时会有bug, 因为只有tcpall插件时, stream都被移动到了nouse链 */
	update_plugin_inf("TCP", "void_entry"); 
	append_plugin_inf("TCP_ALL", "inline_get_tcp_flow_stat_plug"); 
	
	set_pcap_dumpfile("for_gtest_only/inline/tcp_flow_stat.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "917fd6b8bc70e02812a036adf637479b"),0);

	const char *sapp_argv[4];
	sapp_argv[0] = (char *)"./sapp ";
	sapp_argv[1] = (char *)"--dumpfile";
	call_libsapp_devel_with_args(2, sapp_argv);

}

void inline_get_udp_flow_stat_run(void)
{
	set_default_sapp_inline_env();
	update_config_file("etc/sapp.toml", "timeout", "3"); /* inline模式必须靠polling结束超时的流 */
	set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");
	set_project_list_conf_default();
	update_plugin_inf("UDP", "inline_get_udp_flow_stat_plug"); 
	
	set_pcap_dumpfile("for_gtest_only/inline/udp_flow_stat.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "d2be5655bede9f831469db1fffff13e0"),0);

	const char *sapp_argv[4];
	sapp_argv[0] = (char *)"./sapp ";
	sapp_argv[1] = (char *)"--dumpfile";
	sapp_argv[2] = NULL;
	call_libsapp_devel_with_args(2, sapp_argv);
}


void inline_ssdp_run(void)
{
	set_default_sapp_inline_env();
	update_config_file_by_lastline("etc/sapp.toml", "packet_io.polling","enabled", "1");
	update_config_file("etc/sapp.toml", "timeout", "3"); /* inline模式必须靠polling结束超时的流 */
	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "192.168.1.10");
	set_project_list_conf_default();
	update_plugin_inf("UDP", "inline_ssdp_udp_entry"); 
	set_pcap_dumpfile("ssdp/ssdp_inline.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "bb0a7f7ebdcc6bf01dac576c719022c5"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/ssdp/ssdp_inline.pcap", g_inline_test_timeout_s);
	
	start_run_stop_libsapp(5);
}


void inline_nbns_run(void)
{
	set_default_sapp_inline_env();
	update_config_file_by_lastline("etc/sapp.toml", "packet_io.polling","enabled", "1");
	update_config_file("etc/sapp.toml", "timeout", "3"); /* inline模式必须靠polling结束超时的流 */
	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "192.168.1.10");
	set_project_list_conf_default();
	update_plugin_inf("UDP", "inline_nbns_udp_entry"); 
	
	set_pcap_dumpfile("nbns/nbns_inline.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "4b01a59f8299deb070323594b32b4351"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/nbns/nbns_inline.pcap", g_inline_test_timeout_s);
	
	start_run_stop_libsapp(5);
}

/*
	inline模式下, 插件调用RAW_PKT_GET_DATA, 获取的应该是用户发出或接收的原始数据包, 
	即经过inline设备之前的包, 而不是经过vxlan封装后给sapp的包.
*/
void inline_get_rawpkt_data_run(void)
{
	set_default_sapp_inline_env();

	update_config_file_by_lastline("etc/sapp.toml", "packet_io.polling","enabled", "1");
	update_config_file("etc/sapp.toml", "timeout", "3"); /* inline模式必须靠polling结束超时的流 */
	
	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "192.168.1.10");
	set_project_list_conf_default();
	update_plugin_inf("UDP", "inline_get_raw_pkt_data_entry"); 
	
	set_pcap_dumpfile("for_gtest_only/vxlan/vxlan_dns.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "844de2098c057c82cab8b9e47b6e6123"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/vxlan/vxlan_dns.pcap", g_inline_test_timeout_s);

	start_run_stop_libsapp(5);
}


#if (0 == HIGH_PERF)
void inline_raw_ip_frag_list_run(void)
{
	set_default_sapp_inline_env();
	update_config_file_by_lastline("etc/sapp.toml", "packet_io.polling","enabled", "1");
	update_config_file("etc/sapp.toml", "timeout", "3"); /* inline模式必须靠polling结束超时的流 */
	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "192.168.1.10");
	set_project_list_conf_default();
	append_project_list_conf("ipv4_frag_list", "struct");
	update_plugin_inf("UDP", "inline_ipv4_frag_list_entry");
	
	set_pcap_dumpfile("vxlan/vxlan_ipv4_frag_udp.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "395574c5b55f1e2955421fad4bcb15e5"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/vxlan/vxlan_ipv4_frag_udp.pcap", g_inline_test_timeout_s);

	gtest_set_timeout_default_result(GTEST_SAPP_ERR);
	start_run_stop_libsapp(5);
}
#endif

/* inline模式获取vxlan info参数 */
void inline_vxlan_info_run(void)
{
	set_default_sapp_inline_env();
	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "192.168.1.10");
	update_plugin_inf("UDP", "inine_udp_get_vxlan_info_plug"); 
	
	set_pcap_dumpfile("for_gtest_only/vxlan/get_vxlan_info.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "8027a7e72305c97a471dcffe46f547e7"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/vxlan/get_vxlan_info.pcap", g_inline_test_timeout_s);
	start_run_stop_libsapp(5);
}

/* inline模式, vxlan内层是hdlc封装格式测试 */
void inline_inner_hdlc_run(void)
{
	set_default_sapp_inline_env();
	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "172.26.70.1");
	update_plugin_inf("UDP", "inine_inner_hdlc_udp_plug"); 
	
	set_pcap_dumpfile("for_gtest_only/vxlan/vxlan_with_hdlc_oicq.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "a259f6c7b8080ba8446b7dd7b989ca1e"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/vxlan/vxlan_with_hdlc_oicq.pcap", g_inline_test_timeout_s);
	start_run_stop_libsapp(5);
}


/* inline模式 GRE v0 反向发送RST测试 */
void inline_grev0_inject_reverse_run(void)
{
	set_default_sapp_inline_env();
	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "192.168.1.10");
	update_plugin_inf("TCP", "inline_rst_c2s_entry"); 
	
	set_pcap_dumpfile("for_gtest_only/inline/gre_v0_reverse_inject.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "6f24d4d3f3c13c925afae812f0114626"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/inline/gre_v0_reverse_inject.pcap", g_inline_test_timeout_s);
	gtest_start_sapp_progress(sapp_inline_start_args);

}


/* vxlan HDLC封装格式注入RST包测试, 
	注入包方向: C2S
	触发包方向: C2S
*/
void inline_inject_rst_inner_hdlc_run(void)
{
	set_default_sapp_inline_env();
	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "172.26.70.1");
	update_plugin_inf("TCP_ALL", "inline_rst_c2s_entry");
	/* 单向流反向发包不要开启非对称地址,否则肯定是错误的 */
 	set_default_asymmetric_addr_layer_conf("#\n");
	
	set_pcap_dumpfile("for_gtest_only/inline/tcp_rst_vxlan_with_hdlc.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "e588fef2066daa25ffe0e61ab5586728"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/inline/tcp_rst_vxlan_with_hdlc.pcap",g_inline_test_timeout_s);
	gtest_start_sapp_progress(sapp_inline_start_args);
}


/* inline模式, vxlan内层是ppp封装格式测试 */
void inline_inner_ppp_run(void)
{
	set_default_sapp_inline_env();
	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "172.26.70.1");
	update_plugin_inf("UDP", "inine_inner_ppp_udp_plug"); 

	set_pcap_dumpfile("for_gtest_only/vxlan/vxlan_with_ppp_oicq.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "e22da1283cbd1fe1fe2fe4f1d7ebf048"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/vxlan/vxlan_with_ppp_oicq.pcap", g_inline_test_timeout_s);
	
	start_run_stop_libsapp(5);
}

/* vxlan PPP封装格式注入RST包测试, 
	注入包方向: C2S
	触发包方向: C2S
*/
void inline_inject_rst_inner_ppp_run(void)
{
	set_default_sapp_inline_env();
	update_config_file("etc/sapp.toml", "syn_mandatory", "1"); //就一个SYN包
	update_config_file("etc/gdev.conf", "sendto_gdev_ip", "172.26.70.1");
	update_plugin_inf("TCP_ALL", "inline_rst_c2s_entry");
	/* 单向流反向发包不要开启非对称地址,否则肯定是错误的 */
 	set_default_asymmetric_addr_layer_conf("#\n");
 	
	set_pcap_dumpfile("for_gtest_only/inline/tcp_rst_vxlan_with_ppp.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "509e6213660f2c33964db8dd7c348917"),0);

	gtest_start_inline_env_progress(GTEST_INLINE_PROG_NAME, "../benchmark_pcap/for_gtest_only/inline/tcp_rst_vxlan_with_ppp.pcap",g_inline_test_timeout_s);
	
	gtest_start_sapp_progress(sapp_inline_start_args);
}


