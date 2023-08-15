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


void transparent_network_env_init(void)
{
	update_config_file("etc/sapp.toml", "overlay_mode", "none");
	update_config_file_by_lastline("etc/sapp.toml", "packet_io.deployment", "mode", "transparent");
	update_config_file("etc/sapp.toml", "pcap_capture_direction", "\"in\"");

	/* name,type顺序不固定, 不一定在第一行或第二行, 所以都尝试一遍 */
	update_config_file_by_lastNline("etc/sapp.toml", "packet_io.internal.interface", 1, "name", GTEST_TAP_UP_DEV_NAME);
	update_config_file_by_lastNline("etc/sapp.toml", "packet_io.internal.interface", 2, "name", GTEST_TAP_UP_DEV_NAME);

	update_config_file_by_lastNline("etc/sapp.toml", "packet_io.internal.interface", 1, "type", "pcap");
	update_config_file_by_lastNline("etc/sapp.toml", "packet_io.internal.interface", 2, "type", "pcap");
	
	update_config_file_by_lastNline("etc/sapp.toml", "packet_io.external.interface", 1, "name", GTEST_TAP_DOWN_DEV_NAME);
	update_config_file_by_lastNline("etc/sapp.toml", "packet_io.external.interface", 2, "name", GTEST_TAP_DOWN_DEV_NAME);

	update_config_file_by_lastNline("etc/sapp.toml", "packet_io.external.interface", 1, "type", "pcap");
	update_config_file_by_lastNline("etc/sapp.toml", "packet_io.external.interface", 2, "type", "pcap");

}

/* 双臂串联模式, 广播、组播包基本回流回注测试 */
void transparent_arp_forward_run(void)
{
	set_default_config();
	transparent_network_env_init();

	//update_plugin_inf("TCP", "tcp_simple"); /* 基本回流,回注功能,挂不挂载插件都可以, 默认全部返回PASS */

	set_pcap_dumpfile("for_gtest_only/transparent/broadcast_and_multicast.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "0898b506eddfce273a970aa9d69370a4"),0);	

	gtest_start_transparent_env_progress(GTEST_TRANSPARENT_PROG_NAME, "../benchmark_pcap/for_gtest_only/transparent/broadcast_and_multicast.pcap");
	
	//gtest_start_sapp_progress(sapp_transparent_start_args);
	call_libsapp_devel_online_mode();

}


/* 双臂串联模式, tcp包基本回流回注测试 */
void transparent_tcp_simple_run(void)
{
	set_default_config();
	transparent_network_env_init();
	update_config_file("etc/sapp.toml", "timeout", "3");
	update_plugin_inf("TCP", "transparent_tcp_simple");
	
	set_pcap_dumpfile("tcp/tcp_simple.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);
	
	gtest_start_transparent_env_progress(GTEST_TRANSPARENT_PROG_NAME, "../benchmark_pcap/tcp/tcp_simple.pcap");
	
	//gtest_start_sapp_progress(sapp_transparent_start_args);
	call_libsapp_devel_online_mode();
}


/* 双臂串联模式, tcp包drop, 同时发送一个C2S方向的rst包测试 */
void transparent_drop_and_rst_c2s_trigger_by_c2s_run(void)
{
	set_default_config();
	set_default_asymmetric_addr_layer_conf("\n");
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "inbound_route_dir", "0");

	transparent_network_env_init();

	update_plugin_inf("TCP", "transparent_rst_c2s_entry");

	set_pcap_dumpfile("for_gtest_only/transparent/tcp_drop_rst_c2s_trigger_by_c2s.pcap");

	/*  tcp_drop_rst_c2s_trigger_by_c2s.pcap, tcp_drop_rst_s2c_trigger_by_c2s.pcap,
	    这个两个pcap包其实内容是一样的, 但为了区别不同, 必须靠md5区分, 改了一下时间戳, 这样md5就不一样了 */
	ASSERT_EQ(file_md5_checksum("dumpfile", "8e95cfbe797756b35e4771ecc7b1ad8a"),0);
	
	gtest_start_transparent_env_progress(GTEST_TRANSPARENT_PROG_NAME, "../benchmark_pcap/for_gtest_only/transparent/tcp_drop_rst_c2s_trigger_by_c2s.pcap");
	
	//gtest_start_sapp_progress(sapp_transparent_start_args);
	call_libsapp_devel_online_mode();
}


/* 双臂串联模式, tcp包drop, 同时发送一个S2C方向的rst包测试 */
void transparent_drop_and_rst_s2c_trigger_by_c2s_run(void)
{
	set_default_config();
	set_default_asymmetric_addr_layer_conf("\n");
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "inbound_route_dir", "0");
	transparent_network_env_init();
	update_plugin_inf("TCP", "transparent_rst_s2c_entry");

	set_pcap_dumpfile("for_gtest_only/transparent/tcp_drop_rst_s2c_trigger_by_c2s.pcap");
	/*  tcp_drop_rst_c2s_trigger_by_c2s.pcap, tcp_drop_rst_s2c_trigger_by_c2s.pcap,
	    这个两个pcap包其实内容是一样的, 但为了区别不同, 必须靠md5区分, 改了一下时间戳, 这样md5就不一样了 */
	ASSERT_EQ(file_md5_checksum("dumpfile", "0f65d93dece662dc982c3f193e5fe80e"),0);
	
	gtest_start_transparent_env_progress(GTEST_TRANSPARENT_PROG_NAME, "../benchmark_pcap/for_gtest_only/transparent/tcp_drop_rst_s2c_trigger_by_c2s.pcap");
	//gtest_start_sapp_progress(sapp_transparent_start_args);
	call_libsapp_devel_online_mode();
}



/* 双臂串联模式, tcp包drop, 同时注入一个C2S方向的数据包测试 */
void transparent_drop_and_inject_c2s_trigger_by_c2s_run(void)
{
	set_default_config();
	set_default_asymmetric_addr_layer_conf("\n");
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "inbound_route_dir", "0");
	transparent_network_env_init();
	update_plugin_inf("TCP", "transparent_inject_c2s_entry");

	set_pcap_dumpfile("for_gtest_only/transparent/tcp_drop_inject_c2s_trigger_by_c2s.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "b369a07c6425ba3f15c64caeebaba57a"),0);
	
	gtest_start_transparent_env_progress(GTEST_TRANSPARENT_PROG_NAME, "../benchmark_pcap/for_gtest_only/transparent/tcp_drop_inject_c2s_trigger_by_c2s.pcap");
	
	//gtest_start_sapp_progress(sapp_transparent_start_args);
	call_libsapp_devel_online_mode();
}


/* 双臂串联模式, 将tcp原始S2C方向的包drop, 同时反向注入一个C2S方向的数据包测试 */
void transparent_drop_and_inject_c2s_trigger_by_s2c_run(void)
{
	set_default_config();
	set_default_asymmetric_addr_layer_conf("\n");
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "inbound_route_dir", "0");
	transparent_network_env_init();
	set_default_asymmetric_addr_layer_conf("gre[*]\ngtp[*]\n\n");

	update_plugin_inf("TCP", "transparent_inject_c2s_trigger_by_sc2_entry");

	set_pcap_dumpfile("for_gtest_only/transparent/tcp_drop_inject_c2s_trigger_by_s2c.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "7bf11e398e4dc0993843d1364fbe701d"),0);
	
	gtest_start_transparent_env_progress(GTEST_TRANSPARENT_PROG_NAME, "../benchmark_pcap/for_gtest_only/transparent/tcp_drop_inject_c2s_trigger_by_s2c.pcap");
	
	//gtest_start_sapp_progress(sapp_transparent_start_args);
	call_libsapp_devel_online_mode();
}



void control_drop_current_tcp_pkt_run(void)
{
	set_default_config();
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "inbound_route_dir", "0");
	transparent_network_env_init();
	update_plugin_inf("TCP", "drop_current_pkt_entry");
	
	set_pcap_dumpfile("for_gtest_only/control/drop_currrent_tcp.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "687e907fc50d2dae52e14168c179d4df"),0);
	
	gtest_start_transparent_env_progress(GTEST_TRANSPARENT_PROG_NAME, "../benchmark_pcap/for_gtest_only/control/drop_currrent_tcp.pcap");
	
	start_run_stop_libsapp(5);
}

void control_drop_current_udp_pkt_run(void)
{
	set_default_config();

	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "inbound_route_dir", "0");
	transparent_network_env_init();
	
	update_plugin_inf("UDP", "drop_current_pkt_entry");
	
	set_pcap_dumpfile("for_gtest_only/control/drop_currrent_udp.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "4023b9c75003711f8d1e7bdbfb8cf799"),0);
	
	gtest_start_transparent_env_progress(GTEST_TRANSPARENT_PROG_NAME, "../benchmark_pcap/for_gtest_only/control/drop_currrent_udp.pcap");
	
	start_run_stop_libsapp(5);
}


