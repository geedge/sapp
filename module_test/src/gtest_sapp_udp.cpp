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
#include <sys/time.h>

#include "gtest_sapp_fun.h"
#include <gtest/gtest.h>

void udp_simple_run(void)
{
	set_default_config();
	
	update_plugin_inf("UDP", "udp_simple_entry");

	set_pcap_dumpfile("udp/udp_simple.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "328951b2b04af765e6a0a7fe34ee29ad"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}

#if SAPP_V4 
void udp_link_c2s_1pkt_run(void)
{
	set_default_config();
	
	update_config_file_by_lastline("etc/sapp.toml", "packet_io.polling","enabled", "1");
	update_config_file("etc/sapp.toml", "timeout", "3");
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "meaningful_statistics_minimum_pkt", "3");
	update_config_file("etc/sapp.toml", "meaningful_statistics_minimum_byte", "5");
	
	update_plugin_inf("UDP", "udp_link_c2s_1pkt_entry");
	append_plugin_inf("TCP", "udp_link_check_result_tcp_entry");

	set_pcap_dumpfile("for_gtest_only/udp/udp_C2S_1.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "7872fd733ba5610ad23e4d2dee133793"),0);

	printf("test for udp timeout and close, set --dumpfile-speed=timestamp please wait for a monment......\n");

	call_libsapp_devel_for_dumpfile_timestamp();
}


void udp_link_c2s_10pkt_run(void)
{
	set_default_config();
	
	update_config_file_by_lastline("etc/sapp.toml", "packet_io.polling","enabled", "1");
	update_config_file("etc/sapp.toml", "timeout", "3");
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "meaningful_statistics_minimum_pkt", "3");
	update_config_file("etc/sapp.toml", "meaningful_statistics_minimum_byte", "5");
	
	update_plugin_inf("UDP", "udp_link_c2s_10pkt_entry");
	append_plugin_inf("TCP", "udp_link_check_result_tcp_entry");

	set_pcap_dumpfile("for_gtest_only/udp/udp_C2S_10.pcap");

	/* udp_C2S_10.pcap测试包需�?个驱动包, 把第一个了连接淘汰, 因为lrustream只淘汰当前stream_state的链�?
		第一个包是UDP_ONE,
		第二个包是UDP_TWO,
		第三个包是UDP_MORE, 在lrustream之后才更新状�? 但是还没来得及淘汰第一个连�?
		第四个包是UDP_MORE,且把第一个连接淘�?
	*/
	ASSERT_EQ(file_md5_checksum("dumpfile", "ff140c986f5d412d6cd234f1b44024fa"),0);

	printf("test for udp timeout and close, set --dumpfile-speed=timestamp please wait for a monment......\n");
	
	call_libsapp_devel_for_dumpfile_timestamp();
}


void udp_link_s2c_1pkt_run(void)
{
	set_default_config();
	
	update_config_file_by_lastline("etc/sapp.toml", "packet_io.polling","enabled", "1");
	update_config_file("etc/sapp.toml", "timeout", "3");
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "meaningful_statistics_minimum_pkt", "3");
	update_config_file("etc/sapp.toml", "meaningful_statistics_minimum_byte", "5");
	
	update_plugin_inf("UDP", "udp_link_s2c_1pkt_entry");
	append_plugin_inf("TCP", "udp_link_check_result_tcp_entry");

	set_pcap_dumpfile("for_gtest_only/udp/udp_S2C_1.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "8944e363d3398b0cde08990d33052f8e"),0);

	printf("test for udp timeout and close, set --dumpfile-speed=timestamp please wait for a monment......\n");
	
	call_libsapp_devel_for_dumpfile_timestamp();
}

void udp_link_s2c_10pkt_run(void)
{
	set_default_config();

	update_config_file_by_lastline("etc/sapp.toml", "packet_io.polling","enabled", "1");
	update_config_file("etc/sapp.toml", "timeout", "3");
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "meaningful_statistics_minimum_pkt", "3");
	update_config_file("etc/sapp.toml", "meaningful_statistics_minimum_byte", "5");
	
	update_plugin_inf("UDP", "udp_link_s2c_10pkt_entry");
	append_plugin_inf("TCP", "udp_link_check_result_tcp_entry");

	set_pcap_dumpfile("for_gtest_only/udp/udp_S2C_10.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "e487e9dc01b973bc90115dd4b4f7c54f"),0);

	printf("test for udp timeout and close, set --dumpfile-speed=timestamp please wait for a monment......\n");
	
	call_libsapp_devel_for_dumpfile_timestamp();

}

void udp_dup_pkt_positive_run(void)
{
	set_default_config();

	update_config_file("etc/sapp.toml", "original_ipv4_udp_enabled", "1");
	update_config_file("etc/sapp.toml", "bloom_capacity", "1000000");
	update_config_file("etc/sapp.toml", "bloom_error_rate", "0.00001");
	update_config_file("etc/sapp.toml", "bloom_timeout", "10");	

	update_plugin_inf("UDP", "udp_dup_pkt_positive_check");

	/* 此pcap包一共有9个包,前两个和后两个是人为制造的重复包, 插件应该只收到 7 个包才是对的 */	
	set_pcap_dumpfile("for_gtest_only/duplicate_packet/udp_dup.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "d3641c8f301e78006d7cdb199538e73b"),0);

	call_libsapp_devel_for_dumpfile_topspeed();
}

void udp_dup_pkt_negative_run(void)
{
	set_default_config();

	update_config_file("etc/sapp.toml", "original_ipv4_udp_enabled", "0");
	update_config_file("etc/sapp.toml", "inject_all_enabled", "1");
	update_config_file("etc/sapp.toml", "bloom_capacity", "1000000");
	update_config_file("etc/sapp.toml", "bloom_error_rate", "0.00001");
	update_config_file("etc/sapp.toml", "bloom_timeout", "10");	

	update_plugin_inf("UDP", "udp_dup_pkt_negative_check");

	/* 此pcap包一共有9个包,前两个和后两个是人为制造的重复包, 关闭重复包检查, 插件应该也收到 9 个包才是对的 */	
	set_pcap_dumpfile("for_gtest_only/duplicate_packet/udp_dup.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "d3641c8f301e78006d7cdb199538e73b"),0);

	call_libsapp_devel_for_dumpfile_topspeed();
}


/*
期待�?gtest_sapp_hybrid_stream.log 日志内容:


stream:192.168.36.103.54275>224.0.0.252.5355,c2s_pkt:1,c2s_byte:21,s2c_pkt:0,s2c_byte:0
stream:192.168.36.103.61104>224.0.0.252.5355,c2s_pkt:1,c2s_byte:21,s2c_pkt:0,s2c_byte:0
stream:192.168.36.103.63216>116.203.151.74.123,c2s_pkt:1,c2s_byte:48,s2c_pkt:0,s2c_byte:0
stream:192.168.36.103.64282>162.159.200.1.123,c2s_pkt:1,c2s_byte:48,s2c_pkt:0,s2c_byte:0
stream:192.168.36.103.64286>192.168.36.96.1900,c2s_pkt:0,c2s_byte:0,s2c_pkt:1,s2c_byte:500
stream:192.168.36.103.50512>224.0.0.252.5355,c2s_pkt:2,c2s_byte:42,s2c_pkt:0,s2c_byte:0
stream:192.168.36.103.52158>224.0.0.252.5355,c2s_pkt:2,c2s_byte:42,s2c_pkt:0,s2c_byte:0
stream:192.168.36.103.50927>114.114.114.114.53,c2s_pkt:1,c2s_byte:21,s2c_pkt:1,s2c_byte:96
stream:192.168.36.103.55598>224.0.0.252.5355,c2s_pkt:2,c2s_byte:42,s2c_pkt:0,s2c_byte:0
stream:192.168.36.103.62968>224.0.0.252.5355,c2s_pkt:2,c2s_byte:42,s2c_pkt:0,s2c_byte:0
stream:192.168.36.103.54476>114.114.114.114.53,c2s_pkt:1,c2s_byte:31,s2c_pkt:1,s2c_byte:90
stream:192.168.36.103.56704>114.114.114.114.53,c2s_pkt:1,c2s_byte:35,s2c_pkt:1,s2c_byte:84
stream:192.168.36.103.58711>114.114.114.114.53,c2s_pkt:1,c2s_byte:35,s2c_pkt:1,s2c_byte:84
stream:192.168.36.103.51437>114.114.114.114.53,c2s_pkt:1,c2s_byte:31,s2c_pkt:1,s2c_byte:90
stream:192.168.36.103.50377>114.114.114.114.53,c2s_pkt:1,c2s_byte:35,s2c_pkt:1,s2c_byte:84
stream:192.168.36.103.56298>114.114.114.114.53,c2s_pkt:1,c2s_byte:35,s2c_pkt:1,s2c_byte:84
stream:192.168.36.103.55184>114.114.114.114.53,c2s_pkt:1,c2s_byte:31,s2c_pkt:1,s2c_byte:90
stream:192.168.36.103.50320>114.114.114.114.53,c2s_pkt:1,c2s_byte:31,s2c_pkt:1,s2c_byte:90
stream:192.168.36.103.63433>114.114.114.114.53,c2s_pkt:1,c2s_byte:34,s2c_pkt:1,s2c_byte:84
stream:192.168.36.103.51913>114.114.114.114.53,c2s_pkt:1,c2s_byte:35,s2c_pkt:1,s2c_byte:84
stream:192.168.36.103.53973>114.114.114.114.53,c2s_pkt:1,c2s_byte:40,s2c_pkt:1,s2c_byte:134
stream:192.168.36.103.54373>114.114.114.114.53,c2s_pkt:1,c2s_byte:36,s2c_pkt:1,s2c_byte:84
stream:192.168.36.103.60698>114.114.114.114.53,c2s_pkt:1,c2s_byte:31,s2c_pkt:1,s2c_byte:78
stream:192.168.36.103.53822>114.114.114.114.53,c2s_pkt:1,c2s_byte:31,s2c_pkt:1,s2c_byte:78
stream:192.168.36.103.51901>114.114.114.114.53,c2s_pkt:1,c2s_byte:31,s2c_pkt:1,s2c_byte:78
stream:192.168.36.103.52000>114.114.114.114.53,c2s_pkt:1,c2s_byte:31,s2c_pkt:1,s2c_byte:78
stream:192.168.36.103.58198>114.114.114.114.53,c2s_pkt:1,c2s_byte:38,s2c_pkt:1,s2c_byte:140
stream:192.168.36.103.52722>114.114.114.114.53,c2s_pkt:1,c2s_byte:35,s2c_pkt:1,s2c_byte:84
stream:192.168.36.103.57658>114.114.114.114.53,c2s_pkt:1,c2s_byte:32,s2c_pkt:1,s2c_byte:81
stream:192.168.36.103.54002>114.114.114.114.53,c2s_pkt:1,c2s_byte:32,s2c_pkt:1,s2c_byte:81
stream:192.168.36.103.62129>114.114.114.114.53,c2s_pkt:1,c2s_byte:48,s2c_pkt:1,s2c_byte:153
stream:192.168.36.103.64982>114.114.114.114.53,c2s_pkt:1,c2s_byte:35,s2c_pkt:1,s2c_byte:86
stream:192.168.36.103.56853>114.114.114.114.53,c2s_pkt:1,c2s_byte:36,s2c_pkt:1,s2c_byte:115
stream:192.168.36.103.64290>114.114.114.114.53,c2s_pkt:1,c2s_byte:39,s2c_pkt:1,s2c_byte:71
stream:192.168.36.103.64003>114.114.114.114.53,c2s_pkt:1,c2s_byte:40,s2c_pkt:1,s2c_byte:72
stream:192.168.36.103.55035>114.114.114.114.53,c2s_pkt:1,c2s_byte:39,s2c_pkt:1,s2c_byte:118
stream:192.168.36.103.58438>114.114.114.114.53,c2s_pkt:1,c2s_byte:39,s2c_pkt:1,s2c_byte:71
stream:192.168.36.103.49923>114.114.114.114.53,c2s_pkt:1,c2s_byte:39,s2c_pkt:1,s2c_byte:71
stream:192.168.36.103.55884>114.114.114.114.53,c2s_pkt:1,c2s_byte:41,s2c_pkt:1,s2c_byte:73
stream:192.168.36.103.51917>114.114.114.114.53,c2s_pkt:1,c2s_byte:40,s2c_pkt:1,s2c_byte:72
stream:192.168.36.103.60181>114.114.114.114.53,c2s_pkt:1,c2s_byte:39,s2c_pkt:1,s2c_byte:71
stream:192.168.36.103.57395>114.114.114.114.53,c2s_pkt:1,c2s_byte:40,s2c_pkt:1,s2c_byte:72
stream:192.168.36.103.52233>114.114.114.114.53,c2s_pkt:1,c2s_byte:37,s2c_pkt:1,s2c_byte:53
stream:192.168.36.103.65083>114.114.114.114.53,c2s_pkt:1,c2s_byte:28,s2c_pkt:1,s2c_byte:116
stream:192.168.36.103.55760>114.114.114.114.53,c2s_pkt:1,c2s_byte:37,s2c_pkt:1,s2c_byte:53
stream:192.168.36.103.62661>114.114.114.114.53,c2s_pkt:1,c2s_byte:44,s2c_pkt:1,s2c_byte:60
stream:192.168.36.103.52080>114.114.114.114.53,c2s_pkt:1,c2s_byte:31,s2c_pkt:1,s2c_byte:92
stream:192.168.36.103.58619>114.114.114.114.53,c2s_pkt:1,c2s_byte:39,s2c_pkt:1,s2c_byte:71
stream:192.168.36.103.51002>114.114.114.114.53,c2s_pkt:1,c2s_byte:42,s2c_pkt:1,s2c_byte:74
stream:192.168.36.103.60614>114.114.114.114.53,c2s_pkt:1,c2s_byte:41,s2c_pkt:1,s2c_byte:57
stream:192.168.36.103.51134>114.114.114.114.53,c2s_pkt:1,c2s_byte:34,s2c_pkt:1,s2c_byte:50
stream:192.168.36.103.54514>114.114.114.114.53,c2s_pkt:1,c2s_byte:36,s2c_pkt:1,s2c_byte:115
stream:192.168.36.103.59095>114.114.114.114.53,c2s_pkt:1,c2s_byte:36,s2c_pkt:1,s2c_byte:68
stream:192.168.36.103.53327>114.114.114.114.53,c2s_pkt:1,c2s_byte:36,s2c_pkt:1,s2c_byte:52
stream:192.168.36.103.57008>114.114.114.114.53,c2s_pkt:1,c2s_byte:35,s2c_pkt:1,s2c_byte:51
stream:192.168.36.103.58634>114.114.114.114.53,c2s_pkt:1,c2s_byte:36,s2c_pkt:1,s2c_byte:115
stream:192.168.36.103.51287>114.114.114.114.53,c2s_pkt:1,c2s_byte:35,s2c_pkt:1,s2c_byte:67
stream:192.168.36.103.56112>114.114.114.114.53,c2s_pkt:1,c2s_byte:40,s2c_pkt:1,s2c_byte:119
stream:192.168.36.103.64948>114.114.114.114.53,c2s_pkt:1,c2s_byte:36,s2c_pkt:1,s2c_byte:52
stream:192.168.36.103.57451>114.114.114.114.53,c2s_pkt:1,c2s_byte:28,s2c_pkt:1,s2c_byte:187
stream:192.168.36.103.61135>114.114.114.114.53,c2s_pkt:1,c2s_byte:38,s2c_pkt:1,s2c_byte:117
stream:192.168.36.103.63590>114.114.114.114.53,c2s_pkt:1,c2s_byte:36,s2c_pkt:1,s2c_byte:203
stream:192.168.36.103.55239>114.114.114.114.53,c2s_pkt:1,c2s_byte:26,s2c_pkt:1,s2c_byte:78
stream:192.168.36.103.62428>114.114.114.114.53,c2s_pkt:1,c2s_byte:24,s2c_pkt:1,s2c_byte:148
stream:192.168.36.103.64825>114.114.114.114.53,c2s_pkt:1,c2s_byte:37,s2c_pkt:1,s2c_byte:158
stream:192.168.36.103.63742>114.114.114.114.53,c2s_pkt:1,c2s_byte:37,s2c_pkt:1,s2c_byte:158
stream:192.168.36.103.59177>114.114.114.114.53,c2s_pkt:1,c2s_byte:37,s2c_pkt:1,s2c_byte:158
stream:192.168.36.103.53971>114.114.114.114.53,c2s_pkt:1,c2s_byte:37,s2c_pkt:1,s2c_byte:158
stream:192.168.36.103.59843>114.114.114.114.53,c2s_pkt:1,c2s_byte:37,s2c_pkt:1,s2c_byte:158
stream:192.168.36.103.59950>114.114.114.114.53,c2s_pkt:1,c2s_byte:37,s2c_pkt:1,s2c_byte:158
stream:192.168.36.103.61094>114.114.114.114.53,c2s_pkt:1,c2s_byte:37,s2c_pkt:1,s2c_byte:158
stream:192.168.36.103.49943>114.114.114.114.53,c2s_pkt:1,c2s_byte:38,s2c_pkt:1,s2c_byte:207
stream:192.168.36.103.54305>114.114.114.114.53,c2s_pkt:1,c2s_byte:27,s2c_pkt:1,s2c_byte:185
stream:192.168.36.103.61956>114.114.114.114.53,c2s_pkt:1,c2s_byte:33,s2c_pkt:1,s2c_byte:146
stream:192.168.36.103.56102>114.114.114.114.53,c2s_pkt:1,c2s_byte:32,s2c_pkt:1,s2c_byte:106
stream:192.168.36.103.53003>114.114.114.114.53,c2s_pkt:1,c2s_byte:33,s2c_pkt:1,s2c_byte:108
stream:192.168.36.103.53573>114.114.114.114.53,c2s_pkt:1,c2s_byte:30,s2c_pkt:1,s2c_byte:86
stream:192.168.36.103.52613>114.114.114.114.53,c2s_pkt:1,c2s_byte:29,s2c_pkt:1,s2c_byte:100
stream:192.168.36.103.49787>114.114.114.114.53,c2s_pkt:1,c2s_byte:30,s2c_pkt:1,s2c_byte:102
stream:192.168.36.103.60634>114.114.114.114.53,c2s_pkt:1,c2s_byte:30,s2c_pkt:1,s2c_byte:86
stream:192.168.36.103.54270>114.114.114.114.53,c2s_pkt:1,c2s_byte:25,s2c_pkt:1,s2c_byte:79
stream:192.168.36.103.49963>114.114.114.114.53,c2s_pkt:1,c2s_byte:29,s2c_pkt:1,s2c_byte:84
stream:192.168.36.103.64579>114.114.114.114.53,c2s_pkt:1,c2s_byte:31,s2c_pkt:1,s2c_byte:193
stream:192.168.36.103.63004>114.114.114.114.53,c2s_pkt:1,c2s_byte:36,s2c_pkt:1,s2c_byte:156
stream:192.168.36.103.63006>162.159.200.1.123,c2s_pkt:1,c2s_byte:48,s2c_pkt:1,s2c_byte:48
stream:192.168.36.103.49838>114.114.114.114.53,c2s_pkt:1,c2s_byte:27,s2c_pkt:1,s2c_byte:80
stream:192.168.36.103.63983>114.114.114.114.53,c2s_pkt:1,c2s_byte:34,s2c_pkt:1,s2c_byte:199
stream:192.168.36.103.64811>114.114.114.114.53,c2s_pkt:1,c2s_byte:38,s2c_pkt:1,s2c_byte:118
stream:192.168.36.103.64813>116.203.151.74.123,c2s_pkt:1,c2s_byte:48,s2c_pkt:1,s2c_byte:48
stream:192.168.36.103.63794>114.114.114.114.53,c2s_pkt:1,c2s_byte:33,s2c_pkt:1,s2c_byte:91
stream:192.168.36.103.54625>114.114.114.114.53,c2s_pkt:1,c2s_byte:31,s2c_pkt:1,s2c_byte:134
stream:192.168.36.103.62616>114.114.114.114.53,c2s_pkt:1,c2s_byte:31,s2c_pkt:1,s2c_byte:47
stream:192.168.36.103.59501>114.114.114.114.53,c2s_pkt:1,c2s_byte:34,s2c_pkt:1,s2c_byte:71
stream:192.168.36.103.50857>114.114.114.114.53,c2s_pkt:1,c2s_byte:34,s2c_pkt:1,s2c_byte:328
stream:192.168.36.103.52904>114.114.114.114.53,c2s_pkt:1,c2s_byte:34,s2c_pkt:1,s2c_byte:328
stream:192.168.36.103.52909>185.255.55.20.123,c2s_pkt:1,c2s_byte:48,s2c_pkt:1,s2c_byte:48
stream:192.168.36.103.52911>144.76.76.107.123,c2s_pkt:1,c2s_byte:48,s2c_pkt:1,s2c_byte:48
stream:192.168.36.103.58002>114.114.114.114.53,c2s_pkt:1,c2s_byte:33,s2c_pkt:1,s2c_byte:49
stream:192.168.36.103.58006>114.114.114.114.53,c2s_pkt:1,c2s_byte:46,s2c_pkt:1,s2c_byte:78
stream:192.168.36.103.58007>114.114.114.114.53,c2s_pkt:1,c2s_byte:24,s2c_pkt:1,s2c_byte:88
stream:192.168.36.103.58008>114.114.114.114.53,c2s_pkt:1,c2s_byte:24,s2c_pkt:1,s2c_byte:74
stream:192.168.36.103.58009>114.114.114.114.53,c2s_pkt:1,c2s_byte:46,s2c_pkt:1,s2c_byte:78
stream:192.168.36.103.58010>114.114.114.114.53,c2s_pkt:1,c2s_byte:25,s2c_pkt:1,s2c_byte:57
stream:192.168.36.103.58011>114.114.114.114.53,c2s_pkt:1,c2s_byte:25,s2c_pkt:1,s2c_byte:80
stream:192.168.36.103.58012>114.114.114.114.53,c2s_pkt:1,c2s_byte:46,s2c_pkt:1,s2c_byte:78
stream:192.168.36.103.58013>114.114.114.114.53,c2s_pkt:1,c2s_byte:26,s2c_pkt:1,s2c_byte:42
stream:192.168.36.103.58014>114.114.114.114.53,c2s_pkt:1,c2s_byte:26,s2c_pkt:1,s2c_byte:26
stream:192.168.36.103.55339>114.114.114.114.53,c2s_pkt:1,c2s_byte:24,s2c_pkt:1,s2c_byte:88
stream:192.168.36.103.54938>114.114.114.114.53,c2s_pkt:1,c2s_byte:28,s2c_pkt:1,s2c_byte:92
stream:192.168.36.103.64304>114.114.114.114.53,c2s_pkt:1,c2s_byte:32,s2c_pkt:1,s2c_byte:175
stream:192.168.36.103.54694>114.114.114.114.53,c2s_pkt:1,c2s_byte:32,s2c_pkt:1,s2c_byte:216
stream:192.168.36.103.49444>114.114.114.114.53,c2s_pkt:1,c2s_byte:29,s2c_pkt:1,s2c_byte:207
stream:192.168.36.103.61403>114.114.114.114.53,c2s_pkt:1,c2s_byte:33,s2c_pkt:1,s2c_byte:159
stream:192.168.36.103.65274>114.114.114.114.53,c2s_pkt:1,c2s_byte:30,s2c_pkt:1,s2c_byte:188
stream:192.168.36.103.65275>162.159.200.1.123,c2s_pkt:1,c2s_byte:48,s2c_pkt:1,s2c_byte:48
stream:192.168.36.103.52789>114.114.114.114.53,c2s_pkt:1,c2s_byte:33,s2c_pkt:1,s2c_byte:316
stream:192.168.36.103.55062>114.114.114.114.53,c2s_pkt:1,c2s_byte:30,s2c_pkt:1,s2c_byte:157
stream:192.168.36.103.50844>114.114.114.114.53,c2s_pkt:1,c2s_byte:30,s2c_pkt:1,s2c_byte:142
stream:192.168.36.103.62238>114.114.114.114.53,c2s_pkt:1,c2s_byte:33,s2c_pkt:1,s2c_byte:65
stream:192.168.36.103.50230>114.114.114.114.53,c2s_pkt:1,c2s_byte:32,s2c_pkt:1,s2c_byte:62
stream:192.168.36.103.59118>114.114.114.114.53,c2s_pkt:1,c2s_byte:40,s2c_pkt:1,s2c_byte:120
stream:192.168.36.103.51856>114.114.114.114.53,c2s_pkt:1,c2s_byte:31,s2c_pkt:1,s2c_byte:95
stream:192.168.36.103.56346>114.114.114.114.53,c2s_pkt:1,c2s_byte:37,s2c_pkt:1,s2c_byte:188
stream:192.168.36.103.49869>114.114.114.114.53,c2s_pkt:1,c2s_byte:31,s2c_pkt:1,s2c_byte:338
stream:192.168.36.103.51672>114.114.114.114.53,c2s_pkt:1,c2s_byte:30,s2c_pkt:1,s2c_byte:62
stream:192.168.36.103.49498>114.114.114.114.53,c2s_pkt:1,c2s_byte:37,s2c_pkt:1,s2c_byte:121
stream:192.168.36.103.56309>114.114.114.114.53,c2s_pkt:1,c2s_byte:33,s2c_pkt:1,s2c_byte:113
stream:192.168.36.103.65481>114.114.114.114.53,c2s_pkt:1,c2s_byte:28,s2c_pkt:1,s2c_byte:148
stream:192.168.36.103.54824>114.114.114.114.53,c2s_pkt:1,c2s_byte:28,s2c_pkt:1,s2c_byte:44
stream:192.168.36.103.63215>114.114.114.114.53,c2s_pkt:1,c2s_byte:32,s2c_pkt:1,s2c_byte:48
stream:192.168.36.103.63218>185.255.55.20.123,c2s_pkt:1,c2s_byte:48,s2c_pkt:1,s2c_byte:48
stream:192.168.36.103.63219>144.76.76.107.123,c2s_pkt:1,c2s_byte:48,s2c_pkt:1,s2c_byte:48
stream:192.168.36.103.64281>114.114.114.114.53,c2s_pkt:1,c2s_byte:33,s2c_pkt:1,s2c_byte:91
stream:192.168.36.103.64283>116.203.151.74.123,c2s_pkt:1,c2s_byte:48,s2c_pkt:1,s2c_byte:48
stream:192.168.36.103.57818>114.114.114.114.53,c2s_pkt:1,c2s_byte:33,s2c_pkt:1,s2c_byte:49
stream:192.168.36.103.57819>185.255.55.20.123,c2s_pkt:1,c2s_byte:48,s2c_pkt:1,s2c_byte:48
stream:192.168.36.103.57820>144.76.76.107.123,c2s_pkt:1,c2s_byte:48,s2c_pkt:1,s2c_byte:48
stream:192.168.36.103.57025>114.114.114.114.53,c2s_pkt:2,c2s_byte:92,s2c_pkt:0,s2c_byte:0
stream:192.168.36.103.57025>114.114.115.115.53,c2s_pkt:2,c2s_byte:92,s2c_pkt:0,s2c_byte:0
stream:192.168.36.103.57025>10.0.254.228.53,c2s_pkt:2,c2s_byte:92,s2c_pkt:0,s2c_byte:0
stream:192.168.36.103.52907>239.255.255.250.1900,c2s_pkt:4,c2s_byte:692,s2c_pkt:0,s2c_byte:0
stream:192.168.36.103.52907>192.168.36.96.1900,c2s_pkt:0,c2s_byte:0,s2c_pkt:3,s2c_byte:1500
stream:192.168.36.103.49664>182.254.21.26.8000,c2s_pkt:5,c2s_byte:1458,s2c_pkt:5,s2c_byte:1330
stream:192.168.36.103.59702>114.114.114.114.53,c2s_pkt:1,c2s_byte:31,s2c_pkt:2,s2c_byte:230
stream:192.168.36.103.64797>182.254.21.27.8000,c2s_pkt:42,c2s_byte:30900,s2c_pkt:42,s2c_byte:8028
stream:192.168.36.103.55460>192.168.10.181.161,c2s_pkt:11,c2s_byte:930,s2c_pkt:11,s2c_byte:963
stream:192.168.36.103.65446>59.37.96.250.8000,c2s_pkt:2,c2s_byte:1157,s2c_pkt:2,s2c_byte:557
stream:192.168.36.103.64286>239.255.255.250.1900,c2s_pkt:4,c2s_byte:692,s2c_pkt:0,s2c_byte:0

*/
void hybrid_pure_udp_run(void)
{
	set_default_config();

	update_config_file("etc/sapp.toml", "timeout", "0");

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "gtest_sapp_slave_init", "hybrid_udp_destroy", "UDP", "hybrid_pure_udp_entry");

	/* hybrid混合包测试用例不开启重复流量检�?*/
	update_config_file("etc/sapp.toml", "inject_all_enabled", "0");
	update_config_file("etc/sapp.toml", "original_ipv4_tcp_enabled", "0");
	update_config_file("etc/sapp.toml", "original_ipv4_udp_enabled", "0");

	set_pcap_dumpfile("for_gtest_only/hybrid_pcap/hybrid_pure_udp.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "0194a9a4a1b7bdfaaedfe42fa3bd97e1"),0);

	char cmd_buf[128];
	sprintf(cmd_buf, "> %s", GTEST_HYBRID_STREAM_LOG_FILE);
	system(cmd_buf);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}

/*
	l2tp_cheat_dup_dns.pcap这包, 外层l2tp的ipid, udp-check都是0, 但是内层ipid,udp-check, dns trans id确实是不一样的,
	所�? 不能被识别成是重复流�?
*/
void cheat_l2tp_dup_dns_run(void)
{
	set_default_config();

	update_config_file("etc/sapp.toml", "timeout", "0");
	update_config_file("etc/sapp.toml", "original_ipv4_udp_enabled", "1");

	update_plugin_inf("UDP", "cheat_l2tp_dup_check_entry");

	set_pcap_dumpfile("for_gtest_only/duplicate_packet/l2tp_cheat_dup_dns.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "565acf88ae3301c4340004a1f8fe7ddc"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}

/*
	gtp_cheat_dup_dns.pcap这包, 外层gtp的ipid, udp-check都是0, 但是内层ipid,udp-check, dns trans id确实是不一样的,
	所�? 不能被识别成是重复流�?
*/
void cheat_gtp_dup_dns_run(void)
{
	set_default_config();

	update_config_file("etc/sapp.toml", "timeout", "0");
	update_config_file("etc/sapp.toml", "original_ipv4_udp_enabled", "1");

	update_plugin_inf("UDP", "cheat_gtp_dup_check_entry");

	set_pcap_dumpfile("for_gtest_only/duplicate_packet/gtp_cheat_dup_dns.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "bbf1ed8a833aa92fd0f4e1acf8a7f3a0"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}

/*
	测试小端口是客户端的四元组创建流方向.
*/
void udp_well_known_port_run_v4(void)
{
	set_default_config();
	
	update_plugin_inf("UDP", "udp_well_known_port_v4_entry");

	system("echo [UDP] > ./etc/well_known_port.conf");
	system("echo 8000  >> ./etc/well_known_port.conf");

	/* TCP的配置其实没啥用, 就是顺带测试一下解析配置文件的功能 */
	system("echo [TCP] >> ./etc/well_known_port.conf");
	system("echo 11111 >> ./etc/well_known_port.conf");
	system("echo 55555 >> ./etc/well_known_port.conf");
	system("echo \"### hahaha\" >> ./etc/well_known_port.conf");

	set_pcap_dumpfile("oicq/oicq_sample.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "b4164565c44d2cb95d453b8d79ccd7df"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}

/*
	测试小端口是客户端的四元组创建流方向.
*/
void udp_well_known_port_run_v6(void)
{
	set_default_config();
	
	update_plugin_inf("UDP", "udp_well_known_port_v6_entry");

	system("echo [UDP] > ./etc/well_known_port.conf");
	system("echo 45678 >> ./etc/well_known_port.conf");

	/* TCP的配置其实没啥用, 就是顺带测试一下解析配置文件的功能 */
	system("echo [TCP] >> ./etc/well_known_port.conf");
	system("echo 11111 >> ./etc/well_known_port.conf");
	system("echo 55555 >> ./etc/well_known_port.conf");
	system("echo \"### hahaha\" >> ./etc/well_known_port.conf");

	set_pcap_dumpfile("for_gtest_only/udp/udp_ipv6_small_sport.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "86537aa064bab59fad77b253bd4a5757"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}


void udp_tuple4_reuse_test(void)
{
	set_default_config();

	update_config_file_by_lastline("etc/sapp.toml", "packet_io.polling","enabled", "0");
	update_config_file("etc/sapp.toml", "timeout", "10");
	
	update_plugin_inf("UDP", "udp_timeout_reset_entry");

	/* 这个pcap�?0秒后会超�? 被sapp分成两个流处�?*/
	set_pcap_dumpfile("for_gtest_only/udp/udp_timeout_reuse.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "b7c83190ac89dd081a6235aafe9ed096"),0);

	printf("test for udp timeout and reset, set --dumpfile-speed=timestamp please wait for a monment......\n");

	call_libsapp_devel_for_dumpfile_timestamp();	
}

void udp_givestate_entry_offload_run(void)
{
	set_default_config();
	
	update_plugin_inf("UDP", "udp_offload_1st_givestate_entry");

	set_pcap_dumpfile("udp/udp_simple.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "328951b2b04af765e6a0a7fe34ee29ad"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}

void udp__givestate_and_giveme_entry_offload_run(void)
{
	set_default_config();
	
	update_plugin_inf("UDP", "udp_offload_1st_givestate_entry");
	update_plugin_inf("UDP", "udp_offload_2st_giveme_entry");

	set_pcap_dumpfile("udp/udp_simple.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "328951b2b04af765e6a0a7fe34ee29ad"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}

#endif

