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

/* Teredo非标准端口解析测试 */
void teredo_unstandard_port_run(void)
{
	set_default_config();

	update_plugin_inf("TCP", "teredo_unstandard_port_tcp_entry");
	
	set_pcap_dumpfile("teredo/teredo_not_port3544.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "1f36c321d9e9cf1d83fe847a644b0d8f"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}

/* Teredo带认证头部解析测试 */
void teredo_with_auth_hdr_run(void)
{
	set_default_config();

	update_plugin_inf("IPV6", "teredo_with_auth_hdr_ip6entry");
	
	set_pcap_dumpfile("teredo/teredo_with_authentication_header.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "940e127d6cc76adc5875519cc1ff879c"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


void gtp_identify_run(void)
{
	set_default_config();

	update_plugin_inf("TCP", "gtp_identify_plug_tcp_entry");
	
	set_pcap_dumpfile("gtp/gtp_simple.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "e10707dedef0680effc4dadeb333b275"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}

void gtp_mpls_identify_run(void)
{
	set_default_config();

	update_plugin_inf("TCP", "gtp_identify_plug_tcp_entry");
	
	set_pcap_dumpfile("gtp/gtp_diff_external_ip_port_same_inner_tuple4.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "7db60c7d3bbec640e77499a328ca591b"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}

void pptp_identify_run(void)
{
	set_default_config();

	update_plugin_inf("TCP", "pptp_identify_plug_tcp_entry");
	
	set_pcap_dumpfile("pptp/pptp_http.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "4eb6fb78d78a4acdb2438949f28a7992"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


void l2tp_identify_run(void)
{
	set_default_config();

	/* l2tp识别目前需要挂载l2tp_protocol插件 */
	insert_into_conflist_inf("protocol", "./plug/protocol/l2tp_protocol_plug/l2tp_protocol_plug.inf");

	update_plugin_inf("TCP", "l2tp_identify_plug_tcp_entry");
	
	set_pcap_dumpfile("l2tp/l2tp_http.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "3862724016e0464569e6720ccc46d368"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}

/* l2tp头部ppp没有control, address字段识别测试 */
void l2tp_without_ppp_control_field_identify_run(void)
{
	set_default_config();

	/* l2tp识别目前需要挂载l2tp_protocol插件 */
	insert_into_conflist_inf("protocol", "./plug/protocol/l2tp_protocol_plug/l2tp_protocol_plug.inf");

	update_plugin_inf("UDP", "l2tp_identify_plug_udp_entry");
	
	set_pcap_dumpfile("l2tp/quic_without_ppp_control_address.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "908e25d12e2cc8561dd8f451893f6bbd"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


/*
	之前的版本l2tp解析层在udp超时free时,会崩溃!
	构造回归测试用例如下:
*/
void l2tp_protocol_timeout_run(void)
{
	const char *sapp_timeout_argv[4];

	sapp_timeout_argv[0] = (char *)"./sapp ";
	sapp_timeout_argv[1] = (char *)"--dumpfile";
	sapp_timeout_argv[2] = (char *)"--dumpfile-speed=timestamp";
	sapp_timeout_argv[3] = NULL;

	set_default_config();

	/* l2tp识别目前需要挂载l2tp_protocol插件 */
	insert_into_conflist_inf("protocol", "./plug/protocol/l2tp_protocol_plug/l2tp_protocol_plug.inf");

	update_plugin_inf("L2TP", "l2tp_biz_timeout_entry");
	
	set_pcap_dumpfile("for_gtest_only/tunnel/l2tp_timeout.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "c2d9ac1876ee3552d9fa4d4f7e7cc831"),0);
	
	gtest_start_sapp_progress(sapp_timeout_argv);
}


void teredo_identify_run(void)
{
	set_default_config();

	update_plugin_inf("TCP", "teredo_identify_plug_tcp_entry");
	
	set_pcap_dumpfile("teredo/teredo_http.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "b87935d6a063bf715d0c364ba9c65c19"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}

void pptp_and_4over6_identify_run(void)
{
	set_default_config();

	update_plugin_inf("TCP", "pptp_and_4over6_identify_plug_tcp_entry");
	
	set_pcap_dumpfile("for_gtest_only/tunnel/tcp_pptp_4over6.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "7c0eddedd983642bf0a02b813da89731"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


void t6over4_identify_run(void)
{
	set_default_config();

	update_plugin_inf("TCP", "t6over4_identify_plug_tcp_entry");
	
	set_pcap_dumpfile("6over4/ipv6_over_ipv4.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "5b512b3321164a73446bdd54f7d20057"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}



/* 内层四元组相同, 但外层mpls不同的流解析测试, 其实理论上是不应该开mpls地址比较的, 仅用于自测试*/
void tcp_same_tuple4_diff_mpls_two_stream_run(void)
{
	set_default_config();

	update_plugin_inf("TCP_ALL", "same_tuple4_diff_mpls_two_stream_tcpall_entry");
	
	set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");
	set_default_asymmetric_presence_layer_conf("mpls ethernet[0] ipv4[1]\n\n");
	set_default_stream_compare_layer_conf("mpls[*]\n"); /* 此用例要故意开启mpls层的hash地址比对 */

	update_config_file("etc/sapp.toml", "skip_not_ip_layer_over_eth", "0");

	set_pcap_dumpfile("for_gtest_only/tunnel/tcp_same_tuple4_with_diff_mpls.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "39e11718cc6620804f96475f58cfe89c"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


/* 内层四元组相同, 但外层mpls不同的流解析测试 */
void tcp_same_tuple4_diff_mpls_one_stream_run(void)
{
	set_default_config();

	update_plugin_inf("TCP_ALL", "same_tuple4_diff_mpls_one_stream_tcpall_entry");
	
	set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");
	set_default_asymmetric_presence_layer_conf("#\n");
	set_default_stream_compare_layer_conf("#\n"); /* 清空地址比较层配置文件 */

	update_config_file("etc/sapp.toml", "inject_all_enabled", "0"); /* 有重复的数据包, 要关闭重复流量检测功能 */
	update_config_file("etc/sapp.toml", "original_ipv4_tcp_enabled", "0");
	
	update_config_file("etc/sapp.toml", "skip_not_ip_layer_over_eth", "0");

	set_pcap_dumpfile("for_gtest_only/tunnel/tcp_same_tuple4_with_diff_mpls.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "39e11718cc6620804f96475f58cfe89c"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}

/* 
	内层TCP四元组相同, 但外层GTP四元组不同的流解析测试, 
	GTP隧道外层地址变化, 但内层四元组不变, 一般是移动设备漫游导致.
*/
void gtp_diff_outer_tuple4_run(void)
{
	set_default_config();

	update_plugin_inf("TCP", "gtp_diff_outer_tuple4_tcp_entry");
	
	set_pcap_dumpfile("gtp/gtp_diff_external_ip_port_same_inner_tuple4.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "7db60c7d3bbec640e77499a328ca591b"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


/*
	与gtp_diff_outer_tuple4_run类似, 
	此插件测试sapp是否能侦测到地址变化, 且更新地址信息.
*/
void gtp_diff_outer_tuple4_track_gtp_teid_run(void)
{
	set_default_config();

	update_plugin_inf("TCP", "gtp_diff_outer_tuple4_track_teid_tcp_entry");
	
	set_pcap_dumpfile("gtp/gtp_diff_external_ip_port_same_inner_tuple4.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "7db60c7d3bbec640e77499a328ca591b"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


/*
	与gtp_diff_outer_tuple4_track_gtp_teid_run类似, 此包改变的是s2c方向的ip和teid,
	此插件测试sapp是否能侦测到地址变化, 且更新地址信息.
*/
void gtp_diff_outer_tuple4_track_gtp_teid_s2c_run(void)
{
	set_default_config();

	update_plugin_inf("TCP", "gtp_diff_outer_tuple4_track_teid_s2c_tcp_entry");
	
	set_pcap_dumpfile("for_gtest_only/gtp/gtp_diff_outer_ip_same_inner_tuple4_s2c.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "9488ebd169c47eb815a15ae7de99634d"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}



/* 本测试插件用于测试完全没有mpls层的Pcap包   ,
   本来没有Mpls, 但是开启了asymmetric_presence配置, 导致创建了空层的问题.
*/
void pcap_no_mpls_tcp_run(void)
{
	set_default_config();

	update_plugin_inf("TCP", "pcap_no_mpls_tcp_entry");

	/* 开启非对称Mpls层配置 */
	set_default_asymmetric_presence_layer_conf("mpls ethernet[0] ipv4[1]\nmpls ethernet[0] ipv6[1]\n\n");
	set_default_stream_compare_layer_conf("#\n");

	set_pcap_dumpfile("tcp/tcp_simple.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


void l2tp_tunnel_pfather_iterate_run(void)
{
	set_default_config();

	/* 此处故意设成inline vxlan模式, 但是读包时不应该受这些参数影响 */
	update_config_file("etc/sapp.toml", "l2_l3_tunnel_support", "1");
	update_config_file("etc/sapp.toml", "overlay_mode", "none");
	update_config_file_by_lastline("etc/sapp.toml", "packet_io.depolyment", "mode", "inline");
	update_config_file_by_lastline("etc/sapp.toml", "packet_io.internal.interface", "name", "lo");

	/* l2tp识别目前需要挂载l2tp_protocol插件 */
	insert_into_conflist_inf("protocol", "./plug/protocol/l2tp_protocol_plug/l2tp_protocol_plug.inf");

	update_plugin_inf("TCP", "l2tp_tunnel_stream_pfather_iterate_entry");
	
	set_pcap_dumpfile("l2tp/l2tp_http.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "3862724016e0464569e6720ccc46d368"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


void pptp_tunnel_pfather_iterate_run(void)
{
	set_default_config();

	/* 此处故意设成inline vxlan模式, 但是读包时不应该受这些参数影响 */
	update_config_file("etc/sapp.toml", "l2_l3_tunnel_support", "1");
	update_config_file("etc/sapp.toml", "overlay_mode", "none");
	update_config_file_by_lastline("etc/sapp.toml", "packet_io.depolyment", "mode", "inline");
	update_config_file_by_lastline("etc/sapp.toml", "packet_io.internal.interface", "name", "lo");

	insert_into_conflist_inf("protocol", "./plug/protocol/pptp_protocol_plug/pptp_protocol_plug.inf");

	update_plugin_inf("TCP", "pptp_tunnel_stream_pfather_iterate_entry");
	
	set_pcap_dumpfile("pptp/pptp_http.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "4eb6fb78d78a4acdb2438949f28a7992"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}





