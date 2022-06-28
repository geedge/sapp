#include "gtest_sapp_fun.h"
#include "stream.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <gtest/gtest.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h> /* See NOTES */
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

void jump_layer_eth_ipv4_tcp_run(void)
{
	set_default_config();

	update_plugin_inf("TCP_ALL", "jump_layer_eth_ipv4_tcp_entry");

	set_pcap_dumpfile("tcp/tcp_simple.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"), 0);

	call_libsapp_devel_with_args(2, sapp_start_args);
}

void jump_layer_eth_ipv4_udp_run(void)
{
	set_default_config();

	update_plugin_inf("UDP", "jump_layer_eth_ipv4_udp_entry");

	set_pcap_dumpfile("udp/udp_simple.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "328951b2b04af765e6a0a7fe34ee29ad"), 0);

	call_libsapp_devel_with_args(2, sapp_start_args);
}

void jump_layer_eth_ipv6_tcp_run(void)
{
	set_default_config();

	update_plugin_inf("TCP_ALL", "jump_layer_eth_ipv6_tcp_entry");

	set_pcap_dumpfile("for_gtest_only/jump_layer/ipv6_tcp.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "9628c627a7e55c2995c3e174e78e55ac"), 0);

	call_libsapp_devel_with_args(2, sapp_start_args);
}

void jump_layer_eth_ipv6_udp_run(void)
{
	set_default_config();

	update_plugin_inf("UDP", "jump_layer_eth_ipv6_udp_entry");

	set_pcap_dumpfile("for_gtest_only/jump_layer/ipv6_udp.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "5eecd0ab3905c9f3d07a3502e5e380f0"), 0);

	call_libsapp_devel_with_args(2, sapp_start_args);
}

void jump_layer_eth_ipv4_gre_ipv4_gre_ipv4_dns_run(void)
{
	set_default_config();

	update_plugin_inf("UDP", "jump_layer_eth_ipv4_gre_ipv4_gre_ipv4_udp_entry");

	set_pcap_dumpfile("gre/gre_dns.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "9242d1b85676308cee9b56e6a5fea3f4"), 0);

	call_libsapp_devel_with_args(2, sapp_start_args);
}

void jump_layer_eth_ipv4_pptp_ipv4_tcp_run(void)
{
	set_default_config();

	update_plugin_inf("TCP_ALL", "jump_layer_eth_ipv4_pptp_ipv4_tcpall_entry");

	set_pcap_dumpfile("for_gtest_only/jump_layer/ipv4_pptp_ipv4_tcp.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "012b4be2106c3482c20602e945943553"), 0);

	call_libsapp_devel_with_args(2, sapp_start_args);
}

void jump_layer_eth_ipv4_gtp_ipv4_tcp_run(void)
{
	set_default_config();
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");

	update_plugin_inf("TCP_ALL", "jump_layer_eth_ipv4_gtp_ipv4_tcpall_entry");

	set_pcap_dumpfile("gtp/gtp_simple.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "e10707dedef0680effc4dadeb333b275"), 0);

	call_libsapp_devel_with_args(2, sapp_start_args);
}

void jump_layer_eth_ip4_l2tp_ip4_tcp_run(void)
{
	set_default_config();

	update_plugin_inf("TCP_ALL", "jump_layer_eth_ip4_l2tp_ip4_tcpall_entry");

	/* l2tp识别目前需要挂载l2tp_protocol插件 */
	insert_into_conflist_inf("protocol", "./plug/protocol/l2tp_protocol_plug/l2tp_protocol_plug.inf");

	set_pcap_dumpfile("for_gtest_only/jump_layer/ipv4_l2tp_ipv4_tcp.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "8371e22c8c49edcd5b8c979ef11e238e"), 0);

	call_libsapp_devel_with_args(2, sapp_start_args);
}

void jump_layer_eth_ip4_l2tp_ip4_udp_run(void)
{
	set_default_config();

	update_plugin_inf("UDP", "jump_layer_eth_ip4_l2tp_ip4_udp_entry");

	/* l2tp识别目前需要挂载l2tp_protocol插件 */
	insert_into_conflist_inf("protocol", "./plug/protocol/l2tp_protocol_plug/l2tp_protocol_plug.inf");

	set_pcap_dumpfile("for_gtest_only/jump_layer/ipv4_l2tp_ipv4_udp.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "5911d72bba20e1fb6bc7e0266c9ac5df"), 0);

	call_libsapp_devel_with_args(2, sapp_start_args);
}

void jump_layer_eth_ip4_l2tp_ppp_compress_ip4_udp_run(void)
{
	set_default_config();

	update_plugin_inf("UDP", "jump_layer_eth_ip4_l2tp_ppp_compress_ip4_udp_entry");

	/* l2tp识别目前需要挂载l2tp_protocol插件 */
	insert_into_conflist_inf("protocol", "./plug/protocol/l2tp_protocol_plug/l2tp_protocol_plug.inf");

	set_pcap_dumpfile("for_gtest_only/jump_layer/ipv4_l2tp_ppp_compress_ipv4_udp.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "62cbdf729199bcca78de9b4944da5256"), 0);

	call_libsapp_devel_with_args(2, sapp_start_args);
}

void jump_layer_eth_vlan_ip6_ip4_pptp_ip4_ip6_tcp_run(void)
{
	set_default_config();

	update_plugin_inf("TCP_ALL", "jump_layer_eth_vlan_ip6_ip4_pptp_ip4_ip6_tcpall_entry");

	set_pcap_dumpfile("hybrid_multi_layer_tunnel/vlan_ipv6_ipv4_pptp_ipv4.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "bd27882b452596223b8179ab8c8dd241"), 0);

	call_libsapp_devel_with_args(2, sapp_start_args);
}

void jump_layer_eth_ip4_udp_teredo_udp_ip6_udp_run(void)
{
	set_default_config();

	update_plugin_inf("UDP", "jump_layer_eth_ip4_udp_teredo_udp_ip6_udp_entry");

	set_pcap_dumpfile("for_gtest_only/jump_layer/ipv4_udp_teredo_ipv6_udp.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "3452c955d6294fedd2fc1437b1daf0aa"), 0);

	call_libsapp_devel_with_args(2, sapp_start_args);
}

void jump_layer_eth_ip4_udp_teredo_udp_ip6_tcp_run(void)
{
	set_default_config();
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");

	update_plugin_inf("TCP_ALL", "jump_layer_eth_ip4_udp_teredo_udp_ip6_tcpall_entry");

	set_pcap_dumpfile("for_gtest_only/jump_layer/ipv4_udp_teredo_ipv6_tcp.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "970a23eaffe82d02e7a6920d52d201f1"), 0);

	call_libsapp_devel_with_args(2, sapp_start_args);
}

void jump_layer_eth_vlan_ip6_udp_gtpext_ip4_tcp_run(void)
{
	set_default_config();
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");

	update_plugin_inf("TCP_ALL", "jump_layer_eth_vlan_ip6_udp_gtpext_ip4_tcpall_entry");

	set_pcap_dumpfile("for_gtest_only/gtp/gtp_with_extension_hdr_and_seq.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "d51cebb81e70baaf9568f13af867f6c4"), 0);

	call_libsapp_devel_with_args(2, sapp_start_args);
}
