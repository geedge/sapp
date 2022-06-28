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
#include <sys/types.h>	 
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include "gtest_sapp_fun.h"
#include <gtest/gtest.h>

/*
	测试vlan和mpls层两侧不对称的解析情况.
*/

void asymmetric_mpls_c2s_run(void)
{
	set_default_config();
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_plugin_inf("TCP", "asymmetric_mpls_c2s_entry");
	set_default_asymmetric_presence_layer_conf("#\n"); 
	
	set_pcap_dumpfile("for_gtest_only/mpls/mpls_asymmetric_c2s.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "b3916fa87bdc68d4c848245c23913841"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}

void asymmetric_mpls_s2c_run(void)
{
	set_default_config();
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_plugin_inf("TCP", "asymmetric_mpls_s2c_entry");
	set_default_asymmetric_presence_layer_conf("#\n"); 
	
	set_pcap_dumpfile("for_gtest_only/mpls/mpls_asymmetric_0vs1.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "50ef8a3004c9460482d8628c8187f533"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}


void asymmetric_vlan_c2s_run(void)
{
	set_default_config();
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_plugin_inf("TCP", "asymmetric_vlan_c2s_entry");
	set_default_asymmetric_presence_layer_conf("#\n"); 
	
	set_pcap_dumpfile("for_gtest_only/vlan/asymmetric_vlan_c2s.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "a64c1067b61b04153948d40d6c0b0a70"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}

void asymmetric_vlan_s2c_run(void)
{
	set_default_config();
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_plugin_inf("TCP", "asymmetric_vlan_s2c_entry");
	set_default_asymmetric_presence_layer_conf("#\n"); 
	
	set_pcap_dumpfile("for_gtest_only/vlan/asymmetric_vlan_s2c.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "8dc6fbd35cb7cfd0f64ea69d6abcf7c8"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}

/*
	asymmetric_mpls_vlan.pcap 这个包非常复杂,
	包括多层mpls和vlan, 而且不对称!
	C2S方向有1层外层MPLS, 但是没有内层的mpls和vlan; 
	S2C方向有2层外层MPLS, 而且内层还有两层mpls和vlan.
*/
void asymmetric_mpls_and_vlan_run(void)
{
	set_default_config();
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_plugin_inf("UDP", "asymmetric_mpls_and_vlan_entry");
	set_default_asymmetric_presence_layer_conf("#\n"); 
	
	set_pcap_dumpfile("for_gtest_only/asymmetric/asymmetric_mpls_vlan.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "1ebd0ff46250aa932d7d05a8bdace8b9"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}


