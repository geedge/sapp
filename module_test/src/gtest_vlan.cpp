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


void vlan_2layer_run(void)
{
	set_default_config();

	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	
	update_plugin_inf("TCP", "tcp_entry_for_vlan_2layer");
	update_config_file("etc/sapp.toml", "skip_not_ip_layer_over_eth", "0");
	
	set_pcap_dumpfile("for_gtest_only/vlan/double_vlan.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "d31d70928b2a647b7820e27a99b247cb"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}


/*
	非对称vlan解析.
*/
void vlan_asymmetric_merge_run(void)
{
	set_default_config();

	update_config_file("etc/sapp.toml", "syn_mandatory", "0");

	update_config_file("etc/sapp.toml", "skip_not_ip_layer_over_eth", "1");
	
	set_default_asymmetric_addr_layer_conf("#\n");
	
	update_plugin_inf("TCP", "tcp_entry_for_vlan_asymmetric");
	
	set_pcap_dumpfile("vlan/asymmetric_vlan.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "502c003b622d9e7a15d242375634837c"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}


