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


void mpls_asymmetric_1vs2_run(void)
{
	set_default_config();

	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	
	update_plugin_inf("TCP", "tcp_entry_for_asymmetric_1vs2");

	set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");
	
	set_pcap_dumpfile("for_gtest_only/mpls/mpls_asymmetric_1vs2.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "3894f69adfab6c2fe690982866aa8d9c"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
	// gtest_start_sapp_progress(sapp_start_args);
}


