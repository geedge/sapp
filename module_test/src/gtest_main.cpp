#include <gtest/gtest.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/types.h>			/* See NOTES */
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include "stream.h"
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "gtest_sapp_fun.h"

void *g_sapp_test_log_handle;
int g_slient_mode = 0;
const char *user_define_args;

const char *for_test_sapp_version = "4.2.68_c9193fe";

static int g_libsapp_devel_res = GTEST_SAPP_ERR; /* 使用lisapp_devel.so在同一个进程内运行的测试结�????*/
int gtest_set_libsapp_devel_result(int res_value)
{
	g_libsapp_devel_res = res_value;
	//printf("set res: %p to value :%x\n", &g_libsapp_devel_res, res_value);
	return 0;
}

int gtest_get_libsapp_devel_result(void)
{
	//printf("get res: %p value :%x\n", &g_libsapp_devel_res, g_libsapp_devel_res);
	return g_libsapp_devel_res;
}

void call_libsapp_devel_with_args(int argc, const char *argv[])
{
	int ret, real_argc = argc;
	gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);

	char *sapp_dumpfile_start_args[argc+2];
	if(g_slient_mode){
		for(int i = 0; i < argc; i++)
		{
			if(argv[i] != NULL)
			{
				sapp_dumpfile_start_args[i] = (char*)calloc(1, strlen(argv[i])+1);
				strcpy(sapp_dumpfile_start_args[i], argv[i]);
			}
		}
		sapp_dumpfile_start_args[argc] = (char*)calloc(3,1);
		strncpy(sapp_dumpfile_start_args[argc], "-n", 2);
		sapp_dumpfile_start_args[argc+1] = (char*)calloc(3,1);
		strncpy(sapp_dumpfile_start_args[argc+1], "-s", 2);
		real_argc+=2;
		
		ret = libsapp_setup_env(real_argc, sapp_dumpfile_start_args);
	}else{
		for(int i = 0; i < argc; i++)
		{
			if(argv[i] != NULL)
			{
				sapp_dumpfile_start_args[i] = (char*)calloc(1, strlen(argv[i])+1);
				strcpy(sapp_dumpfile_start_args[i], argv[i]);
			}
		}
		sapp_dumpfile_start_args[argc] = (char*)calloc(3,1);
		strncpy(sapp_dumpfile_start_args[argc], "-n", 2);
		real_argc+=1;
		
		ret = libsapp_setup_env(real_argc, sapp_dumpfile_start_args);
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

	for(int i=0; i <argc; i++)
	{
		if(sapp_dumpfile_start_args[i] != NULL)
		{
			free(sapp_dumpfile_start_args[i]);
		}
	}
	if(g_slient_mode)
	{
		free(sapp_dumpfile_start_args[argc]);
	}
}

void call_libsapp_devel_for_dumpfile_topspeed(void)
{
	int ret;
	gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);

	if(g_slient_mode){
		char *sapp_dumpfile_start_args[] = {(char *)"./sapp", (char *)"-s", (char *)"-d", (char *)"-n", (char *)NULL};
		ret = libsapp_setup_env(4, sapp_dumpfile_start_args);
	}else{
		char *sapp_dumpfile_start_args[] = {(char *)"./sapp", (char *)"-d", (char *)"-n", (char *)NULL};
		ret = libsapp_setup_env(3, sapp_dumpfile_start_args);
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

void call_libsapp_devel_for_dumpfile_timestamp(void)
{
	int ret;
	gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);

	if(g_slient_mode){
		char *sapp_dumpfile_timestamp_start_args[] = {(char *)"./sapp", (char *)"-s", (char *)"-d", (char *)"-p", (char *)"timestamp", (char *)"-n", (char *)NULL};
		ret = libsapp_setup_env(6, sapp_dumpfile_timestamp_start_args);
	}else{
		char *sapp_dumpfile_timestamp_start_args[] = {(char *)"./sapp", (char *)"-d", (char *)"-p", (char *)"timestamp", (char *)"-n", (char *)NULL};
		ret = libsapp_setup_env(5, sapp_dumpfile_timestamp_start_args);
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


void call_libsapp_devel_online_mode(void)
{
	int ret;
	gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
	
	if(g_slient_mode){
		char *sapp_online_start_args_3[] = {(char *)"./sapp", (char *)"-s", (char *)"-n",  (char *)NULL};
		ret = libsapp_setup_env(3, sapp_online_start_args_3);
	}else{
		char *sapp_online_start_args_2[] = {(char *)"./sapp", (char *)"-n", (char *)NULL};
		ret = libsapp_setup_env(2, sapp_online_start_args_2);
	}

	if(ret < 0){
		printf("call libsapp_setup_env() fail");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return;
	}
	while(sapp_get_current_state() != SAPP_STATE_PROCESSING){
		usleep(100);
	}
	sleep(3); /* TODO: 此处不用超时, 而是靠一个标志位或特定状�????*/
	libsapp_destroy_env();

}


/************************* IPv4 frag simple Test ******************************/
#define ipv4_frag_simple 1  // for SI symbol view
TEST(ipv4, frag_simple)
{
	ipv4_frag_assemble_simple_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define ipv4_frag_checksum 1  // for SI symbol view
TEST(ipv4, frag_checksum)
{
	ipv4_frag_assemble_checksum_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


/********************** IPv4 frag out of order Test ***************************/
#define ipv4_frag_out_of_order 1  // for SI symbol view
TEST(ipv4, frag_out_of_order)
{
	ipv4_frag_assemble_oos_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#if (0 == HIGH_PERF)	
#define ipv4_frag_assemble_udp 1  // for SI symbol view
TEST(ipv4, frag_assemble_udp)
{
	ipv4_frag_udp_assemble_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}
#endif

/********************************* IPv6 Test ******************************/


/************************* IPv6 frag simple Test ******************************/
#define ipv6_frag_simple 1  // for SI symbol view
TEST(ipv6, frag_simple)
{
	ipv6_frag_assemble_simple_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


/********************** IPv6 frag out of order Test ***************************/
#define ipv6_frag_out_of_order 1  // for SI symbol view
TEST(ipv6, frag_out_of_order)
{
	ipv6_frag_assemble_oos_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#if (0 == HIGH_PERF)	
#define ipv6_frag_assemble_udp 1  // for SI symbol view
TEST(ipv6, frag_assemble_udp)
{
	ipv6_frag_udp_assemble_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}
#endif

/*************************** UDP simple Test ********************************/
#define udp_simple 1  // for SI symbol view
TEST(udp, simple)
{
	udp_simple_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#if SAPP_V4 

#define udp_link_c2s_1pkt 1  // for SI symbol view
TEST(udp, link_c2s_1pkt)
{
	udp_link_c2s_1pkt_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define udp_link_c2s_10pkt 1  // for SI symbol view
TEST(udp, link_c2s_10pkt)
{
	udp_link_c2s_10pkt_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define udp_link_s2c_1pkt 1  // for SI symbol view
TEST(udp, link_s2c_1pkt)
{
	udp_link_s2c_1pkt_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define udp_link_s2c_10pkt 1  // for SI symbol view
TEST(udp, link_s2c_10pkt)
{
	udp_link_s2c_10pkt_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define udp_dup_pkt_positive 1  // for SI symbol view
TEST(udp, dup_pkt_positive)
{
	udp_dup_pkt_positive_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define udp_dup_pkt_negative 1  // for SI symbol view
TEST(udp, dup_pkt_negative)
{
	udp_dup_pkt_negative_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define udp_cheat_l2tp_dup_dns 1  // for SI symbol view
TEST(udp, cheat_l2tp_dup_dns)
{
	cheat_l2tp_dup_dns_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define udp_cheat_gtp_dup_dns 1 
TEST(udp, cheat_gtp_dup_dns)
{
	cheat_gtp_dup_dns_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define udp_well_known_port_v4 1 
TEST(udp, well_known_port_v4)
{
	udp_well_known_port_run_v4();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define udp_well_known_port_v6 1 
TEST(udp, well_known_port_v6)
{
	udp_well_known_port_run_v6();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define udp_tuple4_reuse 1 
TEST(udp, DISABLED_tuple4_reuse)
{
	udp_tuple4_reuse_test();
	ASSERT_EQ(gtest_get_libsapp_devel_result(), GTEST_SAPP_SUCC);
}

#define udp_offload_givestate_entry 1
TEST(offload, udp_givestate_entry)
{
	udp_givestate_entry_offload_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define udp_offload_givestate_and_giveme_entry 1
TEST(offload, udp_givestate_and_giveme_entry)
{
	udp__givestate_and_giveme_entry_offload_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#endif


/*************************** TCPALL simple Test ********************************/
#if (0 == HIGH_PERF)	
#define _tcpall_simple 1  // for SI symbol view
TEST(tcpall, simple)
{
	tcpall_simple_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}
#endif

/*************************** TCP simple Test **********************************/
#define _tcp_simple 1  // for SI symbol view
TEST(tcp, simple)
{
	tcp_simple_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

/************************** TCP out of order Test ****************************/
#define _tcp_oos 1  // for SI symbol view
TEST(tcp, oos)
{
	tcp_oos_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

/********************** TCP out of order lost pkt Test ***********************/
#define _tcp_oos_lost_pkt 1  // for SI symbol view
TEST(tcp, oos_lost_pkt)
{
	tcp_oos_lost_pkt_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define _tcp_plug_droppkt_test 1  // for SI symbol view
TEST(tcp, plug_killother)
{
	tcp_plug_killother_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#if SAPP_V4 

#define tcp_lost_pkt_test 1  // for SI symbol view
TEST(tcp, lost_pkt)
{
	int result;
	tcp_lost_pkt_run();
	result = gtest_get_libsapp_devel_result();

	if(GTEST_SAPP_ERR_SKIP == result){
		/* 因为结构体变化导致的测试用例无法运行 */
		printf("\033[1;31;40mcase tcp.lost_pkt error, because sapp internal structure is changed!\033[0m\n");
	}
	ASSERT_EQ(GTEST_SAPP_SUCC, result);
}
#endif

#define tcp_lost_pkt_manual_test 1  // for SI symbol view
TEST(tcp, lost_pkt_manual)
{
	int result;
	tcp_lost_pkt_manual_run();
	result = gtest_get_libsapp_devel_result();

	ASSERT_EQ(GTEST_SAPP_SUCC, result);
}


/************************* TCP timeout and reset Test **************************/
#if (0 == HIGH_PERF)	
#define tcp_timeout_reset 1  // for SI symbol view
TEST(tcp, timeout_reset)
{
	tcp_timeout_reset_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}
#endif

/************************* TCP deduce flow stat Test **************************/
#define tcp_deduce_test 1  // for SI symbol view
TEST(tcp, deduce_flow)
{
	tcp_deduce_flow_stat_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

/************************* TCP call order Test **************************/
#define tcp_call_order_test 1  // for SI symbol view
TEST(tcp, call_order)
{
	tcp_call_order_check_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

/********************* TCP call order for reset Test ***********************/

#define tcp_raw_entry_test 1  // for SI symbol view
TEST(tcp, raw_entry)
{
	tcp_raw_entry_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define tcp_dumpfile_listtest 1  // for SI symbol view
TEST(tcp, dumpfile_list)
{
	tcp_dumpfile_list_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define tcp_dup_pkt_positive 1  // for SI symbol view
TEST(tcp, dup_pkt_positive)
{
	tcp_dup_pkt_positive_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define tcp_dup_pkt_negative 1  // for SI symbol view
TEST(tcp, dup_pkt_negative)
{
	tcp_dup_pkt_negative_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define tcp_dropstream_and_unorder 1  // for SI symbol view
TEST(tcp, dropstream_and_unorder)
{
	tcp_dropstream_and_unorder_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define tcp_tuple4_reuse_with_fin 1  // for SI symbol view
TEST(tcp, tuple4_reuse_with_fin)
{
	tcp_tuple4_reuse_with_fin_run();
	EXPECT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define tcpall_tuple4_reuse_with_fin 1  // for SI symbol view
TEST(tcpall, tuple4_reuse_with_fin)
{
	tcpall_tuple4_reuse_with_fin_run();
	EXPECT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define tcp_tuple4_reuse_no_close 1  // for SI symbol view
TEST(tcp, tuple4_reuse_no_close)
{
	tcp_tuple4_reuse_no_close_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define tcp_well_known_port_v4 1  // for SI symbol view
TEST(tcp, well_known_port_v4)
{
	tcp_well_known_port_run_v4();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define tcp_not_use_well_known_port_v4 1  // for SI symbol view
TEST(tcp, not_use_well_known_port_v4)
{
	tcp_not_use_well_known_port_run_v4();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define tcp_well_known_port_v6 1  // for SI symbol view
TEST(tcp, well_known_port_v6)
{
	tcp_well_known_port_run_v6();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define tcp_retransmit 1  // for SI symbol view
TEST(tcp, retransmit)
{
	tcp_retransmit_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define tcp_overlap 1  // for SI symbol view
TEST(tcp, overlap)
{
	tcp_overlap_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#if (0 == HIGH_PERF)	
#define tcp_first_unorder_pkt 1  // for SI symbol view
TEST(tcp, first_unorder_pkt)
{
	tcp_first_unorder_rawpkt_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}
#endif

#define tcp_over_gtp_with_seq_no_ext 1  // for SI symbol view
TEST(tcp, gtp_with_seq_no_ext)
{
	gtp_with_seq_no_ext_tcp_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#if (0 == HIGH_PERF)	
#define tcp_over_gtp_with_seq_and_ext 1  // for SI symbol view
TEST(tcp, gtp_with_seq_and_ext)
{
	gtp_with_seq_and_ext_tcp_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}
#endif

#define tcp_over_gtp_without_seq_and_ext 1  // for SI symbol view
TEST(tcp, gtp_without_seq_and_ext)
{
	gtp_without_seq_and_ext_tcp_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define tcp_tfo 1 
TEST(tcp, tfo)
{
	tcp_tfo_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

/*************************** TCPALL simple Test ********************************/
#define _tcpall_offload_givestate_entry 1  // for SI symbol view
TEST(offload, tcpall_givestate_entry)
{
	tcpall_offload_givestate_entry_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

/*************************** TCPALL simple Test ********************************/
#define _tcpall_offload_givestate_and_giveme_entry_run_entry 1  // for SI symbol view
TEST(offload, tcpall_givestate_and_giveme_entry)
{
	tcpall_offload_givestate_and_giveme_entry_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define _tcp_offload_givestate_entry 1  // for SI symbol view
TEST(offload, tcp_givestate_entry)
{
	tcp_offload_givestate_entry_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

/*************************** TCPALL simple Test ********************************/
#define _tcp_offload_givestate_and_giveme_entry 1  // for SI symbol view
TEST(offload, tcp_givestate_and_giveme_entry)
{
	tcp_offload_givestate_and_giveme_entry_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


/************************** stream_control.h API test *************************/
#if (0 == HIGH_PERF)
#define control_tcp_need_ack 1  // for SI symbol view
TEST(control, tcp_need_ack)
{
	control_tcp_need_ack_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}
#endif

#define control_takeover 1  // for SI symbol view
TEST(control, takeover)
{
	control_takeover_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define control_timeout 1  // for SI symbol view
TEST(control, DISABLED_timeout)
{
	control_timeout_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define control_max_unorder 1  // for SI symbol view
TEST(control, max_unorder)
{
	control_max_unorder_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define control_tcp_isn_c2s 1  // for SI symbol view
TEST(control, tcp_isn_c2s)
{
	control_tcp_isn_c2s_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define control_tcp_isn_s2c 1  // for SI symbol view
TEST(control, tcp_isn_s2c)
{
	control_tcp_isn_s2c_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define control_tcp_syn_option 1  // for SI symbol view
TEST(control, tcp_syn_option)
{
	control_tcp_option_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define control_tunnel_type_6over4 1  // for SI symbol view
TEST(control, tunnel_type_6over4)
{
	control_tunnel_type_6over4_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define control_tunnel_type_gre 1  // for SI symbol view
TEST(control, tunnel_type_gre)
{
	control_tunnel_type_gre_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define control_tunnel_type_teredo 1  // for SI symbol view
TEST(control, tunnel_type_teredo)
{
	control_tunnel_type_teredo_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define control_tunnel_type_l2tp 1  // for SI symbol view
TEST(control, tunnel_type_l2tp)
{
	control_tunnel_type_l2tp_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define control_tunnel_type_pptp 1  // for SI symbol view
TEST(control, tunnel_type_pptp)
{
	control_tunnel_type_pptp_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define control_tunnel_type_gtp 1  // for SI symbol view
TEST(control, tunnel_type_gtp)
{
	control_tunnel_type_gtp_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#if SAPP_V4
#define control_get_stream_id 1  // for SI symbol view
TEST(control, get_stream_id)
{
	global_stream_id_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define control_get_stream_id_tuple4_reuse 1  // for SI symbol view
TEST(control, get_stream_id_tuple4_reuse)
{
	global_stream_id_tuple4_reuse_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define control_stream_createtime_tuple4_reuse 1  // for SI symbol view
TEST(control, stream_createtime_tuple4_reuse)
{
	stream_creattime_tuple4_reuse_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define control_get_tcp_stream_id 1  // for SI symbol view
TEST(control, control_get_tcp_streamid)
{
	control_get_tcp_streamid_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define control_get_udp_stream_id 1  // for SI symbol view
TEST(control, control_get_udp_streamid)
{
	control_get_udp_streamid_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#endif

#define control_platform_opt 1  // for SI symbol view
TEST(control, platform_opt)
{
	control_platform_opt_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#if (0 == HIGH_PERF)	
#define control_stream_and_traffic 1  // for SI symbol view
TEST(control, stream_and_traffic)
{
	control_stream_and_traffic_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}
#endif

#define control_stream_create_timestamp_ms 1  // for SI symbol view
TEST(control, stream_create_timestamp_ms)
{
	control_stream_create_timestamp_ms_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define control_up_layer_tunnel_gtp 1  // for SI symbol view
TEST(control, up_layer_tunnel_gtp)
{
	control_up_layer_tunnel_gtp_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define control_up_layer_tunnel_l2tp 1  // for SI symbol view
TEST(control, up_layer_tunnel_l2tp)
{
	control_up_layer_tunnel_l2tp_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define control_up_layer_tunnel_teredo 1  // for SI symbol view
TEST(control, up_layer_tunnel_teredo)
{
	control_up_layer_tunnel_teredo_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define control_get_plug_pme 1  // for SI symbol view
TEST(control, get_plug_pme)
{
	control_get_plug_pme_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define control_plug_necessary 1  // for SI symbol view
TEST(control, plug_necessary)
{
	EXPECT_EXIT(control_plug_necessary_run(), testing::ExitedWithCode(1), "");
}

#define control_plug_necessary_no_inf 1  // for SI symbol view
TEST(control, plug_necessary_no_inf)
{
	EXPECT_EXIT(control_plug_necessary_run_no_inf(), testing::ExitedWithCode(1), "");
}


#define control_plug_necessary_no_sofile 1  // for SI symbol view
TEST(control, plug_necessary_no_sofile)
{
	EXPECT_EXIT(control_plug_necessary_run_no_sofile(), testing::ExitedWithCode(1), "");
}


#define control_plug_dup_pkt_tcp 1  // for SI symbol view
TEST(control, plug_dup_pkt_tcp)
{
	control_plug_dup_pkt_tcp_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result()); 
}

#define control_plug_dup_pkt_udp 1  // for SI symbol view
TEST(control, plug_dup_pkt_udp)
{
	control_plug_dup_pkt_udp_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result()); 
}

// #if (0 == HIGH_PERF)	
// #define control_find_streaminfo_v4 1 
// TEST(control, find_streaminfo_v4)
// {
// 	find_streaminfo_v4_run();
// 	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result()); 
// }
// #endif

// #define control_find_streaminfo_v6 1 
// TEST(control, find_streaminfo_v6)
// {
// 	find_streaminfo_v6_run();
// 	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result()); 
// }

// #define control_find_streaminfo_diff_tunnel_v4 1 
// TEST(control, find_streaminfo_diff_tunnel_v4)
// {
// 	find_streaminfo_diff_tunnel_v4_run();
// 	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result()); 
// }


#define control_get_root_dir 1 
TEST(control, get_root_dir)
{
	control_get_root_dir_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result()); 
}


#define control_fork_listen_port 1 
TEST(control, fork_listen_port)
{
	control_fork_listen_port_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result()); 
}


#define control_toml_array_parse_run 1 
TEST(control, toml_array_parse)
{
	toml_array_parse_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result()); 
}


// #define control_get_linkdir_from_mac0 1 
// TEST(control, get_linkdir_from_mac0)
// {
// 	get_linkdir_from_mac_run();
// 	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result()); 
// }


// #define control_get_linkdir_from_mac1 1 
// TEST(control, get_linkdir_from_mac1)
// {
// 	get_linkdir_from_mac_run2();
// 	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result()); 
// }

#define control_get_depmode_mirror 1 
TEST(control, get_depmode_mirror)
{
	EXPECT_EXIT(get_deployment_mode_mirror(), testing::ExitedWithCode(0),  "get_deployment_mode_entry test success");
}


#define control_get_depmode_inline 1 
TEST(control, get_depmode_inline)
{
	EXPECT_EXIT(get_deployment_mode_inline(), testing::ExitedWithCode(0),  "get_deployment_mode_entry test success");
}


#define control_get_depmode_transparent 1 
TEST(control, get_depmode_transparent)
{
	EXPECT_EXIT(get_deployment_mode_transparent(), testing::ExitedWithCode(0),  "get_deployment_mode_entry test success");
}

#define _control_tcp_drop_current_pkt 1  // for SI symbol view
TEST(control, DISABLED_tcp_drop_current_pkt)
{
	EXPECT_EXIT(control_drop_current_tcp_pkt_run(), testing::ExitedWithCode(0),  "");
	ASSERT_EQ(GTEST_TRANSPARENT_TO_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define _control_udp_drop_current_pkt 1  // for SI symbol view
TEST(control, DISABLED_udp_drop_current_pkt)
{
	EXPECT_EXIT(control_drop_current_udp_pkt_run(), testing::ExitedWithCode(0),  "");
	ASSERT_EQ(GTEST_TRANSPARENT_TO_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define control_get_tcp_flow_stat 1 
TEST(control, get_tcp_flow_stat)
{
	inline_get_tcp_flow_stat_run();
	//EXPECT_EXIT(inline_get_tcp_flow_stat_run(), testing::ExitedWithCode(0),  "inline_get_tcp_flow_stat_entry() test success");
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result()); 
}

#define control_get_udp_flow_stat 1 
TEST(control, get_udp_flow_stat)
{
	inline_get_udp_flow_stat_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result()); 
}

#define control_get_ip_ttl 1 
TEST(control, get_ip_ttl)
{
	control_get_ip_ttl_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result()); 
}


#define control_get_tcp_rtt 1  
TEST(control, get_tcp_rtt)
{
#if 0	
	//control_get_tcp_rtt_run();
	//ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result()); 
#else	
	EXPECT_EXIT(control_get_tcp_rtt_run(), testing::ExitedWithCode(0),  "test succ");
#endif	
}

#define control_get_tcp_rtt_c2s 1  
TEST(control, get_tcp_rtt_c2s)
{
	control_get_tcp_rtt_c2s_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result()); 
	// EXPECT_EXIT(control_get_tcp_rtt_run(), testing::ExitedWithCode(0),  "test succ");
}

#define control_get_tcp_rtt_s2c 1  
TEST(control, get_tcp_rtt_s2c)
{
	control_get_tcp_rtt_s2c_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result()); 
	// EXPECT_EXIT(control_get_tcp_rtt_run(), testing::ExitedWithCode(0),  "test succ");
}

TEST(control, get_stream_uuid)
{
	control_get_stream_uuid_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result()); 
	// EXPECT_EXIT(control_get_tcp_rtt_run(), testing::ExitedWithCode(0),  "test succ");
}

/************************ project_requirement.h API test ***********************/
#define project_simple 1  // for SI symbol view
TEST(project, simple)
{
	project_simple_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#if 0  /* project_notify接口被stream_bridge替代, 关闭测试用例 */
#define project_notify 1  // for SI symbol view
TEST(project, notify)
{
	project_nodify_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}
#endif

#define stream_bridge_simple 1  // for SI symbol view
TEST(stream_bridge, simple)
{
	stream_bridge_test_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}



/************************ tunnel process test ***********************/
#if SAPP_V4

#define tunnel_tcp_same_tuple4_diff_mpls_two_stream 1  // for SI symbol view
TEST(tunnel, tcp_same_tuple4_diff_mpls_two_stream)
{
	tcp_same_tuple4_diff_mpls_two_stream_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define tunnel_tcp_same_tuple4_diff_mpls_one_stream 1  // for SI symbol view
TEST(tunnel, tcp_same_tuple4_diff_mpls_one_stream)
{
	tcp_same_tuple4_diff_mpls_one_stream_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define tunnel_gtp_identify 1  // for SI symbol view
TEST(tunnel, gtp_identify)
{
	gtp_identify_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define tunnel_gtp_mpls_identify 1  // for SI symbol view
TEST(tunnel, gtp_mpls_identify)
{
	gtp_mpls_identify_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define tunnel_gtp_diff_outer_tuple4 1  // for SI symbol view
TEST(tunnel, gtp_diff_outer_tuple4)
{
	gtp_diff_outer_tuple4_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define tunnel_gtp_diff_outer_tuple4_track_teid 1  // for SI symbol view
TEST(tunnel, gtp_diff_outer_tuple4_track_teid)
{
	gtp_diff_outer_tuple4_track_gtp_teid_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define tunnel_gtp_diff_outer_tuple4_track_teid_s2c 1  // for SI symbol view
TEST(tunnel, gtp_diff_outer_tuple4_track_teid_s2c)
{
	gtp_diff_outer_tuple4_track_gtp_teid_s2c_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}





#endif


#define tunnel_pptp_identify 1  // for SI symbol view
TEST(tunnel, pptp_identify)
{
	pptp_identify_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#if SAPP_V4

#define tunnel_l2tp_identify 1  // for SI symbol view
TEST(tunnel, l2tp_identify)
{
	l2tp_identify_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}
#endif

#define tunnel_l2tp_identify_without_ppp_control 1  // for SI symbol view
TEST(tunnel, l2tp_identify_without_ppp_control)
{
	l2tp_without_ppp_control_field_identify_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}



#define tunnel_l2tp_protocol_timeout 1  // for SI symbol view
TEST(tunnel, l2tp_protocol_timeout)
{
	l2tp_protocol_timeout_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}



#define tunnel_teredo_identify 1  // for SI symbol view
TEST(tunnel, teredo_identify)
{
	teredo_identify_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define tunnel_pptp_and_4over6_identify 1  // for SI symbol view
TEST(tunnel, pptp_and_4over6_identify)
{
	pptp_and_4over6_identify_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define tunnel_6over4_identify 1  // for SI symbol view
TEST(tunnel, t6over4_identify)
{
	t6over4_identify_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define tunnel_mpls_1vs2 1  // for SI symbol view
TEST(tunnel, mpls_1vs2)
{
	mpls_asymmetric_1vs2_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define tunnel_vlan_2layer 1  // for SI symbol view
TEST(tunnel, vlan_2layer)
{
	vlan_2layer_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}



#define tunnel_vlan_asymmetric 1  // for SI symbol view
TEST(tunnel, vlan_asymmetric)
{
	vlan_asymmetric_merge_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define tunnel_no_mpls_tcp 1  // for SI symbol view
TEST(tunnel, no_mpls_tcp)
{
	pcap_no_mpls_tcp_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}




#define tunnel_l2tp_pfather_iterate 1  // for SI symbol view
TEST(tunnel, l2tp_pfather_iterate)
{
	l2tp_tunnel_pfather_iterate_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define tunnel_pptp_pfather_iterate 1  // for SI symbol view
TEST(tunnel, pptp_pfather_iterate)
{
	pptp_tunnel_pfather_iterate_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}



#if 0  /* 仅针对sapp-feature_parallel_teredo_identify分支测试 */
/************************ tunnel teredo test ***********************/
#define teredo_unstandard_port_test  1  // for SI symbol view
TEST(tunnel, teredo_unstandard_port)
{
	teredo_unstandard_port_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

/************************ tunnel teredo test ***********************/
#define teredo_with_auth_hdr_test  1  // for SI symbol view
TEST(tunnel, teredo_with_auth_hdr)
{
	teredo_with_auth_hdr_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}
#endif

/************************ app state test ***********************/
#if SAPP_V4

#define app_state_kill_follow_head_pending  1  // for SI symbol view
TEST(appstate, kill_follow_head_pending)
{
	app_state_kill_follow_head_pending_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define app_state_kill_follow_head_pending_dropme  1  // for SI symbol view
TEST(appstate, kill_follow_head_pending_dropme)
{
	app_state_kill_follow_head_pending_dropme_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define app_state_kill_follow_middle_pending  1  // for SI symbol view
TEST(appstate, kill_follow_middle_pending)
{
	app_state_kill_follow_middle_pending_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define app_state_kill_follow_tail_pending  1  // for SI symbol view
TEST(appstate, kill_follow_tail_pending)
{
	app_state_kill_follow_tail_pending_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define app_state_kill_follow_head_data  1  // for SI symbol view
TEST(appstate, kill_follow_head_data)
{
	app_state_kill_follow_head_data_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define app_state_kill_follow_head_data_dropme  1  // for SI symbol view
TEST(appstate, kill_follow_head_data_dropme)
{
	app_state_kill_follow_head_data_dropme_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define app_state_kill_follow_middle_data  1  // for SI symbol view
TEST(appstate, kill_follow_middle_data)
{
	app_state_kill_follow_middle_data_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define app_state_kill_follow_tail_data  1  // for SI symbol view
TEST(appstate, kill_follow_tail_data)
{
	app_state_kill_follow_tail_data_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define app_state_kill_other_head_pending  1  // for SI symbol view
TEST(appstate, kill_other_head_pending)
{
	app_state_kill_other_head_pending_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define app_state_kill_other_middle_pending  1  // for SI symbol view
TEST(appstate, kill_other_middle_pending)
{
	app_state_kill_other_middle_pending_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define app_state_kill_other_tail_pending  1  // for SI symbol view
TEST(appstate, kill_other_tail_pending)
{
	app_state_kill_other_tail_pending_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define app_state_kill_other_tail_pending_dropme  1  // for SI symbol view
TEST(appstate, kill_other_tail_pending_dropme)
{
	app_state_kill_other_tail_pending_dropme_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define app_state_kill_other_head_data  1  // for SI symbol view
TEST(appstate, kill_other_head_data)
{
	app_state_kill_other_head_data_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define app_state_kill_other_middle_data  1  // for SI symbol view
TEST(appstate, kill_other_middle_data)
{
	app_state_kill_other_middle_data_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define app_state_kill_other_tail_data  1  // for SI symbol view
TEST(appstate, kill_other_tail_data)
{
	app_state_kill_other_tail_data_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define app_state_kill_follow_ip_entry  1  // for SI symbol view
TEST(appstate, kill_follow_ip_entry)
{
	app_state_kill_follow_ip_entry_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}
#endif

/************************ sapp timer test ***********************/
#if SAPP_V4 //timer only support in sapp-v4.0
#define timer_simple 1  // for SI symbol view
TEST(timer, DISABLED_simple)
{
	timer_simple_run();
	//ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
	ASSERT_EQ(GTEST_SAPP_ERR, gtest_get_libsapp_devel_result());
}
#endif


/********************* inject rst packet Test ***********************/
#if SAPP_V4 //rst_tcp only support in sapp-v4.0

#if 0 /* 改成用sapp_benchmark框架测试, 不需要写代码、不用重新编�????*/
#define inject_rst_packet_test_v4 1  // for SI symbol view
TEST(inject, rst_pkt_v4)
{
	MESA_rst_tcp_test_v4_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}
#endif

/********************* inject  rst packet Test ***********************/
#define inject_rst_packet_test_v6 1  // for SI symbol view
#if 0 /* 改成用sapp_benchmark框架测试, 不需要写代码、不用重新编�????*/
TEST(inject, rst_pkt_v6)
{
	MESA_rst_tcp_test_v6_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}
#endif

#define inject_rst_packet_with_vlan_single_c2s 1  // for SI symbol view
TEST(inject, rst_pkt_with_vlan_single_c2s)
{
	MESA_rst_tcp_with_vlan_single_c2s_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define inject_rst_packet_with_vlan_pppoe 1  // for SI symbol view
TEST(inject, rst_pkt_with_vlan_pppoe_v4)
{
	MESA_rst_tcp_with_vlan_pppoe_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define inject_rst_packet_with_mpls_1vs2 1  // for SI symbol view
TEST(inject, rst_pkt_with_mpls_1vs2)
{
	MESA_rst_tcp_with_mpls_1vs2_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define inject_rst_packet_with_mpls_0vs2 1  // for SI symbol view
TEST(inject, rst_pkt_with_mpls_0vs2)
{
	MESA_rst_tcp_with_mpls_0vs2_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define inject_rst_packet_with_mpls_single_c2s 1  // for SI symbol view
TEST(inject, rst_pkt_with_mpls_single_c2s)
{
	MESA_rst_tcp_with_mpls_single_c2s_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define inject_rst_packet_with_vpls 1  // for SI symbol view
TEST(inject, rst_pkt_with_vpls)
{
	MESA_rst_tcp_with_vpls_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define inject_rst_packet_with_double_vlan 1  // for SI symbol view
TEST(inject, rst_pkt_with_double_vlan)
{
	MESA_rst_tcp_with_double_vlan_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define inject_rst_packet_with_8021ad_qinq 1  // for SI symbol view
TEST(inject, rst_pkt_with_8021ad_qinq)
{
	MESA_rst_tcp_with_8021ad_qinq_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}



#define inject_rst_with_mpls_vlan_mpls 1  // for SI symbol view
TEST(inject, rst_with_mpls_vlan_mpls)
{
	MESA_rst_tcp_mpls_vlan_mpls_c2s_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define inject_kill_tcp_v4 1  // for SI symbol view
TEST(inject, kill_tcp_v4)
{
	MESA_kill_tcp_test_v4_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define _sapp_inject_tcp_payload_v4 1  // for SI symbol view
TEST(inject, sapp_inject_tcp_payload_v4)
{
	sapp_inject_tcp_payload_test_v4_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define _MESA_inject_tcp_payload_v4 1  // for SI symbol view
TEST(inject, MESA_inject_tcp_payload_v4)
{
	MESA_inject_tcp_payload_test_v4_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define _MESA_inject_udp_payload_v4 1  // for SI symbol view
TEST(inject, MESA_inject_udp_payload_v4)
{
	MESA_inject_udp_mpls_vlan_mpls_s2c_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define _sapp_inject_tcp_payload_asymmetric_double_v4 1  // for SI symbol view
TEST(inject, MESA_inject_tcp_payload_asymmetric_double_v4)
{
	sapp_inject_tcp_mpls_vlan_mpls_asymmetric_double_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define _sapp_inject_tcp_pure_ipv4_with_fake_mpls 1  // for SI symbol view
TEST(inject, pure_ipv4_with_fake_mpls)
{
	MESA_rst_tcp_pure_ipv4_with_fake_mpls_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define _sapp_inject_tcp_rst_reverse_ethernet 1  // for SI symbol view
TEST(inject, tcp_rst_reverse_ethernet)
{
	MESA_rst_tcp_reverse_ethernet_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define _sapp_inject_gtp_single_reverse_asymmetric 1  // for SI symbol view
TEST(inject, gtp_single_reverse_asymmetric)
{
	sapp_inject_gtp_single_reverse_asymmetric_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define _sapp_inject_gtp_single_reverse_not_asymmetric 1  // for SI symbol view
TEST(inject, gtp_single_reverse_not_asymmetric)
{
	sapp_inject_gtp_single_reverse_not_asymmetric_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define _sapp_inject_gtp_seq_single_reverse_not_asymmetric 1  // for SI symbol view
TEST(inject, gtp_seq_single_reverse_not_asymmetric)
{
	sapp_inject_gtp_seq_single_reverse_not_asymmetric_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define _sapp_inject_gtp_double 1  // for SI symbol view
TEST(inject, gtp_double)
{
	sapp_inject_gtp_double_dir_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define _sapp_inject_gtp_double_payload 1  // for SI symbol view
TEST(inject, gtp_double_payload)
{
	sapp_inject_gtp_payload_double_dir_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define _sapp_inject_gtp_double_raw_ippkt 1  // for SI symbol view
TEST(inject, gtp_double_raw_ippkt)
{
	sapp_inject_gtp_raw_ip_pkt_double_dir_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define _sapp_inject_l2tp 1  // for SI symbol view
TEST(inject, l2tp)
{
	sapp_inject_l2tp_double_dir_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define _sapp_inject_l2tp_ppp_compress 1  // for SI symbol view
TEST(inject, l2tp_ppp_compress)
{
	sapp_inject_l2tp_ppp_compress_double_dir_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define _sapp_inject_4over6 1  // for SI symbol view
TEST(inject, inject_4over6)
{
	sapp_inject_4over6_layer_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define _sapp_inject_4over6_exclude 1  // for SI symbol view
TEST(inject, inject_4over6_exclude)
{
	sapp_inject_4over6_exclude_layer_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define _sapp_inject_6over4_exclude 1  // for SI symbol view
TEST(inject, inject_6over4_exclude)
{
	sapp_inject_6over4_exclude_layer_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define _sapp_inject_6over4 1  // for SI symbol view
TEST(inject, inject_6over4)
{
	sapp_inject_6over4_layer_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#endif

/********************* plug ctrl Test ***********************/
#if SAPP_V4

#define plug_ctrl_simple 1  // for SI symbol view
TEST(plug_ctrl, simple)
{
	plug_ctrl_simple_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define plug_ctrl_flag_change 1  // for SI symbol view
TEST(plug_ctrl, flag_change)
{
	plug_ctrl_flag_change_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define plug_ctrl_state_pd_d_dc 1  // for SI symbol view
TEST(plug_ctrl, state_pd_d_dc)
{
	plug_ctrl_state_pd_d_dc_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}



#define plug_ctrl_2state_pd_dc 1  // for SI symbol view
TEST(plug_ctrl, 2state_pd_dc)
{
	plug_ctrl_2state_pd_dc_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define plug_ctrl_3state_pdc 1  // for SI symbol view
TEST(plug_ctrl, 3state_pdc)
{
	plug_ctrl_3state_pdc_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define plug_ctrl_dropme_in_pending 1  // for SI symbol view
TEST(plug_ctrl, dropme_in_pending)
{
	plug_ctrl_biz_dropme_in_pending_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define plug_ctrl_dropme_in_data 1  // for SI symbol view
TEST(plug_ctrl, dropme_in_data)
{
	plug_ctrl_biz_dropme_in_data_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define plug_ctrl_dropme_in_close 1  // for SI symbol view
TEST(plug_ctrl, dropme_in_close)
{
	plug_ctrl_biz_dropme_in_close_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define plug_ctrl_giveme_in_close 1  // for SI symbol view
TEST(plug_ctrl, giveme_in_close)
{
	plug_ctrl_biz_giveme_in_close_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#if 0
#define plug_ctrl_wire_graft 1  // for SI symbol view
TEST(plug_ctrl, wire_graft)
{
	special_plug_wire_graft_test();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}
#endif



#endif

/************************* jump layer start ****************************/


#define _jump_layer_eth_ipv4_tcp 1  // for SI symbol view
TEST(jump_layer, eth_ipv4_tcp)
{
	jump_layer_eth_ipv4_tcp_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define _jump_layer_eth_ipv4_udp 1  // for SI symbol view
TEST(jump_layer, eth_ipv4_udp)
{
	jump_layer_eth_ipv4_udp_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define _jump_layer_eth_ipv6_tcp 1  // for SI symbol view
TEST(jump_layer, eth_ipv6_tcp)
{
	jump_layer_eth_ipv6_tcp_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define _jump_layer_eth_ipv6_udp 1  // for SI symbol view
TEST(jump_layer, eth_ipv6_udp)
{
	jump_layer_eth_ipv6_udp_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define _jump_layer_eth_ipv4_pptp_ipv4_tcp 1  // for SI symbol view
TEST(jump_layer, eth_ipv4_pptp_ipv4_tcp)
{
	jump_layer_eth_ipv4_pptp_ipv4_tcp_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define _jump_layer_eth_ipv4_gtp_ipv4_tcp 1  // for SI symbol view
TEST(jump_layer, eth_ipv4_gtp_ipv4_tcp)
{
	jump_layer_eth_ipv4_gtp_ipv4_tcp_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}



#define _jump_layer_eth_ip4_l2tp_ip4_tcp 1  // for SI symbol view
TEST(jump_layer, eth_ip4_l2tp_ip4_tcp)
{
	jump_layer_eth_ip4_l2tp_ip4_tcp_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define _jump_layer_eth_ip4_l2tp_ip4_udp 1  // for SI symbol view
TEST(jump_layer, eth_ip4_l2tp_ip4_udp)
{
	jump_layer_eth_ip4_l2tp_ip4_udp_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define _jump_layer_eth_ip4_l2tp_ppp_compress_ip4_udp 1  // for SI symbol view
TEST(jump_layer, eth_ip4_l2tp_ppp_compress_ip4_udp)
{
	jump_layer_eth_ip4_l2tp_ppp_compress_ip4_udp_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define _jump_layer_eth_ipv4_gre_ipv4_gre_ipv4_dns 1  // for SI symbol view
TEST(jump_layer, eth_ipv4_gre_ipv4_gre_ipv4_dns)
{
	jump_layer_eth_ipv4_gre_ipv4_gre_ipv4_dns_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}



#define _jump_layer_eth_vlan_ip6_ip4_pptp_ip4_ip6_tcp 1  // for SI symbol view
TEST(jump_layer, eth_vlan_ip6_ip4_pptp_ip4_ip6_tcp)
{
	jump_layer_eth_vlan_ip6_ip4_pptp_ip4_ip6_tcp_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define _jump_layer_eth_ip4_udp_teredo_udp_ip6_udp 1  // for SI symbol view
TEST(jump_layer, eth_ip4_udp_teredo_udp_ip6_udp)
{
	jump_layer_eth_ip4_udp_teredo_udp_ip6_udp_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define _jump_layer_eth_ip4_udp_teredo_udp_ip6_tcp 1  // for SI symbol view
TEST(jump_layer, eth_ip4_udp_teredo_udp_ip6_tcp)
{
	jump_layer_eth_ip4_udp_teredo_udp_ip6_tcp_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define _jump_layer_eth_vlan_ip6_udp_gtpext_ip4_tcp 1  // for SI symbol view
TEST(jump_layer, eth_vlan_ip6_udp_gtpext_ip4_tcp)
{
	jump_layer_eth_vlan_ip6_udp_gtpext_ip4_tcp_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


/************************* inline test  start ****************************/
#define _sapp_vxlan_header 1  // for SI symbol view
TEST(inline_mode, vxlan_header)
{
	EXPECT_EXIT(inline_vxlan_header_run(), testing::ExitedWithCode(0),  "test succ");
}


#define _sapp_inline_forward_simple 1  // for SI symbol view
TEST(inline_mode, forward_simple)
{
	EXPECT_EXIT(inline_flow_forward_simple_run(), testing::ExitedWithCode(0),  "test succ");
}

#define _sapp_inline_tcp_simple 1  // for SI symbol view
TEST(inline_mode, tcp_simple)
{
	EXPECT_EXIT(inline_tcp_simple_run(), testing::ExitedWithCode(0),  "test succ");
}


#define _sapp_inject_c2s_rst 1  // for SI symbol view
TEST(inline_mode, DISABLED_inject_c2s_rst_trigger_by_c2s_pkt)
{
	inline_inject_rst_c2s_trigger_by_c2s_pkt_run();
	ASSERT_EQ(GTEST_INLINE_TO_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define _inject_s2c_rst_trigger_by_s2c_pkt 1  // for SI symbol view
TEST(inline_mode, DISABLED_inject_s2c_rst_trigger_by_s2c_pkt)
{
	inline_inject_rst_s2c_trigger_by_s2c_pkt_run();
	ASSERT_EQ(GTEST_INLINE_TO_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define _inject_s2c_rst_trigger_by_c2s_pkt 1  // for SI symbol view
TEST(inline_mode, DISABLED_inject_s2c_rst_trigger_by_c2s_pkt)
{
	inline_inject_rst_s2c_trigger_by_c2s_pkt_run();
	ASSERT_EQ(GTEST_INLINE_TO_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define _inject_c2s_rst_trigger_by_s2c_pkt 1  // for SI symbol view
TEST(inline_mode, DISABLED_inject_c2s_rst_trigger_by_s2c_pkt)
{
	inline_inject_rst_c2s_trigger_by_s2c_pkt_run();
	ASSERT_EQ(GTEST_INLINE_TO_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#if 0
#define _inject_pyaload_s2c_trigger_by_c2s_ipv6 1  // for SI symbol view
TEST(inline_mode, inject_pyaload_s2c_trigger_by_c2s_ipv6)
{
	inline_inject_payload_s2c_trigger_by_c2s_ipv6_run();
	ASSERT_EQ(GTEST_INLINE_TO_SAPP_SUCC, gtest_get_libsapp_devel_result());
}
#endif

#define _inline_ip_plug_entry_not_call 1  // for SI symbol view
TEST(inline_mode, ip_plug_entry_not_call)
{
	EXPECT_EXIT(inline_ip_plug_entry_not_call_run(), testing::ExitedWithCode(0),  "test succ");
}

#define _inline_udp_plug_entry_not_call 1  // for SI symbol view
TEST(inline_mode, udp_plug_entry_not_call)
{
	EXPECT_EXIT(inline_udp_plug_entry_not_call_run(), testing::ExitedWithCode(0),  "test succ");
}

#define _inline_udp_plug_drop 1  // for SI symbol view
TEST(inline_mode, DISABLED_udp_plug_drop)
{
	inline_udp_plug_drop_entry_run();
	ASSERT_EQ(GTEST_INLINE_TO_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define _inline_layer_addr_ntop 1  // for SI symbol view
TEST(inline_mode, test_layer_addr_ntop)
{
	EXPECT_EXIT(inline_layer_addr_ntop_run(), testing::ExitedWithCode(0),  "test succ");
}

#define _inline_stream_addr_ntop 1  // for SI symbol view
TEST(inline_mode, stream_addr_ntop)
{
	EXPECT_EXIT(inline_stream_addr_ntop_run(), testing::ExitedWithCode(0),  "test succ");
}

#define _inline_stream_pfather 1  // for SI symbol view
TEST(inline_mode, stream_pfather)
{
	EXPECT_EXIT(inline_stream_pfather_run(), testing::ExitedWithCode(0),  "test succ");
}


#define _inline_plug_stat 1  // for SI symbol view
TEST(inline_mode, plug_stat)
{
	EXPECT_EXIT(inline_plug_stat_run(), testing::ExitedWithCode(0),  "test succ");
}

#define inline_polling_timeout 1  // for SI symbol view
TEST(inline_mode, polling_timeout_tcp)
{
	EXPECT_EXIT(inline_polling_timeout_tcp_run(), testing::ExitedWithCode(0),  "test succ");
}


#define inline_polling_timeout_tcpall 1  // for SI symbol view
TEST(inline_mode, polling_timeout_tcpall)
{
	EXPECT_EXIT(inline_polling_timeout_tcpall_run(), testing::ExitedWithCode(0),  "test succ");
}


#define inline_polling_timeout_udp 1  // for SI symbol view
TEST(inline_mode, polling_timeout_udp)
{
	EXPECT_EXIT(inline_polling_timeout_udp_run(), testing::ExitedWithCode(0),  "test succ");
}

#define inline_asymmetric_vxlan_addr 1  // for SI symbol view
TEST(inline_mode, asymmetric_vxlan_addr)
{
	EXPECT_EXIT(inline_asymmetric_vxlan_addr_run(), testing::ExitedWithCode(0),  "test succ");
}

#define inline_cheat_dup_tcp 1  
TEST(inline_mode, cheat_dup_tcp)
{
	EXPECT_EXIT(inline_cheat_dup_tcp_run(), testing::ExitedWithCode(0),  "test succ");
}

#define inline_dup_inject_ipv4_tcp 1  
TEST(inline_mode, dup_inject_ipv4_tcp)
{
	EXPECT_EXIT(inline_dup_inject_ipv4_tcp_run(), testing::ExitedWithCode(0),  "test succ");

}

#define inline_dup_inject_ipv6_tcp 1  
TEST(inline_mode, dup_inject_ipv6_tcp)
{
	EXPECT_EXIT(inline_dup_inject_ipv6_tcp_run(), testing::ExitedWithCode(0),  "test succ");
}

#define inline_dup_inject_ipv4_udp 1  
TEST(inline_mode, dup_inject_ipv4_udp)
{
	EXPECT_EXIT(inline_dup_inject_ipv4_udp_run(), testing::ExitedWithCode(0),  "test succ");
}

#define inline_dup_inject_ipv6_udp 1  
TEST(inline_mode, dup_inject_ipv6_udp)
{
	EXPECT_EXIT(inline_dup_inject_ipv6_udp_run(), testing::ExitedWithCode(0),  "test succ");
}

#define inline_ssdp 1  
TEST(inline_mode, ssdp)
{
	EXPECT_EXIT(inline_ssdp_run(), testing::ExitedWithCode(0),  "test succ");
}

#define inline_nbns 1  
TEST(inline_mode, nbns)
{
	EXPECT_EXIT(inline_nbns_run(), testing::ExitedWithCode(0),  "test succ");
}


#define inline_get_rawpkt_data 1  
TEST(inline_mode, get_rawpkt_data)
{
	EXPECT_EXIT(inline_get_rawpkt_data_run(), testing::ExitedWithCode(0),  "test succ");
}

#if (0 == HIGH_PERF)	
#define inline_raw_ip_frag_list 1  
TEST(inline_mode, raw_ip_frag_list)
{
	EXPECT_EXIT(inline_raw_ip_frag_list_run(), testing::ExitedWithCode(0),  "test succ");
}
#endif

#define inline_get_vxlan_info 1  
TEST(inline_mode, get_vxlan_info)
{
	EXPECT_EXIT(inline_vxlan_info_run(), testing::ExitedWithCode(0),  "test succ");
}


#define inline_vxlan_inner_hdlc 1  
TEST(inline_mode, inner_hdlc)
{
	EXPECT_EXIT(inline_inner_hdlc_run(), testing::ExitedWithCode(0),  "test succ");
}


#define inline_vxlan_inner_ppp 1  
TEST(inline_mode, inner_ppp)
{
	EXPECT_EXIT(inline_inner_ppp_run(), testing::ExitedWithCode(0),  "test succ");
}

#define inline_vxlan_inject_inner_ppp 1  
TEST(inline_mode, DISABLED_inject_inner_ppp)
{
	inline_inject_rst_inner_ppp_run();
	ASSERT_EQ(GTEST_INLINE_TO_SAPP_SUCC, gtest_get_libsapp_devel_result()); 
}


#define inline_vxlan_inject_inner_hdlc 1  
TEST(inline_mode, DISABLED_inject_inner_hdlc)
{
	inline_inject_rst_inner_hdlc_run();
	ASSERT_EQ(GTEST_INLINE_TO_SAPP_SUCC, gtest_get_libsapp_devel_result()); 
}


#define inline_grev0_inject_reverse 1  
TEST(inline_mode, DISABLED_grev0_inject_reverse)
{
	inline_grev0_inject_reverse_run();
	ASSERT_EQ(GTEST_INLINE_TO_SAPP_SUCC, gtest_get_libsapp_devel_result()); 
}


/************************* inline test  end ****************************/

/************************* asymmetric test start ***********************/

#define _asymmetric_mpls_c2s 1   
TEST(asymmetric, mpls_c2s)
{
	asymmetric_mpls_c2s_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define _asymmetric_mpls_s2c 1   
TEST(asymmetric, mpls_s2c)
{
	asymmetric_mpls_s2c_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define _asymmetric_vlan_c2s 1   
TEST(asymmetric, vlan_c2s)
{
	asymmetric_vlan_c2s_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}


#define _asymmetric_vlan_s2c 1   
TEST(asymmetric, vlan_s2c)
{
	asymmetric_vlan_s2c_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define _asymmetric_mpls_and_vlan 1   
TEST(asymmetric, mpls_and_vlan)
{
	asymmetric_mpls_and_vlan_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

/************************* asymmetric test end ***********************/



/************************* proxy test start ***********************/

#define _proxy_simple 1   
TEST(proxy, simple)
{
	sapp_deal_proxy_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define _proxy_kill_tcp 1   
/* 
	TODO:
		使用libsapp_devel实测, 两个用例不能顺序执行, 疑似与解析层dlopen有关�???? 暂未定位原因, 待解�????!!!
*/
#if 0 
TEST(proxy, kill_tcp)
{
	sapp_deal_proxy_kill_tcp_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}
#endif

/************************* proxy test end ***********************/


/************************* transparent Test start ***********************/

#define _transparent_tcp_simple 1  // for SI symbol view
TEST(transparent, tcpsimple)
{
	transparent_tcp_simple_run();
	ASSERT_EQ(GTEST_TRANSPARENT_TO_SAPP_SUCC, check_test_result());
}


#define _transparent_arp_forward 1  // for SI symbol view
TEST(transparent, arp_forward)
{
	transparent_arp_forward_run();
	ASSERT_EQ(GTEST_TRANSPARENT_TO_SAPP_SUCC, check_test_result());
}


#define _transparent_tcp_drop_rst_c2s_trigger_by_c2s 1  // for SI symbol view
TEST(transparent, tcp_drop_rst_c2s_trigger_by_c2s)
{
	transparent_drop_and_rst_c2s_trigger_by_c2s_run();
	ASSERT_EQ(GTEST_TRANSPARENT_TO_SAPP_SUCC, check_test_result());
}


#define _transparent_tcp_drop_rst_s2c_trigger_by_c2s 1  // for SI symbol view
TEST(transparent, tcp_drop_rst_s2c_trigger_by_c2s)
{
	transparent_drop_and_rst_s2c_trigger_by_c2s_run();
	ASSERT_EQ(GTEST_TRANSPARENT_TO_SAPP_SUCC, check_test_result());
}



#define _transparent_tcp_drop_inject_c2s_trigger_by_c2s 1  // for SI symbol view
TEST(transparent, tcp_drop_inject_c2s_trigger_by_c2s)
{
	transparent_drop_and_inject_c2s_trigger_by_c2s_run();
	ASSERT_EQ(GTEST_TRANSPARENT_TO_SAPP_SUCC, check_test_result());
}

#define _transparent_tcp_drop_inject_c2s_trigger_by_s2c 1  // for SI symbol view
TEST(transparent, tcp_drop_inject_c2s_trigger_by_s2c)
{
	transparent_drop_and_inject_c2s_trigger_by_s2c_run();
	ASSERT_EQ(GTEST_TRANSPARENT_TO_SAPP_SUCC, check_test_result());
}

/************************* transparent Test end ***********************/



/************************* hybrid test start ***********************/

#define _hybrid_pure_tcp 1   
TEST(hybrid, pure_tcp)
{
	hybrid_pure_tcp_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define _hybrid_pure_udp 1   
TEST(hybrid, pure_udp)
{
	hybrid_pure_udp_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#define _hybrid_dataset 1   
TEST(hybrid, dataset)
{
	hybrid_dataset_run();
	ASSERT_EQ(GTEST_SAPP_SUCC, gtest_get_libsapp_devel_result());
}
/************************* hybrid test end ***********************/


/************************* fake marsio test start ***********************/

#define _fake_marsio_vlan_flip_no_mac_flip 1   
TEST(fake_marsio, vlan_flip_no_mac_flip)
{
	EXPECT_EXIT(fake_marsio_vlan_flipping_run(), testing::ExitedWithCode(0),  "test success");
}

#define _fake_marsio_vlan_flip_and_mac_flip 1   
TEST(fake_marsio, vlan_flip_and_mac_flip)
{
	EXPECT_EXIT(fake_marsio_vlan_flipp_and_mac_flip_run(), testing::ExitedWithCode(0),  "test success");
}


#define _fake_marsio_vlan_flip_and_symmetric_mpls0vs1 1   
TEST(fake_marsio, vlan_flip_and_symmetric_mpls0vs1)
{
	EXPECT_EXIT(fake_marsio_vlan_flipp_and_symmetric_mpls0vs1_run(), testing::ExitedWithCode(0),  "test success");
}


#define _fake_marsio_vlan_flip_and_symmetric_mpls1vs2 1   
TEST(fake_marsio, vlan_flip_and_symmetric_mpls1vs2)
{
	EXPECT_EXIT(fake_marsio_vlan_flipp_and_symmetric_mpls1vs2_run(), testing::ExitedWithCode(0),  "test success");
}

#define _fake_marsio_vlan_mac_flip_inject_no_asymmetric 1   
TEST(fake_marsio, vlan_mac_flip_inject_no_asymmetric)
{
	/* 别着�???? 不是BUG!
	   这个测试用例就是应该错的 !!!
	*/
	EXPECT_EXIT(fake_marsio_vlan_mac_flipping_inject_run(0), testing::ExitedWithCode(1),  "index:4, mac addr error");
}

#define _fake_marsio_vlan_mac_flip_inject_with_asymmetric 1   
TEST(fake_marsio, vlan_mac_flip_inject_with_asymmetric)
{
	EXPECT_EXIT(fake_marsio_vlan_mac_flipping_inject_run(1), testing::ExitedWithCode(0),  "test success");
}



/************************* fake marsio test end ***********************/


#define __test_pkt_dump 1   
TEST(pkt_dump, rewrite)
{
	int ret;
	ret = test_pkt_dump_run();
	ASSERT_EQ(0, ret);
}


#if 0
#define performance_simple 1  // for SI symbol view
TEST(performance, simple)
{
	sapp_perf_test_run();
	ASSERT_EQ(GTEST_INLINE_TO_SAPP_SUCC, gtest_get_libsapp_devel_result());
}

#endif

#include "sapp_global_val.h"

TEST(dabloom, simple)
{
	ASSERT_EQ(0, sapp_bloom_filter_test_run(BLOOM_LIBRARY_DABLOOM, user_define_args));
}

TEST(apbloom, simple)
{
	ASSERT_EQ(0, sapp_bloom_filter_test_run(BLOOM_LIBRARY_APBLOOM, user_define_args));
}

TEST(apbloom, merge)
{
	ASSERT_EQ(0, sapp_apbloom_merge_test_run());
}

static const char *gtest_cla_short_options = "hvLsf:l:u:";

static const struct option gtest_cla_long_options[] = 
{
	{"help",			no_argument,      	NULL,      'h'},
	{"version",			no_argument,      	NULL,      'v'},
	{"log_level",	required_argument,      	NULL,      'l'},
	{"gtest_list_tests",	no_argument,      	NULL,      'L'},
	{"gtest_filter",	required_argument,      	NULL,      'f'},
	{"slient",	no_argument,      	NULL,      's'},
	{"user-define",	required_argument,      	NULL,      'u'},
	{NULL,          	0,      			NULL,      0}
};


static void usage(int argc, char *argv[])
{
	printf("args example:\n"); 
	printf("\t%s short-arg long-arg\n", argv[0]);
	printf("\t%s -v \t--version\n", argv[0]);
	printf("\t%s -l \t--log_level\n", argv[0]);
	printf("\t%s -L \t--gtest_list_tests\n", argv[0]);
	printf("\t%s -s \t--slient\n", argv[0]);
	printf("\t%s -f \t--gtest_filter=tcp.simple\n", argv[0]);
	printf("\t%s -f \t--gtest_filter=tcp*\n", argv[0]);
	printf("\t%s -f \t--gtest_filter=apbloom.simple -u \"capacity=2500000,error_rate=0.000001\"\n", argv[0]);
	exit(0);
}


int main(int argc, char *argv[])
{
	int c;
	int to_gtest_argc = 1;
	char *to_gtest_args[4] = {(char *)"gtest_sapp_v4", NULL,NULL,NULL};
	char temp_string[1024] = {};
	int user_log_level = RLOG_LV_DEBUG;

	while(1){
		c = getopt_long(argc, argv, gtest_cla_short_options, gtest_cla_long_options, NULL);
		if(c == -1){
			break;	
		}

		switch(c){

		case 'h':
			usage(argc, argv);
		break;

		case 'v':
			printf("Best matching sapp version: %s\n", for_test_sapp_version);
			exit(0);			
		break;

		case 'l':
			user_log_level = atoi(optarg);
		break;

		case 'L':
			to_gtest_args[1] = (char *)"--gtest_list_tests";
			to_gtest_argc++;
		break;

		case 'f':
			strncpy(temp_string, (char *)"--gtest_filter=", strlen("--gtest_filter="));
			strcat(temp_string, optarg);
			to_gtest_argc++;
			to_gtest_args[1] = temp_string;
		break;		

		case 's':
			g_slient_mode = 1;
		break;

		case 'u':
			user_define_args = optarg;
		break;

		case '?': /* invalid or unknown option */
			return -1;
		break;

		}
	}

	system("> gtest_sapp.log");

	MESA_handle_runtime_log_creation("./etc/sapp_log.conf");
	g_sapp_test_log_handle = MESA_create_runtime_log_handle("./log/test_sapp_benchmark.log", user_log_level);

	MESA_handle_runtime_log(g_sapp_test_log_handle, RLOG_LV_DEBUG, "sapp_module_test", "starting sapp module test....\n");
	
	gtest_sapp_master_init();
	::testing::InitGoogleTest(&to_gtest_argc, to_gtest_args);
	::testing::FLAGS_gtest_death_test_style = "fast";
	int ret=RUN_ALL_TESTS();
	MESA_destroy_runtime_log_handle(g_sapp_test_log_handle);	
	MESA_handle_runtime_log_destruction();
	return ret;
}


