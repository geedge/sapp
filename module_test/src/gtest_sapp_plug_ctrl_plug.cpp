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

static long long g_protocol_flags = 0;
static unsigned short g_protocol_plug_id;
static int g_protocol_project_id = -1;
static int g_biz_project_id = -1;


static int biz_plug_called_times = 0;
static void *biz_plug_pme;	 /* 此处要保存plugin的pme, 为了简单, 使用static变量 */
static int protocol_call_times = 0;
static int biz_recv_close_state_times = 0; /* 业务插件收到close状态的次数, 理论上只有一次 */

static unsigned int send_result_in_destroy_flag = 0; /* 插件阶段不能发送结果, 因为状态还不能确定, 最终要在sapp进程结束时发送 */
static unsigned int default_result_in_destroy_state = GTEST_SAPP_SUCC; /* 最后发送结果的值, 默认是SUCC */


/*
	TODO:
	截止到2021-04-29, close时解析层最后还会调用一次业务层, 但是为了保证语义一致, 应该把最后一次的buf和buflen设成0, 仅表示close.
*/
extern "C" char plugctrl_biz_simple_entry(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
{
	send_result_in_destroy_flag = 1;
	biz_plug_called_times++;

	/* 解析层只调用了三次, 且是下面三个状态 */
	if(((SESSION_STATE_PENDING|SESSION_STATE_DATA) != session_info->session_state)
	&& (SESSION_STATE_DATA != session_info->session_state)
	&& ((SESSION_STATE_DATA|SESSION_STATE_CLOSE) != session_info->session_state)){
		printf("\033[1;31;40mbiz_state_pd_d_dc_entry() state error, expect 'pending|data', 'data', 'data|close', but actual is:0x%x\033[0m\n", session_info->session_state);
		sendto_test_result(GTEST_SAPP_ERR);
	}


	/* 只有三个数据包, 且解析层最后发送了(SESSION_STATE_DATA|SESSION_STATE_CLOSE)状态, 只能被调用3次 */
	if(biz_plug_called_times > 3){
		printf("\033[1;31;40mbiz_state_pd_d_dc_entry() error, this plug has been called %d times, this state is:0x%x!\033[0m\n", biz_plug_called_times, session_info->session_state);
		sendto_test_result(GTEST_SAPP_ERR);
	}

	/* 此entry不能发送正确结果, 因为不知道还会不会被调用, 只能在 plut_ctrl_biz_destroy() 最后看结果如何 */

	/* 虽然会收到了CLOSE状态, 但是此处故意返回GIVEME, 实际插件管理不应该再再调用本业务插件了, CLOSE之后已经无意义了甚至是错误, pme可能都被free了 */
	return PROT_STATE_GIVEME;
}


/*
	解析层插件, 测试pcap就一个包, 同时输出三个状态, 调用业务插件.

	正常模式下, 其实close状态通常是因超时而淘汰的, 尤其是UDP和TCP_ALL插件, 
	此处为了方便测试, 解析层不看sapp的close状态, 直接输出测试状态, 用于测插件管理. 
*/
extern "C" char protocol_3state_pdc_entry(struct streaminfo *a_udp,  void **pme, int thread_seq, const void *ip_hdr)
{
	stSessionInfo tmp_ss = {};
	void *call_biz_plugins_pme;

	if(OP_STATE_PENDING == a_udp->opstate){
		*pme = malloc(sizeof(void *));
	}
	call_biz_plugins_pme = (*pme);

	if(ip_hdr != NULL){
		tmp_ss.session_state = SESSION_STATE_PENDING|SESSION_STATE_DATA|SESSION_STATE_CLOSE;
		tmp_ss.prot_flag = 1;
		tmp_ss.plugid = g_protocol_plug_id;
		tmp_ss.app_info = NULL;
		tmp_ss.buf = (void *)"protocol test 3state pdc\n";
		tmp_ss.buflen = strlen("protocol test 3state pdc\n");

		PROT_PROCESS(&tmp_ss, &call_biz_plugins_pme, a_udp->threadnum, (struct streaminfo * )a_udp, ip_hdr);

		protocol_call_times++;
		if(protocol_call_times > 1){
			printf("\033[1;31;40mprotocol_3state_pdc_entry error, this plug has been called %d times with payload packet!\033[0m\n", protocol_call_times);
			sendto_test_result(GTEST_SAPP_ERR);			
		}		
	}

	if(OP_STATE_CLOSE == a_udp->opstate){
		free(*pme);
	}
	
	return APP_STATE_GIVEME;
}

/*
	同时获取三个状态的业务插件.
*/
extern "C" char biz_3state_pdc_entry(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
{
	send_result_in_destroy_flag = 1;
	biz_plug_called_times++;

	if((SESSION_STATE_PENDING|SESSION_STATE_DATA|SESSION_STATE_CLOSE) != session_info->session_state){
		printf("\033[1;31;40mbiz_3state_pdc_entry() state error, expect 'pending|data|close', but actual is:0x%x\033[0m\n", session_info->session_state);
		sendto_test_result(GTEST_SAPP_ERR);
	}

	if(biz_plug_called_times > 1){
		printf("\033[1;31;40mbiz_3state_pdc_entry() error, this plug has been called %d times,  this state is:0x%x!\033[0m\n", biz_plug_called_times, session_info->session_state);
		sendto_test_result(GTEST_SAPP_ERR);
	}

	if(SESSION_STATE_CLOSE & session_info->session_state){
		biz_recv_close_state_times++;
		if(biz_recv_close_state_times >= 2){
			printf("\033[1;31;40mbiz_3state_pdc_entry() error, this plug has been recv CLOSE %d times!\033[0m\n", biz_recv_close_state_times);
			sendto_test_result(GTEST_SAPP_ERR);			
		}
	}
	

	/* 此处不能发送正确结果, 因为不知道还会不会被调用, 只能在plut_ctrl_biz_destroy()最后看结果如何 */

	/* 虽然收到了CLOSE状态, 但是此处故意返回GIVEME, 实际解析层不应该再再被调用一次了, 已经无意义了甚至是错误了, 业务插件的pme可能都被free了 */
	return PROT_STATE_GIVEME;
}




/*
	pcap就两个包, 同时输出两个状态, 调用业务插件, 分别是:
	SESSION_STATE_PENDING|SESSION_STATE_DATA
	SESSION_STATE_DATA|SESSION_STATE_CLOSE
	正常模式下, 其实close状态通常是因超时而淘汰的, 尤其是UDP和TCP_ALL插件, 
	此处为了方便测试, 解析层不看sapp的close状态, 直接输出测试状态, 用于测插件管理. 
*/
extern "C" char protocol_2state_pd_dc_entry(struct streaminfo *a_tcp,  void **pme, int thread_seq, const void *ip_hdr)
{
	stSessionInfo tmp_ss = {};

	if(ip_hdr != NULL){
		tmp_ss.prot_flag = 1;
		tmp_ss.plugid = g_protocol_plug_id;
		tmp_ss.app_info = NULL;
		tmp_ss.buf = (void *)"protocol test 2state_pd_dc\n";
		tmp_ss.buflen = strlen("protocol test 2state_pd_dc\n");
		
		if(0 == protocol_call_times){
			tmp_ss.session_state = SESSION_STATE_PENDING|SESSION_STATE_DATA;
		}else if(1 == protocol_call_times){
			tmp_ss.session_state = SESSION_STATE_DATA|SESSION_STATE_CLOSE;
		}
		
		PROT_PROCESS(&tmp_ss, &biz_plug_pme, a_tcp->threadnum, (struct streaminfo * )a_tcp, ip_hdr);

		protocol_call_times++;

		if(protocol_call_times > 2){
			printf("\033[1;31;40mprotocol_2state_pd_dc_entry() error, this plug has been called %d times with payload packet!\033[0m\n", protocol_call_times);
			sendto_test_result(GTEST_SAPP_ERR);			
		}
	}
	
	return APP_STATE_GIVEME;
}


/*
	pcap就两个包, 同时获取两个状态的业务插件.
*/
extern "C" char biz_2state_pd_dc_entry(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
{
	send_result_in_destroy_flag = 1;
	biz_plug_called_times++;

	/* 解析层只调用了两次, 且是下面这两个状态 */
	if(((SESSION_STATE_PENDING|SESSION_STATE_DATA) != session_info->session_state)
	&& ((SESSION_STATE_DATA|SESSION_STATE_CLOSE) != session_info->session_state)){
		printf("\033[1;31;40mbiz_2state_pd_dc_entry() state error, expect 'pending|data' or 'data|close', but actual is:0x%x\033[0m\n", session_info->session_state);
		sendto_test_result(GTEST_SAPP_ERR);
	}

	if(biz_plug_called_times > 2){
		printf("\033[1;31;40mbiz_3state_pdc_entry() error, this plug has been called %d times, this state is:0x%x!\033[0m\n", biz_plug_called_times, session_info->session_state);
		sendto_test_result(GTEST_SAPP_ERR);
	}

	if(SESSION_STATE_CLOSE & session_info->session_state){
		biz_recv_close_state_times++;
		if(biz_recv_close_state_times >= 2){
			printf("\033[1;31;40mbiz_3state_pdc_entry() error, this plug has been recv CLOSE %d times!\033[0m\n", biz_recv_close_state_times);
			sendto_test_result(GTEST_SAPP_ERR);			
		}
	}

	/* 此处不能发送正确结果, 因为不知道还会不会被调用, 只能在plut_ctrl_biz_destroy()最后看结果如何 */

	/* 虽然收到了CLOSE状态, 但是此处故意返回GIVEME, 实际不应该再再被调用一次了, 已经无意义了甚至是错误了, pme可能都被free了 */
	return PROT_STATE_GIVEME;
}


/*
	pcap就三个包, 三次调用业务插件, 分别是:
	SESSION_STATE_PENDING|SESSION_STATE_DATA,
	SESSION_STATE_DATA,
	SESSION_STATE_DATA|SESSION_STATE_CLOSE
	正常模式下, 其实close状态通常是因超时而淘汰的, 尤其是UDP和TCP_ALL插件, 
	此处为了方便测试, 解析层不看sapp的close状态, 直接输出测试状态, 用于测插件管理. 
*/
extern "C" char protocol_state_pd_d_dc_entry(struct streaminfo *a_udp,  void **pme, int thread_seq, const void *ip_hdr)
{
	stSessionInfo tmp_ss = {};

	if(ip_hdr != NULL){
		tmp_ss.prot_flag = 1;
		tmp_ss.plugid = g_protocol_plug_id;
		tmp_ss.buf = (void *)"protocol test state_pd_d_dc\n";
		tmp_ss.buflen = strlen("protocol test state_pd_d_dc\n");
		tmp_ss.app_info = NULL;
		
		if(0 == protocol_call_times){
			tmp_ss.session_state = SESSION_STATE_PENDING|SESSION_STATE_DATA;
		}else if(1 == protocol_call_times){
			tmp_ss.session_state = SESSION_STATE_DATA;
		}else if(2 == protocol_call_times){
			tmp_ss.session_state = SESSION_STATE_DATA|SESSION_STATE_CLOSE;
		}
		
		PROT_PROCESS(&tmp_ss, &biz_plug_pme, a_udp->threadnum, (struct streaminfo * )a_udp, ip_hdr);

		protocol_call_times++;
		if(protocol_call_times > 3){
			printf("\033[1;31;40mprotocol_state_pd_d_dc_entry error, this plug has been called %d times with payload packet!\033[0m\n", protocol_call_times);
			sendto_test_result(GTEST_SAPP_ERR);			
		}			
	}
	
	return APP_STATE_GIVEME;
}

extern "C" char biz_state_pd_d_dc_entry(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
{
	send_result_in_destroy_flag = 1;
	biz_plug_called_times++;

	/* 解析层只调用了三次, 且是下面三个状态 */
	if(((SESSION_STATE_PENDING|SESSION_STATE_DATA) != session_info->session_state)
	&& (SESSION_STATE_DATA != session_info->session_state)
	&& ((SESSION_STATE_DATA|SESSION_STATE_CLOSE) != session_info->session_state)){
		printf("\033[1;31;40mbiz_state_pd_d_dc_entry() state error, expect 'pending|data', 'data', 'data|close', but actual is:0x%x\033[0m\n", session_info->session_state);
		sendto_test_result(GTEST_SAPP_ERR);
	}

	if(biz_plug_called_times > 3){
		printf("\033[1;31;40mbiz_state_pd_d_dc_entry() error, this plug has been called %d times, this state is:0x%x!\033[0m\n", biz_plug_called_times, session_info->session_state);
		sendto_test_result(GTEST_SAPP_ERR);
	}

	if(SESSION_STATE_CLOSE & session_info->session_state){
		biz_recv_close_state_times++;
		if(biz_recv_close_state_times >= 2){
			printf("\033[1;31;40mbiz_3state_pdc_entry() error, this plug has been recv CLOSE %d times!\033[0m\n", biz_recv_close_state_times);
			sendto_test_result(GTEST_SAPP_ERR);			
		}
	}

	/* 此处不能发送正确结果, 因为不知道还会不会被调用, 只能在plut_ctrl_biz_destroy()最后看结果如何 */

	/* 虽然收到了CLOSE状态, 但是此处故意返回GIVEME, 实际不应该再再被调用一次了, 已经无意义了甚至是错误了, pme可能都被free了 */
	return PROT_STATE_GIVEME;
}


extern "C" char protocol_push_3state_entry(struct streaminfo *a_tcp,  void **pme, int thread_seq, const void *ip_hdr)
{
	stSessionInfo tmp_ss = {};

	if(ip_hdr != NULL){
		tmp_ss.prot_flag = 1;
		tmp_ss.plugid = g_protocol_plug_id;
		tmp_ss.app_info = NULL;
		tmp_ss.buf = (void *)"protocol test push_3state\n";
		tmp_ss.buflen = strlen("protocol test push_3state\n");
		
		if(0 == protocol_call_times){
			tmp_ss.session_state = SESSION_STATE_PENDING|SESSION_STATE_DATA;
		}else if(1 == protocol_call_times){
			tmp_ss.session_state = SESSION_STATE_DATA;
		}else if(2 == protocol_call_times){
			tmp_ss.session_state = SESSION_STATE_DATA|SESSION_STATE_CLOSE;
		}
		
		PROT_PROCESS(&tmp_ss, &biz_plug_pme, a_tcp->threadnum, (struct streaminfo * )a_tcp, ip_hdr);

		protocol_call_times++;
		if(protocol_call_times > 3){
			printf("\033[1;31;40mprotocol_state_pd_d_dc_entry error, this plug has been called %d times with payload packet!\033[0m\n", protocol_call_times);
			sendto_test_result(GTEST_SAPP_ERR);			
		}			
	}
	
	return APP_STATE_GIVEME;
}

/*
	此插件返回了DROPME, 在什么情况下都不能再被调用了.
*/
extern "C" char biz_dropme_in_pending_state_entry(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
{
	send_result_in_destroy_flag = 1;
	biz_plug_called_times++;

	if(0 == (session_info->session_state & SESSION_STATE_PENDING)){
		printf("\033[1;31;40mbiz_dropme_in_pending_entry() error, not SESSION_STATE_PENDING state!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);		
	}

	if(biz_plug_called_times > 1){
		printf("\033[1;31;40mbiz_dropme_in_pending_entry() error, this plug has been called %d times!\033[0m\n", biz_plug_called_times);
		sendto_test_result(GTEST_SAPP_ERR);
	}

	/* 此处不能发送正确结果, 因为不知道还会不会被调用, 只能在 plut_ctrl_biz_destroy() 最后看结果如何 */

	return PROT_STATE_DROPME;
}


/*
	此插件返回了DROPME, 在什么情况下都不能再被调用了.
*/
extern "C" char biz_dropme_in_data_state_entry(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
{
	send_result_in_destroy_flag = 1;
	biz_plug_called_times++;

	if(SESSION_STATE_DATA == session_info->session_state){
		return PROT_STATE_DROPME;	
	}

	if(biz_plug_called_times > 2){
		printf("\033[1;31;40mbiz_dropme_in_data_entry() error, this plug has been called %d times!\033[0m\n", biz_plug_called_times);
		sendto_test_result(GTEST_SAPP_ERR);
	}

	/* 此处不能发送正确结果, 因为不知道还会不会被调用, 只能在 plut_ctrl_biz_destroy() 最后看结果如何 */

	return PROT_STATE_GIVEME;
}


/*
	此插件返回了DROPME, 在什么情况下都不能再被调用了.
*/
extern "C" char biz_dropme_in_close_state_entry(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
{
	send_result_in_destroy_flag = 1;
	biz_plug_called_times++;

	if(SESSION_STATE_CLOSE & session_info->session_state){
		return PROT_STATE_DROPME;	
	}

	if(biz_plug_called_times > 3){
		printf("\033[1;31;40mbiz_dropme_in_close_state_entry() error, this plug has been called %d times!\033[0m\n", biz_plug_called_times);
		sendto_test_result(GTEST_SAPP_ERR);
	}

	/* 此处不能发送正确结果, 因为不知道还会不会被调用, 只能在 plut_ctrl_biz_destroy() 最后看结果如何 */

	return PROT_STATE_GIVEME;
}


extern "C" char protocol_push_close_state_entry(struct streaminfo *a_tcp,  void **pme, int thread_seq, const void *ip_hdr)
{
	stSessionInfo tmp_ss = {};

	if(ip_hdr != NULL){
		tmp_ss.prot_flag = 1;
		tmp_ss.plugid = g_protocol_plug_id;
		tmp_ss.app_info = NULL;
		tmp_ss.buf = (void *)"protocol test push close_state\n";
		tmp_ss.buflen = strlen("protocol test close_state\n");

		if(0 == protocol_call_times){
			tmp_ss.session_state = SESSION_STATE_PENDING|SESSION_STATE_DATA|SESSION_STATE_CLOSE;
		}else if(1 == protocol_call_times){
			tmp_ss.session_state = SESSION_STATE_DATA|SESSION_STATE_CLOSE; /* 此处故意伪造一种错误调用, 其实不应该有多个CLOSE状态 */
		}else if(2 == protocol_call_times){
			tmp_ss.session_state = SESSION_STATE_DATA|SESSION_STATE_CLOSE; /* 此处故意伪造一种错误调用, 其实不应该有多个CLOSE状态 */
		}
		
		PROT_PROCESS(&tmp_ss, &biz_plug_pme, a_tcp->threadnum, (struct streaminfo * )a_tcp, ip_hdr);

		protocol_call_times++;
		if(protocol_call_times > 3){
			printf("\033[1;31;40mprotocol_state_pd_d_dc_entry error, this plug has been called %d times with payload packet!\033[0m\n", protocol_call_times);
			sendto_test_result(GTEST_SAPP_ERR);			
		}			
	}
	
	return APP_STATE_GIVEME;
}


/*
	此插件故意返回GIVEME, 但实际上, 什么情况下都不能再被调用了.
*/
extern "C" char biz_giveme_in_close_state_entry(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
{
	send_result_in_destroy_flag = 1;
	biz_plug_called_times++;

	if(SESSION_STATE_CLOSE & session_info->session_state){
		return PROT_STATE_GIVEME;	
	}

	if(biz_plug_called_times > 1){
		printf("\033[1;31;40mbiz_dropme_in_close_state_entry() error, this plug has been called %d times!\033[0m\n", biz_plug_called_times);
		sendto_test_result(GTEST_SAPP_ERR);
	}

	/* 此处不能发送正确结果, 因为不知道还会不会被调用, 只能在 plut_ctrl_biz_destroy() 最后看结果如何 */

	return PROT_STATE_GIVEME;
}


extern "C" char flag_change_biz_entry(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
{
	if(project_req_get_int(a_stream, g_biz_project_id) == 1){
		sendto_test_result(GTEST_SAPP_SUCC);
	}else{
		printf("\033[1;31;40mflag_change_biz_entry: flags has not set, current is 0!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
	}

	return PROT_STATE_DROPME;
}


extern "C" char flag_change_protocol_tcp_entry(struct streaminfo *a_tcp,  void **pme, int thread_seq, const void *ip_hdr)
{
	stSessionInfo tmp_ss;
	void *tmp_pme;	

	tmp_ss.session_state = SESSION_STATE_PENDING;
	tmp_ss.prot_flag = 1;
	tmp_ss.plugid = g_protocol_plug_id;
	tmp_ss.app_info = NULL;

	if(g_protocol_flags != 0){
		project_req_add_int(a_tcp, g_protocol_project_id, 1);
	}
	
	PROT_PROCESS(&tmp_ss, &tmp_pme, a_tcp->threadnum, (struct streaminfo * )a_tcp, ip_hdr);
	return APP_STATE_DROPME;
}


extern "C" char special_plug_wire_graft_check_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	/* wire_graft.conf配置文件打开了标签:  mirror_linkinfo_from_mac, 如果初始化失败, 此处也不能注册成功 */
	int project_id = project_customer_register("mirror_linkinfo_from_mac", "struct");

	if(project_id < 0){
		printf("\033[1;31;40mspecial_plug_wire_graft_check_entry() error, project_customer_register 'mirror_linkinfo_from_mac' failed!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);	
		return APP_STATE_DROPME;
	}

	FILE *check_cmd_fp = popen("cat ./load_plugin_stat.log | grep SUCC | grep wire_graft", "r");
	if(NULL == check_cmd_fp){
		printf("\033[1;31;40mspecial_plug_wire_graft_check_entry() error, popen 'cat ./load_plugin_stat.log | grep SUCC | grep wire_graft' failed!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);	
		return APP_STATE_DROPME;		
	}

	char check_cmd_result[256] = {};

	fgets(check_cmd_result, sizeof(check_cmd_result), check_cmd_fp);

	if(strlen(check_cmd_result) >= strlen("plug/platform/wire_graft/libwire_graft.so")){
		printf("\033[32m special_plug_wire_graft_check_entry() test succ\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);			
	}

	fclose(check_cmd_fp);

	return APP_STATE_DROPME;
}



extern "C" long long protocol_flag_change(char* flag_str)
{
	return 0x0FFFFFFFFFFFFFL;
}

extern "C" void protocol_flag_stat(unsigned long long protflag)
{
	g_protocol_flags = 0x0FFFFFFFFFFFFFL;
}

/*
	此函数被平台调用, 传入当前解析层插件被分配的唯一id.
*/
extern "C" void protocol_flag_get_plugid(unsigned short plugid)
{
	g_protocol_plug_id = plugid;
	return;
}

extern "C" int flag_change_protocol_init(void)
{
	protocol_call_times = 0;
	
	g_protocol_project_id = project_producer_register("flag_change", "int", NULL);
	if(g_protocol_project_id < 0){
		printf("\033[1;31;40mflag_change_protocol_init error, project_producer_register(flag_change) error !\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
	}
	return 0;
}


extern "C" void plut_ctrl_biz_destroy(void)
{
	if(send_result_in_destroy_flag != 0){
		printf("\033[32mplug destroy test result:0x%x\033[0m\n", default_result_in_destroy_state);
		sendto_test_result(default_result_in_destroy_state);
	}
}

extern "C" int flag_change_biz_init(void)
{
	biz_plug_called_times = 0;
	send_result_in_destroy_flag = 1;
	biz_recv_close_state_times = 0; 
	if(gtest_sapp_slave_init() < 0){
		sendto_test_result(GTEST_SAPP_ERR);
		return -1;
	}

	g_biz_project_id = project_customer_register("flag_change", "int");
	if(g_biz_project_id < 0){
		printf("\033[1;31;40mflag_change_biz_init error, project_producer_register(flag_change) error !\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
	}

	return 0;
}


