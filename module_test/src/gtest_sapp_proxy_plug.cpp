#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include "stream.h"
#include <sys/types.h>			/* See NOTES */
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include "gtest_sapp_fun.h"


typedef struct {
	struct proxydetail fake_proxy_detail;
	struct streaminfo fake_proxy_stream;
	long long pad_for_mem_chek[32];
}fake_proxy_t;

extern "C" char proxy_protocol_tcp_entry(struct streaminfo *a_tcp,void **pme, int thread_seq, void *a_packet)
{
	fake_proxy_t *p_proxy_context;
	
	if(OP_STATE_PENDING == a_tcp->opstate){
		if(strncasecmp((char *)a_tcp->ptcpdetail->pdata, "11111111111111111111111", strlen("11111111111111111111111")) != 0){
			/* 第二次调用不是从"11111"开始, 防止死循环 */
			return APP_STATE_DROPME;
		}
		p_proxy_context = (fake_proxy_t *)calloc(1, sizeof(fake_proxy_t));
		p_proxy_context->fake_proxy_detail.iType = STREAM_TYPE_HTTP_PROXY;
		p_proxy_context->fake_proxy_detail.pUser = (unsigned char *)malloc(strlen("test_proxy") + 1);
		memcpy(p_proxy_context->fake_proxy_detail.pUser, "test_proxy", strlen("test_proxy"));
		p_proxy_context->fake_proxy_detail.uiIP = 0x04030201;
		p_proxy_context->fake_proxy_detail.uiPort = htons(8888);
		p_proxy_context->fake_proxy_stream.pdetail = &p_proxy_context->fake_proxy_detail;
		p_proxy_context->fake_proxy_stream.type = STREAM_TYPE_HTTP_PROXY;

		/* sapp有时候会读streaminfo_private, 会读越界,此处故意写一些非法值, 而不是NULL   */
		memset(p_proxy_context->pad_for_mem_chek, 0xAA, sizeof(p_proxy_context->pad_for_mem_chek));
		
		set_proxy_fstream(a_tcp, &p_proxy_context->fake_proxy_stream);
		*pme = p_proxy_context;
	}

	p_proxy_context = (fake_proxy_t *)(*pme);
	p_proxy_context->fake_proxy_stream.opstate = a_tcp->opstate;

	if(a_tcp->ptcpdetail->datalen > 0){
		a_tcp->ptcpdetail->pdata = (char *)a_tcp->ptcpdetail->pdata + strlen("11111111111111111111111");
		a_tcp->ptcpdetail->datalen -= strlen("11111111111111111111111");
	}

	deal_tcp_in_proxy_stream(a_tcp,a_packet,&p_proxy_context->fake_proxy_stream);

	if(OP_STATE_CLOSE == a_tcp->opstate){
		p_proxy_context = (fake_proxy_t *)(*pme);
		free(p_proxy_context->fake_proxy_detail.pUser);
		free(*pme);
	}

	return APP_STATE_GIVEME;
}




extern "C" char proxy_business_tcp_entry(struct streaminfo *a_tcp,void **pme, int thread_seq, void *a_packet)
{
	char local_buf[2000] = {};

	if(OP_STATE_PENDING == a_tcp->opstate){
		if(a_tcp->pfather->addr.addrtype == ADDR_TYPE_MAC){
			/* 从mac直接调用的, 不是socks代理, 不处理 */
			return APP_STATE_DROPME;
		}
		if(strncasecmp((char *)a_tcp->ptcpdetail->pdata, "11111111111111111111111", strlen("11111111111111111111111")) == 0){
			/* 第一次收到11111开始的流, 假设不认识,  dropme */
			return APP_STATE_DROPME;
		}
	}
	memcpy(local_buf, a_tcp->ptcpdetail->pdata, a_tcp->ptcpdetail->datalen);
	//printf("cur stream addr prefix:%s\n", layer_addr_prefix_ntop(a_tcp));

	if(NULL == layer_addr_prefix_ntop(a_tcp->pfather)){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "proxy_business_tcp_entry","\033[1;31;40maddr prefix type is NULL!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);		
		return APP_STATE_DROPME;
	}

	if(strncasecmp(layer_addr_prefix_ntop(a_tcp->pfather), "http_proxy", strlen("http_proxy")) != 0){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "proxy_business_tcp_entry","\033[1;31;40maddr prefix type is:%s,  but expect: HTTP_PROXY !\033[0m\n", layer_addr_prefix_ntop(a_tcp->pfather));
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);		
		return APP_STATE_DROPME;
	}	
	//printf("pfather->stream addr prefix:%s\n", layer_addr_prefix_ntop(a_tcp->pfather));

/*   debug
	if(OP_STATE_CLOSE != a_tcp->opstate){
		printf("pstream:%s, pdata:%s\n", printaddr(&a_tcp->addr, thread_seq), local_buf);
	}
*/

	if(a_tcp->pfather->type != STREAM_TYPE_HTTP_PROXY){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "proxy_business_tcp_entry","\033[1;31;40mstream type is not STREAM_TYPE_HTTP_PROXY\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	if(a_tcp->addr.tuple4_v4->daddr != 0x04030201){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "proxy_business_tcp_entry","\033[1;31;40mstream dest ip is not 1.2.3.4\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	if(a_tcp->addr.tuple4_v4->dest != htons(8888)){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "proxy_business_tcp_entry","\033[1;31;40mstream dest port is not 8888\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	if(OP_STATE_CLOSE == a_tcp->opstate){
		SAPP_PLUG_LOG(RLOG_LV_INFO, "proxy_business_tcp_entry","\033[32mproxy_business_tcp_entry test succ!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);
	}
		
	return APP_STATE_GIVEME;
}



extern "C" char proxy_business_kill_tcp_entry(struct streaminfo *a_tcp,void **pme, int thread_seq, void *a_packet)
{
	char local_buf[2000] = {};

	if(OP_STATE_PENDING == a_tcp->opstate){
		if(a_tcp->pfather->addr.addrtype == ADDR_TYPE_MAC){
			/* 从mac直接调用的, 不是代理, 也不处理 */
			return APP_STATE_DROPME;
		}
		if(strncasecmp((char *)a_tcp->ptcpdetail->pdata, "11111111111111111111111", strlen("11111111111111111111111")) == 0){
			/* 第一次收到11111开始的流, 假设不认识,  dropme */
			return APP_STATE_DROPME;
		}
	}

	memcpy(local_buf, a_tcp->ptcpdetail->pdata, a_tcp->ptcpdetail->datalen);

/*   debug
	if(OP_STATE_CLOSE != a_tcp->opstate){
		printf("pstream:%s, pdata:%s\n", printaddr(&a_tcp->addr, thread_seq), local_buf);
	}
*/

	if(a_tcp->pfather->type != STREAM_TYPE_HTTP_PROXY){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "proxy_business_kill_tcp_entry","\033[1;31;40mstream type is not STREAM_TYPE_HTTP_PROXY\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	if(a_tcp->addr.tuple4_v4->daddr != 0x04030201){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "proxy_business_kill_tcp_entry","\033[1;31;40mstream dest ip is not 1.2.3.4\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	if(a_tcp->addr.tuple4_v4->dest != htons(8888)){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "proxy_business_kill_tcp_entry","\033[1;31;40mstream dest port is not 8888\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	/* 此处仅调用一下kill_tcp, 之前经过socks代理的业务插件调用kill_tcp会coredump, 暂不严格判断ip,port的正确性 */
	MESA_kill_tcp(a_tcp, a_packet);

	if(OP_STATE_CLOSE == a_tcp->opstate){
		SAPP_PLUG_LOG(RLOG_LV_INFO, "proxy_business_kill_tcp_entry","\033[32mproxy_business_kill_tcp_entry test succ!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);
	}
		
	return APP_STATE_GIVEME;
}


