#include "stream.h"
#include "sapp_api.h"
#include "sapp_private_api.h"
#include "gdev_keepalive.h"
#include "stream_base.h"

#ifdef __cplusplus
extern "C" {
#endif


#define DEBUG_PRINT  1
#if DEBUG_PRINT
#define DPRINT(fmt, args...)    printf(fmt, ## args)
#define DFPRINT(fmt, args...)    fprintf(fmt, ## args)
#define DSPRINT(fmt, args...)    sprintf(fmt, ## args)
#define DSNPRINT(fmt, args...)    snprintf(fmt, ## args)
#else
#define DPRINT(fmt, args...)    /* Don't do anything in release builds */
#endif

static int test_tcp_flow_id = -1;
static unsigned short phony_protocol_plugid; 


#define TEST_NETWORK_FLOW  1
#define TEST_SAPP_API		   1

#ifndef MAX
#define MAX(a, b)  	(((a) > (b)) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a, b)       (((a) < (b)) ? (a) : (b))
#endif

typedef struct{
	int ivalue1;
	int ivalue2;
	char str_value1[NAME_MAX];
	char str_value2[NAME_MAX];

	int test_project_id;
	int test_bridge_id;
}test_app_val_t;

/* ����һЩȫ�ֱ���, �и��ֲ�ͬ������, ��������������ݲ���, 
   �����������ɸ��������Լ����� 
*/
static test_app_val_t g_test_app_val;
static const char *g_test_app_cfg_file="./etc/test_app.conf";

char test_gtp_volatile_addr_entry(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
	enum stream_carry_tunnel_t tunnel_type;
	int opt_len = sizeof(tunnel_type);
	char addr_list_str[1024];

	if(stream_addr_list_ntop(pstream, addr_list_str, sizeof(addr_list_str)) < 0){
		DPRINT("stream_addr_list_ntop() error!\n");
		return -1;
	}

	if(pstream->opstate== OP_STATE_PENDING){
		MESA_get_stream_opt(pstream, MSO_STREAM_TUNNEL_TYPE, &tunnel_type, &opt_len);
		if(tunnel_type != STREAM_TUNNEL_GPRS_TUNNEL){
			return APP_STATE_DROPME;
		}
		
		DPRINT("gtp layer pending: %s\n", addr_list_str);
	}else if(pstream->opstate== OP_STATE_CLOSE){
		DPRINT("gtp layer close  : %s\n", addr_list_str);
	}else{
		DPRINT("gtp layer data   : %s\n", addr_list_str);
	}

	return APP_STATE_GIVEME;
}

struct hierarchical_layer{
	int addrtype;
	int layer_index;
};
#define MAX_LAYER_DEPTH (15)
#define MAX_LAYER_STAT_NUM (128)

static int hierarchical_layer_stat_num = 0;
static struct hierarchical_layer g_hierarchical_layer_stat[MAX_LAYER_STAT_NUM][MAX_LAYER_DEPTH];

extern const char *addr_type_to_prefix(enum addr_type_t layer_type);

static int hierarchical_layer_stat_cmp(const struct hierarchical_layer *layer1, const struct hierarchical_layer *layer2)
{
	int i;

	for(i = 0; i < MAX_LAYER_DEPTH; i++){
		if(layer1[i].addrtype != layer2[i].addrtype){
			return -1;
		}	
	}

	return 0;
}

/*
	return value:
		1: bingo, found;
		0: not found;
*/
static int search_g_hierarchical_layer_stat(const struct hierarchical_layer *stream_hierarchical_layer_stat)
{
	int i;
	
	for(i = 0; i < hierarchical_layer_stat_num; i++){
		if(hierarchical_layer_stat_cmp(&g_hierarchical_layer_stat[i][0], stream_hierarchical_layer_stat) == 0){
			return 1;
		}
	}

	return 0;
}


static void show_hierarchical_layer_stat(void)
{
	int i, layer_index;

	for(i = 0; i < hierarchical_layer_stat_num; i++){
		for(layer_index = 0; layer_index < MAX_LAYER_DEPTH; layer_index++){
			if(g_hierarchical_layer_stat[i][layer_index].addrtype <= 0){
				break;
			}
			DPRINT("%s-", addr_type_to_prefix((enum addr_type_t )g_hierarchical_layer_stat[i][layer_index].addrtype));
		}
		DPRINT("\b\n");
	}
}


static int update_hierarchical_layer_stat(const struct hierarchical_layer *stream_hierarchical_layer_stat)
{
	if(search_g_hierarchical_layer_stat(stream_hierarchical_layer_stat) == 0){ //不存�? �?新的流结�?
		memcpy(&g_hierarchical_layer_stat[hierarchical_layer_stat_num], stream_hierarchical_layer_stat, sizeof(struct hierarchical_layer) * MAX_LAYER_DEPTH);
		hierarchical_layer_stat_num++;
		show_hierarchical_layer_stat();
	}

	return 0;
}

char hierarchical_embed_layer_entry(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
	struct hierarchical_layer stream_hierarchical_layer_stat[MAX_LAYER_DEPTH] = {};
	int layer_num;
	if(0 != thread_seq){
		DPRINT("hierarchical_embed_layer_entry only support one thread!\n");
		return APP_STATE_DROPME;
	}

	if(OP_STATE_CLOSE == pstream->opstate){
		layer_num = 0;
		while(pstream){
			stream_hierarchical_layer_stat[layer_num].addrtype = pstream->addr.addrtype;
			layer_num++;
			pstream = pstream->pfather;
		}

		update_hierarchical_layer_stat(stream_hierarchical_layer_stat);
	}

	return APP_STATE_GIVEME;
}

#if TEST_SAPP_API
char phony_biz_test(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
{
	//DPRINT("I am biz plug, from pro info: %s\n", session_info->buf);

	if(SESSION_STATE_PENDING & session_info->session_state){
		*pme = malloc(10);
		DPRINT("session_info:%p, pme:%p, state:%d\n", session_info,*pme, session_info->session_state);
	}

	if(SESSION_STATE_CLOSE & session_info->session_state){
		DPRINT("session_info:%p, pme:%p, state:%d\n", session_info,*pme, session_info->session_state);
		free(*pme);
	}

	if(SESSION_STATE_DATA & session_info->session_state){
		DPRINT("session_info:%p, pme:%p, state:%d\n", session_info,*pme, session_info->session_state);
	}

	return PROT_STATE_GIVEME;
}

void phony_protocol_funstat(unsigned long long protflag)
{

}

long long phony_protocol_flag_change(char* flag_str)
{
	return 0xFFFF;
}

void phony_protocol_get_plugid(unsigned short plugid)
{
	phony_protocol_plugid= plugid;
}

/* ģ�������, �������ļ�PLUGNAME=xxxʶ�� */
char phony_protocol_test(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	stSessionInfo stinfo;
	static void *biz_pme = NULL;

	memset(&stinfo, 0, sizeof(stSessionInfo));

	stinfo.plugid = phony_protocol_plugid;
	stinfo.session_state = SESSION_STATE_PENDING;
	stinfo.buf = (void *)"hello!\n";
	stinfo.buflen = strlen("hello!\n");
	stinfo.prot_flag = 0xFFFF;

	DPRINT("I am protocol plug\n");
	PROT_PROCESS(&stinfo, &biz_pme, thread_seq, a_tcp, a_packet);

	return APP_STATE_GIVEME;
}


char print_vxlan_info(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	struct vxlan_info vinfo;
	int opt_val_len = sizeof(vinfo);
	int ret;

	if(OP_STATE_PENDING == a_tcp->opstate || OP_STATE_CLOSE == a_tcp->opstate){
		ret = MESA_get_stream_opt(a_tcp, MSO_STREAM_VXLAN_INFO, &vinfo, &opt_val_len);
		if(ret < 0){
			DPRINT("get vxlan info error!\n");
		}else{
			DPRINT("OPSTATE:%d, tuple4:%s, vxlan info:\n", a_tcp->opstate, printaddr(&a_tcp->addr, thread_seq));
			DPRINT("\tencap_type:%d\n", vinfo.encap_type);
			DPRINT("\tntrance_id:%d\n", vinfo.entrance_id);
			DPRINT("\tdev_id:%d\n", vinfo.dev_id);
			DPRINT("\tlink_id:%d\n", vinfo.link_id);
			DPRINT("\tlink_dir:%d\n", vinfo.link_dir);

			DPRINT("\tinner_smac:%s\n", vinfo.inner_smac);
			DPRINT("\tinner_dmac:%s\n", vinfo.inner_dmac);
		}
	}

	return APP_STATE_DROPME;
}


char print_stream_tunnel_type(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	unsigned short tunnel_type = 0;
	int opt_val_len = sizeof(short);

	MESA_get_stream_opt(a_tcp, MSO_STREAM_TUNNEL_TYPE, &tunnel_type, &opt_val_len);
	if(tunnel_type != 0){
		DPRINT("stream tunnel type:%d\n", tunnel_type);
	}

	return APP_STATE_DROPME;
}
char test_get_this_layer_header(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	struct mesa_ip4_hdr *ip4hdr = (struct mesa_ip4_hdr *)get_this_layer_header(a_tcp);

	DPRINT("iphdr:%p, ip->v=%d, ip->hl=%d, ip->len=%u\n", ip4hdr, ip4hdr->ip_v, ip4hdr->ip_hl*4, ntohs(ip4hdr->ip_len));

	return APP_STATE_GIVEME;
}

static void test_get_tcp_opts_show_detail(struct tcp_option *opt_array, int optnum)
{
	int i;

	for(i = 0; i < optnum; i++){
		if(opt_array[i].len > 0){
			DPRINT("\ttype:%d, len:%d, value:%llu\n", opt_array[i].type, opt_array[i].len, opt_array[i].long_value);
		}else{
			DPRINT("\ttype:%d, len:%d,  no value\n", opt_array[i].type, opt_array[i].len);
		}	
	}
}


char test_get_pkt_tcp_opts(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	struct tcp_option to[20];
	const struct mesa_ip4_hdr *iph = (const struct mesa_ip4_hdr *)a_packet;
	const struct mesa_tcp_hdr *tcph;
	int ret;

	if(NULL == a_packet){
		return APP_STATE_DROPME;
	}

	if(ADDR_TYPE_IPV4 == a_tcp->addr.addrtype){
		tcph = (const struct mesa_tcp_hdr * )((char *)a_packet + iph->ip_hl *4);
	}else{
		tcph = (const struct mesa_tcp_hdr * )((char *)a_packet + 40);
	}
	
	ret = MESA_get_tcp_pkt_opts((const struct tcphdr *)tcph, to, 20);
	if(ret > 0){
		DPRINT("MESA_get_tcp_pkt_opts OK:\n");
		test_get_tcp_opts_show_detail(to, ret);
	}

	return APP_STATE_GIVEME;
}


static void test_get_tcp_opts_show_ext_detail(struct tcp_option_ext *opt_array, int optnum)
{
	int i;

	for(i = 0; i < optnum; i++){
		if(opt_array[i].len > 0){
			DPRINT("\ttype:%d, len:%d, value:%llu\n", opt_array[i].type, opt_array[i].len, opt_array[i].long_value);
		}else{
			DPRINT("\ttype:%d, len:%d,  no value\n", opt_array[i].type, opt_array[i].len);
		}	
	}
}

char test_get_pkt_tcp_opts_ext(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	struct tcp_option_ext to[32];
	const struct mesa_ip4_hdr *iph = (const struct mesa_ip4_hdr *)a_packet;
	const struct mesa_tcp_hdr *tcph;
	int ret;

	if(NULL == a_packet){
		return APP_STATE_DROPME;
	}

	if(ADDR_TYPE_IPV4 == a_tcp->addr.addrtype){
		tcph = (const struct mesa_tcp_hdr * )((char *)a_packet + iph->ip_hl *4);
	}else{
		tcph = (const struct mesa_tcp_hdr * )((char *)a_packet + 40);
	}
	
	ret = MESA_get_tcp_pkt_opts_ext((const struct tcphdr *)tcph, to, 32);
	if(ret > 0){
		DPRINT("MESA_get_tcp_pkt_opts_ext OK:\n");
		test_get_tcp_opts_show_ext_detail(to, ret);
	}

	return APP_STATE_GIVEME;
}
/* ���Ե�����ͳ�� */
char test_tcp_uni_stream_stats(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	struct tcpdetail *raw_pdetail;
	struct tcp_flow_stat *tflow_project;
	
	if(-1 == test_tcp_flow_id){
		test_tcp_flow_id = project_customer_register("tcp_flow_stat", "struct");
		if(-1 == test_tcp_flow_id){
			DPRINT("'tcp_flow_stat' is disable, no statistics\n");
		}
	}
	
	if(OP_STATE_CLOSE == a_tcp->opstate){
		if(DIR_DOUBLE == a_tcp->dir){
			/* ֻ�������� */
			return APP_STATE_DROPME;
		}

		raw_pdetail=(struct tcpdetail *)a_tcp->pdetail;
		DPRINT("from-detail: server pkt=%d, count=%d, client pkt=%d, count=%d\n",
			raw_pdetail->serverpktnum,   raw_pdetail->serverbytes,
			raw_pdetail->clientpktnum,    raw_pdetail->clientbytes);

		if(test_tcp_flow_id != -1){
			/* 2015-12-29 lijia add */
			tflow_project = (struct tcp_flow_stat *)project_req_get_struct(a_tcp, test_tcp_flow_id);
			if(tflow_project){
				DPRINT("from-project: server pkt=%u, count=%llu, client pkt=%u, count=%llu\n",
					tflow_project->C2S_data_pkt,tflow_project->C2S_data_byte,
					tflow_project->S2C_data_pkt, tflow_project->S2C_data_byte);		
			}
		}
		
		if((raw_pdetail->serverbytes && raw_pdetail->clientbytes) == 0){
			DPRINT("stream-detail: %s\n", printaddr(&a_tcp->addr, thread_seq));
		}

		if((tflow_project->C2S_data_byte && tflow_project->S2C_data_byte) == 0){
			DPRINT("stream-project: %s\n", printaddr(&a_tcp->addr, thread_seq));
		}
		
	}

	return APP_STATE_GIVEME;
}


char test_get_stream_tcp_opts(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	struct tcp_option *opt_array;
	int opt_num = 8;
	int ret;

	unsigned int isn = -1;
	int len = sizeof(int);
	ret = MESA_get_stream_opt(a_tcp, MSO_TCP_ISN_C2S, &isn, &len);	
	if(ret >= 0){
		DPRINT("MESA_get_stream_opt() MSO_TCP_ISN_C2S, %u!\n", isn);
	}else{
		DPRINT("MESA_get_stream_opt() MSO_TCP_ISN_C2S error!\n");
		abort();
	}
	ret = MESA_get_stream_opt(a_tcp, MSO_TCP_ISN_S2C, &isn, &len);	
	if(ret >= 0){
		DPRINT("MESA_get_stream_opt() MSO_TCP_ISN_S2C, %u!\n", isn);
	}else{
		DPRINT("MESA_get_stream_opt() MSO_TCP_ISN_S2C error!\n");
		abort();
	}
	ret = MESA_get_stream_opt(a_tcp, MSO_TCP_SYN_OPT, &opt_array, &opt_num);
	if(ret >= 0){
		DPRINT("stream:%p, SYN-OPTS:\n", a_tcp);
		test_get_tcp_opts_show_detail(opt_array, opt_num);
	}else{
		DPRINT("MESA_get_stream_opt() MSO_TCP_SYN_OPT error!\n");
	}

	ret = MESA_get_stream_opt(a_tcp, MSO_TCP_SYNACK_OPT, &opt_array, &opt_num);
	if(ret >= 0){
		DPRINT("stream:%p, SYNACK-OPTS:\n", a_tcp);
		test_get_tcp_opts_show_detail(opt_array, opt_num);
	}else{
		DPRINT("MESA_get_stream_opt() MSO_TCP_SYNACK_OPT error!\n");
	}	

	return APP_STATE_DROPME;
}


char test_set_stream_timeout(struct streaminfo *pstream,  void **pme, int thread_seq,void *a_packet)
{
	int ret;
	unsigned short tout_val;
	unsigned char close_reason;
	int opt_len;
	
	if(pstream->opstate== OP_STATE_PENDING){
		/* 
			for test, port 11111=timeout=11s, port 22222=timeout=22s, 
			������nc����3��udp����, �˿ڷֱ�Ϊ11111, 22222, 33333,
			��11s֮��, 11111Ӧ�ý���,
			22s֮��, 22222Ӧ�ý���,
			33333����Ĭ��ȫ�ֳ�ʱ��̭ʱ��, �������ȫ�ֳ�ʱ��̭, Ӧ�ò������(dumpfileģʽ����).
		*/
		if((pstream->addr.tuple4_v4->source == ntohs(11111))
		|| (pstream->addr.tuple4_v4->dest == ntohs(11111))){
			tout_val = 11;
			ret = MESA_set_stream_opt(pstream, MSO_TIMEOUT, &tout_val, sizeof(short));
			if(ret < 0){
				DPRINT("stream:%p, MESA_set_stream_opt error:\n", pstream);
				return APP_STATE_DROPME;
			}			
		}

		if((pstream->addr.tuple4_v4->source == ntohs(22222))
		|| (pstream->addr.tuple4_v4->dest == ntohs(22222))){
			tout_val = 22;
			ret = MESA_set_stream_opt(pstream, MSO_TIMEOUT, &tout_val, sizeof(short));
			if(ret < 0){
				DPRINT("stream:%p, MESA_set_stream_opt error:\n", pstream);
				return APP_STATE_DROPME;
			}			
		}		
	}

	if(pstream->opstate== OP_STATE_CLOSE){
		opt_len = sizeof(char);
		ret = MESA_get_stream_opt(pstream, MSO_STREAM_CLOSE_REASON, &close_reason, &opt_len);
		if(ret >= 0){
			DPRINT("stream: %p %s closed, reason: %d!\n", pstream, printaddr(&pstream->addr, thread_seq), close_reason);
		}else{
			DPRINT("stream: %p %s closed!\n", pstream, printaddr(&pstream->addr, thread_seq));
		}
	}

	return APP_STATE_GIVEME;	
}



static char set_stream_timed(struct streaminfo *pstream,  void **pme, int thread_seq,void *a_packet, unsigned char opstate, int timed_s)
{
	int ret;
	int tout_val = timed_s;

	long timed_cnt = *(long *)pme;

    if (opstate == OP_STATE_PENDING)
    {
        ret = MESA_set_stream_opt(pstream, MSO_STREAM_TIMED, &tout_val, sizeof(int));
        if (ret < 0)
        {
            DPRINT("stream:%p, MESA_set_stream_opt %ds error:\n", pstream, timed_s);
            return APP_STATE_DROPME;
        }
        DPRINT("timed_%d_stream: %p %s set timer %d at %ld!\n", timed_s, pstream, printaddr(&pstream->addr, thread_seq), timed_s, time(NULL));
    }
    if (opstate == OP_STATE_TIMED)
    {
		timed_cnt+=1;
        DPRINT("timed_%d_stream timed callback: %p %s, cnt=%ld at %ld!\n", timed_s, pstream, printaddr(&pstream->addr, thread_seq), timed_cnt, time(NULL));
		if(timed_cnt >= 3)
		{
        	DPRINT("timed_%d_stream timed callback: %p %s, cnt=%ld >= 3, dropme!\n", timed_s, pstream, printaddr(&pstream->addr, thread_seq), timed_cnt);
			return APP_STATE_DROPME;	
		}
		*(long *)pme = timed_cnt;	
    }
    if (opstate == OP_STATE_CLOSE)
    {
        DPRINT("timed_%d_stream close: %p %s at %ld!\n",timed_s, pstream, printaddr(&pstream->addr, thread_seq), time(NULL));
    }
    return APP_STATE_GIVEME;	
}

char test_tcpall_stream_timed_1s(struct streaminfo *pstream,  void **pme, int thread_seq,void *a_packet)
{
	 return set_stream_timed(pstream, pme, thread_seq, a_packet, pstream->pktstate, 1);
}


char test_tcpall_stream_timed_2s(struct streaminfo *pstream,  void **pme, int thread_seq,void *a_packet)
{
	 return set_stream_timed(pstream, pme, thread_seq, a_packet, pstream->pktstate, 2);
}

char test_app_stream_timed_1s(struct streaminfo *pstream,  void **pme, int thread_seq,void *a_packet)
{
	 return set_stream_timed(pstream, pme, thread_seq, a_packet, pstream->opstate, 1);
}


char test_app_stream_timed_2s(struct streaminfo *pstream,  void **pme, int thread_seq,void *a_packet)
{
	 return set_stream_timed(pstream, pme, thread_seq, a_packet, pstream->opstate, 2);
}


char test_sapp_get_platform_opt(struct streaminfo *pstream,  void **pme, int thread_seq,void *a_packet)
{
	unsigned long long totpkt, totbyte, rand_num;
	unsigned long long totpkt_in, totpkt_out;
	int opt_len;
	char time_str[32];

	opt_len = sizeof(long long);
	sapp_get_platform_opt(SPO_TOTAL_RCV_PKT, &totpkt, &opt_len);

	sapp_get_platform_opt(SPO_TOTAL_RCV_BYTE, &totbyte, &opt_len);

	opt_len = 32;
	sapp_get_platform_opt(SPO_CURTIME_STRING, time_str, &opt_len);

	opt_len = sizeof(long long );
	sapp_get_platform_opt(SPO_RAND_NUMBER, &rand_num, &opt_len);

	opt_len = sizeof(long long );
	sapp_get_platform_opt(SPO_TOTAL_INBOUND_PKT, &totpkt_in, &opt_len);
	
	opt_len = sizeof(long long );
	sapp_get_platform_opt(SPO_TOTAL_OUTBOUND_PKT, &totpkt_out, &opt_len);


	DPRINT("tot recv pkt by sapp_get_platform_opt is:%llu\n", totpkt);

	DPRINT("tot recv byte by sapp_get_platform_opt is:%llu\n", totbyte);

	DPRINT("curtime-str by sapp_get_platform_opt is:%s\n", time_str);

	DPRINT("randnum by sapp_get_platform_opt is:%llu\n", rand_num);

	DPRINT("tot recv inbound pkt by sapp_get_platform_opt is:%llu\n", totpkt_in);
	DPRINT("tot recv outbound pkt by sapp_get_platform_opt is:%llu\n", totpkt_out);
	

	return APP_STATE_GIVEME;
}


char test_get_stream_in_out_bound(struct streaminfo *pstream,  void **pme, int thread_seq,void *a_packet)
{
	int ret;
	unsigned long long inound_stat[2];
	unsigned long long outound_stat[2];
	int opt_len;

	
	
	if(pstream->opstate== OP_STATE_CLOSE){
		opt_len = sizeof(long long);
		ret = MESA_get_stream_opt(pstream, MSO_TOTAL_INBOUND_PKT, &inound_stat[0], &opt_len);
		assert(ret >= 0);

		opt_len = sizeof(long long);
		ret = MESA_get_stream_opt(pstream, MSO_TOTAL_INBOUND_BYTE, &inound_stat[1], &opt_len);
		assert(ret >= 0);

		opt_len = sizeof(long long);
		ret = MESA_get_stream_opt(pstream, MSO_TOTAL_OUTBOUND_PKT, &outound_stat[0], &opt_len);
		assert(ret >= 0);

		opt_len = sizeof(long long);
		ret = MESA_get_stream_opt(pstream, MSO_TOTAL_OUTBOUND_BYTE, &outound_stat[1], &opt_len);
		assert(ret >= 0);		

		DPRINT("stream: %s, inbound: %llu, %llu, outbound: %llu, %llu\n", printaddr(&pstream->addr, thread_seq), 
				inound_stat[0], inound_stat[1], outound_stat[0], outound_stat[1]);
	}
	
	return APP_STATE_GIVEME;	
}


char test_stream_with_platform_in_out_traffic(struct streaminfo *pstream,  void **pme, int thread_seq,void *a_packet)
{
	unsigned long long stream_totpkt_in = 0, stream_totpkt_out = 0, stream_totbyte_in = 0, stream_totbyte_out = 0;
	unsigned long long platform_totpkt_in = 0, platform_totpkt_out = 0, platform_totbyte_in = 0, platform_totbyte_out = 0;
	
	int opt_len;

	if(pstream->opstate== OP_STATE_CLOSE){
		opt_len = sizeof(long long );
		sapp_get_platform_opt(SPO_TOTAL_INBOUND_PKT, &platform_totpkt_in, &opt_len);

		opt_len = sizeof(long long );
		sapp_get_platform_opt(SPO_TOTAL_OUTBOUND_PKT, &platform_totpkt_out, &opt_len);

		opt_len = sizeof(long long );
		sapp_get_platform_opt(SPO_TOTAL_INBOUND_BYTE, &platform_totbyte_in, &opt_len);

		opt_len = sizeof(long long );
		sapp_get_platform_opt(SPO_TOTAL_OUTBOUND_BYTE, &platform_totbyte_out, &opt_len);



		opt_len = sizeof(long long);
		MESA_get_stream_opt(pstream, MSO_TOTAL_INBOUND_PKT, &stream_totpkt_in, &opt_len);

		opt_len = sizeof(long long);
		//MESA_get_stream_opt(pstream, MSO_TOTAL_INBOUND_BYTE, &stream_totbyte_in, &opt_len);
		MESA_get_stream_opt(pstream, MSO_TOTAL_INBOUND_BYTE_RAW, &stream_totbyte_in, &opt_len);
		
		opt_len = sizeof(long long);
		MESA_get_stream_opt(pstream, MSO_TOTAL_OUTBOUND_PKT, &stream_totpkt_out, &opt_len);

		opt_len = sizeof(long long);
		//MESA_get_stream_opt(pstream, MSO_TOTAL_OUTBOUND_BYTE, &stream_totbyte_out, &opt_len);	
		MESA_get_stream_opt(pstream, MSO_TOTAL_OUTBOUND_BYTE_RAW, &stream_totbyte_out, &opt_len);	

		DPRINT("stream  : pkt_in:%llu, pkt_out:%llu, byte_in:%llu, byte_out:%llu\n", stream_totpkt_in, stream_totpkt_out, stream_totbyte_in, stream_totbyte_out);
		DPRINT("platform: pkt_in:%llu, pkt_out:%llu, byte_in:%llu, byte_out:%llu\n", platform_totpkt_in, platform_totpkt_out, platform_totbyte_in, platform_totbyte_out);
	}

	return APP_STATE_GIVEME;	
}


static int test_sapp_get_device_opt(const char *device)
{
	int ret;
	unsigned char dev_mac[6];
	unsigned int dev_ipaddr;
	int dev_mtu;
	int opt_len;

	opt_len = 6;
	ret = sapp_get_device_opt(device, SDO_MAC_ADDR, dev_mac, &opt_len);
	if(ret < 0){
		DPRINT("sapp_get_device_opt->%s : SDO_MAC_ADDR error!\n ", device);
	}else{
		DPRINT("sapp_get_device_opt->%s : SDO_MAC_ADDR: %02x, %02x, %02x, %02x, %02x, %02x\n", device, dev_mac[0],dev_mac[1],dev_mac[2],dev_mac[3],dev_mac[4],dev_mac[5]);
	}

	opt_len = 4;
	ret = sapp_get_device_opt(device, SDO_IPV4_ADDR, &dev_ipaddr, &opt_len);
	if(ret < 0){
		DPRINT("sapp_get_device_opt->%s : SDO_IPV4_ADDR error!\n ",device);
	}else{
		char ipstr[16];
		inet_ntop(AF_INET, &dev_ipaddr, ipstr,16);
		DPRINT("sapp_get_device_opt->%s : SDO_IPV4_ADDR: %s\n", device, ipstr);
	}
	opt_len = 4;
	ret = sapp_get_device_opt(device, SDO_MTU, &dev_mtu, &opt_len);	
	if(ret < 0){
		DPRINT("sapp_get_device_opt->%s : SDO_MTU error!\n ", device);
	}else{
		DPRINT("sapp_get_device_opt->%s : SDO_MTU: %d\n", device, dev_mtu);
	}
	return 0;
}

#endif


#if TEST_NETWORK_FLOW
static int check_ipv4_hdr(const struct mesa_ip4_hdr * iph)
{
	int tot_len = ntohs(iph->ip_len);
	
	if (tot_len < (int)sizeof(struct mesa_ip4_hdr) 
		|| iph->ip_hl < 5 
		|| iph->ip_v != 4 
		|| tot_len < iph->ip_hl << 2){	
		return -1;
	}

	switch(iph->ip_p){
		case IPPROTO_IPIP:
		case IPPROTO_ICMP:
		case IPPROTO_TCP:
		case IPPROTO_UDP:
		case IPPROTO_IPV6:
		case IPPROTO_GRE:
			break;

		default:
			return -1;
	}

	return 0;
}

char testIPFragApp_1(struct streaminfo *pstream,unsigned char routedir, int thread_seq,void *a_packet)
{
	static int testcount;
	DPRINT("ip_frag_entry test %d\n",testcount++);
	return APP_STATE_GIVEME;
}

char ipv4_pkt_detail_entry(struct streaminfo *pstream,unsigned char routedir, int thread_seq,void *a_packet)
{
	char ip_src_str[INET6_ADDRSTRLEN];
	char ip_dst_str[INET6_ADDRSTRLEN];
	struct mesa_ip4_hdr *ihdr4 = (struct mesa_ip4_hdr *)a_packet;
	struct mesa_tcp_hdr *thdr;
	struct mesa_udp_hdr *uhdr;
	if(NULL == a_packet){
		return APP_STATE_GIVEME;
	}

	inet_ntop(AF_INET, &ihdr4->ip_src.s_addr, ip_src_str, sizeof(ip_src_str));
	inet_ntop(AF_INET, &ihdr4->ip_dst.s_addr, ip_dst_str, sizeof(ip_dst_str));

	if(IPPROTO_TCP == ihdr4->ip_p){
		thdr = (struct mesa_tcp_hdr *)((char *)ihdr4 + ihdr4->ip_hl * 4);
		DPRINT("tid:%d, IP pkt: %s:%u --> %s:%u, ipid:%u, proto:%d, routedir:%d\n", thread_seq,
				ip_src_str, ntohs(thdr->th_sport),
				ip_dst_str, ntohs(thdr->th_dport),
				ntohs(ihdr4->ip_id), ihdr4->ip_p,
				routedir);
	}else if(IPPROTO_UDP == ihdr4->ip_p){
		uhdr = (struct mesa_udp_hdr *)((char *)ihdr4 + ihdr4->ip_hl * 4);
		DPRINT("tid:%d, IP pkt: %s:%u --> %s:%u, ipid:%u, proto:%d,routedir:%d\n", thread_seq,
				ip_src_str, ntohs(uhdr->uh_sport),
				ip_dst_str, ntohs(uhdr->uh_dport),
				ntohs(ihdr4->ip_id), ihdr4->ip_p,
				routedir);		
	}else{
		DPRINT("tid:%d, IP pkt: %s --> %s, ipid:%u, proto:%d, routedir:%d\n", thread_seq,
				ip_src_str, ip_dst_str, ntohs(ihdr4->ip_id), ihdr4->ip_p, routedir);
	}
	
	return APP_STATE_GIVEME;
}



char testIPApp_1(struct streaminfo *pstream,unsigned char routedir, int thread_seq,void *a_packet)
{
	static int testcount;
	DPRINT("ip_entry test %d\n",testcount++);
	return APP_STATE_GIVEME;
}

char testIPv6App_1(struct streaminfo *pstream,unsigned char routedir, int thread_seq,void *a_packet)
{
	static int testcount;
	DPRINT("ip_v6 test %d\n",testcount++);
	return APP_STATE_GIVEME;
}

static unsigned long long test_get_stream_id(struct streaminfo *a_stream)
{
	int ret = 0;
	int device_id_size = sizeof(unsigned long long);
	unsigned long long device_id = 0;

	ret = MESA_get_stream_opt(a_stream, MSO_GLOBAL_STREAM_ID, (void *)&device_id, &device_id_size);
	if (ret == 0)
	{
		return device_id;
	}

	return -1;
}
static int test_udp_flow_id = -1;
char testudpApp_1(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
	struct udpdetail *pdetail=(struct udpdetail *)pstream->pdetail;
	struct udp_flow_stat *plug_stat;
	char no_use[65536];

	if(-1 == test_udp_flow_id){
		test_udp_flow_id = project_customer_register(PROJECT_REQ_UDP_FLOW, "struct");
		if(-1 == test_udp_flow_id){
			DPRINT("'udp_flow_stat' is disable, no statistics\n");
		}
	}

        if(pstream->opstate== OP_STATE_PENDING)
        {
test_set_stream_timeout(pstream, pme, thread_seq, a_packet);        
        	plug_stat = (struct udp_flow_stat *)malloc(sizeof(struct udp_flow_stat));
        	memset(plug_stat, 0, sizeof(struct udp_flow_stat));
                *pme=plug_stat;
        }

        plug_stat = (struct udp_flow_stat *)(*pme);

	if(pdetail->datalen > 0){
		if(DIR_C2S == pstream->curdir){
			plug_stat->C2S_byte += pdetail->datalen;
			plug_stat->C2S_pkt++;
		}else{
			plug_stat->S2C_byte += pdetail->datalen;
			plug_stat->S2C_pkt++;
		}
		memcpy(no_use, pdetail->pdata, pdetail->datalen);
	}

	if(pstream->opstate==OP_STATE_CLOSE)
	{
		if(pdetail != NULL){
			DPRINT("%20s: %s, %llu, ", "UdpallstreaM-inter", printaddr(&(pstream->addr), pstream->threadnum), test_get_stream_id(pstream));
			DPRINT("server-pkt=%u, server-count=%u, client-pkt=%u, client-count=%u, datalen=%u, ",
				pdetail->serverpktnum, pdetail->serverbytes,
				pdetail->clientpktnum,pdetail->clientbytes, pdetail->datalen);
			DPRINT("total-pkt=%d, ", pdetail->serverpktnum + pdetail->clientpktnum);
			DPRINT("total-count=%u\n", pdetail->serverbytes + pdetail->clientbytes);       
		
		
		DPRINT("%20s: %s, ", "udpallstream-plug", printaddr(&(pstream->addr),	pstream->threadnum));
		DPRINT("server-pkt=%u, server-count=%llu, client-pkt=%u, client-count=%llu, datalen=%u, ",
			plug_stat->C2S_pkt,plug_stat->C2S_byte,
			plug_stat->S2C_pkt,plug_stat->S2C_byte, pdetail->datalen);
		}
		DPRINT("total-pkt=%d, ", plug_stat->C2S_pkt + plug_stat->S2C_pkt);
		DPRINT("total-count=%llu\n", plug_stat->C2S_byte+plug_stat->S2C_byte);
                free(*pme);

		struct udp_flow_stat *flow_project = (struct udp_flow_stat *)project_req_get_struct(pstream, test_udp_flow_id);
		if(flow_project != NULL){
			DPRINT("%20s: %s, ", "UdpallstreaM-project", printaddr(&(pstream->addr),	pstream->threadnum));
			DPRINT("server-pkt=%u, server-count=%llu, client-pkt=%u, client-count=%llu, datalen=%u, ",
				flow_project->C2S_pkt,flow_project->C2S_byte,
				flow_project->S2C_pkt,flow_project->S2C_byte, pdetail->datalen);
			DPRINT("total-pkt=%d, ", flow_project->C2S_pkt + flow_project->S2C_pkt);
			DPRINT("total-count=%llu\n", flow_project->C2S_byte+flow_project->S2C_byte);       
		}
	}
	return APP_STATE_GIVEME;
	
}

char testudpApp_2(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
	struct udpdetail *pdetail=(struct udpdetail *)pstream->pdetail;
	if(pdetail->clientpktnum >10)
		return APP_STATE_DROPME;
	else 
		return APP_STATE_GIVEME;
	
}

char testtcpApp_1(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
	struct tcpdetail *pdetail=(struct tcpdetail *)pstream->pdetail;

	if(pdetail->clientpktnum >3)
		return APP_STATE_DROPME;
	else 
		return APP_STATE_GIVEME;
}	

char tcp_data_dump(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
	char sip_str[20], dip_str[20];
	char file_name[128];
	if(pstream->opstate== OP_STATE_PENDING){
		inet_ntop(AF_INET, &pstream->addr.tuple4_v4->saddr, sip_str, 20);
		inet_ntop(AF_INET, &pstream->addr.tuple4_v4->daddr, dip_str, 20);
		DSNPRINT(file_name, 128, "%s_%u_%s_%u.T%ld.dump", 
				sip_str, ntohs(pstream->addr.tuple4_v4->source), 
				dip_str, ntohs(pstream->addr.tuple4_v4->dest),
				(long)time(NULL)); 
		*pme = malloc(sizeof(void *));
		*pme = fopen(file_name, "w+");		
	}

	if(NULL == *pme){
		assert(0);
	}
	if(pstream->ptcpdetail->datalen > 0){
		fwrite(pstream->ptcpdetail->pdata, pstream->ptcpdetail->datalen, 1, (FILE *)(*pme));
	}

	if(pstream->opstate== OP_STATE_CLOSE){
		fclose((FILE *)(*pme));
	}

	return APP_STATE_GIVEME;
}

char test_print_mac(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{

	if(pstream->opstate== OP_STATE_PENDING)
	{
		DPRINT("tcpstream: %s, ",printaddr(&(pstream->addr),	pstream->threadnum));
		while(pstream){
			if(pstream->addr.addrtype == ADDR_TYPE_MAC){
				struct layer_addr_mac *mac_addr = (struct layer_addr_mac *)pstream->addr.mac;
				DPRINT("smac: %02x-%02x-%02x-%02x-%02x-%02x,  dmac: %02x-%02x-%02x-%02x-%02x-%02x\n",
				         mac_addr->src_addr.h_source[0], mac_addr->src_addr.h_source[1], mac_addr->src_addr.h_source[2], 
				         mac_addr->src_addr.h_source[3], mac_addr->src_addr.h_source[4], mac_addr->src_addr.h_source[5], 
				         mac_addr->src_addr.h_dest[0], mac_addr->src_addr.h_dest[1], mac_addr->src_addr.h_dest[2], 
				         mac_addr->src_addr.h_dest[3], mac_addr->src_addr.h_dest[4], mac_addr->src_addr.h_dest[5]);
				break;
			}else{
				pstream = pstream->pfather;
			}
		}
	}

        return APP_STATE_GIVEME;
}


static void sapp_timer_test_cbfun(sapp_timer_handle h, sapp_timer_event ev, int pkt_process_thread_id, void *user_arg)
{
	struct streaminfo *pstream = (struct streaminfo *)user_arg;
	struct timeval curt;

	gettimeofday(&curt, NULL);

	DPRINT("tid:%d, tcpstream %s  timeout: %ld.%ld \n",
			pstream->threadnum, 
			printaddr(&(pstream->addr),pstream->threadnum),
			curt.tv_sec, curt.tv_usec);
}



static void *sapp_timer_ev_new(int tid, void *arg)
{
	sapp_timer_handle th;
	sapp_timer_event tev;
	int iopt, ret;
	struct timeval topt;

	th = sapp_get_platform_timer(tid);
	assert(th);
	tev = sapp_timer_event_new(th);
	assert(tev);

	iopt = tid;
	sapp_event_set_opt(tev, STEO_EFFECTIVE_THREAD_ID, &iopt, sizeof(iopt));
	
	topt.tv_sec = 1;
	topt.tv_usec = 0;
	sapp_event_set_opt(tev, STEO_TIMEOUT_VAL, &topt, sizeof(topt));
	sapp_event_set_opt(tev, STEO_CALLBACK_FUN, (void *)&sapp_timer_test_cbfun, sizeof(void *));
	sapp_event_set_opt(tev, STEO_CALLBACK_FUN_ARG, arg, sizeof(void *));

	ret = sapp_timer_add(th, tev);
	assert(ret >= 0);

	return tev;
}

char on_tcp_sapp_timer_test(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
	sapp_timer_handle th;
	sapp_timer_event tev;
	
	if(pstream->opstate== OP_STATE_PENDING){
		tev = sapp_timer_ev_new(pstream->threadnum, pstream);
		*pme = tev;
	}else{
		tev = *pme;

		if(pstream->opstate== OP_STATE_CLOSE){
			th = sapp_get_platform_timer(pstream->threadnum);
			sapp_timer_del(th, tev);
			DPRINT("tid:%d, tcpstream close: %s, del timer\n",pstream->threadnum, printaddr(&(pstream->addr),pstream->threadnum));
			return APP_STATE_DROPME;
		}
	}

	return APP_STATE_GIVEME;
}


char testtcpApp_2(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
	struct tcpdetail *raw_pdetail=(struct tcpdetail *)pstream->pdetail;
	struct tcp_flow_stat *plug_stat;

	if(-1 == test_tcp_flow_id){
		test_tcp_flow_id = project_customer_register("tcp_flow_stat", "struct");
		if(-1 == test_tcp_flow_id){
			DPRINT("'tcp_flow_stat' is disable, no statistics\n");
		}
	}
	
	if(pstream->opstate== OP_STATE_PENDING)
	{
test_set_stream_timeout(pstream, pme, thread_seq, a_packet);   
		plug_stat = (struct tcp_flow_stat *)calloc(1, sizeof(struct tcp_flow_stat));
		*pme = plug_stat;
	}
	plug_stat = (struct tcp_flow_stat *)(*pme);
	
	if(raw_pdetail->datalen > 0){
		if(DIR_C2S == pstream->curdir){
			plug_stat->C2S_data_byte += raw_pdetail->datalen;
			plug_stat->C2S_data_pkt++;
		}else{
			plug_stat->S2C_data_byte += raw_pdetail->datalen;
			plug_stat->S2C_data_pkt++;
		}
	}
	
	if(pstream->opstate== OP_STATE_CLOSE)
	{	
		DPRINT("%17s: %s, ","tcpstream-plug", printaddr(&(pstream->addr),	pstream->threadnum));
		//DPRINT("%17s: %s, ","tcpstream-plug", printaddr_r(&(pstream->addr),	addr_str_buf, 1024));
		DPRINT("final_dir=%d, server pkt=%d, count=%d, client pkt=%d, count=%d\n",
			pstream->dir,
			raw_pdetail->serverpktnum,   raw_pdetail->serverbytes,
			raw_pdetail->clientpktnum,    raw_pdetail->clientbytes);
		free(plug_stat);

		/* 2015-12-29 lijia add */
		struct tcp_flow_stat *tflow_inter = ((struct tcpdetail_private *)pstream->pdetail)->flow_stat;
		if(tflow_inter){
			DPRINT("%17s: %s, %llu,", "TcpstreaM-inter", printaddr(&(pstream->addr), pstream->threadnum), test_get_stream_id(pstream));
			DPRINT("opstate=%d, server pkt=%u, count=%llu, client pkt=%u, count=%llu\n",
				pstream->opstate,
				tflow_inter->C2S_data_pkt,tflow_inter->C2S_data_byte,
				tflow_inter->S2C_data_pkt, tflow_inter->S2C_data_byte);		
		}

		if(test_tcp_flow_id != -1){
			/* 2015-12-29 lijia add */
			struct tcp_flow_stat *tflow_project = (struct tcp_flow_stat *)project_req_get_struct(pstream, test_tcp_flow_id);
			if(tflow_project){
				DPRINT("%17s: %s, ", "TcpstreaM-project", printaddr(&(pstream->addr),	pstream->threadnum));
				DPRINT("opstate=%d, server pkt=%u, count=%llu, client pkt=%u, count=%llu\n",
					pstream->opstate,
					tflow_project->C2S_data_pkt,tflow_project->C2S_data_byte,
					tflow_project->S2C_data_pkt, tflow_project->S2C_data_byte);		
			}
		}
	}
        return APP_STATE_GIVEME;
}


/* 关于网络相关字�??, 均为网络�? network order */
struct __test_inline_vxlan_hdr{
	unsigned char flags;

	/*------------byte delim -------*/
#if 0	
	unsigned char reserved[3];
#else
	unsigned char nat_type; /* 复用�?�?保留字�?? 表示NAT类型 */
	unsigned char reserved[2];
#endif
	/*--------int delim -------*/
	unsigned char vlan_id_half_high;
	unsigned char link_layer_type : 4; /* 二层报文封�?�格�? */
	unsigned char vlan_id_half_low : 4;
	unsigned int dir : 1;
	unsigned int link_id : 6;
	unsigned int online_test : 1;

	unsigned int r7 : 1;
	unsigned int r6 : 1;
	unsigned int r5 : 1;
	unsigned int r4 : 1;
	unsigned int vni_flag : 1;
	unsigned int r2 : 1;
	unsigned int r1 : 1;
	unsigned int r0 : 1;
}__attribute__((packed));
typedef struct __test_inline_vxlan_hdr test_inline_vxlan_hdr_t;


char tcpentry_vlink_info(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
#if IOMODE_MARSIO
	int ret;
	char link_dir;
	long long vlink_id;
	const struct ip *ihdr;
	char srcstr[INET6_ADDRSTRLEN], dststr[INET6_ADDRSTRLEN];
	const struct mesa_ethernet_hdr *ehdr;
	unsigned char inline_dev_mac[6], local_dev_mac[6];
	unsigned int local_dev_ip;
	
	if(pstream->opstate== OP_STATE_PENDING)
	{
		if(ADDR_TYPE_IPV4 != pstream->addr.addrtype){
			return APP_STATE_DROPME;
		}
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_VXLAN_LINK_DIR, &link_dir);
		if(ret < 0){
			DPRINT("tcpentry_vlink_info(): get_rawpkt_opt_from_streaminfo of RAW_PKT_GET_VXLAN_LINK_DIR error!\n");
			return APP_STATE_DROPME;
		}
		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_VIRTUAL_LINK_ID, &vlink_id);
		if(ret < 0){
			DPRINT("tcpentry_vlink_info(): get_rawpkt_opt_from_streaminfo of RAW_PKT_GET_VIRTUAL_LINK_ID error!\n");
			return APP_STATE_DROPME;
		}	

		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_VXLAN_OUTER_GDEV_MAC, inline_dev_mac);
		if(ret < 0){
			DPRINT("tcpentry_vlink_info(): get_rawpkt_opt_from_streaminfo of RAW_PKT_GET_VXLAN_OUTER_GDEV_MAC error!\n");
			return APP_STATE_DROPME;
		}	

		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_VXLAN_OUTER_LOCAL_MAC, local_dev_mac);
		if(ret < 0){
			DPRINT("tcpentry_vlink_info(): get_rawpkt_opt_from_streaminfo of RAW_PKT_GET_VXLAN_OUTER_LOCAL_MAC error!\n");
			return APP_STATE_DROPME;
		}	

		ret = get_rawpkt_opt_from_streaminfo(pstream, RAW_PKT_GET_VXLAN_OUTER_LOCAL_MAC, local_dev_mac);
		if(ret < 0){
			DPRINT("tcpentry_vlink_info(): get_rawpkt_opt_from_streaminfo of RAW_PKT_GET_VXLAN_OUTER_LOCAL_MAC error!\n");
			return APP_STATE_DROPME;
		}	
		

		ihdr = (struct ip *)a_packet;
		inet_ntop(AF_INET, &ihdr->ip_src.s_addr, srcstr, sizeof(srcstr));
		inet_ntop(AF_INET, &ihdr->ip_dst.s_addr, dststr, sizeof(dststr));

		ehdr = (struct mesa_ethernet_hdr *)((char *)a_packet - 14);

		DPRINT("--------------------------------------------link info-----------------------------------------\n");
		DPRINT("outer mac:%02x-%02x-%02x-%02x-%02x-%02x -> %02x-%02x-%02x-%02x-%02x-%02x\n",
				inline_dev_mac[0], inline_dev_mac[1],inline_dev_mac[2],inline_dev_mac[3],inline_dev_mac[4],inline_dev_mac[5],
				local_dev_mac[0],local_dev_mac[1],local_dev_mac[2],local_dev_mac[3],local_dev_mac[4],local_dev_mac[5]);
		
		DPRINT("inner mac:%02x-%02x-%02x-%02x-%02x-%02x -> %02x-%02x-%02x-%02x-%02x-%02x\n",
				ehdr->ether_shost[0], ehdr->ether_shost[1], ehdr->ether_shost[2], ehdr->ether_shost[3], ehdr->ether_shost[4], ehdr->ether_shost[5], 
				ehdr->ether_dhost[0],ehdr->ether_dhost[1],ehdr->ether_dhost[2],ehdr->ether_dhost[3],ehdr->ether_dhost[4],ehdr->ether_dhost[5]);
		DPRINT("inner ip: %s->%s\n", srcstr, dststr);
		DPRINT("link_dir:%d, mrzcpd_vlink_id:%lld\n", link_dir, vlink_id);

		DPRINT("--------------------------------------------------------------------------------------------\n");

	}
#else
	DPRINT("tcpentry_vlink_info(): not compile in marsio mode, do nothing!\n");
#endif	
    return APP_STATE_DROPME;
}


static int test_tcpall_flow_id = -1;

char testtcpApp_allpkt(struct streaminfo *pstream,void **pme, int thread_seq, const void *a_packet)
{
	struct tcpdetail *pdetail=(struct tcpdetail *)pstream->pdetail;
	struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private *)pstream->pdetail;
	struct tcp_flow_stat *tcpallflow;

	if(-1 == test_tcpall_flow_id){
		test_tcpall_flow_id = project_customer_register("tcp_flow_stat", "struct");
		if(-1 == test_tcpall_flow_id){
			DPRINT("'tcp_flow_stat' is disable, no statistics\n");
		}		
	}
	
	if(pstream->pktstate== OP_STATE_PENDING)
	{
		*pme=(void *)malloc(sizeof(struct tcp_flow_stat));
		tcpallflow= (struct tcp_flow_stat *)*pme;
		memset(tcpallflow, 0, sizeof(struct tcp_flow_stat));
	}

	tcpallflow= (struct tcp_flow_stat *)*pme;

	if(a_packet != NULL){
		if(DIR_C2S == pstream->curdir){
			tcpallflow->C2S_all_byte += pdetail->datalen;
			tcpallflow->C2S_all_pkt++;
		}else{
			tcpallflow->S2C_all_byte += pdetail->datalen;
			tcpallflow->S2C_all_pkt++;
		}  		
	}

	if(pstream->pktstate== OP_STATE_CLOSE)
	{	
		DPRINT("%20s: %s, ", "tcpallstream-plug", printaddr(&(pstream->addr),	pstream->threadnum));
		//DPRINT("index=%d,state=%d ",*(int*)((char *)(pstream)-8),*(char *)((char *)(pstream)-4));
		DPRINT("out:%d, final_dir=%d server-pkt=%u, server-count=%llu, client-pkt=%u, client-count=%llu, ",
		pdetail_pr->link_state, pstream->dir,
		tcpallflow->C2S_all_pkt, tcpallflow->C2S_all_byte,
		tcpallflow->S2C_all_pkt, tcpallflow->S2C_all_byte);
		DPRINT("total-pkt=%u, ", tcpallflow->C2S_all_pkt + tcpallflow->S2C_all_pkt);
		DPRINT("total-count=%llu\n", tcpallflow->C2S_all_byte + tcpallflow->S2C_all_byte);
		free(*pme);

		/* 2015-12-29 lijia add */
		struct tcp_flow_stat *tflow_inter = pdetail_pr->flow_stat;
		if(tflow_inter){
			DPRINT("%20s: %s, %llu", "TcpallstreaM-inter", printaddr(&(pstream->addr),	pstream->threadnum), test_get_stream_id(pstream));
			DPRINT("out:%d, pktstate=%d, opstate=%d, server-pkt=%u, server-count=%llu, client-pkt=%u, client-count=%llu, ",
				pdetail_pr->link_state,pstream->pktstate,pstream->opstate,
				tflow_inter->C2S_all_pkt,tflow_inter->C2S_all_byte,
				tflow_inter->S2C_all_pkt, tflow_inter->S2C_all_byte);	
			DPRINT("total-pkt=%u, ", tflow_inter->C2S_all_pkt + tflow_inter->S2C_all_pkt);
			DPRINT("total-count=%llu\n", tflow_inter->C2S_all_byte + tflow_inter->S2C_all_byte);				
		}


		if(-1 != test_tcpall_flow_id){
			/* 2015-12-29 lijia add */
			struct tcp_flow_stat *tflow_project = (struct tcp_flow_stat *)project_req_get_struct(pstream, test_tcpall_flow_id);
			if(tflow_project){
				DPRINT("%20s: %s, ", "TcpallstreaM-project", printaddr(&(pstream->addr),	pstream->threadnum));
				DPRINT("out:%d, pktstate=%d, opstate=%d, server-pkt=%u, server-count=%llu, client-pkt=%u, client-count=%llu, ",
					pdetail_pr->link_state,pstream->pktstate,pstream->opstate,
					tflow_project->C2S_all_pkt,tflow_project->C2S_all_byte,
					tflow_project->S2C_all_pkt, tflow_project->S2C_all_byte);	
				DPRINT("total-pkt=%u, ", tflow_project->C2S_all_pkt + tflow_project->S2C_all_pkt);
				DPRINT("total-count=%llu\n", tflow_project->C2S_all_byte + tflow_project->S2C_all_byte);				
			}
		}
	}
        return APP_STATE_GIVEME;
}

char tcpall_valid_after_kill(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
	unsigned char mopt = 1;

	MESA_kill_tcp(pstream, a_packet);
	
	if(pstream->pktstate== OP_STATE_PENDING){
		if(MESA_set_stream_opt(pstream, MSO_TCPALL_VALID_AFTER_KILL, &mopt, sizeof(mopt)) < 0){
			abort();
		}
	}

	return testtcpApp_allpkt(pstream, pme, thread_seq, a_packet);
}

struct stream_static
{
   int pktnum;
   int iplen;
   int payloadlen;
};

char test_allpkt_v4_len(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet,char checklen)
{
        struct tcpdetail *pdetail=(struct tcpdetail *)pstream->pdetail;
        struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private *)pstream->pdetail;
	struct ip *this_iphdr =(struct ip *) a_packet;
	struct	tcphdr *this_tcphdr =NULL;
	struct udphdr *udph =NULL;
	int datalen, iplen;
	struct stream_static *p=NULL;
	char type=pstream->type;
	char opstate;
	int isprint=1;

	if(a_packet && (check_ipv4_hdr((const struct mesa_ip4_hdr *)this_iphdr) < 0)){
		return APP_STATE_GIVEME;
	}
	if(type==STREAM_TYPE_TCP)
		opstate=pstream->pktstate;
	else
		opstate=pstream->opstate;
        if(opstate== OP_STATE_PENDING)
        {
                *pme=(void *)malloc(sizeof(struct stream_static));
                p=(struct stream_static *)(*pme);
                memset(p,0,sizeof(struct stream_static));
		
        }
        else
        {
                p=(struct stream_static *)(*pme);
        }

	if(this_iphdr!=NULL)
	{
		iplen = ntohs (this_iphdr->ip_len);
		if(this_iphdr->ip_p== IPPROTO_TCP)
		{
			this_tcphdr = (struct tcphdr *) ((char *)a_packet + 4 * this_iphdr->ip_hl);
			datalen = iplen - 4 * this_iphdr->ip_hl - 4 * this_tcphdr->doff;
		}
		else
		{
			udph = (struct udphdr *) ((char*)a_packet +4 * this_iphdr->ip_hl );
			datalen = ntohs (udph->len)- sizeof (struct udphdr);
		}
		p->payloadlen+=datalen;
		p->pktnum++;
		p->iplen+=iplen;
 	}
        if(opstate== OP_STATE_CLOSE)
        {
		if(checklen)
		{
		 if(((pdetail->serverbytes+pdetail->clientbytes) != (p->payloadlen))
			||((pdetail->serverpktnum+pdetail->clientpktnum)!=(p->pktnum)))
		  isprint=1;
		 else
		  isprint=0;
        	}
		if(isprint==1)
		{
		  if(type==STREAM_TYPE_TCP) 
			DPRINT("tcpallstream:");
		  else 
			DPRINT("udpallstream:");
		 DPRINT(" %s ",printaddr(&(pstream->addr),  pstream->threadnum));
                //DPRINT("index=%d,state=%d ",*(int*)((char *)(pstream)-8),*(char *)((char *)(pstream)-4));
                DPRINT("out:%d,pktstate=%d,opstate=%d,server pkt=%d, count=%d,client pkt=%d,count=%d, datalen=%d,lostlen=%d",
                pdetail_pr->link_state,pstream->pktstate,pstream->opstate,pdetail->serverpktnum,pdetail->serverbytes,
                pdetail->clientpktnum,pdetail->clientbytes,pdetail->datalen,pdetail->lostlen);
                DPRINT(" \t total pkt= %d,datalen=%d",(p->pktnum),p->payloadlen);
                DPRINT("\n");
		}
                free(*pme);
        }
        return APP_STATE_GIVEME;
}

char test_allpkt_stream(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
  return test_allpkt_v4_len(pstream,pme, thread_seq,a_packet,0);
}

char test_allpkt_stream_checklen(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
  return test_allpkt_v4_len(pstream,pme, thread_seq,a_packet,1);
}

char testtcpApp_takeover(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
	struct tcpdetail *pdetail=(struct tcpdetail *)pstream->pdetail;

	if(pdetail->clientpktnum >3)
	{
		tcp_set_single_stream_takeoverflag(pstream, TCP_TAKEOVER_STATE_FLAG_ON);
	}

	
        return APP_STATE_GIVEME;
}

static char test_project_read_ipv4_frag_list(struct streaminfo *pstream,void **pme, int thread_seq,const void *a_packet)
{
	static int __init_flag = 0;
	static int project_id;
	raw_ipfrag_list_t *frag_head, *tmp;
	
	if(0 == __init_flag){
		project_id = project_customer_register("ipv4_frag_list", PROJECT_VAL_TYPE_STRUCT);
		if(project_id < 0){
			DPRINT("test_project_add error, 'ipv4_frag_list' is not enable!\n");
			exit(0);
		}
		__init_flag = 1;
	}
	
	if(OP_STATE_DATA == pstream->opstate){
		frag_head = (raw_ipfrag_list_t *)project_req_get_struct(pstream, project_id);		
		if(frag_head){
			DPRINT("stream-%p frag len: ", pstream);
			while(frag_head){
				tmp = frag_head->next;
				DPRINT("%d, ",  frag_head->pkt_len);
				frag_head = tmp;
			}
			DPRINT("\n");
		}
	}

	return APP_STATE_GIVEME;
}

static void __test_project_cb(int thread_seq, void *project_req_value)
{
	return;
}

static void print_tuple4(struct streaminfo *stream)
{
	if(ADDR_TYPE_IPV4 == stream->addr.addrtype){
		char ip1[16], ip2[16];
		struct stream_tuple4_v4 *tuple_v4 = (struct stream_tuple4_v4 *)(stream->addr.paddr);
		inet_ntop(AF_INET, &tuple_v4->saddr, ip1, 16);
		inet_ntop(AF_INET, &tuple_v4->daddr, ip2, 16);
		DPRINT("tuple4_v4 is:%s:%u -- %s:%u\n", ip1, ntohs(tuple_v4->source),
			 ip2, ntohs(tuple_v4->dest));
	}else{
		char ip1[128], ip2[128];
		struct stream_tuple4_v6 *tuple_v6 = (struct stream_tuple4_v6 *)(stream->addr.paddr);;
		inet_ntop(AF_INET6, tuple_v6->saddr, ip1, 128);
		inet_ntop(AF_INET6, tuple_v6->daddr, ip2, 128);
		DPRINT("tuple4_v6 is:%s:%u -- %s:%u\n", ip1, ntohs(tuple_v6->source),
			 ip2, ntohs(tuple_v6->dest));
	}

}

/* ����ֵ 1:���Լ��İ�  0:�����Լ��İ�  -1:�������ݴ��� */
static int check_rst_ip_new (unsigned int dip_net_order,unsigned short dport_net_order, unsigned short ipid_host_order, 
					unsigned short win_host_order, int iMaxRandVal, int iRandKey)
{

	if((iMaxRandVal -ipid_host_order + dip_net_order%iRandKey) % iRandKey != 0){
		return 0;
	}

	if((iMaxRandVal -win_host_order + dport_net_order%iRandKey) % iRandKey != 0){
		return 0;
	}
	
	return 1;
}

/* ����ֵ 1:���Լ��İ�  0:�����Լ��İ�  -1:�������ݴ��� */
static int check_rst_ip_old (unsigned int sip_net_order, unsigned int dip_net_order, unsigned short ipid, 
					unsigned short window, int iMaxRandVal, int iRandKey)
{
        unsigned short window_compute;
        if (sip_net_order == INADDR_NONE) {
                DFPRINT (stderr, "source IP wrong.\n");
                return -1;
        }
        if (dip_net_order == INADDR_NONE) {
                DFPRINT (stderr, "destination IP wrong.\n");
                return -1;
        }

        if (window == 0)
                return 0;

        if ((iMaxRandVal - ipid + sip_net_order%window)%iRandKey != 0) // ������������
                return 0;
        int val = (iMaxRandVal - ipid + sip_net_order%window)/iRandKey;
        window_compute = (unsigned short)(val+dip_net_order%iRandKey);
        if (window == 1 ) {
                if (window_compute == 0 || window_compute == 1 )
                        return 1;
        }
        if (window == window_compute) { // ����ȣ�������������Լ�������
                return 1;
        }
        return 0;
}

static char test_rst_pkt(struct streaminfo *pstream,unsigned char routedir,int thread_seq,  const void *void_pkt)
{
	const raw_pkt_t *real_raw_pkt = (const raw_pkt_t *)void_pkt;
	const struct mesa_ip4_hdr *ip4_hdr;
	const struct mesa_tcp_hdr *tcp_hdr;

	ip4_hdr = (const struct mesa_ip4_hdr *)MESA_jump_layer((const void *)real_raw_pkt->raw_pkt_data, real_raw_pkt->low_layer_type, __ADDR_TYPE_IP_PAIR_V4);
	if(NULL == ip4_hdr){
		return 1;
	}
	
	tcp_hdr = (const struct mesa_tcp_hdr *)((char *)ip4_hdr + ip4_hdr->ip_hl * 4);
	if((tcp_hdr->th_flags & TH_RST) == 0){
		return 1;
	}

	if(check_rst_ip_old(ip4_hdr->ip_src.s_addr, ip4_hdr->ip_dst.s_addr, ntohs(ip4_hdr->ip_id),ntohs(tcp_hdr->th_win), 65535, 13) == 1){
		DPRINT("@@@MESA RST pkt!\n");
	}else{
		DPRINT("### recv RST, but not MESA RST pkt!\n");
	}

	return 1;
}



char test_ipv4_frag(const struct streaminfo *pstream,unsigned char routedir,int thread_seq,  const void *ipv4_hdr)
{
	static long ip_pkt_tot = 0;
	const struct mesa_ip4_hdr *ip4hdr = (const struct mesa_ip4_hdr *)ipv4_hdr;
	unsigned short offset, flags;
	
	/*See, is this a fragment*/
	offset = ntohs(ip4hdr->ip_off);
	flags = offset & ~IPv4_FRAG_OFFSET;
	offset &= IPv4_FRAG_OFFSET;

	
	if(((flags & IPv4_FRAG_MF) != 0) || (offset != 0)) {
		//DPRINT("recv a ipv4 frag pkt!\n");
	}

	/* ffff.pcap, 5698811 */
	ip_pkt_tot++;
	if(ip_pkt_tot > 5680000){
		DPRINT("recv ip pkt tot:%ld\n", ip_pkt_tot);
	}
	
	return APP_STATE_GIVEME;	
}

char test_ipv6_frag(const struct streaminfo *pstream,unsigned char routedir,int thread_seq,  const void *ipv4_hdr)
{
	DPRINT("recv a ipv6 frag pkt!\n");
	return APP_STATE_GIVEME;	
}


char test_layer_addr_prefix_ntop(const struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	const char *addr_type_ntop_str;
	const struct streaminfo *tmp = stream;
	
	if(OP_STATE_PENDING == stream->opstate){

		while(tmp != NULL){
			addr_type_ntop_str = layer_addr_prefix_ntop(tmp);
			DPRINT("%s ",  addr_type_ntop_str);		
			tmp = tmp->pfather;
		}
		DPRINT("\n");
	}
	return APP_STATE_GIVEME;
}


char test_get_rawpkt_options(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	int ret;
	int gdev_ip;
	int vxlan_id;
	int vpn_id;
	unsigned short vxlan_sport;
	unsigned char service_id;
	
	ret = get_rawpkt_opt_from_streaminfo(stream, RAW_PKT_GET_GDEV_IP, &gdev_ip);
	if(ret >= 0){
		char tmp_ip_str[32];
		inet_ntop(AF_INET, &gdev_ip, tmp_ip_str, 32);
		DPRINT("[debug], test_get_rawpkt_options get gdev-ip:%s\n", tmp_ip_str);
	}else{
		DPRINT("[error], test_get_rawpkt_options GDEV_IP error\n");
	}

	ret = get_rawpkt_opt_from_streaminfo(stream, RAW_PKT_GET_VXLAN_ID, &vxlan_id);
	if(ret >= 0){
		DPRINT("[debug], test_get_rawpkt_options get vlan-id:%d\n", vxlan_id);
	}else{
		DPRINT("[error], test_get_rawpkt_options VXLAN_ID error\n");
	}

	ret = get_rawpkt_opt_from_streaminfo(stream, RAW_PKT_GET_VXLAN_VPNID, &vpn_id);
	if(ret >= 0){
		DPRINT("[debug], test_get_rawpkt_options get VPNID:%d\n", ntohl(vpn_id)); /* to host order */
	}else{
		DPRINT("[error], test_get_rawpkt_options VPNID error\n");
	}
	
	service_id = vxlan_id_map_to_service_id(ntohl(vxlan_id));
	DPRINT("service id from vxlan_id: %u\n", service_id);
	
	ret = get_rawpkt_opt_from_streaminfo(stream, RAW_PKT_GET_VXLAN_SPORT, &vxlan_sport);
	if(ret >= 0){
		DPRINT("[debug], test_get_rawpkt_options get sport:%u\n", ntohs(vxlan_sport));
	}else{
		DPRINT("[error], test_get_rawpkt_options VXLAN_SPORT error\n");
	}

	service_id = vxlan_sport_map_to_service_id(ntohs(vxlan_sport));
	DPRINT("service id from sport: %u\n", service_id);
	
	return APP_STATE_GIVEME;
}

char test_layer_index(const struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	const struct streaminfo_private *stream_pr = (struct streaminfo_private *)stream;

	while(stream_pr){
		DPRINT(" --- layer_index:%d, addr_type:%d, addr_ntop:%s\n", stream_pr->layer_index, stream_pr->stream_public.addr.addrtype, layer_addr_ntop(&stream_pr->stream_public));
		stream_pr = (struct streaminfo_private *)stream_pr->stream_public.pfather;
	}
	DPRINT(" --- \n");
	return APP_STATE_DROPME;
}



char test_stream_addr_list_ntop(const struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	int ret;
	char addr_list_str[4096];

	if(OP_STATE_CLOSE == stream->opstate){
		ret = stream_addr_list_ntop(stream, addr_list_str, 4096);
		if(ret < 0){
			DPRINT("stream_addr_list_ntop ret = %d\n", ret);
			assert(0);
		}
		DPRINT("addr-list len is:\t%d, value:\t%s\n", ret, addr_list_str);
	}

	return APP_STATE_GIVEME;
}


char test_inet_addr_list_addr(const struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	int ret;
	char addr_list_str[4096];
	char addr_list_str_recover[4096];
	struct streaminfo recover_stream[32];
	
	if(OP_STATE_CLOSE == stream->opstate){
		ret = stream_addr_list_ntop(stream, addr_list_str, 4096);
		if(ret < 0){
			DPRINT("stream_addr_list_ntop ret = %d\n", ret);
			assert(0);
		}
		DPRINT("    raw-addr-list len is:\t%d, value:\t%s\n", ret, addr_list_str);
		ret = stream_addr_list_pton(addr_list_str, recover_stream, sizeof(struct streaminfo)*32, stream->threadnum);
		if(ret < 0){
			DPRINT("stream_addr_list_pton ret = %d\n", ret);
			assert(0);
		}		

		assert(thread_seq == recover_stream[0].threadnum);

		ret =  stream_addr_list_ntop(recover_stream, addr_list_str_recover, 4096);
		if(ret < 0){
			DPRINT("stream_addr_list_ntop ret = %d\n", ret);
			assert(0);
		}		
		DPRINT("recover-addr-list len is:\t%d, value:\t%s\n", ret, addr_list_str_recover);

		if(strncasecmp(addr_list_str, addr_list_str_recover, 4096) != 0){
			DPRINT("stream_addr_list not name!\n");
		}
	}

	return APP_STATE_GIVEME;
}

char test_kill_tunnel_ip_entry( struct streaminfo *f_stream,unsigned char routedir,int thread_seq,struct ip * a_packet)
{
	char ret = APP_STATE_GIVEME;
	const struct mesa_ip4_hdr *iph = (const struct mesa_ip4_hdr *)a_packet;
	
	switch(a_packet->ip_p){
		case IPPROTO_GRE:
		case IPPROTO_IPIP:
		case IPPROTO_IPV6:
		case IPPROTO_ESP:
		case IPPROTO_AH:
		case IPPROTO_L2TPV3:
			ret |= APP_STATE_DROPPKT;
		break;

		case IPPROTO_TCP:
		case IPPROTO_UDP:
		case IPPROTO_ICMP:
		break;

		default:
			ret |= APP_STATE_DROPPKT;
		break;
	}

	return ret;
}

char test_kill_tunnel(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	char kill_flag = 0;
	char ret = APP_STATE_GIVEME;
	
	if(stream->pfather->addr.addrtype != ADDR_TYPE_MAC) {
		if(STREAM_TYPE_TCP == stream->type){
			MESA_kill_tcp(stream, raw_pkt);
		}
		kill_flag = 1;
	}

	if(STREAM_TYPE_OPENVPN == stream->pfather->type){
		if(STREAM_TYPE_TCP == stream->type){
			MESA_kill_tcp(stream, raw_pkt);
		}
		kill_flag = 1;
	}

	if(kill_flag){
		ret |= APP_STATE_DROPPKT;
	}

	return ret;
}

char test_kill_connection( struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	char ip1[16], ip2[16];
	struct stream_tuple4_v4 *tuple_v4;

	if(OP_STATE_DATA != stream->opstate){ /* ֻ��DATA״̬����KILL */
		return APP_STATE_GIVEME;
	}

	tuple_v4 = (struct stream_tuple4_v4 *)(stream->addr.tuple4_v4);
	
	// for test MESA_kill_tcp
	//if((0xC0A80A9F) == ntohl(tuple_v4->daddr)
	 //|| (0xC0A80A9F) == ntohl(tuple_v4->saddr))
	{
		if(1){
			inet_ntop(AF_INET, &tuple_v4->saddr, ip1, 16);
			inet_ntop(AF_INET, &tuple_v4->daddr, ip2, 16);
			MESA_kill_connection((struct streaminfo *)stream, raw_pkt);
			DPRINT("Kill connection: ,%s:%u -- %s:%u\n", ip1, ntohs(tuple_v4->source),
				 ip2, ntohs(tuple_v4->dest));
		}
	}
	
	return APP_STATE_GIVEME;
}


char test_kill_tcp_syn_ack(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	//struct layer_addr *tuple;
	char ip1[16], ip2[16];
	struct stream_tuple4_v4 *tuple_v4;

	if(OP_STATE_DATA != stream->opstate){
		return APP_STATE_GIVEME;
	}
	
	tuple_v4 = (struct stream_tuple4_v4 *)(stream->addr.paddr);
	
	// for test MESA_kill_tcp
		if(1){
			inet_ntop(AF_INET, &tuple_v4->saddr, ip1, 16);
			inet_ntop(AF_INET, &tuple_v4->daddr, ip2, 16);
			MESA_kill_tcp_synack(stream, raw_pkt);
			DPRINT("Send fake SYN/ACK: ,%s:%u -- %s:%u\n", ip1, ntohs(tuple_v4->source),
				 ip2, ntohs(tuple_v4->dest));
		}
	
	return APP_STATE_GIVEME;
}

char test_send_pkt(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	struct ip *iphdr;
	if(OP_STATE_DATA != stream->opstate){
		return APP_STATE_GIVEME;
	}

	iphdr = (struct ip *)raw_pkt;
	if(iphdr->ip_v != 4){
		DPRINT("not ipv4!\n");
	}
	MESA_sendpacket_ethlayer(stream->threadnum, (char *)raw_pkt-14, 14+ntohs(iphdr->ip_len), 0);

	return APP_STATE_GIVEME;
}

char test_send_iplayer_pkt(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	//struct ip *iphdr;
	/* ICMP request, from 10.10.6.108 to 10.0.6.59 */
	char snd_pkt_data[] = 
	{
		0x45,0x00,0x00,0x54,0x00,0x00,0x40,0x00,
		0x40,0x01,0x19,0xF9,0x0A,0x0A,0x06,0x6C,
		0x0A,0x00,0x06,0x3B,
		0x08,0x00,0xC2,0x6A,0x18,0x8B,0x00,0x07,
		0xE5,0xB8,0xA8,0x54,0x00,0x00,0x00,0x00,
		0x22,0x5C,0x06,
		0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
	};

	MESA_sendpacket_iplayer(stream->threadnum, (char *)snd_pkt_data, sizeof(snd_pkt_data), 0);

	return APP_STATE_GIVEME;
}

char test_sendfake_ipv4_pkt(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	/* ICMP request, from 10.10.6.108 to 10.0.6.59 */
	char snd_pkt_payload[] = 
	{
		0x08,0x00,0xD9,0x71,0x18,0x8B,0x00,0x07,
		0xE5,0xB8,0xA8,0x54,0x00,0x00,0x00,0x00,
		0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
	};

	MESA_fakepacket_send_ipv4(stream->threadnum, 128, 1, 0x0A0A066C, 0x0A00063B, 
							snd_pkt_payload, sizeof(snd_pkt_payload), 0);

	return APP_STATE_GIVEME;
}

char test_sendfake_tcp_pkt(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	MESA_fakepacket_send_tcp(stream->threadnum, 0x0A0A066C, 0x0A00063B, 0x1111,0x2222,
							0x12345678, 0x87654321, 0x10, "TCP payload test", strlen("TCP payload test"), 0);	
	return APP_STATE_GIVEME;
}

char test_sendfake_udp_pkt(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	MESA_fakepacket_send_udp(stream->threadnum, 0x0A0A066C, 0x0A00063B, 0x1111,0x2222,
							"UDP payload test", strlen("UDP payload test"), 0);	
	return APP_STATE_GIVEME;
}


static void test_inject_tcp_pkt_with_this_hdr(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	char fake_http_data[] = "HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\nContent-Type: text/html;charset=UTF-8\r\nContent-Language: zh-CN\r\nContent-Length: 32\r\nConnection: Close\r\n\r\n<html><head>HaHaHa</head></html>";

	char pkt_header_payload[2048];
	struct mesa_ip4_hdr *send_ihdr;
	struct mesa_tcp_hdr *send_thdr;
	
	const struct mesa_ip4_hdr *raw_ihdr;
	const struct mesa_tcp_hdr *raw_thdr;	
	int raw_tcp_payload_len;
	int send_pkt_len;

	raw_ihdr = (struct mesa_ip4_hdr *)raw_pkt;
	raw_thdr = (struct mesa_tcp_hdr *)((char *)raw_ihdr + raw_ihdr->ip_hl*4);
	raw_tcp_payload_len = ntohs(raw_ihdr->ip_len) - raw_ihdr->ip_hl*4 - raw_thdr->th_off * 4;

	/* 当前包是C2S方向的GET, �?要回复一�?虚假的S2C方向的RESPONSE */
	send_ihdr = (struct mesa_ip4_hdr *)pkt_header_payload;
	send_thdr = (struct mesa_tcp_hdr *)((char *)send_ihdr + sizeof(struct mesa_ip4_hdr));

	sendpacket_build_tcp(ntohs(raw_thdr->th_dport),
						ntohs(raw_thdr->th_sport),
						ntohl(raw_thdr->th_ack),
						ntohl(raw_thdr->th_seq)+raw_tcp_payload_len,
						0x18,
						100,
						0,
						NULL,
						0,
						(char *)send_thdr);	

	sendpacket_build_ipv4(sizeof(struct mesa_tcp_hdr) + sizeof(fake_http_data), 
						0, 
						0x1111, 
						IP_DF, 
						100, 
						IPPROTO_TCP, 
						raw_ihdr->ip_dst.s_addr,
						raw_ihdr->ip_src.s_addr,
						NULL,
						0, 
						(unsigned char *)send_ihdr);
	memcpy(pkt_header_payload + sizeof(struct mesa_ip4_hdr) + sizeof(struct mesa_tcp_hdr),
			fake_http_data,
			sizeof(fake_http_data));
						
	sendpacket_do_checksum((unsigned char *)send_ihdr, IPPROTO_IP, sizeof(struct mesa_ip4_hdr));
	sendpacket_do_checksum((unsigned char *)send_ihdr, IPPROTO_TCP, sizeof(struct mesa_tcp_hdr) + sizeof(fake_http_data));

	send_pkt_len = sizeof(struct mesa_ip4_hdr) + sizeof(struct mesa_tcp_hdr) + sizeof(fake_http_data);
	
	sapp_inject_pkt(stream, SIO_EXCLUDE_THIS_LAYER_HDR, pkt_header_payload, send_pkt_len, stream->routedir ^ 1);

	return;
}

char test_inject_tcp_pkt(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	const char *fake_http_pattern = "HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\nContent-Type: text/html;charset=UTF-8\r\nContent-Language: zh-CN\r\nContent-Length: %d\r\nConnection: Close\r\n\r\n%s";
	char plug_ret = APP_STATE_DROPME;
	int i, optval;
	int total_payload_len, payload_char_len;
	char payload_buf[8192];
	char payload_with_html_buf[8192];
	char fake_http_send_buf[8192];
	
	if(OP_STATE_CLOSE == stream->opstate){
		return plug_ret;
	}

	if(OP_STATE_PENDING == stream->opstate){
		if((DIR_C2S == stream->curdir)
		  && (memmem(stream->ptcpdetail->pdata, stream->ptcpdetail->datalen, "hijack", 6) != NULL)){
		  	memset(payload_buf, '*', sizeof(payload_buf));
		  	for(i = 0; i < sizeof(payload_buf); i++){
				if(0 == (i % 80)){
					payload_buf[i] ='\r';
				}else if(0 == (i % 81)){
					payload_buf[i] ='\n';
				}				
		  	}

		  	payload_char_len = MIN(g_test_app_val.ivalue1, 4096);
		  	payload_buf[payload_char_len] = '\0';
		  	DSNPRINT(payload_with_html_buf, sizeof(payload_with_html_buf), "<html><head>%s</head></html>", payload_buf);

			total_payload_len = strlen(payload_with_html_buf);
			DSNPRINT(fake_http_send_buf, sizeof(fake_http_send_buf), fake_http_pattern, total_payload_len, payload_with_html_buf);
		  	
		  	DPRINT("found key 'hijack', send fake http response, len=%d\n", total_payload_len);
			//MESA_inject_pkt(stream, fake_http_data, sizeof(fake_http_data), raw_pkt, stream->routedir ^ 1);
			sapp_inject_pkt(stream, SIO_DEFAULT, fake_http_send_buf, strlen(fake_http_send_buf), stream->routedir ^ 1);
			//test_inject_tcp_pkt_with_this_hdr(stream, pme, thread_seq, raw_pkt);
			plug_ret |= APP_STATE_DROPPKT;

			optval = 1;
			MESA_set_stream_opt(stream, MSO_DROP_STREAM, &optval, sizeof(int));
		}
	}

	
	return plug_ret;
}

char test_inject_tcp_pkt2(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	char fake_http_data[] = "HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\nContent-Type: text/html;charset=UTF-8\r\nContent-Language: zh-CN\r\nContent-Length: 41\r\nConnection: Close\r\n\r\n<html><head>sapp inject pkt</head></html>";
	char plug_ret = APP_STATE_DROPME;
	
	if(OP_STATE_CLOSE == stream->opstate){
		return APP_STATE_DROPME;
	}

	sapp_inject_pkt(stream, SIO_DEFAULT, fake_http_data, strlen(fake_http_data), stream->routedir ^ 1);

	return plug_ret;
}



/* ʹ���µķ����ӿ�  sapp_inject_pkt()����α��� */
static int send_by_sapp_inject_pkt(struct streaminfo *a_tcp, const struct mesa_ip4_hdr *raw_ip4hdr)
{
#define HIJACK_RESPONSE_HDR "HTTP/1.1 200 OK\r\nServer: hijack.com\r\nContent-Length:%d\r\nContent-Type: text/html; charset=UTF-8\r\nConnection: close\r\n\r\n"
#define HIJACK_RESPONSE_BODY "<!Doctype html><html xmlns=http://www.w3.org/1999/xhtml><title>Your web page was hijacked!</title><body><strong><span style=\"color:#E53333;\">Your web page was hijacked!</span></strong></body></html>"
		
	static char http_hijack_buf[1500];
	static int http_hijack_len;

	const struct mesa_tcp_hdr *raw_thdr = (struct mesa_tcp_hdr *)((char *)raw_ip4hdr + raw_ip4hdr->ip_hl * 4); //no options

	struct mesa_ip4_hdr *send_ip4hdr = (struct mesa_ip4_hdr *)http_hijack_buf;
	struct mesa_tcp_hdr *send_thdr = (struct mesa_tcp_hdr *)((char *)send_ip4hdr + sizeof(struct mesa_ip4_hdr)); //no options

	int hdr_len = DSNPRINT(http_hijack_buf+sizeof(struct mesa_ip4_hdr) + sizeof(struct mesa_tcp_hdr), 
	                   1460, HIJACK_RESPONSE_HDR, (int)strlen(HIJACK_RESPONSE_BODY));
	int body_len = DSNPRINT(http_hijack_buf+sizeof(struct mesa_ip4_hdr) + sizeof(struct mesa_tcp_hdr)+hdr_len, 
	                   1500-hdr_len, "%s", HIJACK_RESPONSE_BODY);

	http_hijack_len = sizeof(struct mesa_ip4_hdr) + sizeof(struct mesa_tcp_hdr) + hdr_len + body_len;
	

	send_thdr->th_sport = raw_thdr->th_dport;
	send_thdr->th_dport = raw_thdr->th_sport;
	send_thdr->th_seq = raw_thdr->th_ack;
	send_thdr->th_ack = htonl(ntohl(raw_thdr->th_seq) + ntohs(raw_ip4hdr->ip_len) - raw_ip4hdr->ip_hl * 4 - raw_thdr->th_off*4);
	send_thdr->th_off = 5;
	send_thdr->th_win = 0x222;
	send_thdr->th_sum = 0;
	send_thdr->th_flags = 0x18;
	

	send_ip4hdr->ip_v = 4;
	send_ip4hdr->ip_hl = 5;
	send_ip4hdr->ip_len = htons(http_hijack_len);
	send_ip4hdr->ip_id = 0x3333;
	send_ip4hdr->ip_off = 0;
	send_ip4hdr->ip_ttl = 128;
	send_ip4hdr->ip_p = 6;
	send_ip4hdr->ip_sum = 0;
	send_ip4hdr->ip_src.s_addr = raw_ip4hdr->ip_dst.s_addr;
	send_ip4hdr->ip_dst.s_addr = raw_ip4hdr->ip_src.s_addr;

	sendpacket_do_checksum((unsigned char*)http_hijack_buf, IPPROTO_TCP, sizeof(struct mesa_tcp_hdr) + hdr_len + body_len);
	sendpacket_do_checksum((unsigned char*)http_hijack_buf, IPPROTO_IP, sizeof(struct mesa_ip4_hdr));
	
	return sapp_inject_pkt(a_tcp, SIO_EXCLUDE_THIS_LAYER_HDR, http_hijack_buf, http_hijack_len, MESA_dir_reverse(a_tcp->routedir));

}


char MESA_inject_pkt_for_l2_l3_tcp(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	const char *modify_raw_data_c2s =    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"; //C2Sԭʼ�ַ�������	
	const char *modify_inject_data_s2c = "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/8.5\r\nContent-Type: text/html\r\nContent-Length: 4000\r\n\r\n<html><pre> sapp test inject data.........";

	int ret;
	char ret_flag = 0;
	
	if(OP_STATE_CLOSE == stream->opstate){
		return APP_STATE_DROPME;
	}

	if(DIR_C2S == stream->curdir){
		if(memmem(stream->ptcpdetail->pdata, stream->ptcpdetail->datalen, modify_raw_data_c2s, strlen(modify_raw_data_c2s)) != NULL){

			//������һ��get����, ������һ�����Ӧ��
			ret = MESA_inject_pkt(stream, modify_inject_data_s2c, 1460, raw_pkt, stream->routedir ^ 1); 
			if(ret < 0){
				DPRINT("%s, MESA_inject_pkt S2C error!\n", printaddr(&stream->addr, thread_seq));
			}else{
				DPRINT("%s, MESA_inject_pkt S2C succ:%d\n", printaddr(&stream->addr, thread_seq), ret);
			}	

			if(stream->ptcpdetail->serverpktnum <= 3){
				ret_flag = APP_STATE_DROPPKT;//����C2S�����һ��GET��, ��MESA_inject_pkt_for_l2_l3_tcpall()�ᷢ��һ���ٵ�
			}
		}
	}else{
		if(memmem(stream->ptcpdetail->pdata, stream->ptcpdetail->datalen, "<html><pre>******", strlen("<html><pre>******")) != NULL){
			/* ��һ��S2CӦ����Ѿ���α�췢��, �˴�����Ҫ */
			ret_flag = APP_STATE_DROPPKT;
			return APP_STATE_DROPME | ret_flag;
		}
	}
	
	return APP_STATE_GIVEME | ret_flag;
}

char MESA_inject_pkt_for_l2_l3_tcpall(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	const char *modify_inject_data_c2s = "GET / HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\nUser-Agent: Mozilla/5.1 (Windows NT 10.1; Win64; x64)\r\nAccept: */*\r\nAccept-Language: en-us\r\nAccept-Encoding: gzip, deflate, compress\r\n\r\n";

	char raw_data_c2s[2048];
	char server_ip[32] = {};
	char ret_flag = 0;
	int ret;
	
	if(OP_STATE_CLOSE == stream->pktstate || NULL == raw_pkt){
		return APP_STATE_DROPME;
	}

	if((DIR_C2S == stream->curdir) 
	 && (stream->ptcpdetail->serverpktnum == 2)
	 && (stream->ptcpdetail->datalen == 0)){ /* ֻ���������ָո���ɺ�, �յ�ACK������һ��get����,������ŶԲ��� */
		inet_ntop(AF_INET, &stream->addr.tuple4_v4->daddr, server_ip, 32);

		DSPRINT(raw_data_c2s, modify_inject_data_c2s, server_ip);
		if(strlen(raw_data_c2s) != 197){
			DPRINT("MESA_inject_pkt_for_l2_l3_tcpall(), C2S inject len is not 197, %d\n", (int)strlen(raw_data_c2s)); //Ҫ���Ǳ������������һ��, ������SEQ���ܲ���
			return APP_STATE_DROPME;
		}		
		ret = MESA_inject_pkt(stream, raw_data_c2s, strlen(raw_data_c2s), raw_pkt, stream->routedir);
		if(ret < 0){
			DPRINT("%s, MESA_inject_pkt C2S error!\n", printaddr(&stream->addr, thread_seq));
		}else{
			DPRINT("%s, MESA_inject_pkt C2S succ:%d\n",printaddr(&stream->addr, thread_seq), ret);
		}
		ret_flag = APP_STATE_DROPPKT;
	}
	
	return APP_STATE_GIVEME | ret_flag;
}


#if 0
#include "http.h"
char test_sapp_inject_http(stSessionInfo* session_info, void **param, int thread_seq, struct streaminfo *a_tcp, void *a_packet)
{
	http_infor *a_http = (http_infor *)(session_info->app_info);

	switch(session_info->prot_flag)
	{
		case HTTP_MESSAGE_URL:
			if(memmem((char*)session_info->buf, session_info->buflen, "hijack", strlen("hijack"))){
				send_by_sapp_inject_pkt(a_tcp, (struct mesa_ip4_hdr *)a_packet);
				//DPRINT("----hit key, hijack it!!\n");
				DPRINT("hijack stream: %s, URL: %s\n", printaddr(&a_tcp->addr, thread_seq), (char*)session_info->buf);
			}
		break;

	}

	return PROT_STATE_GIVEME;
}
#endif


static char test_sapp_inject_pkt(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt, unsigned char send_route_dir)
{
	char MESA_inject_pkt_payload[] = "send by MESA_inject_pkt() ";
	char sapp_inject_pkt_def_payload[] = "send by sapp_inject_pkt default ";
	char sapp_inject_pkt_exclude_payload[] = "send by sapp_inject_pkt SIO_EXCLUDE_THIS_LAYER_HDR ";
	char sapp_inject_pkt_no_hdr_payload[256];
	struct stream_tuple4_v4 *tuple_v4;

	if(OP_STATE_CLOSE == stream->opstate){
		return APP_STATE_DROPME;
	}

	tuple_v4 = (struct stream_tuple4_v4 *)(stream->addr.paddr);

	MESA_inject_pkt(stream, MESA_inject_pkt_payload, strlen(MESA_inject_pkt_payload), raw_pkt, send_route_dir);
	sapp_inject_pkt(stream, SIO_DEFAULT, sapp_inject_pkt_def_payload, strlen(sapp_inject_pkt_def_payload), send_route_dir);

	struct mesa_ip4_hdr *ip4hdr = (struct mesa_ip4_hdr *)sapp_inject_pkt_no_hdr_payload;
	struct mesa_tcp_hdr *thdr = (struct mesa_tcp_hdr *)((char *)ip4hdr + sizeof(struct mesa_ip4_hdr)); //no options

	thdr->th_sport = tuple_v4->source;
	thdr->th_dport = tuple_v4->dest;
	thdr->th_seq = 0x11111111;
	thdr->th_ack = 0x22222222;
	thdr->th_off = 5;
	thdr->th_win = 100;
	thdr->th_sum = 0;

	ip4hdr->ip_v = 4;
	ip4hdr->ip_hl = 5;
	ip4hdr->ip_len = htons(sizeof(struct mesa_ip4_hdr) + sizeof(struct mesa_tcp_hdr) + strlen(sapp_inject_pkt_exclude_payload));
	ip4hdr->ip_id = 0x3333;
	ip4hdr->ip_off = 0;
	ip4hdr->ip_ttl = 128;
	ip4hdr->ip_p = 6;
	ip4hdr->ip_sum = 0;
	ip4hdr->ip_src.s_addr = tuple_v4->saddr;
	ip4hdr->ip_dst.s_addr = tuple_v4->daddr;
	
	strncpy(sapp_inject_pkt_no_hdr_payload + sizeof(struct mesa_ip4_hdr) + sizeof(struct mesa_tcp_hdr), sapp_inject_pkt_exclude_payload, 200);

	sapp_inject_pkt(stream, SIO_EXCLUDE_THIS_LAYER_HDR, sapp_inject_pkt_no_hdr_payload, ntohs(ip4hdr->ip_len), send_route_dir);
	
	return APP_STATE_GIVEME;
}

char test_sapp_inject_pkt_same_dir(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	return test_sapp_inject_pkt(stream, pme, thread_seq, raw_pkt, stream->routedir);
}


char test_sapp_inject_pkt_reverse_dir(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	return test_sapp_inject_pkt(stream, pme, thread_seq, raw_pkt, MESA_dir_reverse( stream->routedir));
}



static struct streaminfo *g_polling_stream = NULL;
char polling_inject_tcpall_entry(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	/* polling_inject_tcp_entry��polling������, �ò���stream, ��tcpall_entry����ȫ�ֱ���g_polling_stream,�Ի�ȡĳ���������� */

	if((OP_STATE_DATA == stream->pktstate) && (stream->addr.tuple4_v4->dest == htons(22))){
		DPRINT("update polling stream %p: %s \n", stream, printaddr(&stream->addr, thread_seq));
		g_polling_stream = stream;
	}

	return APP_STATE_GIVEME;
}


char polling_inject_tcp_entry(struct streaminfo *no_stream,void **no_pme, int thread_seq, const void *no_raw_pkt)
{
	char MESA_inject_pkt_payload[] = "send by MESA_inject_pkt    ";
	char sapp_inject_pkt_def_payload[] = "send by sapp_inject_pkt def";
	char sapp_inject_pkt_no_hdr_payload[256];
	struct stream_tuple4_v4 *tuple_v4;

	struct streaminfo *stream = g_polling_stream;
	if(NULL == stream){
		//DPRINT("stream is NULL return!\n");
		return APP_STATE_GIVEME;
	}
	if(OP_STATE_DATA != stream->opstate){
		//DPRINT("stream opstate is %d, return!\n", stream->opstate);
		return APP_STATE_GIVEME;

	}

	tuple_v4 = (struct stream_tuple4_v4 *)(stream->addr.paddr);

	MESA_inject_pkt(stream, MESA_inject_pkt_payload, strlen("send by MESA_inject_pkt    "), NULL, stream->routedir);
	sapp_inject_pkt(stream, SIO_DEFAULT, sapp_inject_pkt_def_payload, strlen("send by sapp_inject_pkt def"), stream->routedir);

	struct mesa_ip4_hdr *ip4hdr = (struct mesa_ip4_hdr *)sapp_inject_pkt_no_hdr_payload;
	struct mesa_tcp_hdr *thdr = (struct mesa_tcp_hdr *)((char *)ip4hdr + sizeof(struct mesa_ip4_hdr)); //no options

	thdr->th_sport = tuple_v4->source;
	thdr->th_dport = tuple_v4->dest;
	thdr->th_seq = 0x11111111;
	thdr->th_ack = 0x22222222;
	thdr->th_off = 5;
	thdr->th_win = 100;
	thdr->th_sum = 0;
	thdr->th_flags = 0x18;

	ip4hdr->ip_v = 4;
	ip4hdr->ip_hl = 5;
	ip4hdr->ip_len = htons(sizeof(struct mesa_ip4_hdr) + sizeof(struct mesa_tcp_hdr) + strlen("send by sapp_inject_pkt hdr"));
	ip4hdr->ip_id = 0x3333;
	ip4hdr->ip_off = 0;
	ip4hdr->ip_ttl = 128;
	ip4hdr->ip_p = 6;
	ip4hdr->ip_sum = 0;
	ip4hdr->ip_src.s_addr = tuple_v4->saddr;
	ip4hdr->ip_dst.s_addr = tuple_v4->daddr;
	
	strncpy(sapp_inject_pkt_no_hdr_payload + sizeof(struct mesa_ip4_hdr) + sizeof(struct mesa_tcp_hdr), "send by sapp_inject_pkt hdr", 200);

	int ret = sapp_inject_pkt(stream, SIO_EXCLUDE_THIS_LAYER_HDR, sapp_inject_pkt_no_hdr_payload, ntohs(ip4hdr->ip_len), 0);
	DPRINT("polling inject pkt dir = 0: %s, ret = %d \n", printaddr(&stream->addr, thread_seq), ret);

	ret = sapp_inject_pkt(stream, SIO_EXCLUDE_THIS_LAYER_HDR, sapp_inject_pkt_no_hdr_payload, ntohs(ip4hdr->ip_len), 1);
	DPRINT("polling inject pkt dir = 1: %s, ret = %d \n", printaddr(&stream->addr, thread_seq), ret);
	
	return APP_STATE_GIVEME;
}


char test_project_add(struct streaminfo *pstream,void **pme, int thread_seq,const void *a_packet)
{
	static int __init_flag = 0;
	static int project_id;
	char *pro_value = (char *)"test project!";
	
	project_req_add_struct(pstream, g_test_app_val.test_project_id, pro_value);		

	return APP_STATE_GIVEME;
}

char test_project_read(struct streaminfo *pstream,void **pme, int thread_seq,const void *a_packet)
{
	static int __init_flag = 0;
	static int project_id;
	char *pro_value;
	
	if(0 == __init_flag){
		project_id = project_customer_register("test_project", PROJECT_VAL_TYPE_STRUCT);
		if(project_id < 0){
			DPRINT("test_project_add error, 'test_project' is not enable!\n");
			exit(0);
		}
		__init_flag = 1;
	}
	
	if(OP_STATE_DATA == pstream->opstate){
		pro_value = (char *)project_req_get_struct(pstream, project_id);	
		DPRINT("### get project : %s\n", pro_value);
	}

	return APP_STATE_GIVEME;
}


char test_project_read_ipv6_frag_list(struct streaminfo *pstream,void **pme, int thread_seq,const void *a_packet)
{
	static int __init_flag = 0;
	static int project_id;
	raw_ipfrag_list_t *frag_head, *tmp;
	
	if(0 == __init_flag){
		project_id = project_customer_register("ipv6_frag_list", PROJECT_VAL_TYPE_STRUCT);
		if(project_id < 0){
			DPRINT("test_project_add error, 'ipv6_frag_list' is not enable!\n");
			exit(0);
		}
		__init_flag = 1;
	}
	
	if(OP_STATE_DATA == pstream->opstate){
		frag_head = (raw_ipfrag_list_t *)project_req_get_struct(pstream, project_id);		
		if(frag_head){
			DPRINT("stream-%p frag len: ", pstream);
			while(frag_head){
				tmp = frag_head->next;
				DPRINT("%d, ",  frag_head->pkt_len);
				frag_head = tmp;
			}
			DPRINT("\n");
		}
	}

	return APP_STATE_GIVEME;
}

void print_stream_list(const struct streaminfo *pstream)
{
	int i, level = 1;
	const struct streaminfo *pfather;
	while(pstream){
		pfather = pstream->pfather;
		for(i = 0; i < level; i++){
			DPRINT("    ");
		}
		DPRINT("stream:%p, stream-type:%d, addr-type:%d\n", pstream, pstream->type, pstream->addr.addrtype);
		pstream = pfather;
		level++;
	}

	return;
}

char test_proxy_cb(struct streaminfo *pstream,void **pme, int thread_seq,const void *a_packet)
{
	struct tcpdetail *a_tcp;

	if(OP_STATE_PENDING == pstream->opstate){
		a_tcp = (struct tcpdetail *)pstream->pdetail;
		DPRINT("into test_proxy_cb----------\n");
		print_stream_list(pstream);
		write(1, a_tcp->pdata, a_tcp->datalen);
	}else if (OP_STATE_DATA == pstream->opstate){
		a_tcp = (struct tcpdetail *)pstream->pdetail;
	}else if(OP_STATE_CLOSE == pstream->opstate){
		DPRINT("test_tcp_cb-close: strem %s\n", printaddr(&pstream->addr, pstream->threadnum));
		return APP_STATE_DROPME;
	}

	return APP_STATE_GIVEME;
}

char test_tcp_cb(struct streaminfo *pstream,void **pme, int thread_seq,const void *a_packet)
{
	struct tcpdetail *a_tcp;
	//int addr_type;
	//void *tuple4;

	if(OP_STATE_PENDING == pstream->opstate){
		a_tcp = (struct tcpdetail *)pstream->pdetail;
		//DPRINT("######### %p, %x\n", a_tcp->pdata, ((char *)a_tcp->pdata)[0]);
		//print_tuple4(pstream);
		DPRINT("test_tcp_cb-pending: stream:%p, %s, len:%d\n", pstream, printaddr(&pstream->addr, pstream->threadnum), a_tcp->datalen);
		
		//DPRINT("cb(): recv a new tcp connection, %p, streamid is %ld, total stream num is:%ld!\n", pstream, stream_id, ++stream_num);
		//DPRINT("cb(): recv %d data from %p!\n", a_tcp->datalen, pstream);
	}else if (OP_STATE_DATA == pstream->opstate){
		a_tcp = (struct tcpdetail *)pstream->pdetail;
		//DPRINT("cb(): recv %d data from %p!\n", a_tcp->datalen, pstream);
		//write(1, a_tcp->pdata, a_tcp->datalen);
		//print_tuple4(pstream);
		//DPRINT("test_tcp_cb-data: %s, len:%d\n", printaddr(&pstream->addr, pstream->threadnum), a_tcp->datalen );
	}else if(OP_STATE_CLOSE == pstream->opstate){
		DPRINT("test_tcp_cb-close: strem %s\n", printaddr(&pstream->addr, pstream->threadnum));
		//print_tuple4(pstream);
		return APP_STATE_DROPME;
	}

	return APP_STATE_GIVEME;
}

char test_udp_cb(struct streaminfo *pstream,void **pme, int thread_seq,const void *a_packet)
{
	if(OP_STATE_PENDING == pstream->opstate){
		DPRINT("udp-pending: %s\n", printaddr(&pstream->addr, pstream->threadnum));
	}else if (OP_STATE_DATA == pstream->opstate){
		//DPRINT("udp-data: %s\n", printaddr(&pstream->addr, pstream->threadnum));
	}else if(OP_STATE_CLOSE == pstream->opstate){
		DPRINT("udp-close: %s\n", printaddr(&pstream->addr, pstream->threadnum));
		return APP_STATE_DROPME;
	}
	
	return APP_STATE_GIVEME;
}

void test_project_tcp_free_cb(int thread_seq, void *project_req_value)
{
//	DPRINT(" ### test_project_tcp_free_cb()\n");
	free(project_req_value);
}

char test_project(struct streaminfo *pstream,void **pme, int thread_seq,const raw_pkt_t *raw_pkt)
{
	static int project_id = -999;
	void *value;

	if(-999 == project_id){
		project_id = project_producer_register("test_project", "struct", test_project_tcp_free_cb);
		if(project_id < 0){
			DPRINT("project_producer_register 'test_project' fail!\n");
		}else{
//			DPRINT("project_req_register OK, id = %d!\n", project_id);
		}
	}

	if(OP_STATE_PENDING == pstream->opstate){
		value = malloc(100);
		strncpy((char *)value, "hello, project", 100);
//		DPRINT("add project %p value\n", pstream);
		project_req_add_struct(pstream, project_id, value);
	}else{
		value = (void *)project_req_get_struct(pstream, 	project_id);
 		DPRINT("get progect %p value is:%s\n", pstream, (char *)value);
	}
	
	return APP_STATE_GIVEME;
}


char test_project_terminal_tag(struct streaminfo *pstream,void **pme, int thread_seq,const raw_pkt_t *raw_pkt)
{
	static int project_id = -123;
	char *value;

	if(-123 == project_id){
		project_id = project_customer_register("terminal_tag", "struct");
		if(project_id < 0){
			DPRINT("project_customer_register 'terminal_tag' fail!\n");
		}else{
//			DPRINT("project_req_register OK, id = %d!\n", project_id);
		}
	}

	if(OP_STATE_DATA== pstream->opstate){
		value = (char *)project_req_get_struct(pstream, 	project_id);
		if(value){
 			DPRINT("get terminal_tag %p value is:%s\n", pstream, value);
 		}else{
			DPRINT("can't get terminal_tag %p \n", pstream);
 		}
	}
	
	return APP_STATE_GIVEME;
}

char print_udp_checksum(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	if(NULL == a_packet){
		return APP_STATE_GIVEME;
	}
	
	const struct mesa_ip4_hdr *iph = (const struct mesa_ip4_hdr *)a_packet;
	const struct mesa_udp_hdr *udph = (struct mesa_udp_hdr *)((char *)a_packet + iph->ip_hl * 4);	

	DPRINT("%u\n", udph->uh_sum);

	return APP_STATE_GIVEME;
}
int test_pkt_handle(const unsigned char *data, int datalen, int dir, int thread_num)
{
	DPRINT("tid:%d, recv a new pkt!\n", thread_num);

	return 0;
}

static int __checkip4pkt(const struct mesa_ip4_hdr * iph)
{
	int tot_len = ntohs(iph->ip_len);
	
	if (tot_len < (int)sizeof(struct mesa_ip4_hdr) 
		|| iph->ip_hl < 5 
		|| iph->ip_v != 4 
		|| tot_len < iph->ip_hl << 2){	
		return -1;
	}

	switch(iph->ip_p){
		case IPPROTO_IPIP:
		case IPPROTO_ICMP:
		case IPPROTO_TCP:
		case IPPROTO_UDP:
		case IPPROTO_IPV6:
		case IPPROTO_GRE:
			break;

		default:
			return -1;
	}

	return 0;
}

static int __checkip6pkt(const struct mesa_ip6_hdr * iph)
{
	if((iph->ip6_flags[0] & 0xF0) != 0x60){
		return -1;
	}
	
	switch(iph->ip6_nxt_hdr){
		case  NEXTHDR_HOP			:  
		case  NEXTHDR_TCP			:  
		case  NEXTHDR_UDP			:  
		case  NEXTHDR_IPV6			:
		case  NEXTHDR_ROUTING		:  
		case  NEXTHDR_FRAGMENT	:
		case  NEXTHDR_ESP			:  
		case  NEXTHDR_AUTH		:
		case  NEXTHDR_ICMP			:
		case  NEXTHDR_NONE		:
		case  NEXTHDR_DEST			:
		case  NEXTHDR_MOBILITY	:
			break;

		default:
			return -1;
	}

	return 0;
}

char test_jump_layer_tcp_entry(struct streaminfo *stream,  void **pme, int thread_seq,void *a_packet)
{
	if(NULL == a_packet){
		return APP_STATE_DROPME;
	}
	const void *next_hdr;
	int raw_ip_layer_type;
	const char *raw_ip_layer_string;
	int expect_layer_type;
	const char *expect_layer_string;
	
	if(ADDR_TYPE_IPV4 == stream->addr.addrtype){
		raw_ip_layer_type = ADDR_TYPE_IPV4;
		raw_ip_layer_string = "ipv4";
	}else{
		raw_ip_layer_type = ADDR_TYPE_IPV6;
		raw_ip_layer_string = "ipv6";
	}

	if(STREAM_TYPE_TCP == stream->type){
		expect_layer_type = ADDR_TYPE_TCP;
		expect_layer_string = "tcp";
	}else{
		expect_layer_type = ADDR_TYPE_UDP;
		expect_layer_string = "udp";
	}

	next_hdr = MESA_jump_layer(a_packet, raw_ip_layer_type, expect_layer_type);
	if(next_hdr){
		DPRINT("bingo! jump to %s from %s succ!\n", expect_layer_string, raw_ip_layer_string);
	}else{
		DPRINT("error! in tcp entry, jump to %s from %s fail!\n", expect_layer_string, raw_ip_layer_string);
	}	

	return APP_STATE_GIVEME;
}

char test_jump_layer_ip_entry(struct streaminfo *f_stream,unsigned char routedir,int thread_seq, const void *arg)
{
	const raw_pkt_t *raw_pkt = ((struct streaminfo_private*)f_stream)->raw_pkt;

	if(NULL == raw_pkt){
		return 0;
	}

	const struct mesa_ip4_hdr * iphdr, *iphdr_greedy;
	const struct mesa_ip6_hdr * ip6hdr, *ip6hdr_greedy;
	char ipsrc[64], ipdst[64];
	char ipsrc_greedy[64], ipdst_greedy[64];

	ipsrc[0] = '\0';
	ipdst[0] = '\0';
	ipsrc_greedy[0] = '\0';
	ipdst_greedy[0] = '\0';

	iphdr = (const struct mesa_ip4_hdr *)MESA_jump_layer(raw_pkt->raw_pkt_data, raw_pkt->low_layer_type, __ADDR_TYPE_IP_PAIR_V4);
	if(iphdr){
		inet_ntop(AF_INET, &iphdr->ip_src.s_addr, ipsrc, 64);
		inet_ntop(AF_INET, &iphdr->ip_dst.s_addr, ipdst, 64);
	}
	iphdr_greedy = (const struct mesa_ip4_hdr *)MESA_jump_layer_greedy(raw_pkt->raw_pkt_data, raw_pkt->low_layer_type, __ADDR_TYPE_IP_PAIR_V4);
	if(iphdr_greedy){
		inet_ntop(AF_INET, &iphdr_greedy->ip_src.s_addr, ipsrc_greedy, 64);
		inet_ntop(AF_INET, &iphdr_greedy->ip_dst.s_addr, ipdst_greedy, 64);
	}
	if(iphdr || iphdr_greedy){
		DPRINT("jump to ip4hdr:%s-%s, greedy jump ip4hdr:%s-%s\n", ipsrc, ipdst, ipsrc_greedy, ipdst_greedy);
	}

	ipsrc[0] = '\0';
	ipdst[0] = '\0';
	ipsrc_greedy[0] = '\0';
	ipdst_greedy[0] = '\0';

	ip6hdr = (const struct mesa_ip6_hdr *)MESA_jump_layer(raw_pkt->raw_pkt_data, raw_pkt->low_layer_type, __ADDR_TYPE_IP_PAIR_V6);
	if(ip6hdr){
		inet_ntop(AF_INET6, &ip6hdr->ip6_src, ipsrc, 64);
		inet_ntop(AF_INET6, &ip6hdr->ip6_dst, ipdst, 64);
	}
	ip6hdr_greedy = (const struct mesa_ip6_hdr *)MESA_jump_layer_greedy(raw_pkt->raw_pkt_data, raw_pkt->low_layer_type, __ADDR_TYPE_IP_PAIR_V6);
	if(ip6hdr_greedy){
		inet_ntop(AF_INET6, &ip6hdr_greedy->ip6_src, ipsrc_greedy, 64);
		inet_ntop(AF_INET6, &ip6hdr_greedy->ip6_dst, ipdst_greedy, 64);
	}
	if(ip6hdr || ip6hdr_greedy){
		DPRINT("jump to ip6hdr:%s-%s, greedy jump ip6hdr:%s-%s\n", ipsrc, ipdst, ipsrc_greedy, ipdst_greedy);
	}

	return APP_STATE_GIVEME;
}

char test_get_opt_from_rawpkt( const struct streaminfo *pstream, const void *this_hdr, const void *raw_pkt, void **pme)
{
	void *this_layer_hdr = NULL, *raw_pkt_hdr = NULL;
	int tot_len = -1, this_layer_remain_len = -1;

	get_opt_from_rawpkt(raw_pkt, RAW_PKT_GET_DATA, &raw_pkt_hdr);
	get_opt_from_rawpkt(raw_pkt, RAW_PKT_GET_TOT_LEN, &tot_len);
	get_opt_from_rawpkt(raw_pkt, RAW_PKT_GET_THIS_LAYER_HDR, &this_layer_hdr);	
	get_opt_from_rawpkt(raw_pkt, RAW_PKT_GET_THIS_LAYER_REMAIN_LEN, &this_layer_remain_len);

	DPRINT("get opt from rawpkt: totlen:%d, remain_len:%d, raw_hdr:%p, this_hader:%p\n",
		tot_len, this_layer_remain_len, raw_pkt_hdr, this_layer_hdr);

	return APP_STATE_GIVEME;	
}

char test_get_rawpkt_opt_from_streaminfo(struct streaminfo *f_stream,unsigned char routedir,int thread_seq, const void *voidpkt)
{
	void *this_layer_hdr = NULL, *raw_pkt_hdr = NULL;
	int tot_len = -1, this_layer_remain_len = -1;
	int ret;

	if((OP_STATE_DATA != f_stream->opstate) && (OP_STATE_DATA != f_stream->pktstate)){ /* ��ͬʱ���ص�tcp,tcpall */
		return APP_STATE_GIVEME;
	}

	ret = get_rawpkt_opt_from_streaminfo(f_stream, RAW_PKT_GET_DATA, &raw_pkt_hdr);
	if(ret == 1){
		raw_ipfrag_list_t *tlist = (raw_ipfrag_list_t *)raw_pkt_hdr;
		while(tlist){
			DPRINT("pkt len:%d\n", tlist->pkt_len);
			tlist = tlist->next;
		}
	}
	get_rawpkt_opt_from_streaminfo(f_stream, RAW_PKT_GET_TOT_LEN, &tot_len);
	get_rawpkt_opt_from_streaminfo(f_stream, RAW_PKT_GET_THIS_LAYER_HDR, &this_layer_hdr);	
	get_rawpkt_opt_from_streaminfo(f_stream, RAW_PKT_GET_THIS_LAYER_REMAIN_LEN, &this_layer_remain_len);

	DPRINT("get opt from rawpkt: totlen:%d, remain_len:%d, raw_hdr:%p, this_hader:%p\n",
		tot_len, this_layer_remain_len, raw_pkt_hdr, this_layer_hdr);
	int gdev_ip = 0;
	char gdev_ip_str[32];
	get_rawpkt_opt_from_streaminfo(f_stream, RAW_PKT_GET_GDEV_IP, &gdev_ip);
	inet_ntop(AF_INET, &gdev_ip, gdev_ip_str, 32);

	int link_id = 0;
	get_rawpkt_opt_from_streaminfo(f_stream, RAW_PKT_GET_VXLAN_ID, &link_id);
	
	unsigned short vxlan_sport = 0;
	get_rawpkt_opt_from_streaminfo(f_stream, RAW_PKT_GET_VXLAN_SPORT, &vxlan_sport);
	
	unsigned char link_dir = 0;
	get_rawpkt_opt_from_streaminfo(f_stream, RAW_PKT_GET_VXLAN_LINK_DIR, &link_dir);

	unsigned char gdev_mac[6], local_mac[6];
	
	memset(gdev_mac, 0, 6);
	memset(local_mac, 0, 6);
	
	get_rawpkt_opt_from_streaminfo(f_stream, RAW_PKT_GET_VXLAN_OUTER_GDEV_MAC, gdev_mac);
	get_rawpkt_opt_from_streaminfo(f_stream, RAW_PKT_GET_VXLAN_OUTER_LOCAL_MAC, local_mac);

	DPRINT("get vxlan opt from rawpkt:  gdev_ip:%s, vxlan_link_id:%d, sport:%u, link_dir:%d, smac:%02x-%02x-%02x-%02x-%02x-%02x, dmac:%02x-%02x-%02x-%02x-%02x-%02x \n", 
		 gdev_ip_str, ntohl(link_id), ntohs(vxlan_sport), link_dir,
		 gdev_mac[0], gdev_mac[1], gdev_mac[2], gdev_mac[3], gdev_mac[4], gdev_mac[5],
		 local_mac[0], local_mac[1], local_mac[2],  local_mac[3], local_mac[4], local_mac[5]);

	memset(gdev_mac, 0, 6);
	memset(local_mac, 0, 6);
	
	 get_rawpkt_opt_from_streaminfo(f_stream, RAW_PKT_GET_ORIGINAL_LOWEST_ETH_SMAC, gdev_mac);
	 get_rawpkt_opt_from_streaminfo(f_stream, RAW_PKT_GET_ORIGINAL_LOWEST_ETH_DMAC, local_mac);
	 DPRINT("get vxlan opt from RAW_PKT_GET_ORIGINAL_LOWEST_ETH_, smac:%02x-%02x-%02x-%02x-%02x-%02x, dmac:%02x-%02x-%02x-%02x-%02x-%02x \n", 
		  gdev_mac[0], gdev_mac[1], gdev_mac[2], gdev_mac[3], gdev_mac[4], gdev_mac[5],
		  local_mac[0], local_mac[1], local_mac[2],  local_mac[3], local_mac[4], local_mac[5]);

	DPRINT("\n-----------------------\n");
	return APP_STATE_GIVEME;	
}


static void __stream_bridge_free_cb(const struct streaminfo *stream, int bridge_id, void *data)
{
	free(data);
}

char stream_bridge_tcp_entry(struct streaminfo *pstream,void **pme, int thread_seq,const void *a_packet)
{
	int bridge_id;

	bridge_id = stream_bridge_build("test_bridge", "r");
	if(bridge_id < 0){
		DPRINT("##### stream_bridge_tcp_entry(): stream_bridge_build error!\n");
		return APP_STATE_DROPME;	
	}

	if(OP_STATE_CLOSE == pstream->opstate){
		/* tcp�Ƚ���, �������� */
		void *data = calloc(1, 100);
		strncpy(data, "abcdefg1234567", 100);
		stream_bridge_async_data_put(pstream, bridge_id, data);	
		DPRINT("##### tcp entry bridge put data:%s\n", (char*)data);
	}

	return APP_STATE_GIVEME;
}

char stream_bridge_tcpall_entry(struct streaminfo *pstream,void **pme, int thread_seq,const void *a_packet)
{
	int bridge_id;

	bridge_id = stream_bridge_build("test_bridge", "r");
	if(bridge_id < 0){
		DPRINT("##### stream_bridge_tcpall_entry(): stream_bridge_build error!\n");
		return APP_STATE_DROPME;	
	}

	if(OP_STATE_CLOSE == pstream->pktstate){
		char *data;
		data = (char *)stream_bridge_async_data_get(pstream, bridge_id);
		if(data){
			DPRINT("tcpall entry bridge get:%s\n", data);
		}else{
			DPRINT("tcpall entry bridge get data error\n");
		}
	}

	return APP_STATE_GIVEME;
}

char vxlan_inject_tcp_entry(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	if(a_tcp->ptcpdetail->pdata && a_tcp->ptcpdetail->datalen)
	{
		struct mesa_ip4_hdr *ip4hdr = (struct mesa_ip4_hdr *)a_packet;
		int ret = sapp_inject_pkt(a_tcp, SIO_EXCLUDE_THIS_LAYER_HDR, a_packet, ntohs(ip4hdr->ip_len), 0);
		DPRINT("polling inject pkt dir = 0: %s, ret = %d \n", printaddr(&a_tcp->addr, thread_seq), ret);

		ret = sapp_inject_pkt(a_tcp, SIO_EXCLUDE_THIS_LAYER_HDR, a_packet, ntohs(ip4hdr->ip_len), 1);
		DPRINT("polling inject pkt dir = 1: %s, ret = %d \n", printaddr(&a_tcp->addr, thread_seq), ret);
	}
	
	//ret = sapp_inject_pkt(stream, SIO_EXCLUDE_THIS_LAYER_HDR, a_packet, ntohs(ip4hdr->ip_len), 1);
//	DPRINT("polling inject pkt dir = 1: %s, ret = %d \n", printaddr(&stream->addr, thread_seq), ret);
	
	return APP_STATE_GIVEME;
}


char UDP_ENTRY(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	//test_project_add(a_tcp,pme,thread_seq,a_packet);
	
	testudpApp_1(a_tcp,pme,thread_seq,a_packet);

	//test_allpkt_stream(a_tcp,pme,thread_seq,a_packet);
	//test_project_read_ipv4_frag_list(a_tcp,pme,thread_seq,a_packet);
	
	return APP_STATE_GIVEME;
}

typedef struct{
	FILE *dump_fp_c2s;
	FILE *dump_fp_s2c;	
	unsigned int first_seq_c2s;
	unsigned int first_seq_s2c;	
}tcp_dump_t;

/* 2015-03-25 lijia add */
char TCP_ALL_DUMP(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
if(NULL == a_packet){
	return APP_STATE_GIVEME;
}

	tcp_dump_t *tdump;
	struct tcpdetail *pdetail=(struct tcpdetail *)a_tcp->pdetail;
	struct mesa_ip4_hdr *iphdr = (struct mesa_ip4_hdr *)a_packet;
	struct mesa_tcp_hdr *tcphdr = (struct mesa_tcp_hdr *)((char *)a_packet + iphdr->ip_hl * 4);
	unsigned int this_seq;
	int this_data_len = ntohs(iphdr->ip_len) - (iphdr->ip_hl << 2) - (tcphdr->th_off<<2);
	char *this_data = (char *)a_packet + (iphdr->ip_hl << 2) + (tcphdr->th_off<<2);

	if(a_tcp->pktstate== OP_STATE_PENDING){
		tdump = (tcp_dump_t *)calloc(1, sizeof(tcp_dump_t));
		tdump->dump_fp_c2s = fopen("dumpfile.tcpraw.C2S.data", "w+");
		if(NULL == tdump->dump_fp_c2s){
			assert(0);
		}
		tdump->dump_fp_s2c = fopen("dumpfile.tcpraw.S2C.data", "w+");
		if(NULL == tdump->dump_fp_s2c){
			assert(0);
		}		
		*pme = tdump;
	}

	tdump = (tcp_dump_t *)(*pme);
	this_seq = ntohl(tcphdr->th_seq);
	
	if(0 == tdump->first_seq_c2s){
		if(tcphdr->th_flags == TH_SYN){
			tdump->first_seq_c2s = ntohl(tcphdr->th_seq);
		}
	}
	
	if(0 == tdump->first_seq_s2c){
		if(tcphdr->th_flags == (TH_SYN|TH_ACK)){
			tdump->first_seq_s2c = ntohl(tcphdr->th_seq);
		}
	}

	if(this_data_len > 0){
		if(DIR_C2S == a_tcp->curdir){
			assert(this_seq >= tdump->first_seq_c2s);
			fseek(tdump->dump_fp_c2s, this_seq - tdump->first_seq_c2s, SEEK_SET);
			fwrite(this_data, this_data_len, 1, tdump->dump_fp_c2s);
		}else{
			assert(this_seq >= tdump->first_seq_s2c);
			fseek(tdump->dump_fp_s2c,  this_seq - tdump->first_seq_s2c, SEEK_SET);
			fwrite(this_data, this_data_len, 1, tdump->dump_fp_s2c);
		}
	}
	

	if(a_tcp->pktstate == OP_STATE_CLOSE){
		fclose(tdump->dump_fp_c2s);
		fclose(tdump->dump_fp_s2c);
		free(tdump);
	}

	return APP_STATE_GIVEME;
}

struct test_tcp_lost{
	unsigned int seq_next_c2s;
	unsigned int seq_next_s2c;	
};

char TEST_TCP_LOST(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	struct test_tcp_lost *tcp_status;
	const struct mesa_ip4_hdr *ipv4_hdr;
	const struct mesa_tcp_hdr *tcp_hdr;
	int ret, len;
	const char *pkt_raw_data;
	unsigned int actual_data_seq;
	
	if(a_tcp->opstate== OP_STATE_PENDING){
		*pme = malloc(sizeof(struct test_tcp_lost ));
		tcp_status = (struct test_tcp_lost  *)*pme;
		len = sizeof(int);
		ret = MESA_get_stream_opt(a_tcp, MSO_TCP_ISN_C2S, &tcp_status->seq_next_c2s, &len);
		if(ret < 0){ /* not create by SYN */
			free(*pme);
			return APP_STATE_DROPME;
		}
		ret = MESA_get_stream_opt(a_tcp, MSO_TCP_ISN_S2C, &tcp_status->seq_next_s2c, &len);
		if(ret < 0){ /* not create by SYN */
			free(*pme);
			return APP_STATE_DROPME;
		}
		tcp_status->seq_next_c2s += 1; /* plus SYN flag */
		tcp_status->seq_next_s2c += 1; /* plus SYN flag */
	}

	tcp_status = (struct test_tcp_lost  *)*pme;

	if(a_tcp->ptcpdetail->lostlen > 0){
		DPRINT("%s lost len:%d\n", printaddr(&a_tcp->addr, a_tcp->threadnum), a_tcp->ptcpdetail->lostlen);
	}

	if(a_tcp->ptcpdetail->datalen > 0){
		ipv4_hdr = (const struct mesa_ip4_hdr *)a_packet;
		tcp_hdr = (const struct mesa_tcp_hdr *)((char *)ipv4_hdr + ipv4_hdr->ip_hl * 4);
		pkt_raw_data = (char *)tcp_hdr + tcp_hdr->th_off * 4; /* ���ݰ�ԭʼ����ָ�� */
		/* �����ش�׷�����ݵ�ԭ��, ƽ̨�����������a_tcp->ptcpdetail->pdata����һ������pkt_raw_data, �������ƫ���� */
		actual_data_seq = ntohl(tcp_hdr->th_seq) + ((char *)a_tcp->ptcpdetail->pdata - pkt_raw_data);

		DPRINT("stream:%s, dir:%d, pkt-seq:%u, actual-data-seq:%u\n", printaddr(&a_tcp->addr, a_tcp->threadnum),a_tcp->curdir, ntohl(tcp_hdr->th_seq),  actual_data_seq);
		
		if(DIR_C2S == a_tcp->curdir){
			/* ����ʵ����� == ���ϴμ���ó�������Ӧ�õ������ + ���μ���ó��Ķ������� */
			if(actual_data_seq != tcp_status->seq_next_c2s + a_tcp->ptcpdetail->lostlen){
				DPRINT("\033[41mstream:%s,  seq check fail!\033[0m\n", printaddr(&a_tcp->addr, a_tcp->threadnum));
				//assert(0);
				goto err_exit;
			}
			/* ��һ���ڴ��������: ��ǰʵ����� + ʵ�����ݳ��� */
			tcp_status->seq_next_c2s = actual_data_seq + a_tcp->ptcpdetail->datalen;
		}else{
			if(actual_data_seq  != tcp_status->seq_next_s2c + a_tcp->ptcpdetail->lostlen){
				DPRINT("\033[41mstream:%s,  seq check fail!\033[0m\n", printaddr(&a_tcp->addr, a_tcp->threadnum));
				//assert(0);
				goto err_exit;
			}
			/* ��һ���ڴ��������: ��ǰʵ����� + ʵ�����ݳ��� */
			tcp_status->seq_next_s2c = actual_data_seq + a_tcp->ptcpdetail->datalen;
		}
	}
	
	if(a_tcp->opstate == OP_STATE_CLOSE){
		DPRINT("\033[32mstream %s check SUCC!\033[0m\n", printaddr(&a_tcp->addr, a_tcp->threadnum));
		free(*pme);
	}
	
	return APP_STATE_GIVEME;

err_exit:
	free(*pme);
	return APP_STATE_DROPME;
}

char TCP_ENTRY_ALL(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	return testtcpApp_allpkt(a_tcp,pme,thread_seq,a_packet);
	//return test_allpkt_stream(a_tcp,pme,thread_seq,a_packet);
}

typedef struct  {
	unsigned int magic;
	unsigned short version_major;
	unsigned short version_minor;
	unsigned int thiszone;	/* gmt to local correction */
	unsigned int sigfigs;	/* accuracy of timestamps */
	unsigned int snaplen;	/* max length saved portion of each pkt */
	unsigned int linktype;	/* data link type (LINKTYPE_*) */
}pcap_file_hdr_t;

typedef struct {
	unsigned int tv_sec;	/* time stamp */
	unsigned int tv_usec;	/* time stamp */
	unsigned int caplen;	/* length of portion present */
	unsigned int len;	/* length this packet (off wire) */
}pcap_pkt_hdr_t;

static const pcap_file_hdr_t test_pcap_file_hdr = 
{
	0xA1B2C3D4,
	0x0002, 
	0x0004,
	0,
	0,
	0xFFFF,
	1
};

static unsigned char test_pcap_phony_mac_hdr[14] = 
{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	0x12, 0x23, 0x34, 0x56, 0x67, 0x78,
	0x08, 0x00
};

char TCP_ALL_DUMP_PCAP_PKT(struct streaminfo *pstream,  void **pme, int thread_seq,void *a_packet)
{
	FILE *fp;
	pcap_pkt_hdr_t pcap_pkt_hdr;
	struct mesa_ip4_hdr *ip4hdr = (struct mesa_ip4_hdr *)a_packet;
	
	if(OP_STATE_PENDING == pstream->pktstate){
		char tmp_file[32];
		DSNPRINT(tmp_file, 32, "%p.pcap", pstream);
		fp = fopen(tmp_file, "a+");
		if(NULL == fp){
			DPRINT("fopen ./%p.pcap error!\n", tmp_file);
			return APP_STATE_DROPME;
		}
		fwrite(&test_pcap_file_hdr, sizeof(pcap_file_hdr_t), 1, fp);
		*pme = fp;
	}else if(OP_STATE_CLOSE == pstream->pktstate){
		fclose((FILE *)(*pme));
		return APP_STATE_DROPME;
	}

	fp = (FILE *)(*pme);

	if(a_packet){
		pcap_pkt_hdr.caplen = ntohs(ip4hdr->ip_len) + 14;
		pcap_pkt_hdr.len = ntohs(ip4hdr->ip_len) + 14;
		fwrite(&pcap_pkt_hdr, sizeof(pcap_pkt_hdr_t), 1, fp);
		fwrite(test_pcap_phony_mac_hdr, 14, 1, fp);
		fwrite(a_packet, ntohs(ip4hdr->ip_len), 1, fp);
		fflush(fp);
	}

	return APP_STATE_GIVEME;
}
char IPV4_PKT_DUMP( struct streaminfo *f_stream,unsigned char routedir,int thread_seq,struct ip * a_packet)
{
	FILE *fp;
	int iphl = a_packet->ip_hl*4;
	int payload_len = ntohs(a_packet->ip_len) - iphl;

	fp = fopen("ipv4_dump.pcap", "w+");

	fwrite((char *)a_packet + iphl, payload_len, 1, fp);


	fclose(fp);

	return APP_STATE_GIVEME;
}

char IPV6_PKT_DUMP( struct streaminfo *f_stream,unsigned char routedir,int thread_seq,struct mesa_ip6_hdr* a_packet)
{
	FILE *fp;
	int iphl = sizeof(struct mesa_ip6_hdr);
	int payload_len = ntohs(a_packet->ip6_payload_len);

	fp = fopen("ipv6_dump.pcap", "w+");

	fwrite((char *)a_packet + iphl, payload_len, 1, fp);

	fclose(fp);

	return APP_STATE_GIVEME;
}

char KILL_STREAM_FEEDBACK(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	char pkt_buf[1500];
	int pkt_len = 1500;
	int ret;
	FILE *fp;
	pcap_file_hdr_t pfile_hdr;
	pcap_pkt_hdr_t pkt_hdr;

	if((80 != ntohs(a_tcp->addr.ipv4->source)) && (80 != ntohs(a_tcp->addr.ipv4->dest))){
		return APP_STATE_GIVEME;
	}

	if(a_packet != NULL){	
		ret = MESA_kill_tcp_feedback(a_tcp, a_packet, pkt_buf, &pkt_len);
		if(1500 == pkt_len){
			DPRINT("MESA_kill_tcp_feedback error!\n");
		}else{
			memset(&pfile_hdr, 0, sizeof(pfile_hdr));
			memset(&pkt_hdr, 0, sizeof(pkt_hdr));
			pfile_hdr.magic = 0xA1B2C3D4;
			pfile_hdr.version_major = 2;
			pfile_hdr.version_minor = 4;
			pfile_hdr.linktype = 1;
			pfile_hdr.snaplen = 65535;

			pkt_hdr.caplen = pkt_len;
			pkt_hdr.len = pkt_len;

			fp = fopen("feedback.pcap", "w+");
			fwrite(&pfile_hdr, sizeof(pcap_file_hdr_t), 1, fp);
			fwrite(&pkt_hdr, sizeof(pcap_pkt_hdr_t), 1, fp);
			fwrite(pkt_buf, pkt_len, 1, fp);
			fclose(fp);
		}
	}
	return APP_STATE_GIVEME;
}


char KILL_STREAM_SYNACK(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	MESA_kill_tcp_synack(a_tcp, a_packet);
	return APP_STATE_GIVEME;
}

char SLEEP_ENTRY(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	sleep(1);
	return APP_STATE_GIVEME;
}

char KILL_STREAM(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	if(OP_STATE_CLOSE != a_tcp->opstate){
		MESA_kill_connection(a_tcp, a_packet);
	}
	return APP_STATE_GIVEME | APP_STATE_DROPPKT;
}

char KILL_STREAM_ONLY_DOU(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	if(DIR_DOUBLE == a_tcp->dir){
		MESA_kill_tcp(a_tcp, a_packet);
	}
	return APP_STATE_GIVEME | APP_STATE_DROPPKT;
}

char RST_STREAM_C2S(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	struct rst_tcp_para rst_args = {};
	
	rst_args.th_flags = TH_RST;
	rst_args.rst_pkt_num = 1;
	rst_args.dir = DIR_C2S;
	rst_args.signature_seed1 = 65535;
	rst_args.signature_seed2 = 13;
	
	MESA_rst_tcp(a_tcp, &rst_args, sizeof(struct rst_tcp_para));


	return APP_STATE_GIVEME;

}

char RST_STREAM_S2C(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	struct rst_tcp_para rst_args = {};
	
	rst_args.th_flags = TH_RST;
	rst_args.rst_pkt_num = 1;
	rst_args.dir = DIR_S2C;
	rst_args.signature_seed1 = 65535;
	rst_args.signature_seed2 = 31;
	
	MESA_rst_tcp(a_tcp, &rst_args, sizeof(struct rst_tcp_para));


	return APP_STATE_GIVEME;

}


char RST_STREAM(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	unsigned short sport_host;

	if((OP_STATE_CLOSE != a_tcp->opstate) && (DIR_DOUBLE == a_tcp->dir)){
		sport_host = ntohs(a_tcp->addr.tuple4_v4->source);
		
		if((sport_host >= 10000) && (sport_host <= 19999)){
			if(DIR_C2S == a_tcp->curdir){
				RST_STREAM_C2S(a_tcp, pme, thread_seq, a_packet);  /* C2Sԭʼ������C2Sע��RST */
				DPRINT("inject C2S rst by raw C2S pkt\n");
			}
		}else if((sport_host >= 20000) && (sport_host <= 29999)){
			if(DIR_C2S == a_tcp->curdir){
				RST_STREAM_S2C(a_tcp, pme, thread_seq, a_packet);  /* C2Sԭʼ������S2Cע��RST */
				DPRINT("inject S2C rst by raw C2S pkt\n");
			}
		}else if((sport_host >= 30000) && (sport_host <= 39999)){
			if(DIR_S2C == a_tcp->curdir){
				RST_STREAM_C2S(a_tcp, pme, thread_seq, a_packet);  /* S2Cԭʼ������C2Sע��RST */
				DPRINT("inject C2S rst by raw S2C pkt\n");
			}
		}else if((sport_host >= 40000) && (sport_host <= 49999)){
			if(DIR_S2C == a_tcp->curdir){
				RST_STREAM_S2C(a_tcp, pme, thread_seq, a_packet);  /* S2Cԭʼ������S2Cע��RST */
				DPRINT("inject S2C rst by raw S2C pkt\n");
			}
		}else{
			return APP_STATE_DROPME;
		}
	}
	
	return APP_STATE_GIVEME;
}


char INJECT_STREAM(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	unsigned short sport_host;
	const char *inject_C2S_by_C2S = "sapp inject_C2S_by_C2S payload......";
	const char *inject_S2C_by_C2S = "sapp inject_S2C_by_C2S payload......";
	const char *inject_C2S_by_S2C = "sapp inject_C2S_by_S2C payload......";
	const char *inject_S2C_by_S2C = "sapp inject_S2C_by_S2C payload......";

	//if((OP_STATE_CLOSE != a_tcp->opstate) && (DIR_DOUBLE == a_tcp->dir)){
	if((OP_STATE_CLOSE != a_tcp->opstate)){
		sport_host = ntohs(a_tcp->addr.tuple4_v4->source);

        if (a_tcp->routedir == DIR_ROUTE_UP)
        {
            sapp_inject_pkt(a_tcp, SIO_DEFAULT, inject_S2C_by_C2S, strlen(inject_S2C_by_C2S), a_tcp->routedir ^ 1);
            DPRINT("Get Outbound pkt:%s, CurDir:%d, inject to S2C by raw C2S pkt, raw payload len:%d\n", printaddr(&a_tcp->addr, thread_seq), a_tcp->curdir, a_tcp->ptcpdetail->datalen);
        }
        else
        {
            sapp_inject_pkt(a_tcp, SIO_DEFAULT, inject_S2C_by_S2C, strlen(inject_S2C_by_S2C), a_tcp->routedir);
            DPRINT("Get Inbound pkt:%s, CurDir:%d, inject S2C pkt by raw S2C pkt, raw payload len:%d\n", printaddr(&a_tcp->addr, thread_seq), a_tcp->curdir, a_tcp->ptcpdetail->datalen);
        }
#if 0		
		if((sport_host >= 10000) && (sport_host <= 19999)){
			if(DIR_C2S == a_tcp->curdir){
				sapp_inject_pkt(a_tcp, SIO_DEFAULT, inject_C2S_by_C2S, strlen(inject_C2S_by_C2S), a_tcp->routedir);  /* C2Sԭʼ������C2Sע�� */
				DPRINT("inject C2S pkt by raw C2S pkt\n");
			}
		}else if((sport_host >= 20000) && (sport_host <= 29999)){
			if(DIR_C2S == a_tcp->curdir){
				sapp_inject_pkt(a_tcp, SIO_DEFAULT, inject_S2C_by_C2S, strlen(inject_S2C_by_C2S), a_tcp->routedir ^ 1);  /* C2Sԭʼ������S2Cע�� */
				DPRINT("inject S2C pkt by raw C2S pkt\n");
			}
		}else if((sport_host >= 30000) && (sport_host <= 39999)){
			if(DIR_S2C == a_tcp->curdir){
				sapp_inject_pkt(a_tcp, SIO_DEFAULT, inject_C2S_by_S2C, strlen(inject_C2S_by_S2C), a_tcp->routedir ^ 1);  /* S2Cԭʼ������C2Sע�� */
				DPRINT("inject C2S pkt by raw S2C pkt\n");
			}
		}else if((sport_host >= 40000) && (sport_host <= 49999)){
			if(DIR_S2C == a_tcp->curdir){
				sapp_inject_pkt(a_tcp, SIO_DEFAULT, inject_S2C_by_S2C, strlen(inject_S2C_by_S2C), a_tcp->routedir);  /* S2Cԭʼ������S2Cע�� */
				DPRINT("inject S2C pkt by raw S2C pkt\n");
			}
		}else{
			return APP_STATE_DROPME;
		}
#endif
	}

	return APP_STATE_GIVEME;
}


char TEST_STREAM(struct streaminfo *stream,  void **pme, int thread_seq, const void *a_packet)
{
	char *data = NULL;
	int i, datalen = -1, ret;
	char local_data[65535];
	long result1[65535], result2[65535];
	double nouse_sum = 0.0;

	if(NULL == a_packet){
		return APP_STATE_DROPME;
	}

	int min_num = MIN(65535, g_test_app_val.ivalue1+1); //�������ļ���ȡ

	for(i = 0; i < min_num; i++){
		local_data[i] = rand();
	}
	
	ret = get_rawpkt_opt_from_streaminfo(stream, RAW_PKT_GET_DATA, &data);
	if(ret < 0 || NULL == data){
		return APP_STATE_GIVEME;
	}
	
	ret = get_rawpkt_opt_from_streaminfo(stream, RAW_PKT_GET_TOT_LEN, &datalen);
	if(ret < 0 ){
		return APP_STATE_GIVEME;
	}

	/* ���д�㶫��, �ķ�CPU */
	if(datalen > 0){
		for(i = 0; i < datalen; i++){
			result1[i] = (long)memchr(local_data, data[i], min_num);
			result2[i] = (long long )memmem((void *)local_data, min_num, (void *)&data[i], datalen-i);
			nouse_sum += (double)result1[i] * result2[i];
		}
	}

	return APP_STATE_GIVEME;
}

char KEEP_STREAM(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	return APP_STATE_GIVEME;
}

char DROP_STREAM_PKT(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	return APP_STATE_DROPPKT;
}


char TCP_ENTRY(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	//test_project_add(a_tcp,pme,thread_seq,a_packet);
	
	testtcpApp_2(a_tcp,pme,thread_seq,a_packet);

	//test_project_read_ipv4_frag_list(a_tcp,pme,thread_seq,a_packet);

	return APP_STATE_GIVEME;
}

char IP_FRAG_ENTRY( struct streaminfo *stream,unsigned char routedir,int thread_seq,struct ip * a_packet)
{
	static int call_times = 0;
	
	DPRINT("ip_frag_entry, times:%d\n", ++call_times);

	if(PKT_TYPE_IP_FRAG_LAST & stream->addr.pktipfragtype){
		DPRINT("recv last ip frag pkt!\n");
		return APP_STATE_GIVEME | APP_STATE_DROPPKT;
	}
	
	return APP_STATE_GIVEME;
}


enum anti_flood_stat_type{
	ANTI_FLOOD_TCP_SYN = 0, 
	ANTI_FLOOD_UDP_DNS,
	ANTI_FLOOD_UDP_NTP,
	ANTI_FLOOD_IP_FRAG,
};
static unsigned long long anti_flood_stat[MAX_THREAD_NUM][8];
static time_t last_log_time;
//extern int g_packet_io_thread_num;
//extern time_t g_CurrentTime;
static void anti_flood_stat_log(void)
{
	FILE *fp;
	int tseq;
	int tot_thread_count;
	int opt_len = sizeof(int);

	sapp_get_platform_opt(SPO_THREAD_COUNT, &tot_thread_count, &opt_len);

	unsigned long long tmp_anti_flood_stat[8];
	memset(tmp_anti_flood_stat, 0, sizeof(tmp_anti_flood_stat));
	
	for(tseq =0; tseq < tot_thread_count; tseq++){
		tmp_anti_flood_stat[ANTI_FLOOD_TCP_SYN] += anti_flood_stat[tseq][ANTI_FLOOD_TCP_SYN];
		tmp_anti_flood_stat[ANTI_FLOOD_UDP_DNS] += anti_flood_stat[tseq][ANTI_FLOOD_UDP_DNS];
		tmp_anti_flood_stat[ANTI_FLOOD_UDP_NTP] += anti_flood_stat[tseq][ANTI_FLOOD_UDP_NTP];
		tmp_anti_flood_stat[ANTI_FLOOD_IP_FRAG] += anti_flood_stat[tseq][ANTI_FLOOD_IP_FRAG];
	}

	fp = fopen("./log/anti_flood_stat.log", "w+");

	DFPRINT(fp, "tcp_syn\t %llu\n", tmp_anti_flood_stat[ANTI_FLOOD_TCP_SYN]);
	DFPRINT(fp, "udp_dns\t %llu\n", tmp_anti_flood_stat[ANTI_FLOOD_UDP_DNS]);
	DFPRINT(fp, "udp_ntp\t %llu\n", tmp_anti_flood_stat[ANTI_FLOOD_UDP_NTP]);
	DFPRINT(fp, "ip_frag\t %llu\n", tmp_anti_flood_stat[ANTI_FLOOD_IP_FRAG]);

	fclose(fp);
}

char ANTI_FLOOD_STAT_IP_FRAG_ENTRY( struct streaminfo *f_stream,unsigned char routedir,int thread_seq,struct ip * a_packet)
{
	anti_flood_stat[thread_seq][ANTI_FLOOD_IP_FRAG]++;
	return APP_STATE_GIVEME;
}

char ANTI_FLOOD_STAT_IP_ENTRY( struct streaminfo *f_stream,unsigned char routedir,int thread_seq,struct ip * a_packet)
{
	const struct mesa_ip4_hdr *ip4hdr = (struct mesa_ip4_hdr *)a_packet;
	const struct mesa_tcp_hdr *tcphdr;
	const struct mesa_udp_hdr *udphdr;

	time_t cur_time;
	int opt_len = sizeof(cur_time);

	sapp_get_platform_opt(SPO_CURTIME_TIMET, &cur_time, &opt_len);

	if(IPPROTO_TCP == ip4hdr->ip_p){
		tcphdr = (const struct mesa_tcp_hdr *)((char *)a_packet + ip4hdr->ip_hl*4);
		if(TH_SYN == tcphdr->th_flags){ 
			anti_flood_stat[thread_seq][ANTI_FLOOD_TCP_SYN]++;
		}
	}else if(IPPROTO_UDP == ip4hdr->ip_p){
		udphdr = (const struct mesa_udp_hdr *)((char *)a_packet + ip4hdr->ip_hl*4);
		if(53 == ntohs(udphdr->uh_sport) || 53 == ntohs(udphdr->uh_dport)){
			anti_flood_stat[thread_seq][ANTI_FLOOD_UDP_DNS]++;
		}else if(123 == ntohs(udphdr->uh_sport) || 123 == ntohs(udphdr->uh_dport)){
			anti_flood_stat[thread_seq][ANTI_FLOOD_UDP_NTP]++;
		}
	}

	if(0 == thread_seq){
		if(cur_time > last_log_time){
			last_log_time = cur_time;
			anti_flood_stat_log();
		}	
	}

	return  APP_STATE_GIVEME;
}

char IP_ENTRY( struct streaminfo *f_stream,unsigned char routedir,int thread_seq,struct ip * a_packet)
{
	return testIPApp_1(f_stream,routedir,thread_seq,a_packet);
}

char IPv6_ENTRY(const struct streaminfo *pstream,unsigned char routedir,int thread_seq,const void *ipv6_hdr)
{
	char ips[128], ipd[128];
	const struct mesa_ip6_hdr *ip6h = (const struct mesa_ip6_hdr *)ipv6_hdr;
	
	inet_ntop(AF_INET6, &ip6h->ip6_src, ips, 128);
	inet_ntop(AF_INET6, &ip6h->ip6_dst, ipd, 128);
	DPRINT("recv ip6 pkt, %s --> %s, protocol:%u, routedir:%d\n", ips, ipd, ip6h->ip6_nxt_hdr, routedir);

	return APP_STATE_GIVEME;
}

char IPv6_RAW_ENTRY(const struct streaminfo *pstream, const void *this_hdr, const void *raw_pkt)
{
	DPRINT("into IPv6_RAW_ENTRY()!\n");
	return APP_STATE_GIVEME;
}

#endif

static volatile int _g_enable_keepalive;
static void *gdev_keepalive_control_thread(void *arg)
{
	SAPP_TLV_T option;
	int ret;
	
	while(1){
		if((time(NULL) % 10) <= 5){
			_g_enable_keepalive = 0;
			DPRINT("gdev_keepalive_set_opt() disable keepalive.....\n");
		}else{
			_g_enable_keepalive = 1;
			DPRINT("gdev_keepalive_set_opt() enable  keepalive.....\n");
		}

		option.type = GDEV_KEEPALIVE_OPT_GLOBAL_SWITCH;
		option.length = sizeof(int);
		option.int_value = _g_enable_keepalive;

		ret = gdev_keepalive_set_opt(&option);
		if(ret < 0){
			DPRINT("gdev_keepalive_set_opt() -> GDEV_KEEPALIVE_OPT_GLOBAL_SWITCH error!\n");
		}
	
		sleep(1);
	}
	return NULL;
}

char gdev_keepalive_control_entry(struct streaminfo *pstream,unsigned char routedir, int thread_seq,void *a_packet)
{
	
	static volatile int __thread_created = 0;

	if(0 == __thread_created){
		pthread_t pid;
		pthread_create(&pid, NULL, gdev_keepalive_control_thread, NULL);
		__thread_created = 1;
	}

	return APP_STATE_GIVEME;
}


char arp_plug_entry(const struct streaminfo *pstream,unsigned char routedir,int thread_seq,  const void *arp_hdr)
{
	const struct mesa_arp_hdr *aph = (struct mesa_arp_hdr *)arp_hdr;
	char ip4_str[32];

	inet_ntop(AF_INET, aph->ar_spa, ip4_str, 32);

	DPRINT("rev arp response: ip:%s--->mac:%02x-%02x-%02x-%02x-%02x-%02x \n", ip4_str, 
				aph->ar_sha[0],aph->ar_sha[1],aph->ar_sha[2],aph->ar_sha[3],aph->ar_sha[4],aph->ar_sha[5]);
	return APP_STATE_GIVEME;	
}


char POLLING_ENTRY(struct streaminfo *stream,  void **pme, int thread_seq,void *a_packet)
{
	DPRINT("polling entry, tid:%d\n", thread_seq);
	return APP_STATE_GIVEME;	
}

extern long long sapp_random(void);
char fake_deadlock(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
	/* ����������߳�, ģ������ */
	int opt_val_len = sizeof(int);
	int tid;
	int tot_thread_cnt;
	sapp_get_platform_opt(SPO_THREAD_COUNT, &tot_thread_cnt, &opt_val_len);

	tid = sapp_random() % tot_thread_cnt;

	if(tid == pstream->threadnum){
		DPRINT("thread:%d, fake deadlock!\n", tid);
		while(1){pause();}
	}

	return APP_STATE_GIVEME;	
}


void CHAR_CONFIG_INIT(void)
{
	int ret;
	ret = MESA_load_profile_int_def(g_test_app_cfg_file, "main", "int_value1", &g_test_app_val.ivalue1, 0);
	if(ret < 0){
		DPRINT("test_app plug: get config %s error, use default value:%d\n", "int_value1", 0);
	}else{
		DPRINT("test_app plug: get config %s succ, value:%d\n", "int_value1", g_test_app_val.ivalue1);
	}
	
	MESA_load_profile_int_def(g_test_app_cfg_file, "main", "int_value2", &g_test_app_val.ivalue2, 0);
	if(ret < 0){
		DPRINT("test_app plug: get config %s error, use default value:%d\n", "int_value2", 0);
	}else{
		DPRINT("test_app plug: get config %s succ, value:%d\n", "int_value2", g_test_app_val.ivalue2);
	}

	MESA_load_profile_string_def(g_test_app_cfg_file, "main", "string_value1", g_test_app_val.str_value1, sizeof(g_test_app_val.str_value1), "null");
	if(ret < 0){
		DPRINT("test_app plug: get config %s error, use default value:%s\n", "string_value1", "null");
	}else{
		DPRINT("test_app plug: get config %s succ, value:%s\n", "string_value1", g_test_app_val.str_value1);
	}	
	MESA_load_profile_string_def(g_test_app_cfg_file, "main", "string_value2", g_test_app_val.str_value2, sizeof(g_test_app_val.str_value1), "");
	if(ret < 0){
		DPRINT("test_app plug: get config %s error, use default value:%s\n", "string_value2", "null");
	}else{
		DPRINT("test_app plug: get config %s succ, value:%s\n", "string_value2", g_test_app_val.str_value2);
	}		
}


static void __fake_project_free_cb(int thread_seq, void *project_req_value)
{
	;
}

static void *test_app_thread(void *arg)
{
	while(1){
		if((time(NULL) % 10) == 0){
			DPRINT("test thread: call libsapp_destroy_env()....\n");
			libsapp_destroy_env();	
			DPRINT("test thread: libsapp_destroy_env() done!\n");
			exit(0);		
		}

		sleep(1);
	}

	return NULL;
}

int CHAR_INIT()
{
	int i;
	CHAR_CONFIG_INIT();

	/* �������ڳ�ʼ��ʱ����ע��project */
	g_test_app_val.test_project_id =  project_producer_register("test_project", "struct", __fake_project_free_cb);
	if(g_test_app_val.test_project_id < 0){
		DPRINT("##### project_producer_register error!\n");
		return -1;	
	}
	g_test_app_val.test_bridge_id = stream_bridge_build("test_bridge", "w");
	if(g_test_app_val.test_bridge_id < 0){
		DPRINT("##### stream_bridge_build error!\n");
		return -1;	
	}
	stream_bridge_register_data_free_cb(g_test_app_val.test_bridge_id, __stream_bridge_free_cb);

	
	if((g_test_app_val.ivalue1 > 0) 
	 && (strncasecmp("test sapp destroy", g_test_app_val.str_value1, strlen("test sapp destroy")) == 0)){
		DPRINT("\033[1;31;40m Warning: etc/test_app.conf : enable 'test sapp destroy', maybe exit after N seconds....\033[0m\n ");
		pthread_t pid;

		for( i = 0; i < g_test_app_val.ivalue1; i++){
			pthread_create(&pid, NULL, test_app_thread, NULL);
			pthread_detach(pid);
		}
	}

	return 1;
}

void CHAR_DESTROY(void)
{

}

void test_funstat(unsigned long long protflag)
{
	;
}

long long test_flag_change(char* flag_str)
{
	return 0xFFFF;
}

void test_get_plugid(unsigned short plugid)
{
	return;
}


void test_destroy(void)
{
	;
}

#ifdef __cplusplus
}
#endif


