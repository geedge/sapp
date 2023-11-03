#include "sapp_api.h"
#include "sapp_private_api.h"
#include "sapp_declaration.h"
#include "stream_register.h"

#include "plugin_serial.h"

#ifdef __cplusplus
extern "C" {
#endif
#define CALL_FUN_TYPE_RAW		1
#define CALL_FUN_TYPE_NORAW	2	

extern stBusinessPlugInfo* g_business_plug_info;
extern int g_business_plug_type;
extern stPlugRuntimeInfo plugctrl_runtime_info;

extern void plug_record_start_time(int plug_id, int thread_seq);
extern void plug_record_end_time(int plug_id, int thread_seq);

static int g_StreamTcpFunNum=0;
static stFunArray g_StreamTcpFun[MAX_FUN_NUM];

static int g_StreamTcpAllFunNum=0;
static stFunArray g_StreamTcpAllFun[MAX_FUN_NUM];

static char (*g_StreamTcpTakeover)(const struct streaminfo *pstream,void **pme, int thread_seq, const void *raw_pkt)=NULL;

static int g_StreamUdpFunNum=0;
static stFunArray g_StreamUdpFun[MAX_FUN_NUM];

static int g_Ipv4FunNum=0;
static stFunArray g_Ipv4Fun[MAX_FUN_NUM];

static int g_Ipv6FunNum=0;
static stFunArray g_Ipv6Fun[MAX_FUN_NUM];

static int g_Ipv4FragFunNum=0;
static stFunArray g_Ipv4FragFun[MAX_FUN_NUM];

static int g_Ipv6FragFunNum=0;
static stFunArray g_Ipv6FragFun[MAX_FUN_NUM];

/* 2016-09-01 lijia add, phony plug entry, will not be called in fact. */
static int g_PhonyFunNum=0;
static stFunArray g_PhonyFun[MAX_FUN_NUM];

int g_PollingFunNum=0;
static stFunArray g_PollingFun[MAX_FUN_NUM];

static int g_ArpFunNum=0;
static stFunArray g_ArpFun[MAX_FUN_NUM];

static int g_OverlayIpv4FunNum=0;
static stFunArray g_OverlayIpv4Fun[MAX_FUN_NUM];


static int g_OverlayUdpFunNum=0;
static stFunArray g_OverlayUdpFun[MAX_FUN_NUM];


static inline int is_raw_cb(enum fun_type_t cb_type);

extern int G_TCP_FLOW_STAT_PROJECT_ID;

#ifdef IIEFD_DUAL_STACK
static int judge_pure_ipv4_stack(const struct streaminfo *pstream, const void *a_packet);
/* iiefd代码中的总回调函数, 只有纯IPv4的包才处理 */
extern "C" char calltcpApp_old(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet);
extern "C" char callIpApp_old(struct streaminfo *pstream,int routedir, int thread_seq,void *a_packet);
#endif

extern void timestamp_record(enum timestamp_level level, const raw_pkt_t *raw_pkt, int thread_seq);

/* 2014-12-31 lqy add 
	TODO, 这些内置插件没有destroy接口.
*/
int stream_register_funtoArray(enum fun_type_t funtype,char (*x)(void),stFunArray *pArrary,int *pNum, int plug_entry_id)
{
	if(*pNum>=MAX_FUN_NUM)
	{
		sapp_runtime_log(30, "too many funcitons of type:%d, max number is %d\n", funtype, MAX_FUN_NUM);

		return -1;
	}	
	
	pArrary[(*pNum)].funtype=funtype;
	pArrary[(*pNum)].pfun=x;
	pArrary[(*pNum)].entry_id = plug_entry_id;
	(*pNum)++;
	return 0;
}

int stream_register_fun(enum fun_type_t funtype,char (*x)(void), int plug_entry_id)
{
	int ret=0;
	switch(funtype)
	{
		case FUN_TYPE_IPV4:
			ret=stream_register_funtoArray(FUN_TYPE_IPV4,x,g_Ipv4Fun,&g_Ipv4FunNum, plug_entry_id);
			break;
		case FUN_TYPE_IPV4_FRAG:
			ret=stream_register_funtoArray(FUN_TYPE_IPV4_FRAG,x,g_Ipv4FragFun,&g_Ipv4FragFunNum, plug_entry_id);
			break;	
		case FUN_TYPE_IPV6_FRAG:
			ret=stream_register_funtoArray(FUN_TYPE_IPV6_FRAG,x,g_Ipv6FragFun,&g_Ipv6FragFunNum, plug_entry_id);
			break;				
		case FUN_TYPE_IPV6:
			ret=stream_register_funtoArray(FUN_TYPE_IPV6,x,g_Ipv6Fun,&g_Ipv6FunNum, plug_entry_id);
			break;
		case FUN_TYPE_TCP:
			ret=stream_register_funtoArray(FUN_TYPE_TCP,x,g_StreamTcpFun,&g_StreamTcpFunNum, plug_entry_id);
			break;
		case FUN_TYPE_TCPALL:
			ret=stream_register_funtoArray(FUN_TYPE_TCPALL,x,g_StreamTcpAllFun,&g_StreamTcpAllFunNum, plug_entry_id);
			break;
		case FUN_TYPE_UDP:
			ret=stream_register_funtoArray(FUN_TYPE_UDP,x,g_StreamUdpFun,&g_StreamUdpFunNum, plug_entry_id);
			break;
		case FUN_TYPE_IPV4_RAW:
			ret=stream_register_funtoArray(FUN_TYPE_IPV4_RAW,x,g_Ipv4Fun,&g_Ipv4FunNum, plug_entry_id);
			break;
		case FUN_TYPE_IPV4_FRAG_RAW:
			ret=stream_register_funtoArray(FUN_TYPE_IPV4_FRAG_RAW,x,g_Ipv4FragFun,&g_Ipv4FragFunNum, plug_entry_id);
			break;			
		case FUN_TYPE_IPV6_RAW:
			ret=stream_register_funtoArray(FUN_TYPE_IPV6_RAW,x,g_Ipv6Fun,&g_Ipv6FunNum, plug_entry_id);
			break;
		case FUN_TYPE_IPV6_FRAG_RAW:
			ret=stream_register_funtoArray(FUN_TYPE_IPV6_FRAG_RAW,x,g_Ipv6FragFun,&g_Ipv6FragFunNum, plug_entry_id);
			break;			
		case FUN_TYPE_TCP_RAW:
			ret=stream_register_funtoArray(FUN_TYPE_TCP_RAW,x,g_StreamTcpFun,&g_StreamTcpFunNum, plug_entry_id);
			break;

		case FUN_TYPE_TCPALL_RAW:
			ret=stream_register_funtoArray(FUN_TYPE_TCPALL_RAW,x,g_StreamTcpAllFun,&g_StreamTcpAllFunNum, plug_entry_id);
			break;

		case FUN_TYPE_UDP_RAW:
			ret=stream_register_funtoArray(FUN_TYPE_UDP_RAW,x,g_StreamUdpFun,&g_StreamUdpFunNum, plug_entry_id);
			break;	

		case FUN_TYPE_PHONY:
			g_PhonyFunNum = 0;
			g_PhonyFun[0].pfun = NULL;
			ret = 0; /* phony entry, do nothing! */
			break;

		case FUN_TYPE_POLLING:
			ret=stream_register_funtoArray(FUN_TYPE_POLLING, x, g_PollingFun,&g_PollingFunNum, plug_entry_id);
			break;
			
		default:
			ret=-1;
	}

	return ret;
}

int stream_register_ip (IPv4_CB_FUN_T x)
{
	//to do, call plug_mange_get_entry_id() 
	return stream_register_funtoArray(FUN_TYPE_IPV4,(char (*)())x,g_Ipv4Fun,&g_Ipv4FunNum,0);
}

int stream_register_ip_frag (IPv4_CB_FUN_T x)
{
	//to do, call plug_mange_get_entry_id() 
	return stream_register_funtoArray(FUN_TYPE_IPV4_FRAG,(char (*)())x,g_Ipv4FragFun,&g_Ipv4FragFunNum,0);
}

int stream_register_ip_raw (SAPP_PKT_CB_FUN_T  x)
{
	//to do, call plug_mange_get_entry_id() 
	return stream_register_funtoArray(FUN_TYPE_IPV4_RAW,(char (*)())x,g_Ipv4Fun,&g_Ipv4FunNum,0);
}

int stream_register_ipv4_frag_raw (SAPP_PKT_CB_FUN_T x)
{
	//to do, call plug_mange_get_entry_id() 
	return stream_register_funtoArray(FUN_TYPE_IPV4_FRAG_RAW,(char (*)())x,g_Ipv4FragFun,&g_Ipv4FragFunNum,0);
}

int stream_register_ipv6 (IPv6_CB_FUN_T x)
{
	//to do, call plug_mange_get_entry_id() 
	return stream_register_funtoArray(FUN_TYPE_IPV6,(char (*)())x,g_Ipv6Fun,&g_Ipv6FunNum, 0);
}

int stream_register_ipv6_frag(IPv4_CB_FUN_T x)
{
	//to do, call plug_mange_get_entry_id() 
	return stream_register_funtoArray(FUN_TYPE_IPV6_FRAG,(char (*)())x,g_Ipv6FragFun,&g_Ipv6FragFunNum,0);
}

int stream_register_ipv6_raw (SAPP_PKT_CB_FUN_T x)
{
	//to do, call plug_mange_get_entry_id() 
	return stream_register_funtoArray(FUN_TYPE_IPV6_RAW,(char (*)())x,g_Ipv6Fun,&g_Ipv6FunNum, 0);
}

int stream_register_ipv6_frag_raw (IPv4_CB_FUN_T x)
{
	//to do, call plug_mange_get_entry_id() 
	return stream_register_funtoArray(FUN_TYPE_IPV6_FRAG_RAW,(char (*)())x,g_Ipv6FragFun,&g_Ipv6FragFunNum,0);
}

int stream_register_tcp (STREAM_CB_FUN_T x)
{
	//to do, call plug_mange_get_entry_id() 
	return stream_register_funtoArray(FUN_TYPE_TCP,(char (*)())x,g_StreamTcpFun,&g_StreamTcpFunNum, 0);
}


int stream_register_tcp_allpkt (STREAM_CB_FUN_T x)
{
	//to do, call plug_mange_get_entry_id() 
	return stream_register_funtoArray(FUN_TYPE_TCPALL,(char (*)())x,g_StreamTcpAllFun,&g_StreamTcpAllFunNum, 0);

}
int stream_register_udp (STREAM_CB_FUN_T x)
{
	//to do, call plug_mange_get_entry_id() 
	return stream_register_funtoArray(FUN_TYPE_UDP,(char (*)())x,g_StreamUdpFun,&g_StreamUdpFunNum, 0);
}


int stream_register_tcp_raw(SAPP_STREAM_FUN_T x)
{
	//to do, call plug_mange_get_entry_id() 
	return stream_register_funtoArray(FUN_TYPE_TCP_RAW,(char (*)())x,g_StreamTcpFun,&g_StreamTcpFunNum, 0);
}

int stream_register_tcp_allpkt_raw(SAPP_STREAM_FUN_T x)
{
	//to do, call plug_mange_get_entry_id() 
	return stream_register_funtoArray(FUN_TYPE_TCPALL_RAW,(char (*)())x,g_StreamTcpAllFun,&g_StreamTcpAllFunNum, 0);

}
int stream_register_udp_raw(SAPP_STREAM_FUN_T x)
{
	//to do, call plug_mange_get_entry_id() 
	return stream_register_funtoArray(FUN_TYPE_UDP_RAW,(char (*)())x,g_StreamUdpFun,&g_StreamUdpFunNum, 0);
}


int stream_register_tcp_takeover (STREAM_CB_FUN_T x)
{
	if(g_StreamTcpTakeover!=NULL)
	{
		sapp_runtime_log(30, "only support one take over function!\n");
		return -1;
	}
	g_StreamTcpTakeover=x;
	return 0;
}

int stream_register_arp(SAPP_PKT_CB_FUN_T x)
{
	//to do, call plug_mange_get_entry_id() 
	return stream_register_funtoArray(FUN_TYPE_ARP,(char (*)())x, g_ArpFun, &g_ArpFunNum, 0);
}

int stream_register_overlay_ip(IPv4_CB_FUN_T x)
{
	//to do, call plug_mange_get_entry_id() 
	return stream_register_funtoArray(FUN_TYPE_IPV4,(char (*)())x,g_OverlayIpv4Fun,&g_OverlayIpv4FunNum, 0);
}

int stream_register_overlay_udp(STREAM_CB_FUN_T x)
{
	//to do, call plug_mange_get_entry_id() 
	return stream_register_funtoArray(FUN_TYPE_UDP,(char (*)())x,g_OverlayUdpFun,&g_OverlayUdpFunNum, 0);
}

extern const char *sapp_rawpkt_ntop(const raw_pkt_t *raw_pkt, int greedy_inner_layer, char *out_buf, int buf_len);
/*
	lijia 2015-01-12 add this_iphdr, 
	如果是IP分片重组的包, 必须显式的传递IP包头, 否则只传raw_hdr, 无法获取重组后的IP包头.
*/
char plugin_call_streamentry(int type,StreamFunInfo *pFunInfo,struct streaminfo *a_stream,const void *transport_hdr,int thread_seq,const void *a_packet)
{
	char rec;
	struct timespec before_ts, after_ts;
	long long time_spent_ns;
	char debug_raw_pkt_string[256];
	struct streaminfo_private *pstream_pr=(struct streaminfo_private *)a_stream;
	int latency_enabled=MESA_handle_runtime_log_level_enabled(ABBR_PROCESS_LATENCY_LOG_HANDLE, RLOG_LV_INFO);
	if(unlikely(latency_enabled))
	{
		clock_gettime(g_clock_gettime_clock_id, &before_ts);
	}
	if(type==CALL_FUN_TYPE_RAW)
	{
		pstream_pr->cur_plugin_cb_func = (void *)pFunInfo;
		rec=((SAPP_STREAM_FUN_T)pFunInfo->pfun)(a_stream,transport_hdr,a_packet,&(pFunInfo->pAppInfo));
	}
	else
	{
		pstream_pr->cur_plugin_cb_func = (void *)pFunInfo;
		rec=((STREAM_CB_FUN_T)pFunInfo->pfun)(a_stream,&(pFunInfo->pAppInfo),thread_seq, a_packet);
	}

	if(unlikely(latency_enabled)){
		clock_gettime(g_clock_gettime_clock_id, &after_ts);
		time_spent_ns = (after_ts.tv_sec * 1000000000 + after_ts.tv_nsec) - (before_ts.tv_sec * 1000000000 + before_ts.tv_nsec);
		if(sapp_global_val->config.profiling.histogram_enabled && time_spent_ns > 0)
		{
			sapp_fs2_fuzzy_latency_update_per_entry(thread_seq, pFunInfo->entry_id, time_spent_ns);
		}
		if(unlikely(time_spent_ns >= g_timestamp_record_threshold*1000)){
			if(pstream_pr->raw_pkt!=NULL)
			{
				((raw_pkt_t *)(pstream_pr->raw_pkt))->diagnose_error_to_dump=1;
			}
			if(NULL == a_packet || OP_STATE_CLOSE == a_stream->opstate || OP_STATE_CLOSE == a_stream->pktstate){
				sapp_process_latency_log(RLOG_LV_INFO, "plug_name:%s, entry:%s, stream close process latency:%lld us, addr:%s, datalen:%u, c:%u, s:%u, thread_seq:%d", 
								g_plug_global_entry[pFunInfo->entry_id].plug_name, 
								g_plug_global_entry[pFunInfo->entry_id].plug_entry_name, 
								time_spent_ns/1000,
								printaddr(&a_stream->addr, thread_seq), 
								a_stream->pudpdetail->datalen,
								a_stream->pudpdetail->clientpktnum,
								a_stream->pudpdetail->serverpktnum,								
								thread_seq);
			}else{
				sapp_rawpkt_ntop(pstream_pr->raw_pkt, 1, debug_raw_pkt_string, sizeof(debug_raw_pkt_string)); /* 此处优先打印最内层四元组 */
				sapp_process_latency_log(RLOG_LV_INFO, "plug_name:%s, entry:%s, pkt process latency:%lld us, rawpkt:%s, addr:%s, raw_len:%d, c:%u, s:%u, thread:%d", 
								g_plug_global_entry[pFunInfo->entry_id].plug_name, 
								g_plug_global_entry[pFunInfo->entry_id].plug_entry_name, 
								time_spent_ns/1000, 
								debug_raw_pkt_string, 
								printaddr(&a_stream->addr, thread_seq), 
								pstream_pr->raw_pkt->raw_pkt_len,
								a_stream->pudpdetail->clientpktnum,
								a_stream->pudpdetail->serverpktnum,
								thread_seq);
			}
		}		
	}	
	return rec;
}


char plugin_call_ipentry(int type,IPv4_CB_FUN_T stream_fun,SAPP_PKT_CB_FUN_T sapp_fun,struct streaminfo *pfstream, const void* this_layer_hdr,
				int thread_num,unsigned char routedir, const raw_pkt_t *raw_pkt)
{
	char rec;

	if(type==CALL_FUN_TYPE_RAW)
	{
		rec=stream_fun(pfstream,routedir,thread_num,this_layer_hdr);
	}
	else
	{
		rec=sapp_fun(pfstream,this_layer_hdr,raw_pkt);
	}
	return rec;
}

static void plug_entry_kick_out_one(StreamFunInfo *node, struct streaminfo *a_stream)
{
	if(node==NULL)return;

    UCHAR saved_linkstate;
    struct tcpdetail_private *ptcpdetail_pr = (struct tcpdetail_private *)a_stream->ptcpdetail;

    UCHAR saved_opstate = a_stream->opstate;
    UCHAR saved_pktstate = a_stream->pktstate;
    saved_linkstate = ptcpdetail_pr->link_state;

    /* 临时修改为CLOSE, 再恢复原状态 */
    a_stream->opstate = OP_STATE_CLOSE;
    a_stream->pktstate = OP_STATE_CLOSE;
    ptcpdetail_pr->link_state = STREAM_FAKE_CLOSE_BY_DEPRIVE;

    if (is_raw_cb(node->funtype))
    {
        plugin_call_streamentry(CALL_FUN_TYPE_RAW, node, a_stream, NULL, a_stream->threadnum, NULL);
    }
    else
    {
        plugin_call_streamentry(CALL_FUN_TYPE_NORAW, node, a_stream, NULL, a_stream->threadnum, NULL);
    }
    sapp_mem_free(SAPP_MEM_DYN_PLUG_CTRL, a_stream->threadnum, node);

    a_stream->opstate = saved_opstate;
    a_stream->pktstate = saved_pktstate;
    ptcpdetail_pr->link_state = saved_linkstate;
	return;
}


/* 将剩余插件entry链全部CLOSE */
static void plug_entry_kick_out_tot_list(StreamFunInfo *list_head, struct streaminfo *a_stream)
{
	UCHAR saved_linkstate;
	StreamFunInfo *tmp_ptr;
	struct tcpdetail_private *ptcpdetail_pr = (struct tcpdetail_private *)a_stream->ptcpdetail;

	UCHAR saved_opstate = a_stream->opstate;
	UCHAR saved_pktstate = a_stream->pktstate;
	saved_linkstate = ptcpdetail_pr->link_state;
	
	/* 临时修改为CLOSE, 再恢复原状态 */
	a_stream->opstate = OP_STATE_CLOSE;
	a_stream->pktstate = OP_STATE_CLOSE;
	ptcpdetail_pr->link_state = STREAM_FAKE_CLOSE_BY_DEPRIVE;
	
	while(list_head){
		if(is_raw_cb(list_head->funtype)){
			plugin_call_streamentry(CALL_FUN_TYPE_RAW, list_head, a_stream, NULL, a_stream->threadnum, NULL);
		}else{
			plugin_call_streamentry(CALL_FUN_TYPE_NORAW, list_head, a_stream, NULL, a_stream->threadnum, NULL);
		}	

		tmp_ptr = list_head->next;
		sapp_mem_free(SAPP_MEM_DYN_PLUG_CTRL, a_stream->threadnum, list_head);
		list_head = tmp_ptr;
	}

	a_stream->opstate = saved_opstate;
	a_stream->pktstate = saved_pktstate;	
	ptcpdetail_pr->link_state = saved_linkstate;
}

static StreamFunInfo *plug_entry_kick_out_tot_list_by_priority(StreamFunInfo *list_head, struct streaminfo *a_stream, int kicker_priority)
{
	UCHAR saved_linkstate;
	StreamFunInfo *tmp_ptr = NULL, *cur_node = list_head;
	struct tcpdetail_private *ptcpdetail_pr = (struct tcpdetail_private *)a_stream->ptcpdetail;

	UCHAR saved_opstate = a_stream->opstate;
	UCHAR saved_pktstate = a_stream->pktstate;
	saved_linkstate = ptcpdetail_pr->link_state;
	
	/* 临时修改为CLOSE, 再恢复原状态 */
	a_stream->opstate = OP_STATE_CLOSE;
	a_stream->pktstate = OP_STATE_CLOSE;
	ptcpdetail_pr->link_state = STREAM_FAKE_CLOSE_BY_DEPRIVE;

    while (cur_node)
    {
		tmp_ptr = cur_node->next;
        if (plug_priority_get(cur_node->entry_id) <= kicker_priority)
        {
            if (is_raw_cb(cur_node->funtype))
            {
                plugin_call_streamentry(CALL_FUN_TYPE_RAW, cur_node, a_stream, NULL, a_stream->threadnum, NULL);
            }
            else
            {
                plugin_call_streamentry(CALL_FUN_TYPE_NORAW, cur_node, a_stream, NULL, a_stream->threadnum, NULL);
            }
			if(cur_node == list_head)
			{
				list_head=tmp_ptr;
			}
        	sapp_mem_free(SAPP_MEM_DYN_PLUG_CTRL, a_stream->threadnum, cur_node);
        	
        }
		cur_node = tmp_ptr;
		
    }

    a_stream->opstate = saved_opstate;
	a_stream->pktstate = saved_pktstate;	
	ptcpdetail_pr->link_state = saved_linkstate;
	return list_head;
}

static int stream_set_offload_flag(struct streaminfo *pstream, unsigned char smart_offload_flag)
{
	if(STREAM_TYPE_TCP == pstream->type)
	{
		struct tcpdetail_private *tcp_pdetail_pr=(struct tcpdetail_private*)(pstream->pdetail);
		tcp_pdetail_pr->offload_stream_flag|=smart_offload_flag;
	}
	else if(STREAM_TYPE_UDP == pstream->type)
	{
		struct udpdetail_private *udp_pdetail_pr=(struct udpdetail_private*)(pstream->pdetail);
		udp_pdetail_pr->offload_stream_flag|=smart_offload_flag;
	}
	else
	{
		sapp_runtime_log(RLOG_LV_FATAL, "%s,stream_set_offload_flag() OFFLOAD_STREAM error: stream type is not tcp or udp!\n", printaddr(&pstream->addr, pstream->threadnum));
	}

	return 0;
}

static int copy_funcation_from_entry_to_stream(StreamFunInfo **oneStreamFunInfo, stFunArray *oneEntry, UCHAR thread_num)
{
	StreamFunInfo *pFunInfo=(*oneStreamFunInfo);
	if(pFunInfo==NULL)
	{
		pFunInfo=(StreamFunInfo *)sapp_mem_calloc(SAPP_MEM_DYN_PLUG_CTRL, thread_num, sizeof(StreamFunInfo));
		*oneStreamFunInfo=pFunInfo;
	}
	
	pFunInfo->appState=APP_STATE_GIVEME;
	pFunInfo->pAppInfo=NULL;
	pFunInfo->funtype=oneEntry->funtype;
	pFunInfo->pfun=oneEntry->pfun;
	pFunInfo->entry_id=oneEntry->entry_id;
	pFunInfo->next=NULL;

	return 0;
}

int call_streamentry(struct streaminfo *a_stream, const void *this_iphdr, const void *transport_hdr, const void *raw_pkt, StreamFunInfo *pFunInfo)
{
	//add by lqy 20141230
	//注意如下的只有是stream_raw类型的函数，函数调用不一样
	if(is_raw_cb(pFunInfo->funtype))
	{
		pFunInfo->appState=plugin_call_streamentry(CALL_FUN_TYPE_RAW,pFunInfo,a_stream,transport_hdr,a_stream->threadnum,raw_pkt);

	}
	else
	{
		pFunInfo->appState=plugin_call_streamentry(CALL_FUN_TYPE_NORAW,pFunInfo,a_stream,NULL,a_stream->threadnum,this_iphdr);
	}

	return pFunInfo->appState;
}


static int stream_state_pending_process(struct streaminfo *a_stream,const void *this_iphdr, const void *transport_hdr, const void *raw_pkt,
				int funnum,stFunArray *p_plugin_entrys,void **apme,unsigned char *opstate, unsigned char smart_offload_flag)
{
	int ret=PASS;
	StreamFunInfo *p_plugin_runtime_list=NULL;
	StreamFunInfo *p_plugin_runtime_last=NULL;
	StreamFunInfo tmp_runtime;
	UCHAR giveme_cnt=0;
	UCHAR entry_ret;
	
	for(int i=0;i<funnum;i++)
	{
		memset(&tmp_runtime, 0, sizeof(StreamFunInfo));
		tmp_runtime.appState=APP_STATE_GIVEME;
		tmp_runtime.pAppInfo=NULL;
		tmp_runtime.funtype=(p_plugin_entrys+i)->funtype;
		tmp_runtime.pfun=(p_plugin_entrys+i)->pfun;
		tmp_runtime.entry_id=(p_plugin_entrys+i)->entry_id;
		tmp_runtime.next=NULL;
		entry_ret = call_streamentry(a_stream, this_iphdr, transport_hdr, raw_pkt, &tmp_runtime);
		if((entry_ret&APP_STATE_DROPME) != APP_STATE_DROPME)
		{
			StreamFunInfo *new_plugin_runtime=(StreamFunInfo *)sapp_mem_calloc(SAPP_MEM_DYN_PLUG_CTRL, a_stream->threadnum, sizeof(StreamFunInfo));	
			memcpy(new_plugin_runtime, &tmp_runtime, sizeof(StreamFunInfo));
            if ((entry_ret & APP_STATE_GIVESTATE)==APP_STATE_GIVESTATE)
            {
                new_plugin_runtime->appState = APP_STATE_GIVESTATE;
            }
            else
            {
                if ((entry_ret & APP_STATE_GIVEME) == APP_STATE_GIVEME || entry_ret == APP_STATE_GIVEME)
                {
                    giveme_cnt++;
                }
			}
            if (p_plugin_runtime_list == NULL)
            {
                p_plugin_runtime_list = new_plugin_runtime;
                p_plugin_runtime_last = new_plugin_runtime;
            }
            else
            {
                p_plugin_runtime_last->next = new_plugin_runtime;
                p_plugin_runtime_last = new_plugin_runtime;
            }
        }
		if(entry_ret&APP_STATE_KILL_OTHER || entry_ret&APP_STATE_KILL_FOLLOW)
		{
            // 删除优先级小于等于当前处理器的其他节点
            StreamFunInfo* current = p_plugin_runtime_list;
            StreamFunInfo* prev = NULL;
			int kicker_entry_id=(p_plugin_entrys+i)->entry_id;
			int kicker_priority=plug_priority_get(kicker_entry_id);
            while (current != NULL) {
                if (plug_priority_get(current->entry_id) <= kicker_priority && current->entry_id != kicker_entry_id) {
                    if (prev != NULL) {
                        prev->next = current->next;
                    } else {
                        p_plugin_runtime_list = current->next;
                    }
                    StreamFunInfo* to_remove = current;
                    current = current->next;
					plug_entry_kick_out_one(to_remove, a_stream);
                } else {
                    prev = current;
                    current = current->next;
                }
            }

            // 跳过后续优先级小于等于当前插件优先级的入口调用
            while (i + 1 < funnum && plug_priority_get((p_plugin_entrys+i+1)->entry_id) <= kicker_priority) 
			{
                ++i;
            }
        }
		if(entry_ret & APP_STATE_DROPPKT)	
		{
			ret=DROP;
			break;
		}	
	}

	if(p_plugin_runtime_list != NULL)
	{
		*apme = p_plugin_runtime_list;
		*opstate= OP_STATE_DATA;
		if(giveme_cnt == 0)
		{
			stream_set_offload_flag(a_stream, smart_offload_flag);
		}
	}
	else
	{
		*opstate= OP_STATE_CLOSE;	
		stream_set_offload_flag(a_stream, smart_offload_flag);
	}

	return ret;
}

static int stream_state_data_process(struct streaminfo *a_stream,const void *this_iphdr, const void *transport_hdr, const void *raw_pkt,
				int funnum,stFunArray *pfunAarry,void **apme,unsigned char *opstate, unsigned char smart_offload_flag)
{
	StreamFunInfo* prev = NULL;
    StreamFunInfo* current = (StreamFunInfo*)*apme;
    StreamFunInfo* head = (StreamFunInfo*)*apme;
	StreamFunInfo *to_remove = NULL;
	int ret=PASS;
	UCHAR giveme_cnt=0;
	UCHAR entry_ret;
    while (current != NULL)
    {
        if (current->appState == APP_STATE_GIVESTATE)
        {
            current = current->next;
            continue;
        }
        entry_ret = call_streamentry(a_stream, this_iphdr, transport_hdr, raw_pkt, current);
        if ((entry_ret & APP_STATE_GIVESTATE) == APP_STATE_GIVESTATE)
        {
            current->appState = APP_STATE_GIVESTATE;
        }
        else
        {
            if ((entry_ret & APP_STATE_GIVEME) == APP_STATE_GIVEME || entry_ret == APP_STATE_GIVEME) 
            {
                giveme_cnt++;
            }
        }
        if (entry_ret & APP_STATE_KILL_OTHER || entry_ret&APP_STATE_KILL_FOLLOW)
        {
			int kicker_entry_id=current->entry_id;
			int kicker_priority=plug_priority_get(kicker_entry_id);
            StreamFunInfo *iter_prev = NULL;
            StreamFunInfo *iter_current = head;
            while (iter_current != NULL)
            {
                if (plug_priority_get(iter_current->entry_id) <= kicker_priority && iter_current->entry_id != kicker_entry_id)
                {
                    to_remove = iter_current;
                    if (iter_prev != NULL)
                    {
                        iter_prev->next = iter_current->next;
                    }
                    else
                    {
                        head = iter_current->next;
                    }
                    iter_current = iter_current->next;
                    plug_entry_kick_out_one(to_remove, a_stream);
					if (to_remove == prev) // if we remove the 'prev', update 'prev'
                    {
                        prev = iter_prev;
                    }
                }
                else
                {
                    iter_prev = iter_current;
                    iter_current = iter_current->next;
                }
            }
        }
        // Check and process APP_STATE_DROPME separately from APP_STATE_KILL_OTHER or APP_STATE_KILL_FOLLOW.
        if (entry_ret & APP_STATE_DROPME)
        {
            to_remove = NULL;
            if (prev != NULL)
            {
                prev->next = current->next;
                to_remove = current;
                current = current->next;
            }
            else
            {
                head = current->next;
                to_remove = current;
                current = current->next;
            }
            sapp_mem_free(SAPP_MEM_DYN_PLUG_CTRL,a_stream->threadnum,to_remove);
        }
        else
        {
            prev = current;
            current = current->next;
        }
		if(entry_ret & APP_STATE_DROPPKT)	
		{
			ret=DROP;
			break;
		}
	}
	if(head != NULL)
	{
		*opstate= OP_STATE_DATA;
		if(giveme_cnt == 0)
		{
			stream_set_offload_flag(a_stream, smart_offload_flag);
		}
	}
	else
	{
		*opstate= OP_STATE_CLOSE;	
		stream_set_offload_flag(a_stream, smart_offload_flag);
	}
	*apme = head;
	return ret;
}

int stream_state_pending(struct streaminfo *a_stream,const void *this_iphdr, const void *transport_hdr, const void *raw_pkt,
				int funnum,stFunArray *pfunAarry,void **apme,unsigned char *opstate, unsigned char smart_offload_flag)
{
	int i=0;
	int ret=PASS;
	StreamFunInfo *pFunList=NULL;
	StreamFunInfo *pFunInfo=NULL;
	StreamFunInfo *pNext=NULL,*pPrev=NULL;
	UCHAR threadnum = a_stream->threadnum;
	UCHAR local_app_ret;
	int kicker_plugin_priority=-1;

	pFunList = (StreamFunInfo*)(*apme);

	for(i=0;i<funnum;i++)
	{
		copy_funcation_from_entry_to_stream(&pFunInfo, &pfunAarry[i], threadnum);
		local_app_ret=call_streamentry(a_stream, this_iphdr, transport_hdr, raw_pkt, pFunInfo);

		if(local_app_ret&APP_STATE_DROPME)
		{
			/* 2019-11-15 lijia add for plug kill other */
			if(local_app_ret & APP_STATE_KILL_OTHER)
			{

                kicker_plugin_priority = plug_priority_get(pfunAarry[i].entry_id);
                if (kicker_plugin_priority >= max_plug_priority_get())
                {
                    /* 当前插件返回了DROPME, 且KILL_OTHER, 说明所有插件都结束 */
                    plug_entry_kick_out_tot_list(pFunList, a_stream);
                    pFunList = NULL;
                    *apme = NULL; /* 2020-05-08 lijia modify */
                    break;
                }
            }
		}
		else
		{
			/* 2019-11-15 lijia add for plug kill other */
			if(local_app_ret & APP_STATE_KILL_OTHER)
			{
				plug_entry_kick_out_tot_list(pFunList, a_stream);
				pFunList = NULL; /* 将其余插件全部CLOSE, 只剩当前插件 */
			}

			if(local_app_ret & APP_STATE_GIVESTATE)
			{
				pFunInfo->appState=APP_STATE_GIVESTATE;
			}

			if(pFunList==NULL)
			{
				pFunList=pFunInfo;
			}
			else
			{
				pPrev->next=pFunInfo;
			}
			
			pPrev=pFunInfo;
			pFunInfo=NULL;
		}

		if(local_app_ret & APP_STATE_DROPPKT)	
		{
			ret=DROP;
			break; 
		}	

		/* 2019-11-15 lijia add for plug kill other */
		if(local_app_ret & (APP_STATE_KILL_FOLLOW | APP_STATE_KILL_OTHER))
		{
			/* 如果在pending阶段, KILL FOLLOW直接退出循环即可 */
			break;
		}
	}
	
	//不需要再次送入包的fun，在这里释放
	if(pFunInfo!=NULL)
	{
		sapp_mem_free(SAPP_MEM_DYN_PLUG_CTRL, threadnum,pFunInfo);
		pFunInfo = NULL;		
	}

	
	//有需要再次送包的回调函数
	if(pFunList!=NULL)
	{
		*apme = pFunList;
		*opstate= OP_STATE_DATA;

		pNext=pFunList;
		while(pNext)	//所有插件DROPME，或者均设置GIVESTATE状态
		{
			if(pNext->appState!=APP_STATE_GIVESTATE)
			{
				return ret;
			}

			pNext=pNext->next;
		}

		stream_set_offload_flag(a_stream, smart_offload_flag);
	}
	else
	{
		*opstate= OP_STATE_CLOSE;	
		stream_set_offload_flag(a_stream, smart_offload_flag);
	}
	
	return ret;

}

static int stream_state_data(struct streaminfo *a_stream,const void *this_iphdr, const void *transport_hdr, const void *raw_pkt,
				int funnum,stFunArray *pfunAarry,void **apme,unsigned char *opstate, unsigned char smart_offload_flag)
{
	int ret=PASS;
	UCHAR local_app_ret;
	StreamFunInfo *pFunList=NULL;
	StreamFunInfo *pFunInfo=NULL;
	StreamFunInfo *pNext=NULL,*pPrev=NULL;

	pFunList = (StreamFunInfo *)*apme;	
	pFunInfo=pFunList;
	pPrev=NULL;
	while(pFunInfo)
	{
		if(pFunInfo->appState==APP_STATE_GIVESTATE)
		{
			pFunInfo=pFunInfo->next;
			continue;
		}
		
		local_app_ret=call_streamentry(a_stream, this_iphdr, transport_hdr, raw_pkt, pFunInfo);
		if(pFunInfo->appState&APP_STATE_DROPME)
		{
			if(pPrev==NULL)
			{
				pFunList=pFunInfo->next;
				*apme= pFunList;
			}	
			else
			{
				pPrev->next=pFunInfo->next;
			}
			pNext=pFunInfo->next;
			sapp_mem_free(SAPP_MEM_DYN_PLUG_CTRL,a_stream->threadnum,pFunInfo);
			pFunInfo=pNext;

			if(local_app_ret & APP_STATE_KILL_FOLLOW)
			{
				plug_entry_kick_out_tot_list(pNext, a_stream);
				if(NULL == pPrev)
				{
					/* 当前插件在第一个, KILL_FOLLOW &    APP_STATE_DROPME相当于全部插件DROPME*/
					pFunList = NULL; /* 全部插件CLOSE */
					*apme = NULL; /* 2020-05-08 lijia modify */
				}
				else
				{
					pPrev->next = NULL;
				}
			/* 2019-11-15 lijia add for plug kill other */
			}
			else if(local_app_ret & APP_STATE_KILL_OTHER)
			{
				plug_entry_kick_out_tot_list(pFunList, a_stream);
				pFunList = NULL; /* 全部插件CLOSE */
				*apme = NULL; /* 2020-05-08 lijia modify */
			}
		}
		else
		{
			/* 2019-11-15 lijia add for plug kill other */
			if(local_app_ret & APP_STATE_KILL_OTHER){
				/* 把当前plug info从链表中先移除 */
				if(pPrev==NULL)
				{
					pFunList=pFunInfo->next;
				}
				else
				{
					pPrev->next=pFunInfo->next;
				}
				/* 把剩余的全CLOSE */
				plug_entry_kick_out_tot_list(pFunList, a_stream);
				
				pFunList = pFunInfo;
				pFunList->next = NULL;
				*apme= pFunList;
			}
			else if(local_app_ret & APP_STATE_KILL_FOLLOW)
			{
				plug_entry_kick_out_tot_list(pFunInfo->next, a_stream);
				pFunInfo->next = NULL;
			}

			if(local_app_ret & APP_STATE_GIVESTATE)
			{
				pFunInfo->appState=APP_STATE_GIVESTATE;
			}
			
			pPrev=pFunInfo;
			pFunInfo=pFunInfo->next;
		}

		if(local_app_ret&APP_STATE_DROPPKT)	
		{
			ret=DROP;	
			break;
		}

		/* 2019-11-15 lijia add for plug kill other */
		if(local_app_ret & (APP_STATE_KILL_FOLLOW | APP_STATE_KILL_OTHER))
		{
			break;
		}
	}

	//处理过程中大家都不需要了
	if(pFunList==NULL)
	{
		*opstate = OP_STATE_CLOSE;	
		stream_set_offload_flag(a_stream, smart_offload_flag);
	}	

	pNext=pFunList;
	while(pNext)	//所有插件DROPME，或者均设置GIVESTATE状态
	{
		if(pNext->appState!=APP_STATE_GIVESTATE)
		{
			return ret;
		}
	
		pNext=pNext->next;
	}

	//所有插件DROPME，或者均设置GIVESTATE状态	
	stream_set_offload_flag(a_stream, smart_offload_flag);

	return ret;
}


//add end
int stream_process(struct streaminfo *a_stream,const void *this_iphdr, const void *transport_hdr, const void *raw_pkt,
				int funnum,stFunArray *pfunAarry,void **apme,unsigned char *opstate, unsigned char smart_offload_flag)
{
	int ret=PASS;
	StreamFunInfo *pFunInfo=NULL;
	StreamFunInfo *pNext=NULL;

	if(funnum==0)
	{
		stream_set_offload_flag(a_stream, smart_offload_flag);
		*opstate= OP_STATE_CLOSE;
		return ret;
	}

	switch(*opstate)
	{
		case	OP_STATE_PENDING:
			ret = stream_state_pending_process(a_stream, this_iphdr, transport_hdr, raw_pkt, funnum, pfunAarry, apme, opstate, smart_offload_flag);
			break;
		case	OP_STATE_DATA:	
			if(*apme==NULL) //如果已经没有要处理的函数了
			{
				*opstate= OP_STATE_CLOSE;
				break;
			}
			ret =  stream_state_data_process(a_stream, this_iphdr, transport_hdr, raw_pkt, funnum, pfunAarry, apme, opstate, smart_offload_flag);
			break;
		case	OP_STATE_CLOSE: //链接关闭,清除状态
				pFunInfo=(StreamFunInfo *)(*apme);
				while(pFunInfo)
				{
					call_streamentry(a_stream, this_iphdr, transport_hdr, raw_pkt, pFunInfo);
					pNext=pFunInfo->next;
					if(timeout_pending(&pFunInfo->timeout))
					{
						timeouts_del(G_MESA_GLOBAL_STREAM[a_stream->threadnum]->user_define_timer ,&pFunInfo->timeout);
						G_MESA_GLOBAL_STREAM[a_stream->threadnum]->user_define_timer_cnt-=1;
					}
					sapp_mem_free(SAPP_MEM_DYN_PLUG_CTRL,a_stream->threadnum,pFunInfo);
					
					pFunInfo=pNext;
				}
				*apme=NULL;
			break;
		default:
			break;
	}
	
	if(raw_pkt != NULL && ret == DROP)
	{
		raw_pkt_t *p_rawpkt = (raw_pkt_t *)raw_pkt;
		p_rawpkt->drop_current_pkt_flag = 1;
	}

	return ret;
}

int stream_process_udp_single(struct streaminfo *a_udp,const void * a_packet,void **apme,unsigned char *popstate)
{

	int i=0;
	int ret=PASS;
	char appState=APP_STATE_GIVEME;
	void *pAppInfo=NULL;
	int funtype=0;
	
	for(i=0;i<g_StreamUdpFunNum;i++)
	{
		funtype=g_StreamUdpFun[i].funtype;
		//add by lqy 20141230
		//注意如下的只有是stream_raw类型的函数，函数调用不一样
		//if(funtype>FUN_TYPE_IPV6_RAW)
		if(is_raw_cb((enum fun_type_t)funtype)){
			appState=g_StreamUdpFun[i].sapp_stream_fun(a_udp,a_packet,a_packet,&(pAppInfo));
		}else{
			appState=g_StreamUdpFun[i].stream_fun(a_udp,&(pAppInfo),a_udp->threadnum,a_packet);
		}
		if(appState&APP_STATE_DROPPKT)	
		{
				ret=DROP;	
				break;
		}
	}
	return ret;
}

/*
	lijia 2015-01-12 modify, add this_iphdr, 
	如果是IP分片重组的包, 必须显式的传递IP包头, 否则只传raw_hdr, 无法获取重组后的IP包头.
*/
int stream_process_tcp(struct streaminfo *a_tcp, const void *this_iphdr, const void *transport_hdr, 
						const raw_pkt_t * raw_pkt,void **apme,unsigned char *popstate)
{
	int ret;
	struct streaminfo_private *a_tcp_pr = (struct streaminfo_private *)a_tcp;

	//stream_update_tcp_data_count(a_tcp);
	/* 2016-07-14 lijia add */
	if((G_TCP_FLOW_STAT_PROJECT_ID != -1) 
	&& (a_tcp->ptcpdetail->datalen > 0)
	&& (STREAM_TYPE_TCP == a_tcp->type)
	&& (raw_pkt != NULL && raw_pkt->is_ctrl_pkt == 0)){ /* 即使G_TCP_FLOW_STAT_PROJECT_ID开启, a_tcp可能是代理流, 不一定是TCP, 此处要判断流类型 */
		struct tcpdetail_private *pdetail_pr = (struct tcpdetail_private *)a_tcp->pdetail;
		if(DIR_C2S == a_tcp->curdir){
			pdetail_pr->flow_stat->C2S_data_pkt ++;
			pdetail_pr->flow_stat->C2S_data_byte += a_tcp->ptcpdetail->datalen;
		}else{
			pdetail_pr->flow_stat->S2C_data_pkt ++;
			pdetail_pr->flow_stat->S2C_data_byte += a_tcp->ptcpdetail->datalen;
		}
	}
	
	if(raw_pkt!=NULL)
	{	
		a_tcp_pr->plugin_process_context = 1;
	}
	ret = stream_process(a_tcp, this_iphdr, transport_hdr, raw_pkt,g_StreamTcpFunNum, g_StreamTcpFun,apme,popstate, SMART_OFFLOAD_FLAG_TCP);	
	a_tcp_pr->plugin_process_context = 0;
	
	return ret;
}

/*
	lijia 2015-01-12 modify, add this_iphdr, 
	如果是IP分片重组的包, 必须显式的传递IP包头, 否则只传raw_hdr, 无法获取重组后的IP包头.
*/

int stream_process_udp(struct streaminfo *a_udp, const void *this_iphdr, const void *transport_hdr, 
						const raw_pkt_t * raw_pkt,void **apme,unsigned char *popstate)
{
	int ret;
	struct streaminfo_private *a_udp_pr = (struct streaminfo_private *)a_udp;

#if (0 == HIGH_PERF)	
	raw_ip_frag_list_stream_attach(a_udp);
#endif

	if(raw_pkt!=NULL)
	{	
		a_udp_pr->plugin_process_context = 1;
	}
	ret = stream_process(a_udp, this_iphdr, transport_hdr, raw_pkt, g_StreamUdpFunNum, g_StreamUdpFun, apme, popstate, SMART_OFFLOAD_FLAG_UDP);
	a_udp_pr->plugin_process_context = 0;
	
#if (0 == HIGH_PERF)		
	raw_ip_frag_list_stream_detach(a_udp);
#endif

	return ret;
}



int stream_process_overlay_udp(struct streaminfo *a_udp, const void *this_iphdr, const void *transport_hdr, 
						const raw_pkt_t * raw_pkt,void **apme,unsigned char *popstate)
{
	int ret;
	struct streaminfo_private *a_udp_pr = (struct streaminfo_private *)a_udp;


	a_udp_pr->plugin_process_context = 1;
	ret = stream_process(a_udp, this_iphdr, transport_hdr, raw_pkt, g_OverlayUdpFunNum, g_OverlayUdpFun, apme, popstate, SMART_OFFLOAD_FLAG_UNKNOWN);
	a_udp_pr->plugin_process_context = 0;
	
	return ret;
}


/*
	lijia 2015-01-12 modify, add this_iphdr, 
	如果是IP分片重组的包, 必须显式的传递IP包头, 否则只传raw_hdr, 无法获取重组后的IP包头.
*/

int stream_process_tcp_allpkt(struct streaminfo *a_tcp,const void *this_iphdr, const void *transport_hdr, 
							const raw_pkt_t *raw_pkt, void **apme,unsigned char *popstate)
{
	int ret;
	struct streaminfo_private *a_tcp_pr = (struct streaminfo_private *)a_tcp;
	
#if (0 == HIGH_PERF)		
	raw_ip_frag_list_stream_attach(a_tcp);
#endif

	if(raw_pkt!=NULL)
	{	
		a_tcp_pr->plugin_process_context = 1;
	}
	ret = stream_process(a_tcp, this_iphdr, transport_hdr, raw_pkt, g_StreamTcpAllFunNum, g_StreamTcpAllFun, apme, popstate, SMART_OFFLOAD_FLAG_TCPALL);
	a_tcp_pr->plugin_process_context = 0;
	
#if (0 == HIGH_PERF)		
	raw_ip_frag_list_stream_detach(a_tcp);
#endif

	return ret;
}

int stream_process_tcp_takeover(struct streaminfo *a_tcp, const void * iphdr)
{
	return  g_StreamTcpTakeover(a_tcp,NULL,a_tcp->threadnum, iphdr);
}

int stream_process_ipv4(struct streaminfo *pfstream, const struct ip *this_layer_hdr,
				int thread_num,unsigned char routedir, const raw_pkt_t *raw_pkt)
{
	int i;
	int platform_ret = PASS;
	int appret;
	
	for(i=0;i<g_Ipv4FunNum;i++)
	{
		if(g_Ipv4Fun[i].funtype==FUN_TYPE_IPV4)
		{
			appret= plugin_call_ipentry(CALL_FUN_TYPE_RAW,g_Ipv4Fun[i].stream_ipv4_fun,NULL,pfstream,this_layer_hdr,thread_num,routedir, raw_pkt);
		}
		else
		{
//			appret=g_Ipv4Fun[i].sapp_pkt_fun(pfstream,this_layer_hdr,raw_pkt);
			appret= plugin_call_ipentry(CALL_FUN_TYPE_NORAW,NULL,g_Ipv4Fun[i].sapp_pkt_fun,pfstream,this_layer_hdr,thread_num,routedir, raw_pkt);

		}

		/* 2019-11-15 lijia add for plug kill other */
		if(appret & APP_STATE_KILL_OTHER){
			sapp_runtime_log(20, "not support APP_STATE_KILL_OTHER in ip entry!");
		}

		if(unlikely(appret&APP_STATE_DROPPKT))
		{
			return DROP;
		}	

		if(appret & APP_STATE_KILL_FOLLOW){
			break;
		}
	}
	
	return platform_ret;
}

int stream_process_overlay_ipv4(struct streaminfo *pfstream, const struct ip* this_layer_hdr,
				int thread_num,unsigned char routedir, const raw_pkt_t *raw_pkt)
{
	int i;
	int platform_ret = PASS;
	int appret;
	
	for(i=0;i<g_OverlayIpv4FunNum;i++)
	{
		if(g_OverlayIpv4Fun[i].funtype==FUN_TYPE_IPV4)
		{
			appret= plugin_call_ipentry(CALL_FUN_TYPE_RAW,g_OverlayIpv4Fun[i].stream_ipv4_fun,NULL,pfstream,this_layer_hdr,thread_num,routedir, raw_pkt);
		}
		else
		{
			appret= plugin_call_ipentry(CALL_FUN_TYPE_NORAW,NULL,g_OverlayIpv4Fun[i].sapp_pkt_fun,pfstream,this_layer_hdr,thread_num,routedir, raw_pkt);

		}

		/* 2019-11-15 lijia add for plug kill other */
		if(appret & APP_STATE_KILL_OTHER){
			sapp_runtime_log(20, "not support APP_STATE_KILL_OTHER in ip entry!");
		}

		if(unlikely(appret&APP_STATE_DROPPKT))
		{
			return DROP;
		}	

		if(appret & APP_STATE_KILL_FOLLOW){
			break;
		}
	}
	
	return platform_ret;
}


int stream_process_ipv6(struct streaminfo *pfstream,const struct ip6_hdr *this_layer_hdr,
				int thread_num,unsigned char routedir, const raw_pkt_t *raw_pkt)
{
	int i=0;
	int platform_ret = PASS;
	int appret=APP_STATE_GIVEME;
	
	for(i=0;i<g_Ipv6FunNum;i++)
	{
		if(g_Ipv6Fun[i].funtype==FUN_TYPE_IPV6)
		{
//			appret=g_Ipv6Fun[i].stream_ipv6_fun(pfstream,routedir,thread_num,this_layer_hdr);
			appret= plugin_call_ipentry(CALL_FUN_TYPE_RAW,g_Ipv6Fun[i].stream_ipv6_fun,NULL,pfstream,this_layer_hdr,thread_num,routedir, raw_pkt);

		}
		else
		{
//			appret=g_Ipv6Fun[i].sapp_pkt_fun(pfstream,this_layer_hdr,raw_pkt);
			appret= plugin_call_ipentry(CALL_FUN_TYPE_NORAW,NULL,g_Ipv6Fun[i].sapp_pkt_fun,pfstream,this_layer_hdr,thread_num,routedir, raw_pkt);
		}
		
		/* 2019-11-15 lijia add for plug kill other */
		if(appret & APP_STATE_KILL_OTHER){
			sapp_runtime_log(20, "not support APP_STATE_KILL_OTHER in ip entry!");
		}	
		
		if(appret&APP_STATE_DROPPKT)
		{
			return DROP;			
		}

		if(appret & APP_STATE_KILL_FOLLOW){
			break;
		}
	}
	return platform_ret;
}

int stream_process_ipv4_frag(struct streaminfo *pstream, const struct ip *this_layer_hdr,
				int thread_num,unsigned char routedir, const raw_pkt_t *raw_pkt)
{
	int i=0;
	int ret=PASS;
	int appret=APP_STATE_GIVEME;
	
	for(i=0;i<g_Ipv4FragFunNum;i++)
	{
		if(g_Ipv4FragFun[i].funtype==FUN_TYPE_IPV4_FRAG)
		{
			appret=g_Ipv4FragFun[i].stream_ipv4_fun(pstream,routedir,thread_num,this_layer_hdr);
		}
		else
		{
			appret=g_Ipv4FragFun[i].sapp_pkt_fun(pstream,this_layer_hdr,raw_pkt);
		}
		
		/* 2019-11-15 lijia add for plug kill other */
		if((appret & APP_STATE_KILL_FOLLOW) || (appret & APP_STATE_KILL_OTHER)){
			sapp_runtime_log(20, "not support KILL_FOLLOW and KILL_OTHER in ip entry!");
		}	

		if(appret&APP_STATE_DROPPKT)
		{
			ret=DROP;			
			return ret;
		}	
	}
	return ret;
}

int stream_process_ipv6_frag(struct streaminfo *pstream,const struct ip6_hdr *this_layer_hdr,
				int thread_num,unsigned char routedir, const raw_pkt_t *raw_pkt)
{
	int i=0;
	int ret=PASS;
	int appret=APP_STATE_GIVEME;
	
	for(i=0;i<g_Ipv6FragFunNum;i++)
	{
		if(g_Ipv6FragFun[i].funtype==FUN_TYPE_IPV6_FRAG)
		{
			appret=g_Ipv6FragFun[i].stream_ipv6_fun(pstream,routedir,thread_num,this_layer_hdr);
		}
		else
		{
			appret=g_Ipv6FragFun[i].sapp_pkt_fun(pstream,this_layer_hdr,raw_pkt);
		}
		/* 2019-11-15 lijia add for plug kill other */
		if((appret & APP_STATE_KILL_FOLLOW) || (appret & APP_STATE_KILL_OTHER)){
			sapp_runtime_log(20, "not support KILL_FOLLOW and KILL_OTHER in ip entry!");
		}			
		if(appret&APP_STATE_DROPPKT)
		{
			ret=DROP;			
			return ret;
		}	
	}
	return ret;
}

/* 
	2016-09-26 lijia add, 
	没有包时, 插件会阻塞, 
	新增本函数, 底层收不到包时, 也会调用插件, 使插件能及时获得CPU, 做一些非包驱动的处理逻辑.
*/
int stream_process_polling(int thread_seq)
{
	int i;
	char plug_ret, fun_ret = 0;
	
	__st_pkt_proc_context_check_timeout(thread_seq);

	for(i = 0; i < g_PollingFunNum; i++){
		plug_ret = g_PollingFun[i].stream_fun(NULL, NULL, thread_seq, NULL);
		if(plug_ret & POLLING_STATE_WORK){
			fun_ret |= POLLING_STATE_WORK;
		}
	}

	if(POLLING_STATE_WORK & fun_ret){
		sapp_global_val->mthread_volatile[thread_seq]->sys_stat.count[SAPP_POLLING_WORK]++;
	}else{
		sapp_global_val->mthread_volatile[thread_seq]->sys_stat.count[SAPP_POLLING_IDLE]++;
	}

	return fun_ret;
}

int stream_process_arp(struct streaminfo *pfstream, const struct mesa_arp_hdr * this_layer_hdr,
				int thread_num,unsigned char routedir, const raw_pkt_t *raw_pkt)
{
	int i;
	
	for(i=0;i<g_ArpFunNum;i++)
	{
		plugin_call_ipentry(CALL_FUN_TYPE_RAW,g_ArpFun[i].stream_ipv4_fun,NULL,pfstream,this_layer_hdr,thread_num,routedir, raw_pkt);
	}
	
	return PASS;
}


extern int g_use_MESA_sleep_sw;
extern void MESA_sleep(void);
/* 
	2016-09-26 lijia add,
	底层驱动没有包时, 会调用此函数, 根据平台需求是否阻塞等待, 还是调用上层轮询插件. 
*/
void idle_polling_call(int thread_seq)
{
	if(0 == g_PollingFunNum){
		return;
	}else{
		stream_process_polling(thread_seq);
	}

	return;
}

typedef struct 
{
	enum fun_type_t funtype;
	int is_raw;
}raw_cb_fun_identify_t;

const static  raw_cb_fun_identify_t g_raw_cb_fun_identify_array[__FUN_TYPE_MAX] =
{
	{FUN_TYPE_IPV4,			0},
	{FUN_TYPE_IPV6,			0},
	{FUN_TYPE_TCP,				0},
	{FUN_TYPE_TCPALL,			0},
	{FUN_TYPE_UDP,			0},
	{FUN_TYPE_IPV4_RAW,		1},
	{FUN_TYPE_IPV6_RAW,		1},
	{FUN_TYPE_TCP_RAW,		1},
	{FUN_TYPE_TCPALL_RAW,	1},
	{FUN_TYPE_UDP_RAW,		1},
	{FUN_TYPE_IPV4_FRAG,		0},
	{FUN_TYPE_IPV4_FRAG_RAW, 1},
	{FUN_TYPE_IPV6_FRAG, 		0},
	{FUN_TYPE_IPV6_FRAG_RAW, 1},
	
};

static inline int is_raw_cb(enum fun_type_t cb_type)
{
	assert(cb_type < __FUN_TYPE_MAX);
	return g_raw_cb_fun_identify_array[cb_type].is_raw;
}


 int app_function_rationality_check(void)
{
	/* 2015-01-12 lijia add, for error message */
	if((0 == tcp_support_all) && (g_StreamTcpAllFunNum != 0)){
		printf("\033[33m[Warning]You have registered 'TCP_ALL' plugin, but 'TcpAllEnable' in main.conf is disable! \033[0m\n");
		sleep(1);
	}

	if((0 == g_ipv6_decapsulation_enabled) && (g_Ipv6FunNum != 0)){
		printf("\033[33m[Warning]You have registered 'IPV6' plugin, but 'sapp.toml->ipv6_decapsulation_enabled' is disable! \033[0m\n");
		sleep(1);
	}

	if((0 != tcp_support_all) && (g_discard_ack_sw != 0)){
#if HIGH_PERF	
		printf("\033[33m[Warning]Config conflict! 'TcpAllEnable' and 'discard_ack' is all enable, but in high-perf mode, discard_ack is keep enable!\033[0m\n");
#else
		printf("\033[33m[Warning]Config conflict! 'TcpAllEnable' and 'discard_ack' is all enable, TCPALL plug can't get ACK pkt.\033[0m\n");
#endif
		sleep(1);
	}
	
	return 0;
}

char (*g_platform_action_cb_fun)(int net_conn_mode, char plug_action) = NULL;

int platform_register_action_judge(char (*action_cb_fun)(int net_conn_mode, char plug_action))
{
	assert(action_cb_fun);
	g_platform_action_cb_fun = action_cb_fun;

	return 0;
}


/* 清空各种计数, 慎用全局变量!! */
void stream_destroy_plugin(void)
{
	g_StreamTcpFunNum=0;
	g_StreamTcpAllFunNum=0;
	g_StreamUdpFunNum=0;
	g_Ipv4FunNum=0;
	g_Ipv6FunNum=0;
	g_Ipv4FragFunNum=0;
	g_Ipv6FragFunNum=0;
	g_PhonyFunNum=0;
	g_PollingFunNum=0;
	g_ArpFunNum=0;
	g_OverlayIpv4FunNum=0;
	g_OverlayUdpFunNum=0;

}

#ifdef __cplusplus
}
#endif
