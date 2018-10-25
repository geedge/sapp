#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include "stream.h"
#include "stream_internal.h" 
#include "stream_manage.h"
#include "mesa_net.h"
#include "sysinfo.h"
#include "stream_tunnel.h"
#include "MESA_htable.h"

/*
	l2tp解析层, 
	1)用于获取全局插件ID, 并存储于g_l2tp_plugid;
	2)插件名称设为l2tp, 用于创建一个"l2tp"层的协议解析层入口,
	  真正的业务插件需要挂载到"l2tp"层;
	3)识别是否是L2tp协议, 在UDP_stream中记录标记stream_carry_up_layer_tunnel_type.
	
	相关RFC: RFC2661.
*/
const int l2tp_protocol_version_VERSION_20171220 = 20171220;
extern MESA_htable_handle *g_l2tp_htable_array; /* 内存申请和HASH创建由协议解析插件在初始化阶段完成 */
extern unsigned short g_l2tp_plugid;
extern int parse_l2tpv2_hdr(const struct l2tp_hdr_v2 *pl2tphdrv2, struct layer_addr_l2tp *l2tpaddr, UCHAR layer_addr);



/*
	返回值: 
		平台层APP_STATE_xxx;
*/
static inline int l2tp_call_biz_plug(const struct streaminfo *a_udp, struct l2tp_info_pri *l2tp_pri, 
								const void *ip_hdr)
{
	int biz_plug_ret;
	int pro_plug_ret = APP_STATE_GIVEME;
	
	biz_plug_ret = PROT_PROCESS(&l2tp_pri->ssinfo, &l2tp_pri->biz_pme, a_udp->threadnum, (struct streaminfo * )a_udp, ip_hdr);

	/* clear status */
	l2tp_pri->ssinfo.prot_flag = TUNNEL_PHONY_PROT_FLAG;
	l2tp_pri->ssinfo.buf = NULL;
	l2tp_pri->ssinfo.buflen = 0;

	if(biz_plug_ret & PROT_STATE_DROPPKT){
		pro_plug_ret |= APP_STATE_DROPPKT;
	}

	if(biz_plug_ret & PROT_STATE_DROPME){
		pro_plug_ret |= APP_STATE_DROPME;
	}
	
	return pro_plug_ret;
}

static inline void l2tp_context_init(struct l2tp_info_pri *l2tp_pri, int thread_seq, const struct streaminfo *a_udp)
{
	memset(l2tp_pri, 0, sizeof(struct l2tp_info_pri)); 

	l2tp_pri->tunnel_context.tunnel_type = STREAM_TYPE_L2TP;

	l2tp_pri->ssinfo.prot_flag = TUNNEL_PHONY_PROT_FLAG;
	l2tp_pri->ssinfo.plugid = g_l2tp_plugid;
	l2tp_pri->ssinfo.session_state = SESSION_STATE_PENDING;
	l2tp_pri->thread_seq = thread_seq;
	l2tp_pri->my_stream = a_udp;
}

static int guess_if_l2tpv2(const struct streaminfo *a_udp, const struct mesa_udp_hdr *udph)
{
	const struct l2tp_hdr_v2 *pl2tphdrv2;
	unsigned short *l2tp_len;

	if(STREAM_TYPE_UDP != a_udp->type){
		return 0;
	}

	if((NULL == a_udp->pudpdetail->pdata)
	 ||(a_udp->pudpdetail->datalen <= sizeof(struct l2tp_hdr_v2))){
		return 0;
	}	
	
	if((ntohs(udph->uh_sport) != L2TP_REGISTERED_PORT)
	 &&  (ntohs(udph->uh_dport) != L2TP_REGISTERED_PORT)){
		return 0; /* 非L2TP包 */
	} 

#if 0 /* 控制包长度不一定要计算ppp_hdr和ipv4_hdr */
	if(ntohs(udph->uh_ulen) - sizeof(struct mesa_udp_hdr) < sizeof(struct l2tp_hdr_v2) +  sizeof(struct mesa_ppp_hdr) + sizeof(struct mesa_ip4_hdr)){
		return 0; /* 数据小于最小可解析长度, 非L2TP包 */
	}
#endif	

	pl2tphdrv2 = (const struct l2tp_hdr_v2 *)((char *)udph + sizeof(struct mesa_udp_hdr));

	/* TODO, 暂时只处理L2TPv2版本, L2TPv3待添加 */
	if(2 != pl2tphdrv2->version){
		if(3 == pl2tphdrv2->version){
			sapp_runtime_log(20, "recv l2tp version3 packet, but not support yet, TODO!\n");
		}
		return 0;
	}
	
	if(1 == pl2tphdrv2->type){ /* control message valid check */
		if(0 == pl2tphdrv2->length_present){
			return 0; /* control mesage length must be set to 1, refer to RFC2661 page10. */
		}

		if(0 == pl2tphdrv2->seq_present){
			return 0; /* control mesage seq must be set to 1, refer to RFC2661 page10. */
		}

		if(1 == pl2tphdrv2->offset_present){
			return 0; /* control mesage offset must be set to 0, refer to RFC2661 page10. */
		}

		if(1 == pl2tphdrv2->priority){
			return 0; /* control mesage priority must be set to 0, refer to RFC2661 page10. */
		}		
	}
	if(pl2tphdrv2->length_present){
		l2tp_len = (unsigned short *)((char *)pl2tphdrv2 + sizeof(struct l2tp_hdr_v2));

		if(ntohs(*l2tp_len) != ntohs(udph->uh_ulen)-8){
			return 0; /* 长度不匹配, 不是L2TP, 也许是其他协议复用了UDP 1701端口, 凑巧而已 */
		}
	}

	return 1;
}

static int l2tp_insert_to_stream_hash(int tid, struct l2tp_stream_key *l2tp_key, const struct streaminfo *a_udp)
{
	struct l2tp_info_pri *l2tp_pri;
	int hash_ret;

	/* 因为控制连接首先创建HASH节点, 同时插入一个空的l2tp_pri结构, HASH表中的元素在data_channel连接终止时, 在data通道中删除 */
	l2tp_pri = (struct l2tp_info_pri *)dictator_malloc(tid, sizeof(struct l2tp_info_pri));
	l2tp_context_init(l2tp_pri, tid, a_udp);
	l2tp_pri->ssinfo.session_state = 0; /* PPTP数据传输阶段, 不方便判断pending, data, close状态, 靠判断当前session-state值决定 */
	memcpy(&l2tp_pri->l2tp_key, l2tp_key, sizeof(struct l2tp_stream_key));

	/* TODO, 增加嵌套地址链表 */
	hash_ret = MESA_htable_add(g_l2tp_htable_array[tid], (const uchar *)l2tp_key, sizeof(struct l2tp_stream_key), l2tp_pri);
	if(hash_ret < 0){
		dictator_free(tid,  l2tp_pri);
	}else{
#ifdef MESA_HTABLE_VERSION_MACRO
	#if MESA_HTABLE_VERSION_MACRO >= 20170104
		int len, max_times;
		double avg_times;
		len = sizeof(int);
		MESA_htable_get_opt(g_l2tp_htable_array[tid], MHO_HASH_SEARCH_MAX_TIMES, &max_times, &len);

		len = sizeof(double);
		MESA_htable_get_opt(g_l2tp_htable_array[tid], MHO_HASH_SEARCH_AVG_TIMES, &avg_times, &len);

		if(max_times > sapp_global_mthread[tid].l2tp_hash_max_search_times){
			sapp_global_mthread[tid].l2tp_hash_max_search_times = max_times;
			sapp_runtime_log(30, "l2tp hash max search times: %d, thread seq:%d.\n", max_times, tid);
		}
		if(avg_times > sapp_global_mthread[tid].l2tp_hash_avg_search_times){
			sapp_global_mthread[tid].l2tp_hash_avg_search_times = avg_times;
			sapp_runtime_log(30, "l2tp hash avg search times: %.2f, thread seq:%d.\n", avg_times, tid);
		}
	#endif
#else	
		if(hash_ret > 29){
			/* 
				2017-01-03 lijia add, 被迫添加此判断:
				受限于HASH算法只能用IP对, (端口虽然使用, 但通常都是1701),
				当HASH冲突严重时, 主动丢弃部分PPTP流, 防止单包处理延时太长, 保证不影响其他业务. 
			*/
			MESA_htable_del(g_l2tp_htable_array[tid], (const uchar *)l2tp_key, sizeof(struct l2tp_stream_key), NULL);
		}
#endif		
	}
	return hash_ret;
}

static char l2tp_ctrl_pkt_parse(const struct streaminfo *a_udp, struct l2tp_info_pri *l2tp_pri, 
			const struct l2tp_hdr_v2 *pl2tphdrv2, const struct mesa_udp_hdr *udph)
{
	struct layer_addr_l2tp l2tp_addr;
	int l2tp_addr_actual_len;
	const struct l2tp_avp *pavp;
	const unsigned short *p_msg_type;
	const struct streaminfo_private *a_udp_pr = (const struct streaminfo_private *)a_udp;
	struct l2tp_stream_key *l2tp_key;
	
	l2tp_addr_actual_len = parse_l2tpv2_hdr(pl2tphdrv2,  &l2tp_addr, 1);
	if((l2tp_addr_actual_len < 0) || (l2tp_addr_actual_len > 16)){ /* 2017-12-20, 保护性判断, 长度不能超范围 */
		return APP_STATE_DROPME;
	}		

	if(a_udp->pudpdetail->datalen - l2tp_addr_actual_len <= sizeof(struct l2tp_avp)){
		/* 没有可用AVP, 通常是ZLB包, 不用处理 */
		return APP_STATE_GIVEME;
	}

	pavp = (const struct l2tp_avp *)((char *)pl2tphdrv2 + l2tp_addr_actual_len);
	//int avp_len = L2TP_AVP_GET_LEN(pavp->M_H_rsvd_len_union);

	p_msg_type = (const unsigned short *)((char *)pavp + sizeof(struct l2tp_avp));

	l2tp_key = &l2tp_pri->l2tp_key;

	if(0 == ntohs(pavp->attribute_type)){
		switch(ntohs(*p_msg_type)){
			case L2TP_CTRL_MSG_SCCRQ:
				/* TODO, 解析AVP内容, 单向流情况下可获取对方tunnel_id */
			break;

			case L2TP_CTRL_MSG_SCCRP:
				/* TODO, 解析AVP内容, 单向流情况下可获取对方tunnel_id */
			break;
			
			case L2TP_CTRL_MSG_ICRQ:
				/* TODO, 解析AVP内容, 单向流情况下可获取对方session_id */
			break;
			
			case L2TP_CTRL_MSG_ICRP:
				/* TODO, 解析AVP内容, 单向流情况下可获取对方session_id */
			{
				/* NOTE: 此处的IP地址和UDP端口要从原始包中获取, 因为stream->addr的地址按大端口是源的规则, 可能已经转化过了 */
				const struct mesa_ip4_hdr *ip4hdr = (const struct mesa_ip4_hdr *)((char *)udph - a_udp_pr->offset_to_ip_hdr);
				l2tp_key->sip = ip4hdr->ip_dst.s_addr; /* 反向 */
				l2tp_key->dip = ip4hdr->ip_src.s_addr; /* 反向 */
				l2tp_key->sport = udph->uh_dport; /* 反向 */
				l2tp_key->dport = udph->uh_sport; /* 反向 */
				l2tp_key->dip_side_tunnel_id = l2tp_addr.l2tpun.l2tp_addr_v2.tunnelid_C2S;
				l2tp_key->dip_side_session_id = l2tp_addr.l2tpun.l2tp_addr_v2.sessionid_C2S;				
				/* 对侧的id在ICCN包中获取 */
			}				
			break;

			case L2TP_CTRL_MSG_ICCN:
			{
				/* NOTE: 此处的IP地址和UDP端口要从原始包中获取, 因为stream->addr的地址按大端口是源的规则, 可能已经转化过了 */
				const struct mesa_ip4_hdr *ip4hdr = (const struct mesa_ip4_hdr *)((char *)udph - a_udp_pr->offset_to_ip_hdr);
				
				l2tp_key->sip = ip4hdr->ip_src.s_addr;
				l2tp_key->dip = ip4hdr->ip_dst.s_addr;
				l2tp_key->sport = udph->uh_sport;
				l2tp_key->dport = udph->uh_dport;
				l2tp_key->sip_side_tunnel_id = l2tp_addr.l2tpun.l2tp_addr_v2.tunnelid_C2S;
				l2tp_key->sip_side_session_id = l2tp_addr.l2tpun.l2tp_addr_v2.sessionid_C2S;
				/* 对侧的id在ICRP包中获取 */
			}
			break;

			case L2TP_CTRL_MSG_STOP_CCN:
			{
				const struct mesa_ip4_hdr *ip4hdr = (const struct mesa_ip4_hdr *)((char *)udph - a_udp_pr->offset_to_ip_hdr);
				/* 控制连接结束 */
				l2tp_pri->ssinfo.session_state = SESSION_STATE_CLOSE;
				l2tp_call_biz_plug(a_udp, l2tp_pri, ip4hdr);		
				/* 在返回后, l2tp_protocol_entry()中从HASH表删除 */
				return APP_STATE_DROPME;
			}
			break;

			default:
			break;
		}
	}else{
		;/* 其他类型AVP暂不关心 */
	}

	if((l2tp_key->sip_side_tunnel_id != 0)
	 && (l2tp_key->sip_side_session_id != 0)
	 && (l2tp_key->dip_side_tunnel_id != 0)
	 && (l2tp_key->dip_side_session_id != 0)){
	 	/* 获取到了双向id, insert to hash */
		l2tp_insert_to_stream_hash(a_udp->threadnum, l2tp_key, a_udp); 
	} 

	return APP_STATE_GIVEME;
}

static int l2tp_process(const struct streaminfo *a_udp, struct l2tp_info_pri *l2tp_pri, 
					const void *ip_hdr, const struct mesa_udp_hdr *udph)
{
	const struct l2tp_hdr_v2 *pl2tphdrv2;
	int ret = APP_STATE_GIVEME;
	
	pl2tphdrv2 = (const struct l2tp_hdr_v2 *)((char *)udph + sizeof(struct mesa_udp_hdr));

	if(OP_STATE_PENDING == a_udp->opstate){
		l2tp_pri->ssinfo.prot_flag = L2TP_OPT_LINK_TYPE;
		l2tp_pri->tunnel_context.l2tp_info.link_type = TUNNEL_CHANNEL_TYPE_CONTROL;
		l2tp_pri->ssinfo.buf = (void *)&l2tp_pri->tunnel_context.l2tp_info.link_type;
		l2tp_pri->ssinfo.buflen = sizeof(int);
		l2tp_call_biz_plug(a_udp, l2tp_pri, ip_hdr);
	}

	if(1 == pl2tphdrv2->type){
		ret = l2tp_ctrl_pkt_parse(a_udp, l2tp_pri, pl2tphdrv2, udph);
	}
	
	return ret;
}

char l2tp_protocol_entry(const struct streaminfo *a_udp,  void **pme, int thread_seq, 
				const void *ip_hdr)
{
	struct l2tp_info_pri *l2tp_pri;
	int pro_plug_ret = APP_STATE_GIVEME;
	const struct mesa_udp_hdr *udph;
	const struct mesa_ip4_hdr *ip4hdr = (const struct mesa_ip4_hdr *)ip_hdr;

	switch(a_udp->opstate){
		case OP_STATE_PENDING:
		{
			udph = (const struct mesa_udp_hdr *)((char *)ip_hdr + ip4hdr->ip_hl * 4);
			if(0 == guess_if_l2tpv2(a_udp, udph)){
				return APP_STATE_DROPME;
			}
			/* L2TP协议解析层兼顾一个功能, 就是识别出L2TP隧道后, 要在当前UDP流上打标记, 
			   dealipv4udppkt()函数才会继续调用l2tpv2_entry(), 解析隧道上层承载协议.
			 */
			struct streaminfo_private *a_udp_pr = (struct streaminfo_private *)a_udp;
			a_udp_pr->stream_carry_up_layer_tunnel_type |= STREAM_TUNNLE_L2TP;

			l2tp_pri = (struct l2tp_info_pri *)dictator_malloc(thread_seq, sizeof(struct l2tp_info_pri));
			l2tp_context_init(l2tp_pri, thread_seq, a_udp);
			*pme = l2tp_pri;
			pro_plug_ret = l2tp_process(a_udp, l2tp_pri, ip_hdr, udph);
		}	
		break;

		case OP_STATE_DATA:
			udph = (const struct mesa_udp_hdr *)((char *)ip_hdr + ip4hdr->ip_hl * 4);
			l2tp_pri = (struct l2tp_info_pri *)(*pme);
			l2tp_pri->ssinfo.session_state = SESSION_STATE_DATA;
			pro_plug_ret = l2tp_process(a_udp, l2tp_pri, ip_hdr, udph);
		break;

		case OP_STATE_CLOSE:
			l2tp_pri = (struct l2tp_info_pri *)(*pme);
			l2tp_pri->ssinfo.session_state = SESSION_STATE_CLOSE;
			l2tp_call_biz_plug(a_udp, l2tp_pri, ip_hdr);	
			pro_plug_ret = APP_STATE_DROPME;
		break;

		default:
		break;
	}

	if(APP_STATE_DROPME == pro_plug_ret){
		if(*pme != NULL){
			MESA_htable_del(g_l2tp_htable_array[a_udp->threadnum], (const uchar *)&l2tp_pri->l2tp_key, sizeof(struct l2tp_stream_key), NULL);
			dictator_free(thread_seq, *pme);
		}
	}
	
	return pro_plug_ret;
}


/* 强制淘汰回调, 需要最后调用业务层插件 */
static void l2tp_stream_data_free_passive(void *data)
{
	struct l2tp_info_pri *l2tp_data_channel_pri = (struct l2tp_info_pri *)data;
	unsigned char tid = l2tp_data_channel_pri->thread_seq;

	/* 
	    NOTE:
	    l2tp hash元素不靠被动结束, 基于底层UDP流结束, 
	    在控制连接主动调用了stopCCN方法, 或底层UDP被超时淘汰时, 
	    先要把数据连接的l2tp_data_pri清空, 并通知业务插件.
	*/
	l2tp_data_channel_pri->ssinfo.session_state = SESSION_STATE_CLOSE;
	PROT_PROCESS(&l2tp_data_channel_pri->ssinfo, &l2tp_data_channel_pri->biz_pme, tid, (struct streaminfo *)l2tp_data_channel_pri->my_stream, NULL);

	dictator_free(tid, data);
}

static uint l2tp_stream_key2index(const MESA_htable_handle table, const uchar * key, uint size)
{
	const struct l2tp_stream_key *l2tp_key = (const struct l2tp_stream_key *)key;
	/* NOTE:
	   不能使用tunnel_id和session_id做为key, 
	   因为当前包只有一个方向有id, 另一个方向没有, 导致双向hash不一致 
	 */
	unsigned int i;
	unsigned char *ptr;
	unsigned int seed = 13131;
	unsigned int hash = 0;
	unsigned int sip, dip;

	if(l2tp_key->sip >= l2tp_key->dip){
		sip = l2tp_key->sip;
		dip = l2tp_key->dip;
	}else{
		sip = l2tp_key->dip;
		dip = l2tp_key->sip;
	}
	
	ptr = (unsigned char *)&sip;
	for(i = 0; i < sizeof(int); i++){
		hash = hash * seed + (*ptr++);
	}

	ptr = (unsigned char *)&dip;
	for(i = 0; i < sizeof(int); i++){
		hash = hash * seed + (*ptr++);
	}

	return hash;
}


static int l2tp_stream_key_comp(const uchar * key1, uint size1, const uchar * key2, uint size2)
{
	const struct l2tp_stream_key *l2tp_key1 = (const struct l2tp_stream_key *)key1;
	const struct l2tp_stream_key *l2tp_key2 = (const struct l2tp_stream_key *)key2;	

	/* 先判断IP和端口, 分清两个方向 */
	if((l2tp_key1->sip == l2tp_key2->sip) 
	  && (l2tp_key1->dip == l2tp_key2->dip)
	  && (l2tp_key1->sport == l2tp_key2->sport) 
	  && (l2tp_key1->dport == l2tp_key2->dport)){ 
		if((l2tp_key1->sip_side_tunnel_id == l2tp_key2->sip_side_tunnel_id)
		 &&(l2tp_key1->sip_side_session_id == l2tp_key2->sip_side_session_id)){
			return 0;
		}
		if((l2tp_key1->dip_side_tunnel_id == l2tp_key2->dip_side_tunnel_id)
		 &&(l2tp_key1->dip_side_session_id == l2tp_key2->dip_side_session_id)){
			return 0;
		}		
	}
	/* 反向比较 */
      else if((l2tp_key1->sip == l2tp_key2->dip) 
	  && (l2tp_key1->dip == l2tp_key2->sip)
	  && (l2tp_key1->sport == l2tp_key2->dport) 
	  && (l2tp_key1->dport == l2tp_key2->sport)){ 
		if((l2tp_key1->sip_side_tunnel_id == l2tp_key2->dip_side_tunnel_id)
		 &&(l2tp_key1->sip_side_session_id == l2tp_key2->dip_side_session_id)){
			return 0;
		}
		if((l2tp_key1->dip_side_tunnel_id == l2tp_key2->sip_side_tunnel_id)
		 &&(l2tp_key1->dip_side_session_id == l2tp_key2->sip_side_session_id)){
			return 0;
		}	
	}

	/* TODO, 判断嵌套地址链表, 目前仅判断了最外层的IP, PORT和call_id */
	return -1;
}


static uchar *l2tp_stream_key_dup(const uchar *key, uint key_size)
{
	const struct l2tp_stream_key *pptp_stack_key = (const struct l2tp_stream_key *)key;
	struct l2tp_stream_key *l2tp_heap_key;

	/* TODO, 需要和l2tp_stream_key_free()函数匹配, 改为dictator_malloc(), 增加threadnum, free时也要用标准free() */
	l2tp_heap_key = (struct l2tp_stream_key *)malloc(sizeof(struct l2tp_stream_key));
	memcpy(l2tp_heap_key, pptp_stack_key, sizeof(struct l2tp_stream_key));

	return (uchar *)l2tp_heap_key;
}

static void l2tp_stream_key_free(uchar *key, uint key_size)
{
	/* TODO, 需要和l2tp_stream_key_dup()函数匹配, 改为dictator_malloc(), 需要增加threadnum */
	free(key);
}

/* 创建PPTP 流表, 用于存储data阶段的 struct pptp_info_pri结构 */
static MESA_htable_handle l2tp_stream_hash_create(void)
{
	MESA_htable_handle htable;
	int opt_int;
	
	htable = MESA_htable_born();

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_THREAD_SAFE, &opt_int, sizeof(int));

	opt_int = 1024 * 512;
	MESA_htable_set_opt(htable, MHO_HASH_SLOT_SIZE, &opt_int, sizeof(int));

	/* 可能因HASH冲突导致新流无法处理, 需靠超时淘汰旧流 */
	opt_int = 100;
	MESA_htable_set_opt(htable, MHO_EXPIRE_TIME, &opt_int, sizeof(int));

	/* L2TP控制连接数量取决于底层UDP流的数量, 不设主动淘汰或最大值 */
	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_HASH_MAX_ELEMENT_NUM, (void *)&opt_int, sizeof(int));

	MESA_htable_set_opt(htable, MHO_CBFUN_DATA_FREE, (void *)&l2tp_stream_data_free_passive, sizeof(void *));
	
	MESA_htable_set_opt(htable, MHO_CBFUN_KEY_TO_INDEX, (void *)&l2tp_stream_key2index, sizeof(void *));

	MESA_htable_set_opt(htable, MHO_CBFUN_KEY_COMPARE, (void *)&l2tp_stream_key_comp, sizeof(void *));	

	MESA_htable_set_opt(htable, MHO_CBFUN_COMPLEX_KEY_DUP, (void *)&l2tp_stream_key_dup, sizeof(void *));	

	MESA_htable_set_opt(htable, MHO_CBFUN_COMPLEX_KEY_FREE, (void *)&l2tp_stream_key_free, sizeof(void *));

	MESA_htable_mature(htable);

	return htable;
}

void l2tp_protocol_funstat(unsigned long long protflag)
{
	;
}

long long l2tp_protocol_flag_change(char* flag_str)
{
	return (long long)0x7FFFFFFFFFFFFFFFL;
}

void l2tp_protocol_get_plugid(unsigned short plugid)
{
	g_l2tp_plugid = plugid;
}

int l2tp_protocol_init(void)
{
	int thread_cnt = get_thread_count();
	int i;
	
	g_l2tp_htable_array = (MESA_htable_handle *)malloc(sizeof(MESA_htable_handle) * thread_cnt);
	memset(g_l2tp_htable_array, 0, sizeof(MESA_htable_handle) * thread_cnt);

	for(i = 0; i < thread_cnt; i++){
		g_l2tp_htable_array[i] = l2tp_stream_hash_create();
	}

	return g_l2tp_plugid;
}

void l2tp_protocol_destroy(void)
{
	;
}

#ifdef __cplusplus
}
#endif
