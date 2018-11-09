/* 详见: RFC2661, RFC3931 */
#ifdef __cplusplus
extern "C" {
#endif


/*
	TODO 1:

	建立L2TP全局hash, 靠地址链确定一个L2TP隧道,

	例如: 
		MAC--IPv4--UDP--L2TP, 则地址全一样的为一个L2TP隧道,

		L2TP第一个包(HASH中不存在)创建hash节点, l2tp_stream, 
		当另一个方向的L2TP到来时, 查找到hash表节点, 知道两端tunnelid, sessionid的对应关系,
		并存储到l2tp_stream中,
		
		在上层传输层创建TCP, UDP时, 将l2tp_stream指针存储于TCP->father->l2tp层的pdetail_pr结构,


		1-收到C2S方向的L2TP包, 查找HASH不存在, 新创建一个l2tp-stream, 同时传输层创立了一个新TCP流, 
		  将l2tp_stream指针存储于TCP->father->l2tp层的pdetail_pr结构,
		  同时TCP->father->l2tp层的pdetail_pr结构,也存储l2tp_stream指针,
		  此时use_addr_as_hash设为0, 因为还不知道对端情况;

		  l2tp-stream-hash表设置为和tcp一样多, 防止还在使用时就被强制free了.
		  
		2-收到S2C方向的L2TP包, 再查找HASH, 如果底层地址链一样, 则认为是同一个L2TP隧道;
		3-存储两方向的地址到L2TP-stream中, 同时将use_addr_as_hash设为1, 即两端地址都确定了, 要精确匹配;
		4-当l2tp地址dir=3时, 且双向包都超过1个时, 即可主动free掉l2tp-stream了, 节约内存.
		
*/
#include "stream.h" 
#include "stream_internal.h" 
#include "stream_manage.h"
#include "packet_io.h"	
#include "mesa_net.h"
#include "deal_ppp.h"
#include "MESA_htable.h"
#include <assert.h>

#define L2TP_DEBUG    	(0)
#if L2TP_DEBUG
#define L2TP_PRINT(fmt, args...) printf(fmt, ##args)
#else
#define L2TP_PRINT(fmt, args...) 
#endif

#define L2TP_MAX_HDR_LEN		(16)

MESA_htable_handle *g_l2tp_htable_array; 
unsigned short g_l2tp_plugid;

int parse_l2tpv2_hdr(const struct l2tp_hdr_v2 *pl2tphdrv2, struct layer_addr_l2tp *l2tpaddr, UCHAR layer_addr)
{
	unsigned short l2top_tot_len, offset_size;
	const char *ptr = (const char *)pl2tphdrv2 + sizeof(struct l2tp_hdr_v2);
	
	if(pl2tphdrv2->length_present){
		l2top_tot_len = ntohs(*((unsigned short *)ptr));
		ptr += sizeof(short);
		if(l2top_tot_len < sizeof(struct l2tp_hdr_v2) +  sizeof(struct mesa_ppp_hdr) + sizeof(struct mesa_ip4_hdr)){
			return -1; /* 无有效数据 */
		}
	}

	if(1 == layer_addr){
		l2tpaddr->l2tpun.l2tp_addr_v2.tunnelid_C2S = *((unsigned short *)ptr);
		ptr += sizeof(short);
		l2tpaddr->l2tpun.l2tp_addr_v2.sessionid_C2S = *((unsigned short *)ptr);
		ptr += sizeof(short);	
	}else{
		l2tpaddr->l2tpun.l2tp_addr_v2.tunnelid_S2C = *((unsigned short *)ptr);
		ptr += sizeof(short);
		l2tpaddr->l2tpun.l2tp_addr_v2.sessionid_S2C = *((unsigned short *)ptr);
		ptr += sizeof(short);	
	}

	if(pl2tphdrv2->seq_present){
		ptr += sizeof(int);	
	}

	if(pl2tphdrv2->offset_present){
		offset_size = ntohs(*((unsigned short *)ptr));
		ptr += sizeof(short);	 /* 2 byte fix len offset size */
		ptr += offset_size;  /* var bytes offset value length */
	}	

	l2tpaddr->version = 2; /* version, RFC2661 */

	return ptr - (char *)pl2tphdrv2;
}

int calc_l2tp_hdr_len(const struct l2tp_hdr_v2 *l2tp_hdr)
{
	int l2tphdr_len;
	struct layer_addr_l2tp no_use_addr;
	
	l2tphdr_len = parse_l2tpv2_hdr(l2tp_hdr, &no_use_addr, 1);

	return l2tphdr_len;
}


static struct l2tp_info_pri *l2tp_find_ctrl_info(struct streaminfo_private *pstream_pr,
			const struct mesa_udp_hdr *udph, struct layer_addr_l2tp *l2tpaddr)
{
	struct l2tp_stream_key l2tp_key;
	struct l2tp_info_pri * l2tp_pri;
	const struct mesa_ip4_hdr *ip4hdr;
	
	if((NULL == g_l2tp_htable_array) || (0 == g_l2tp_plugid)){
		/* 协议解析层未开启, 或未初始化成功 */
		return NULL;
	}
	
	ip4hdr = (const struct mesa_ip4_hdr *)((char *)udph - pstream_pr->offset_to_ip_hdr);

	memset(&l2tp_key, 0, sizeof(struct l2tp_stream_key));

	l2tp_key.sip = ip4hdr->ip_src.s_addr;
	l2tp_key.dip = ip4hdr->ip_dst.s_addr;
	l2tp_key.sport = udph->uh_sport;
	l2tp_key.dport = udph->uh_dport;
	if(1 == pstream_pr->layer_dir){
		l2tp_key.sip_side_tunnel_id = l2tpaddr->l2tpun.l2tp_addr_v2.tunnelid_C2S;
		l2tp_key.sip_side_session_id = l2tpaddr->l2tpun.l2tp_addr_v2.sessionid_C2S;
	}else{
		l2tp_key.sip_side_tunnel_id = l2tpaddr->l2tpun.l2tp_addr_v2.tunnelid_S2C;
		l2tp_key.sip_side_session_id = l2tpaddr->l2tpun.l2tp_addr_v2.sessionid_S2C;
	}

	l2tp_pri = (struct l2tp_info_pri * )MESA_htable_search(
						g_l2tp_htable_array[pstream_pr->stream_public.threadnum], 
						(const unsigned char*)&l2tp_key, 
						sizeof(struct l2tp_stream_key));

	return l2tp_pri;
}


/* 主动删除回调函数, 直接free(pptp_pri)即可 */
static void l2tp_stream_data_free_active(void *data)
{
	struct l2tp_info_pri *l2tp_pri = (struct l2tp_info_pri *)data;
	unsigned char tid = l2tp_pri->thread_seq;

	if(l2tp_pri->tunnel_context.l2tp_info.chap_username != NULL){
		dictator_free(tid, l2tp_pri->tunnel_context.l2tp_info.chap_username);
	}
	dictator_free(tid, data);
}

static int l2tp_data_channel_remove_hash(int tid, struct l2tp_stream_key *l2tp_key)
{
	int hash_ret;

	/* hash中的数据实际由control_link创建. */
	hash_ret = MESA_htable_del(g_l2tp_htable_array[tid], (const uchar *)l2tp_key, sizeof(struct l2tp_stream_key), l2tp_stream_data_free_active);

	assert(hash_ret >= 0);
	
	return hash_ret;
}


static char l2tp_data_channel_call_biz_plug(struct streaminfo *pstream, struct l2tp_info_pri *l2tp_pri)
{
	char biz_plug_ret;
	void *ip_hdr;
	
	struct streaminfo_private *ip_pstream_pr = (struct streaminfo_private *)pstream->pfather;
	ip_hdr = (char *)ip_pstream_pr->raw_pkt->raw_pkt_data + ip_pstream_pr->offset_to_raw_pkt_hdr;
	
	if(0 == l2tp_pri->ssinfo.session_state){
		/* 第一次先设置session_state, 和data or control类型, 因为外部调用者已经设置了pptp_pri->ssinfo, 所以本次调用使用栈里的临时变量 */
		stSessionInfo tmp_sinfo; 
		int tmp_link_type = TUNNEL_CHANNEL_TYPE_DATA;

		memset(&tmp_sinfo, 0, sizeof(stSessionInfo));
		tmp_sinfo.plugid = g_l2tp_plugid;
		tmp_sinfo.session_state = SESSION_STATE_PENDING; 
		tmp_sinfo.prot_flag = L2TP_OPT_LINK_TYPE; 
		tmp_sinfo.buf = &tmp_link_type;
		tmp_sinfo.buflen = sizeof(int);
		
		PROT_PROCESS(&tmp_sinfo, &l2tp_pri->biz_pme, pstream->threadnum, (struct streaminfo * )pstream, ip_hdr);
		l2tp_pri->ssinfo.session_state = SESSION_STATE_DATA; /* 第一次调用之后, 修改session_state为DATA */
	}

	biz_plug_ret = PROT_PROCESS(&l2tp_pri->ssinfo, &l2tp_pri->biz_pme, pstream->threadnum, (struct streaminfo * )pstream, ip_hdr);	
	
	/* clear status */
	l2tp_pri->ssinfo.prot_flag = TUNNEL_PHONY_PROT_FLAG;
	l2tp_pri->ssinfo.buf = NULL;
	l2tp_pri->ssinfo.buflen = 0;

	return biz_retval_to_platform(biz_plug_ret);
}

static void l2tp_lcp_pkt_parse(struct streaminfo_private *pstream_pr, 
		const struct mesa_ppp_lcp_ack_hdr *plcp_hdr, struct l2tp_info_pri *l2tp_pri)
{
	int ret;
	unsigned long long field_flag = 0;
	ppp_lcp_field_data_t result;

	ret = ppp_lcp_pkt_parse(plcp_hdr, &field_flag, &result);
	if(ret != 0){
		if(PPP_LCP_FIELD_FLAG_AUTH_PRO_TYPE & field_flag){
			l2tp_pri->tunnel_context.l2tp_info.authentication_pro = result.ppp_lcp_field_pro_type; /* 存储认证类型 */
		}

		if(PPP_LCP_FIELD_FLAG_PRO_FIELD_COMPRESS & field_flag){
			l2tp_pri->tunnel_context.pptp_info.protocol_compress_enable = result.ppp_lcp_field_pro_type; /* 存储压缩选项 */
		}

		if(PPP_LCP_OPT_ADDR_CTRL_FIELD_COMPRESS & field_flag){
			l2tp_pri->tunnel_context.pptp_info.addr_ctrl_compress_enable = result.ppp_lcp_field_pro_type; /* 存储压缩选项 */
		}
	}

	return;
}

static void l2tp_ccp_pkt_parse(struct streaminfo_private *pstream_pr, 
		const struct mesa_ppp_ccp_ack_hdr *pccp_hdr, struct l2tp_info_pri *l2tp_pri)
{
	int ret;
	unsigned long long field_flag = 0;
	ppp_ccp_field_data_t result;

	ret = ppp_ccp_pkt_parse(pccp_hdr, &field_flag, &result);
	if(ret != 0){
		if(PPP_CCP_FIELD_FLAG_COMPRESS & field_flag){
			/* what to do? */;
		}

		if(PPP_CCP_FIELD_FLAG_ENCRYPT_TYPE & field_flag){
			l2tp_pri->ssinfo.prot_flag = L2TP_OPT_ENCRYPT_PRO;
			l2tp_pri->ssinfo.buf = &result.ppp_ccp_field_encrypt_type;
			l2tp_pri->ssinfo.buflen = sizeof(int);					
			l2tp_data_channel_call_biz_plug(&pstream_pr->stream_public, l2tp_pri);

			l2tp_pri->tunnel_context.l2tp_info.encrypt_pro = result.ppp_ccp_field_encrypt_type;;
		}
	}
	
}


static void l2tp_chap_pkt_parse(const struct mesa_ppp_chap_hdr *chap_hdr, struct l2tp_info_pri *l2tp_pri)
{
	int ret;
	char chap_uname[256];
	int chap_uname_len = 256;
	
	ret = ppp_chap_pkt_parse(chap_hdr, chap_uname, &chap_uname_len);	
	if(ret >= 0){
		l2tp_pri->tunnel_context.l2tp_info.chap_username = (char *)dictator_malloc(l2tp_pri->thread_seq, chap_uname_len);
		memcpy(l2tp_pri->tunnel_context.l2tp_info.chap_username, chap_uname, chap_uname_len);
	}

	return;
}

/*
	NOTE: 本层的参数this_layer_data->指向承载的UDP层, 因为要判断是否为L2TP协议.
*/
int l2tpv2_entry(struct streaminfo_private *pfstream_pr,const void *this_layer_data,int thread_num, 
						unsigned char routedir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr)
{
#if COMPAT_PAPP_FOR_BENCHMARK
	return PASS;
#endif

	struct streamindex tmp_index;
	struct streamindex *ptmp=&tmp_index;
	struct streaminfo_private *pstream_pr = &ptmp->stream;
	struct streaminfo *pstream = &pstream_pr->stream_public;	
	struct layer_addr_l2tp l2tpaddr;
	const struct l2tp_hdr_v2 *pl2tphdrv2;
	int ret = PASS;
	int l2tphdr_len;
	char *next_layer_hdr; 
	const struct mesa_ppp_hdr *ppp_net_addr;
	int next_layer_offset;
	struct l2tp_info_pri *l2tp_pri;
	
	/* 之前已经通过协议识别插件guess_if_l2tpv2()识别过, 所以在l2tpv2_entry()里不用再次判断 */
	pl2tphdrv2 = (const struct l2tp_hdr_v2 *)((char *)this_layer_data + sizeof(struct mesa_udp_hdr));

	/* L2TP层只有单向id, 先复用father的layer_dir */
	l2tphdr_len = parse_l2tpv2_hdr(pl2tphdrv2, &l2tpaddr, pfstream_pr->layer_dir);
	if((l2tphdr_len < 0) || (l2tphdr_len > L2TP_MAX_HDR_LEN)){
		return PASS;
	}

	if(1 == pl2tphdrv2->type){ 
		/* control message, deal_l2tp模块不处理, 在l2tp_protocol_plug插件中处理 */
		return PASS;
	}

	l2tp_pri = l2tp_find_ctrl_info(pfstream_pr, (const struct mesa_udp_hdr *)this_layer_data, &l2tpaddr);
	
	memset(&tmp_index, 0, sizeof(struct streamindex));
	pstream->addr.paddr = &l2tpaddr;
	pstream->addr.addrtype = ADDR_TYPE_L2TP;
	pstream->addr.addrlen = sizeof(struct layer_addr_l2tp); /* 此处使用结构体长度, l2tphdr_len表示网络中传输的L2TP实际头部长度,可能很多头部字段缺失 */

	/* 
		TODO 1:
		L2TP的ID只有单方向本地意义, 而且本端暂无法获取对端的ID, 不像IP, TCP层源和目的同时存在, 
		和PPTP的协议解析层一样, 获取CS双方的tunnelid和sessionid, 根据四元组,两个ID, 和嵌套地址链表创建L2TP流,
		并调用l2tp业务层插件.
	*/
	//tream_pr->addr_use_as_hash = 1;
	pstream_pr->addr_use_as_hash = 0;
	
	pstream_pr->offset_to_raw_pkt_hdr = offset_to_raw_pkt_hdr;
	pstream_pr->raw_pkt = raw_pkt;
	pstream_pr->layer_dir = pfstream_pr->layer_dir; /* L2TP层不能对本层做出方向性判断, 使用父层的方向值, L2TP只能是UDP或IP承载 */
	
	pstream->pfather=&pfstream_pr->stream_public;
	pstream->type=STREAM_TYPE_L2TP;
	pstream->routedir=routedir;
	pstream->threadnum=thread_num;

	next_layer_hdr = (char *)pl2tphdrv2 + l2tphdr_len + sizeof(struct mesa_ppp_hdr);
	ppp_net_addr = (const struct mesa_ppp_hdr *)((char *)pl2tphdrv2 + l2tphdr_len);
	next_layer_offset = offset_to_raw_pkt_hdr + l2tphdr_len + sizeof(struct mesa_ppp_hdr); 

	//ret=ppp_entry(pstream_pr,(const void *)next_layer_hdr,thread_num,routedir,raw_pkt, offset_to_raw_pkt_hdr + l2tphdr_len);		

	//l2tp_ppp_entry(&tmp_index, (const void *)next_layer_hdr,thread_num,routedir,raw_pkt, offset_to_raw_pkt_hdr + l2tphdr_len);

	switch(ntohs(ppp_net_addr->protocol)){
		case PPP_PROTOCOL_IPv4:
			/* 开始进入隧道内部数据传输阶段, 此时应该先告之业务插件content_type */
			if((l2tp_pri != NULL) && (0 == l2tp_pri->content_notify_biz_flag)){
				l2tp_pri->ssinfo.prot_flag = L2TP_CONTENT_TYPE;
				l2tp_pri->tunnel_context.l2tp_info.content_type = TUNNEL_CONTENT_TYPE_CLEAR;
				l2tp_pri->ssinfo.buf = &l2tp_pri->tunnel_context.l2tp_info.content_type;
				l2tp_pri->ssinfo.buflen = sizeof(int);					
				l2tp_data_channel_call_biz_plug(&pstream_pr->stream_public, l2tp_pri);
				l2tp_pri->content_notify_biz_flag = 1;
			}		
			ret=ipv4_entry(pstream_pr,(const void *)next_layer_hdr,thread_num,routedir,raw_pkt,next_layer_offset);
		break;

		case PPP_PROTOCOL_IPv6:
			/* 开始进入隧道内部数据传输阶段, 此时应该先告之业务插件content_type */
			if((l2tp_pri != NULL) && (0 == l2tp_pri->content_notify_biz_flag)){
				l2tp_pri->ssinfo.prot_flag = L2TP_CONTENT_TYPE;
				l2tp_pri->tunnel_context.l2tp_info.content_type = TUNNEL_CONTENT_TYPE_CLEAR;
				l2tp_pri->ssinfo.buf = &l2tp_pri->tunnel_context.l2tp_info.content_type;
				l2tp_pri->ssinfo.buflen = sizeof(int);					
				l2tp_data_channel_call_biz_plug(&pstream_pr->stream_public, l2tp_pri);
				l2tp_pri->content_notify_biz_flag = 1;
			}			
			ret=ipv6_entry(pstream_pr,(const void *)next_layer_hdr,thread_num,routedir,raw_pkt,next_layer_offset);
		break;

		case PPP_PROTOCOL_LCP:
		{
			/* 数据连接的LCP阶段, 如果找不到控制连接, 不再做后续处理, 结果无法存储 */
			if(NULL == l2tp_pri){
				break;
			}
			const struct mesa_ppp_lcp_ack_hdr *plcp_hdr = (const struct mesa_ppp_lcp_ack_hdr *)((const char *)pl2tphdrv2 + l2tphdr_len + sizeof(struct mesa_ppp_hdr));
			if(PPP_LCP_CODE_ACK == plcp_hdr->code){
				l2tp_lcp_pkt_parse(pstream_pr, plcp_hdr, l2tp_pri);
			}else if((PPP_LCP_CODE_TERMINATE_ACK == plcp_hdr->code)
			         || (PPP_LCP_CODE_TERMINATE_REQ == plcp_hdr->code)){
				/* 数据连接主动结束, 为了兼顾单向流, 收到任何一方的连接终止信息, 都终止当前数据连接的pptp流 */
				l2tp_pri->ssinfo.session_state = SESSION_STATE_CLOSE;
				l2tp_data_channel_call_biz_plug(&pstream_pr->stream_public, l2tp_pri);	
				l2tp_data_channel_remove_hash(thread_num, &l2tp_pri->l2tp_key);
			}
		}
		break;
		
		case PPP_PROTOCOL_CCP:
		{
			/* 数据连接的LCP阶段, 如果找不到控制连接, 不再做后续处理, 结果无法存储 */
			if(NULL == l2tp_pri){
				break;
			}		

			const struct mesa_ppp_ccp_ack_hdr *pccp_hdr = (const struct mesa_ppp_ccp_ack_hdr *)((const char *)pl2tphdrv2 + l2tphdr_len + sizeof(struct mesa_ppp_hdr));
			if(PPP_LCP_CODE_ACK == pccp_hdr->code){
				l2tp_ccp_pkt_parse(pstream_pr, pccp_hdr, l2tp_pri);
			}
		}
		break;

		case PPP_PROTOCOL_PAP:
			/* TODO 1*/
		break;
		
		case PPP_PROTOCOL_CHAP:
		{
			/* 数据连接的LCP阶段, 如果找不到控制连接, 不再做后续处理, 结果无法存储 */
			if(NULL == l2tp_pri){
				break;
			}		
			const struct mesa_ppp_chap_hdr *chap_hdr = (const struct mesa_ppp_chap_hdr *)((const char *)pl2tphdrv2 + l2tphdr_len + sizeof(struct mesa_ppp_hdr));
			l2tp_chap_pkt_parse(chap_hdr, l2tp_pri);
		}
		break;

		case PPP_COMPRESS_DATA:
			/* 开始进入隧道内部数据传输阶段, 此时应该先告之业务插件content_type,
				此时传输的是压缩数据, 如果之前LCP是加密, 则为加密模式, 否则是纯压缩模式.
			*/
			if((l2tp_pri != NULL) && (0 == l2tp_pri->content_notify_biz_flag)){
				l2tp_pri->ssinfo.prot_flag = L2TP_CONTENT_TYPE;
				if(l2tp_pri->tunnel_context.l2tp_info.encrypt_pro != 0){
					l2tp_pri->tunnel_context.l2tp_info.content_type = TUNNEL_CONTENT_TYPE_ENCRYPT;
				}else{
					l2tp_pri->tunnel_context.l2tp_info.content_type = TUNNEL_CONTENT_TYPE_COMPRESS;
				}
				l2tp_pri->ssinfo.buf = &l2tp_pri->tunnel_context.l2tp_info.content_type;
				l2tp_pri->ssinfo.buflen = sizeof(int);					
				l2tp_data_channel_call_biz_plug(&pstream_pr->stream_public, l2tp_pri);
				l2tp_pri->content_notify_biz_flag = 1;
			}
		break;

		default:
		break;
	}
	
	return ret;
}


#ifdef __cplusplus
}
#endif
