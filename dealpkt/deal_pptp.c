#ifdef __cplusplus
extern "C" {
#endif

#include "packet_io.h" 
#include "mesa_net.h" 
#include "deal_ppp.h" 
#include "stream_internal.h" 
#include "sendpacket.h"
#include "stream_manage.h"
#include <MESA/MESA_htable.h>

unsigned short g_pptp_plugid = 0;
MESA_htable_handle *g_pptp_htable_array; /* 内存申请和HASH创建由协议解析插件在初始化阶段完成 */
/* 
	根据当前包的IP, GRE_callid信息, 查找在PPTP控制连接阶段插入的HASH元素,
	如果找到, 直接使用控制连接申请的插件管理pme.
	如果找不到, 则不继续处理.
*/
static struct pptp_info_pri *pptp_find_ctrl_info(struct streaminfo_private *pstream_pr)
{
	struct streaminfo_private *gre_stream_pr;
	struct mesa_gre_hdr *gre_addr;
	struct streaminfo_private *ipv4_stream_pr; 
	struct pptp_stream_key ppp_key;
	struct pptp_info_pri * pptp_pri;

	if((NULL == g_pptp_htable_array) || (0 == g_pptp_plugid)){
		/* 协议解析层未开启, 或未初始化成功 */
		return NULL;
	}

#if 0 /* GRE和PPP同属一个pindex结构 */
	gre_stream_pr = (struct streaminfo_private *)pstream_pr->stream_public.pfather;
#else
	gre_stream_pr = (struct streaminfo_private *)&pstream_pr->stream_public;
#endif

	if(ADDR_TYPE_PPTP != gre_stream_pr->stream_public.addr.addrtype){
		/* 不是承载于GRE之上的PPP, 不是PPTP隧道协议 */
		return NULL;
	}
	ipv4_stream_pr = (struct streaminfo_private *)gre_stream_pr->stream_public.pfather; 
	if((ADDR_TYPE_IPV4 != ipv4_stream_pr->stream_public.addr.addrtype)
	 &&(__ADDR_TYPE_IP_PAIR_V4 != ipv4_stream_pr->stream_public.addr.addrtype)){
	 	/* 非IP层, 无法获取IP地址 */
		return NULL;
	}

	memset(&ppp_key, 0, sizeof(struct pptp_stream_key));
	gre_addr = (struct mesa_gre_hdr *)gre_stream_pr->stream_public.addr.paddr;

	ppp_key.sip = ipv4_stream_pr->stream_public.addr.tuple4_v4->saddr;
	ppp_key.dip = ipv4_stream_pr->stream_public.addr.tuple4_v4->daddr;
	ppp_key.sip_side_call_id = gre_addr->gre_extend.call_id;

	pptp_pri = (struct pptp_info_pri * )MESA_htable_search(
						g_pptp_htable_array[pstream_pr->stream_public.threadnum], 
						(const unsigned char*)&ppp_key, 
						sizeof(struct pptp_stream_key));
	return pptp_pri;
}

void pptp_stream_free(struct streaminfo *pptp_stream)
{
	int tid = pptp_stream->threadnum;
	struct streaminfo *tmp_father;
	
	while(pptp_stream){
		tmp_father = pptp_stream->pfather;
		dictator_free(tid, pptp_stream->addr.paddr);
		dictator_free(tid, pptp_stream);
		pptp_stream = tmp_father;
	}
}

/* 主动删除回调函数, 直接free(pptp_pri)即可 */
static void pptp_stream_data_free_active(void *data)
{
	struct pptp_info_pri *pptp_pri = (struct pptp_info_pri *)data;
	unsigned char tid = pptp_pri->threadnum;

	pptp_pri->ssinfo.session_state = SESSION_STATE_CLOSE;
	PROT_PROCESS(&pptp_pri->ssinfo, &pptp_pri->biz_pme, tid, pptp_pri->my_stream, NULL);

	pptp_stream_free(pptp_pri->my_stream);
	
	dictator_free(tid, data);
}

static int pptp_data_channel_remove_hash(int tid, struct pptp_stream_key *pptp_key)
{
	int hash_ret;

	/* hash中的数据实际由control_link创建. */
	hash_ret = MESA_htable_del(g_pptp_htable_array[tid], (const uchar *)pptp_key, 
							sizeof(struct pptp_stream_key), pptp_stream_data_free_active);

	assert(hash_ret >= 0);
	
	return hash_ret;
}

static char pptp_data_channel_call_biz_plug(struct streaminfo *pstream, struct pptp_info_pri *pptp_pri)
{
	char biz_plug_ret;
	void *ip_hdr;
	struct streaminfo_private *ip_pstream_pr = (struct streaminfo_private *)pstream->pfather;
	ip_hdr = (char *)ip_pstream_pr->raw_pkt->raw_pkt_data + ip_pstream_pr->offset_to_raw_pkt_hdr;
	
	if(0 == pptp_pri->ssinfo.session_state){
		/* 第一次先设置session_state, 和data or control类型, 因为外部调用者已经设置了pptp_pri->ssinfo, 所以本次调用使用栈里的临时变量 */
		stSessionInfo tmp_sinfo; 
		int tmp_link_type = TUNNEL_CHANNEL_TYPE_DATA;

		memset(&tmp_sinfo, 0, sizeof(stSessionInfo));
		tmp_sinfo.plugid = g_pptp_plugid;
		tmp_sinfo.session_state = SESSION_STATE_PENDING; 
		tmp_sinfo.prot_flag = PPTP_OPT_LINK_TYPE; 
		tmp_sinfo.buf = &tmp_link_type;
		tmp_sinfo.buflen = sizeof(int);
		
		PROT_PROCESS(&tmp_sinfo, &pptp_pri->biz_pme, pstream->threadnum, (struct streaminfo * )pstream, ip_hdr);
		pptp_pri->ssinfo.session_state = SESSION_STATE_DATA; /* 第一次调用之后, 修改session_state为DATA */
	}

	biz_plug_ret = PROT_PROCESS(&pptp_pri->ssinfo, &pptp_pri->biz_pme, pstream->threadnum, (struct streaminfo * )pstream, ip_hdr);	
	
	/* clear status */
	pptp_pri->ssinfo.prot_flag = TUNNEL_PHONY_PROT_FLAG;
	pptp_pri->ssinfo.buf = NULL;
	pptp_pri->ssinfo.buflen = 0;

	return biz_retval_to_platform(biz_plug_ret);
}

static void pptp_lcp_pkt_parse(struct streaminfo_private *pstream_pr, 
		const struct mesa_ppp_lcp_ack_hdr *plcp_hdr, struct pptp_info_pri *pptp_pri)
{
	int ret;
	unsigned long long field_flag = 0;
	ppp_lcp_field_data_t result;

	ret = ppp_lcp_pkt_parse(plcp_hdr, &field_flag, &result);
	if(ret != 0){
		if(PPP_LCP_FIELD_FLAG_AUTH_PRO_TYPE & field_flag){
			pptp_pri->ssinfo.prot_flag = PPTP_OPT_AUTHEN_PRO;
			pptp_pri->ssinfo.buf = &result.ppp_lcp_field_pro_type;
			pptp_pri->ssinfo.buflen = sizeof(int);
			pptp_data_channel_call_biz_plug(&pstream_pr->stream_public, pptp_pri);
			pptp_pri->tunnel_context.pptp_info.authentication_pro = result.ppp_lcp_field_pro_type; /* 存储认证类型 */
		}

		if(PPP_LCP_FIELD_FLAG_PRO_FIELD_COMPRESS & field_flag){
			pptp_pri->ssinfo.prot_flag = PPTP_OPT_COMPRESS_PRO;
			pptp_pri->ssinfo.buf = &result.ppp_lcp_filed_pro_compress;
			pptp_pri->ssinfo.buflen = sizeof(int);					
			pptp_data_channel_call_biz_plug(&pstream_pr->stream_public, pptp_pri);
			pptp_pri->tunnel_context.pptp_info.protocol_compress_enable = result.ppp_lcp_field_pro_type; /* 存储压缩选项 */
		}

		if(PPP_LCP_OPT_ADDR_CTRL_FIELD_COMPRESS & field_flag){
			pptp_pri->ssinfo.prot_flag = PPTP_OPT_COMPRESS_PRO;
			pptp_pri->ssinfo.buf = &result.ppp_lcp_filed_addr_ctrl_compress;
			pptp_pri->ssinfo.buflen = sizeof(int);					
			pptp_data_channel_call_biz_plug(&pstream_pr->stream_public, pptp_pri);
			pptp_pri->tunnel_context.pptp_info.addr_ctrl_compress_enable = result.ppp_lcp_field_pro_type; /* 存储压缩选项 */
		}
	}

	return;
}


static void pptp_ccp_pkt_parse(struct streaminfo_private *pstream_pr, 
		const struct mesa_ppp_ccp_ack_hdr *pccp_hdr, struct pptp_info_pri *pptp_pri)
{
	int ret;
	unsigned long long field_flag = 0;
	ppp_ccp_field_data_t result;

	ret = ppp_ccp_pkt_parse(pccp_hdr, &field_flag, &result);
	if(ret != 0){
		if(PPP_CCP_FIELD_FLAG_COMPRESS & field_flag){
			pptp_pri->ssinfo.prot_flag = PPTP_OPT_COMPRESS_PRO;
			pptp_pri->ssinfo.buf = &result.ppp_ccp_field_compress_enable;
			pptp_pri->ssinfo.buflen = sizeof(int);					
			pptp_data_channel_call_biz_plug(&pstream_pr->stream_public, pptp_pri);
		}

		if(PPP_CCP_FIELD_FLAG_ENCRYPT_TYPE & field_flag){
			pptp_pri->ssinfo.prot_flag = PPTP_OPT_ENCRYPT_PRO;
			pptp_pri->ssinfo.buf = &result.ppp_ccp_field_encrypt_type;
			pptp_pri->ssinfo.buflen = sizeof(int);					
			pptp_data_channel_call_biz_plug(&pstream_pr->stream_public, pptp_pri);

			pptp_pri->tunnel_context.pptp_info.encrypt_pro = result.ppp_ccp_field_encrypt_type;;
		}
	}
	
}

/*
	PPP头部压缩, 正常情况下, 应该从协商阶段的LCP, CCP包中获取并存储压缩算法, 
	但可能因为各种原因没有获取到协商数据包, 
	在实际数据传输阶段, 此处猜测一下, 保证大部分明文PPP包仍能被平台处理.
*/
static inline int calc_ppp_hdr_len(const unsigned char *this_layer_data, unsigned short *ppp_next_layer_pro)
{
	int ppp_hdr_len = -1;
	
	switch(this_layer_data[0]){
		case 0xFF:
		{
			if(0x03 == this_layer_data[1]){
				if((0x00 == this_layer_data[2]) && (0x21 == this_layer_data[3])){
					ppp_hdr_len = 4;
					*ppp_next_layer_pro = PPP_PROTOCOL_IPv4;
				}else if((0x00 == this_layer_data[2]) && (0x57 == this_layer_data[3])){
					ppp_hdr_len = 4;
					*ppp_next_layer_pro = PPP_PROTOCOL_IPv6;
				}
			}
		}
		break;

		/* 某些头部压缩只用一个字节表示协议类型 */
		case 0x21:
			if((this_layer_data[1] & 0xF0) == 0x40){ /* 粗略判断下一层必须是IPV4的头部版本号 */
				ppp_hdr_len = 1;
				*ppp_next_layer_pro = PPP_PROTOCOL_IPv4;
			}
		break;

		/* 某些头部压缩只用一个字节表示协议类型 */
		case 0x57:
			if((this_layer_data[1] & 0xF0) == 0x60){ /* 粗略判断下一层必须是IPV6的头部版本号 */
				ppp_hdr_len = 1;
				*ppp_next_layer_pro = PPP_PROTOCOL_IPv6;
			}
		break;
		
		default:
			return -1;
	}

	return ppp_hdr_len;
}


int pptp_entry(struct streamindex *pindex, const void *this_layer_data,int thread_num, 
		unsigned char routedir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr, const struct mesa_gre_hdr *gre_net_addr, int gre_hdr_len)
{
	struct streaminfo_private *pstream_pr = &pindex->stream;
	struct streaminfo *pstream = &pstream_pr->stream_public;		
	const struct streaminfo_private *pfstream_pr = (const struct streaminfo_private *)pstream->pfather;
	struct layer_addr_pptp pptp_addr;
	const struct mesa_ppp_hdr *ppp_net_addr = (const struct mesa_ppp_hdr *)this_layer_data;
	struct pptp_info_pri *pptp_pri;
	int ret = PASS;
	char *next_layer_hdr; 
	int next_layer_offset; 	
	unsigned short ppp_next_layer_pro;
	int ppp_hdr_len;

	/* 更新PPTP层地址类型 */
	pstream->addr.addrtype = ADDR_TYPE_PPTP;
	pstream->type=STREAM_TYPE_PPTP;
#if 0
	pstream->addr.paddr = &pptp_addr; /* 移动到pptp_find_ctrl_info()函数之后 */
#endif

	pptp_pri = pptp_find_ctrl_info(pstream_pr);
	if(NULL == pptp_pri){
		 /* PPTP控制连接未捕获到, 或未获取足够详细的信息 */
		memset(&pptp_addr, 0 , sizeof(struct layer_addr_pptp));
		if(1 == pfstream_pr->layer_dir){ /* 还未到传输层, 暂时以IP层的layer_dir判断当前方向 */
			pptp_addr.C2S_call_id = gre_net_addr->gre_extend.call_id;
		}else{
			pptp_addr.S2C_call_id = gre_net_addr->gre_extend.call_id;
		}
		//sapp_runtime_log(10, "%s, pptp data channel without ctrl channel!\n", stream_addr_list_ntop(pstream, ));
	}else{
		if(1 == pfstream_pr->layer_dir){ /* 还未到传输层, 暂时以IP层的layer_dir判断当前方向 */
			if(gre_net_addr->gre_extend.call_id == pptp_pri->pptp_key.sip_side_call_id){ /* 判断当前包的CALLID是哪个, 真正目的是取另一个方向的CALLID */
				pptp_addr.C2S_call_id = gre_net_addr->gre_extend.call_id; /* C2S是当前包的CALLID */
				pptp_addr.S2C_call_id = pptp_pri->pptp_key.dip_side_call_id;
			}else{
				pptp_addr.C2S_call_id =  pptp_pri->pptp_key.sip_side_call_id;
				pptp_addr.S2C_call_id =  gre_net_addr->gre_extend.call_id;
			}
		}else{
			if(gre_net_addr->gre_extend.call_id == pptp_pri->pptp_key.sip_side_call_id){ /* 判断当前包的CALLID是哪个, 真正目的是取另一个方向的CALLID */
				pptp_addr.S2C_call_id = gre_net_addr->gre_extend.call_id; /* S2C是当前包的CALLID */
				pptp_addr.C2S_call_id = pptp_pri->pptp_key.dip_side_call_id;
			}else{
				pptp_addr.S2C_call_id =  pptp_pri->pptp_key.sip_side_call_id;
				pptp_addr.C2S_call_id =  gre_net_addr->gre_extend.call_id;
			}
		}
	}

	/* 2017-10-31 lijia add, for PPP header compress */
	ppp_hdr_len = calc_ppp_hdr_len((unsigned char *)this_layer_data, &ppp_next_layer_pro);
	if(ppp_hdr_len < 0){
		return PASS;
	}
	
	next_layer_hdr = (char *)this_layer_data + ppp_hdr_len;  /* 已经跳过了GRE头部, 这层仅增加PPP头部 */
	next_layer_offset = offset_to_raw_pkt_hdr + ppp_hdr_len; /* 已经跳过了GRE头部, 这层仅增加PPP头部 */ 
	pstream_pr->cur_layer_raw_hdr_len = gre_hdr_len + ppp_hdr_len;
	
	pstream->addr.paddr = &pptp_addr; /* 注意: 在pptp_find_ctrl_info()之后在更新为pptp_addr, 因为pptp_find_ctrl_info()使用了gre层地址 */

	switch(ppp_next_layer_pro)
	{
		case PPP_PROTOCOL_IPv4:
			/* 开始进入隧道内部数据传输阶段, 此时应该先告之业务插件content_type */
			if((pptp_pri != NULL) && (0 == pptp_pri->content_notify_biz_flag)){
				pptp_pri->ssinfo.prot_flag = PPTP_CONTENT_TYPE;
				pptp_pri->tunnel_context.pptp_info.content_type = TUNNEL_CONTENT_TYPE_CLEAR;
				pptp_pri->ssinfo.buf = &pptp_pri->tunnel_context.pptp_info.content_type;
				pptp_pri->ssinfo.buflen = sizeof(int);					
				pptp_data_channel_call_biz_plug(&pstream_pr->stream_public, pptp_pri);
				pptp_pri->content_notify_biz_flag = 1;
			}
			((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
			ret=ipv4_entry(pstream_pr,(const void *)next_layer_hdr,thread_num,routedir,raw_pkt,next_layer_offset);
			break;
			
		case PPP_PROTOCOL_IPv6:
			/* 开始进入隧道内部数据传输阶段, 此时应该先告之业务插件content_type */
			if((pptp_pri != NULL) && (0 == pptp_pri->content_notify_biz_flag)){
				pptp_pri->ssinfo.prot_flag = PPTP_CONTENT_TYPE;
				pptp_pri->tunnel_context.pptp_info.content_type = TUNNEL_CONTENT_TYPE_CLEAR;
				pptp_pri->ssinfo.buf = &pptp_pri->tunnel_context.pptp_info.content_type;
				pptp_pri->ssinfo.buflen = sizeof(int);					
				pptp_data_channel_call_biz_plug(&pstream_pr->stream_public, pptp_pri);
				pptp_pri->content_notify_biz_flag = 1;
			}		
			((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
			ret=ipv6_entry(pstream_pr,(const void *)next_layer_hdr,thread_num,routedir,raw_pkt,next_layer_offset);
			break;

		case PPP_PROTOCOL_LCP: 
		{
			/* 数据连接的LCP阶段, 如果找不到控制连接, 不再做后续处理 */
			if(NULL == pptp_pri){
				break;
			}
			const struct mesa_ppp_lcp_ack_hdr *plcp_hdr = (const struct mesa_ppp_lcp_ack_hdr *)((const char *)this_layer_data + sizeof(struct mesa_ppp_hdr));
			if(PPP_LCP_CODE_ACK == plcp_hdr->code){
				pptp_lcp_pkt_parse(pstream_pr, plcp_hdr, pptp_pri);
			}else if((PPP_LCP_CODE_TERMINATE_ACK == plcp_hdr->code)
			         || (PPP_LCP_CODE_TERMINATE_REQ == plcp_hdr->code)){
				/* 数据连接主动结束, 为了兼顾单向流, 收到任何一方的连接终止信息, 都终止当前数据连接的pptp流 */
				pptp_pri->ssinfo.session_state = SESSION_STATE_CLOSE;
				pptp_data_channel_call_biz_plug(&pstream_pr->stream_public, pptp_pri);	
				pptp_data_channel_remove_hash(thread_num, &pptp_pri->pptp_key);
			}
		}
		break;

		case PPP_PROTOCOL_CCP:
		{
			if(NULL == pptp_pri){
				break;
			}			
			const struct mesa_ppp_ccp_ack_hdr *pccp_hdr = (const struct mesa_ppp_ccp_ack_hdr *)((const char *)this_layer_data + sizeof(struct mesa_ppp_hdr));
			if(PPP_LCP_CODE_ACK == pccp_hdr->code){
				pptp_ccp_pkt_parse(pstream_pr, pccp_hdr, pptp_pri);
			}
		}
		break;

		case PPP_PROTOCOL_PAD:
		break;
		
		case PPP_PROTOCOL_IPCP:
		/*
			TODO 1:
				协议标准做法是当双向IPCP都确认OK, 进入数据传输阶段时,
				调用业务插件, 告之content_type类型.
				但IPCP是双向的, 必须等服务端的IPCP确认后, 再通知业务层,
				但识别哪个是客户端的IPCP, 哪个是服务端的IPCP有点麻烦,
				所以暂时用一个变量content_notify_biz_flag, 表示pptp的content_type是否通知过业务插件.
		*/
		ret = PASS;
		break;

		case PPP_PROTOCOL_PAP:
		break;
		
		case PPP_PROTOCOL_CHAP:
		{
			/* temp test */
			char tmp_use[256];
			int tmp_len = 256;
			const struct mesa_ppp_chap_hdr *chap_hdr = (const struct mesa_ppp_chap_hdr *)((const char *)this_layer_data + sizeof(struct mesa_ppp_hdr));
			ppp_chap_pkt_parse(chap_hdr, tmp_use, &tmp_len);
		}
		break;

		
		case PPP_COMPRESS_DATA:
			/* 开始进入隧道内部数据传输阶段, 此时应该先告之业务插件content_type,
				此时传输的是压缩数据, 如果之前LCP是加密, 则为加密模式, 否则是纯压缩模式.
			*/
			if((pptp_pri != NULL) && (0 == pptp_pri->content_notify_biz_flag)){
				pptp_pri->ssinfo.prot_flag = PPTP_CONTENT_TYPE;
				if(pptp_pri->tunnel_context.pptp_info.encrypt_pro != 0){
					pptp_pri->tunnel_context.pptp_info.content_type = TUNNEL_CONTENT_TYPE_ENCRYPT;
				}else{
					pptp_pri->tunnel_context.pptp_info.content_type = TUNNEL_CONTENT_TYPE_COMPRESS;
				}
				pptp_pri->ssinfo.buf = &pptp_pri->tunnel_context.pptp_info.content_type;
				pptp_pri->ssinfo.buflen = sizeof(int);					
				pptp_data_channel_call_biz_plug(&pstream_pr->stream_public, pptp_pri);
				pptp_pri->content_notify_biz_flag = 1;
			}
			ret = PASS;
		break;
		
		default:
			ret = PASS;
			sapp_runtime_log(10, "PPTP unknown protocol: 0x%x\n", ntohs(ppp_net_addr->protocol));
			break;
	}

	return ret;
}

void pptp_per_thread_exit(int thread_seq)
{
	if(g_pptp_plugid <= 0){
		return;
	}

	MESA_htable_destroy(g_pptp_htable_array[thread_seq], NULL);

}

void pptp_exit(void)
{
	if(g_pptp_plugid <= 0){
		return;
	}
}

#ifdef __cplusplus
}
#endif
