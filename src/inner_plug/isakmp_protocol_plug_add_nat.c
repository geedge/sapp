#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"
#include "sapp_declaration.h"
/*
	虚拟isakmp解析层, 
	1)用于获取全局插件ID, 并存储于g_isakmp_plugid;
	2)插件名称设为ipsec, 用于创建一个"ipsec"的协议解析层入口,
	  真正的业务插件需要挂载到"ipsec"层.
	3)本模块不负责任何协议相关工作, 真实的解析层逻辑放在deal_isakmp.c中.
*/

#define ISAKMP_DEFAULT_UDP_PORT	(500)	
#define ISAKMP_NAT_UDP_PORT		(4500)

struct isakmp_info_pri{
	struct MESA_tunnel_info tunnel_context;
	stSessionInfo ssinfo; /* 调用业务层上下文 */
	void *biz_pme;
};

unsigned short g_isakmp_plugid;

static inline int isakmp_call_biz_plug(const struct streaminfo *a_udp, struct isakmp_info_pri *ikp_pri, 
								const void *ip_hdr)
{
	int biz_plug_ret;
	int pro_plug_ret = APP_STATE_GIVEME;
	
	biz_plug_ret = PROT_PROCESS(&ikp_pri->ssinfo, &ikp_pri->biz_pme, a_udp->threadnum, (struct streaminfo * )a_udp, ip_hdr);

	/* clear status */
	ikp_pri->ssinfo.prot_flag = TUNNEL_PHONY_PROT_FLAG;
	ikp_pri->ssinfo.buf = NULL;
	ikp_pri->ssinfo.buflen = 0;

	if(biz_plug_ret & PROT_STATE_DROPPKT){
		pro_plug_ret |= APP_STATE_DROPPKT;
	}

	if(biz_plug_ret & PROT_STATE_DROPME){
		pro_plug_ret |= APP_STATE_DROPME;
	}
	
	return pro_plug_ret;
}

static int isakmp_v1_process(const struct streaminfo *a_udp, struct isakmp_info_pri *ikp_pri,
							const struct mesa_isakmp_hdr *ikp_net_hdr, const void *ip_hdr)
{
	int pro_plug_ret;
	
	if(OP_STATE_PENDING == a_udp->opstate){
		/* 第一次调用, 识别版本信息, exchange_type, 是否基于NAT等固定头部字段 */
		ikp_pri->tunnel_context.isakmp_info.major_version = 1;
		ikp_pri->tunnel_context.isakmp_info.minor_version = 0;
		int tmp_version = IPSEC_VERSION_ISAKMP_V1;
		ikp_pri->ssinfo.buf = (void *)&tmp_version;
		ikp_pri->ssinfo.buflen = sizeof(int);
		ikp_pri->ssinfo.prot_flag = IPSEC_OPT_IKE_VERSION;
		pro_plug_ret = isakmp_call_biz_plug(a_udp, ikp_pri, ip_hdr);
		if(APP_STATE_DROPME == pro_plug_ret){
			return APP_STATE_DROPME;
		}
		ikp_pri->ssinfo.session_state = SESSION_STATE_DATA; /* 后续调用修改为DATA */

		ikp_pri->ssinfo.buf = (void *)&ikp_pri->tunnel_context.isakmp_info.upon_udp_nat;
		ikp_pri->ssinfo.buflen = sizeof(char);
		ikp_pri->ssinfo.prot_flag = IPSEC_OPT_IS_NAT;
		pro_plug_ret = isakmp_call_biz_plug(a_udp, ikp_pri, ip_hdr);
		if(APP_STATE_DROPME == pro_plug_ret){
			return APP_STATE_DROPME;
		}			
		
		ikp_pri->tunnel_context.isakmp_info.exchange_type = ikp_net_hdr->exchange_type;
		ikp_pri->ssinfo.buf = (void *)&ikp_pri->tunnel_context.isakmp_info.exchange_type;
		ikp_pri->ssinfo.buflen = sizeof(char);
		ikp_pri->ssinfo.prot_flag = IPSEC_OPT_EXCHG_MODE;
		pro_plug_ret = isakmp_call_biz_plug(a_udp, ikp_pri, ip_hdr);
		if(APP_STATE_DROPME == pro_plug_ret){
			return APP_STATE_DROPME;
		}		
	}

	/* 其他数据包, 暂无其他可解析信息, 空调用业务插件,  */
	pro_plug_ret = isakmp_call_biz_plug(a_udp, ikp_pri, ip_hdr);
		
#if 0	
	/* 已进入加密阶段, 可以认为isakmp协商结束, 调用业务层, 主动结束流退出 */
	if(ikp_net_hdr->flags & 1){ 
		ikp_pri->ssinfo.session_state = SESSION_STATE_CLOSE;
		isakmp_call_biz_plug(a_udp, ikp_pri, ip_hdr);
		return PROT_STATE_DROPME;
	}
#endif	

	/* 只解析SA类型的payload */
	if(ISAKMP_PAYLOAD_TYPE_SA == ikp_net_hdr->next_payload){
		/* TODO 1, 按RFC2408, 细分析包格式中的加密类型、HASH算法等 */
	}

	return pro_plug_ret;
}


static int isakmp_raw_process(const struct streaminfo *a_udp, struct isakmp_info_pri *ikp_pri, 
		int tid, const void *ip_hdr, const struct mesa_isakmp_hdr *ikp_net_hdr)
{
	isakmp_info_t *ikp_info = &ikp_pri->tunnel_context.isakmp_info;
	int pro_plug_ret = APP_STATE_GIVEME;
	
	if(0 == ikp_info->init_cookie){
		ikp_info->init_cookie = ikp_net_hdr->init_cookie;
	}

	if(0 == ikp_info->resp_cookie){
		ikp_info->resp_cookie = ikp_net_hdr->resp_cookie;
	}

	if((1 == ikp_net_hdr->major_version) && (0 == ikp_net_hdr->minor_version)){
		pro_plug_ret = isakmp_v1_process(a_udp, ikp_pri, ikp_net_hdr, ip_hdr);
	}else {
		/* IKE version2 process, 暂不支持 */
		sapp_runtime_log(RLOG_LV_INFO, "unsupport IKEv2 version yet!");
		goto dropme;
	}
	
	return pro_plug_ret;

dropme:
	pro_plug_ret = APP_STATE_DROPME;
	return pro_plug_ret;	
}


static int isakmp_process(const struct streaminfo *a_udp, struct isakmp_info_pri *ikp_pri, int tid, const void *ip_hdr)
{
	if(ikp_pri->tunnel_context.isakmp_info.upon_udp_nat != 0){
		/* NAT模式下, 前4个字节为Non-ESP Marker, refer to RFC3948 Page4 */
		if(a_udp->pudpdetail->datalen > 4 + sizeof(struct mesa_isakmp_hdr)){
			unsigned int *non_esp_hdr = (unsigned int *)a_udp->pudpdetail->pdata;
			if(0 == *non_esp_hdr){
				return isakmp_raw_process(a_udp, ikp_pri, tid, ip_hdr, (const struct mesa_isakmp_hdr *)((char *)a_udp->pudpdetail->pdata + 4));
			}else{
				/* ESP加密数据, 暂无法处理 */
			}
		}
		
		/* 保活或其他包, 暂不处理 */
		return APP_STATE_GIVEME;
	}

	return isakmp_raw_process(a_udp, ikp_pri, tid, ip_hdr, (const struct mesa_isakmp_hdr *)a_udp->pudpdetail->pdata);
}

static inline void isakmp_context_init(struct isakmp_info_pri *ikp_pri)
{
	memset(ikp_pri, 0, sizeof(struct isakmp_info_pri)); 

	ikp_pri->tunnel_context.tunnel_type = STREAM_TYPE_ISAKMP;

	ikp_pri->ssinfo.plugid = g_isakmp_plugid;
	ikp_pri->ssinfo.session_state = SESSION_STATE_PENDING;
	ikp_pri->ssinfo.prot_flag = TUNNEL_PHONY_PROT_FLAG;
}

/*
	TODO 1:
	IKEv2识别, 前几个字节SPI长度不同, 需要分别尝试识别两次.
	
*/
static struct isakmp_info_pri *isakmp_identify(const struct streaminfo *a_udp)
{
	const struct stream_tuple4_v4 *tuple4_v4;
	const struct stream_tuple4_v6 *tuple4_v6;
	const struct mesa_isakmp_hdr *ikp_net_hdr;
	struct isakmp_info_pri *ikp_context = NULL;	
	unsigned short sport, dport;
	int upon_udp_nat = 0;
	unsigned int udp_payload_len;
	int *non_esp_marker;

	if(STREAM_TYPE_UDP != a_udp->type){ /* isakmp使用UDP传输 */
		return NULL;
	}
	
	if(ADDR_TYPE_IPV4 == a_udp->addr.addrtype){
		tuple4_v4 = a_udp->addr.tuple4_v4;
		sport = ntohs(tuple4_v4->source);
		dport = ntohs(tuple4_v4->dest);
	}else{
		tuple4_v6 = a_udp->addr.tuple4_v6;
		sport = ntohs(tuple4_v6->source);
		dport = ntohs(tuple4_v6->dest);
	}

	if((ISAKMP_DEFAULT_UDP_PORT == sport) 
	 || (ISAKMP_DEFAULT_UDP_PORT == dport)){
	 	if(a_udp->pudpdetail->datalen < sizeof(struct mesa_isakmp_hdr)){ /* 小于最基本的ISAKMP头部长度 */
			return NULL;
	 	}
		upon_udp_nat = 0;
		ikp_net_hdr = (const struct mesa_isakmp_hdr *)a_udp->pudpdetail->pdata;
		udp_payload_len = a_udp->pudpdetail->datalen;
	}else if((ISAKMP_NAT_UDP_PORT == sport)
	 || (ISAKMP_NAT_UDP_PORT == dport)){
	 	if(a_udp->pudpdetail->datalen < sizeof(int) + sizeof(struct mesa_isakmp_hdr)){ /* 小于最基本的ISAKMP头部长度 + 4字节non-ESP Marker */
			return NULL;
	 	}
	 	non_esp_marker = (int *)a_udp->pudpdetail->pdata;
	 	if(0 == *non_esp_marker){
	 		/* 跳过4字节non-ESP头部 */
			ikp_net_hdr = (const struct mesa_isakmp_hdr *)((char *)a_udp->pudpdetail->pdata + sizeof(int));
			udp_payload_len = a_udp->pudpdetail->datalen - sizeof(int);
			upon_udp_nat = 1;
		}else{
			/* udp nat esp, 暂不处理 */
			return NULL;
		}
	}else{
		return NULL;
	}


#if 0 /* 实际捕包发现, isakmp-len竟然小于UDP实际宣称的长度, 所以不能用精确等于判断, 用大于做简单错误判断 */
	if(a_udp->pudpdetail->datalen != ntohl(ikp_net_hdr->length)){
		return 0;
	}
#else
	if(ntohl(ikp_net_hdr->length) > udp_payload_len){
		return NULL;
	}
#endif	

	if((ikp_net_hdr->next_payload >= ISAKMP_PAYLOAD_TYPE_RESERVED_BEGIN)
	 && (ikp_net_hdr->next_payload <= ISAKMP_PAYLOAD_TYPE_RESERVED_END)){
		return NULL;
	}

	if((ikp_net_hdr->exchange_type >= ISAKMP_EXCHANGE_TYPE_FEATURE_USE_BEGIN)
	 &&(ikp_net_hdr->exchange_type <= ISAKMP_EXCHANGE_TYPE_FEATURE_USE_END)){
		return NULL;
	}

	/* refer to RFC2408-Page23, 目前仅最低三个bit有意义, 其他必须为0 */
	if((ikp_net_hdr->flags & 0xF8) != 0){
		return NULL;
	}

	ikp_context = (struct isakmp_info_pri *)dictator_malloc(a_udp->threadnum, sizeof(struct isakmp_info_pri));
	isakmp_context_init(ikp_context);
	ikp_context->tunnel_context.isakmp_info.upon_udp_nat = upon_udp_nat;
			
	return ikp_context; /* 可以认定是isakmp协议 */
}



char isakmp_protocol_entry(const struct streaminfo *a_udp,  void **pme, int thread_seq,const void *ip_hdr)
{
	struct isakmp_info_pri *ikp_context;
	char res = APP_STATE_GIVEME;

	switch(a_udp->opstate){
		case OP_STATE_PENDING:
			ikp_context = isakmp_identify(a_udp);
			if(NULL == ikp_context){
				return APP_STATE_DROPME;
			}

			*pme = ikp_context;
			if(a_udp->pudpdetail->datalen > 0){
				res = isakmp_process(a_udp, ikp_context, thread_seq, ip_hdr);
			}
		break;

		case OP_STATE_DATA:
			ikp_context = (struct isakmp_info_pri *)(*pme);
			ikp_context->ssinfo.session_state = SESSION_STATE_DATA;
			res = isakmp_process(a_udp, ikp_context, thread_seq, ip_hdr);
		break;

		case OP_STATE_CLOSE:
			ikp_context = (struct isakmp_info_pri *)(*pme);
			ikp_context->ssinfo.session_state = SESSION_STATE_CLOSE;
			ikp_context->ssinfo.buf = NULL;
			ikp_context->ssinfo.buflen = 0;
			isakmp_call_biz_plug(a_udp, ikp_context, ip_hdr);	
			res = APP_STATE_DROPME;
		break;

		default:
		break;
	}

	if(APP_STATE_DROPME == res){
		if(*pme != NULL){
			dictator_free(thread_seq, *pme);
		}
	}
	
	return res;
}

void isakmp_protocol_funstat(unsigned long long protflag)
{
	;
}

long long isakmp_protocol_flag_change(char* flag_str)
{
	return (long long)0x7FFFFFFFFFFFFFFFL;
}

void isakmp_protocol_get_plugid(unsigned short plugid)
{
	g_isakmp_plugid = plugid;
}

int isakmp_protocol_init(void)
{
	return g_isakmp_plugid;
}

void isakmp_protocol_destroy(void)
{
	;
}

#ifdef __cplusplus
}
#endif


