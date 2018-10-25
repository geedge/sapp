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

struct ppp_lcp_link_info{
	unsigned short mru;
	unsigned short auth_pro;
	unsigned char use_pro_field_compress;
	unsigned char use_addr_ctrl_field_compress;
	unsigned char __pad[2];
};

struct ppp_ccp_opt_payload_t{
	unsigned int MPPC:1;
	unsigned int reserved1:4;
	unsigned int L40_bit_encrypt:1;
	unsigned int S128_bit_encrypt:1;
	unsigned int M56_bit_encrypt:1;
	unsigned int reserved2:16;	
	unsigned int Stateless_mode:1;
	unsigned int reserved3:7;
};

#if 0
static int set_ppp_addr(struct mesa_ppp_hdr *stack_ppp_addr, const void *this_layer_hdr)
{
	const struct mesa_ppp_hdr *net_ppp_addr = (const struct mesa_ppp_hdr *)this_layer_hdr;

	if(0xFF != net_ppp_addr->address){
		return -1;
	}
	stack_ppp_addr->address = net_ppp_addr->address;
	stack_ppp_addr->control = net_ppp_addr->control;
	stack_ppp_addr->protocol = net_ppp_addr->protocol;
	return 0;	
}


static inline const char *ppp_lcp_auth_pro_to_string(unsigned short auth_pro)
{
	const char *str = "NULL";
	
	switch(auth_pro){
		case PPP_LCP_OPT_AUTH_PRO_PAP:
			str = "PAP";
		break;

		case PPP_LCP_OPT_AUTH_PRO_CHAP:
			str = "CHAP";
		break;
		
		default:
		break;
	}

	return str;
}


void ppp_ccp_link_record(struct streaminfo_private *pstream_pr, 
		const struct mesa_ppp_ccp_ack_hdr *pccp_hdr, struct pptp_info_pri *pptp_pri)
{
	int lcp_data_len = ntohs(pccp_hdr->length) - sizeof(struct mesa_ppp_lcp_ack_hdr); /* 减去ccp头部 */
	const unsigned char *popt = (const unsigned char *)((char *)pccp_hdr + sizeof(struct mesa_ppp_lcp_ack_hdr));
	int opt_len;
	
	while(lcp_data_len > 0){
		switch(*popt){
			case PPP_CCP_OPT_MS_PPC:
			{
				unsigned int mppc_bits;
				struct ppp_ccp_opt_payload_t ccp_data;
				if(popt[1] != 6){ /* len != 6 */
					return;
				}
				mppc_bits = ntohl(*(unsigned int *)(popt + 2));
				memcpy(&ccp_data, &mppc_bits, sizeof(int));
				if(ccp_data.MPPC){
					 /* 实际应该是认证方式, 为了和库表统一, 暂且叫"加密方式" */
					pptp_pri->ssinfo.prot_flag = PPTP_OPT_ENCRYPT_PRO;
					pptp_pri->tunnel_context.pptp_info.compress_pro = PPTP_ENCRYPT_MPPC;
#if 0		/* 日志库表中无MPPC字段, 仅保存, 不回调业务插件 */				
					pptp_pri->ssinfo.buf = &pptp_pri->tunnel_context.pptp_info.compress_pro;
					pptp_pri->ssinfo.buflen = sizeof(int);
					pptp_data_channel_call_biz_plug(&pstream_pr->stream_public, pptp_pri);					
#endif
				}
				if(ccp_data.L40_bit_encrypt || ccp_data.M56_bit_encrypt || ccp_data.S128_bit_encrypt){
					pptp_pri->ssinfo.prot_flag = PPTP_OPT_ENCRYPT_PRO;
					pptp_pri->tunnel_context.pptp_info.encryt_pro = PPTP_ENCRYPT_MPPE;
					pptp_pri->ssinfo.buf = &pptp_pri->tunnel_context.pptp_info.encryt_pro;
					pptp_pri->ssinfo.buflen = sizeof(int);
					pptp_data_channel_call_biz_plug(&pstream_pr->stream_public, pptp_pri);
				}
				popt += 6;
				lcp_data_len -= 6;		
			}	
			break;

			default:
			{
				opt_len = popt[1];
				if((opt_len <= 0) || (opt_len > lcp_data_len)){
					return;
				}
				popt += opt_len;
				lcp_data_len -= opt_len;
			}	
			break;
		}
	}
	
	return;
}

void ppp_lcp_link_record(struct streaminfo_private *pstream_pr, 
		const struct mesa_ppp_lcp_ack_hdr *plcp_hdr, struct pptp_info_pri *pptp_pri)
{
	int lcp_data_len = ntohs(plcp_hdr->length) - sizeof(struct mesa_ppp_lcp_ack_hdr); /* 减去lcp头部 */
	const unsigned char *popt = (const unsigned char *)((char *)plcp_hdr + sizeof(struct mesa_ppp_lcp_ack_hdr));
	struct ppp_lcp_link_info plcp_info;
	memset(&plcp_info, 0, sizeof(struct ppp_lcp_link_info));
	int opt_len;
	
	while(lcp_data_len > 0){
		switch(*popt){
			case PPP_LCP_OPT_MAX_RCV_UNIT:
				if(popt[1] != 4){
					return;
				}
				plcp_info.mru = ntohs(*(unsigned short *)(popt + 2));
				lcp_data_len -= 4;
				popt += 4;
			break;

			case PPP_LCP_OPT_AUTH_PRO:
			{
				opt_len = popt[1];
				if(opt_len < 4){
					return;
				}
				plcp_info.auth_pro = ntohs(*(unsigned short *)(popt + 2));
				if((plcp_info.auth_pro != PPP_LCP_OPT_AUTH_PRO_PAP)
				&& (plcp_info.auth_pro != PPP_LCP_OPT_AUTH_PRO_CHAP)){
					return;
				}
				/* 实际应该是认证方式, 为了和库表统一, 暂且叫"加密方式" */
				if(PPP_LCP_OPT_AUTH_PRO_PAP == plcp_info.auth_pro){
					pptp_pri->tunnel_context.pptp_info.authentication_pro= PPTP_ENCRYPT_PAP;				
				}else if(PPP_LCP_OPT_AUTH_PRO_CHAP == plcp_info.auth_pro){
					/* CHAP选项第5个字节表示实际算法类型 */
					if(PPP_LCP_OPT_AUTH_PRO_CHAP_ALGO_MS_CHAP_V2 == popt[4]){
						pptp_pri->tunnel_context.pptp_info.authentication_pro = PPTP_ENCRYPT_MS_CHAP;	
					}else{
						pptp_pri->tunnel_context.pptp_info.authentication_pro = PPTP_ENCRYPT_MS_CHAP;
					}
				}
				pptp_pri->ssinfo.prot_flag = PPTP_OPT_ENCRYPT_PRO; /* 实际应该是认证方式, 为了和库表统一, 暂且叫"加密方式" */
				pptp_pri->ssinfo.buf = &pptp_pri->tunnel_context.pptp_info.authentication_pro;
				pptp_pri->ssinfo.buflen = sizeof(int);					
				pptp_data_channel_call_biz_plug(&pstream_pr->stream_public, pptp_pri);
				lcp_data_len -= opt_len;
				popt += opt_len;			
			}	
			break;

			case PPP_LCP_OPT_PRO_FIELD_COMPRESS:
				if(popt[1] != 2){
					return;
				}	
				plcp_info.use_pro_field_compress = 1;
				lcp_data_len -= 2;
				popt += 2;
			break;

			case PPP_LCP_OPT_ADDR_CTRL_FIELD_COMPRESS:
				if(popt[1] != 2){
					return;
				}
				plcp_info.use_addr_ctrl_field_compress= 1;
				lcp_data_len -= 2;
				popt += 2;
			break;

			default:
			{
				opt_len = popt[1];
				if((opt_len <= 0) || (opt_len > lcp_data_len)){
					return;
				}
				popt += opt_len;
				lcp_data_len -= opt_len;
			}	
			break;
		}
	}

	struct streaminfo *pstream = &pstream_pr->stream_public;
	struct streaminfo *low_ip_stream = NULL;
	
	while(pstream != NULL){
		if((ADDR_TYPE_IPV4 == pstream->addr.addrtype)
		||(ADDR_TYPE_IPV6 == pstream->addr.addrtype)){
			low_ip_stream = pstream;
		}
		pstream = pstream->pfather;
	}

	if(low_ip_stream){
		char tmp_str[128];
		sapp_runtime_log(30, "PPP-LCP: %s, MRU:%d, AUTH:%s, PFC:%s, ACFC:%s\n", 
					    printaddr_r(&low_ip_stream->addr, tmp_str, 128), 
					    plcp_info.mru,
					    ppp_lcp_auth_pro_to_string(plcp_info.auth_pro),
					    plcp_info.use_pro_field_compress != 0 ? "ON":"OFF",
					    plcp_info.use_addr_ctrl_field_compress!= 0 ? "ON":"OFF" );
	}

	return;
}
#endif

int ppp_ccp_pkt_parse(const struct mesa_ppp_ccp_ack_hdr *pccp_hdr, unsigned long long *field_flag, ppp_ccp_field_data_t *res)
{
	int lcp_data_len = ntohs(pccp_hdr->length) - sizeof(struct mesa_ppp_lcp_ack_hdr); /* 减去ccp头部 */
	const unsigned char *popt = (const unsigned char *)((char *)pccp_hdr + sizeof(struct mesa_ppp_lcp_ack_hdr));
	int opt_len;

	*field_flag = 0;
	
	while(lcp_data_len > 0){
		switch(*popt){
			case PPP_CCP_OPT_MS_PPC:
			{
				unsigned int mppc_bits;
				struct ppp_ccp_opt_payload_t ccp_data;
				if(popt[1] != 6){ /* len != 6 */
					return (*field_flag != 0);
				}
				mppc_bits = ntohl(*(unsigned int *)(popt + 2));
				memcpy(&ccp_data, &mppc_bits, sizeof(int));
				if(ccp_data.MPPC){
					*field_flag |= PPP_CCP_FIELD_FLAG_COMPRESS;
					res->ppp_ccp_field_compress_enable = 1;
				}
				if(ccp_data.L40_bit_encrypt){ 
					*field_flag |= PPP_CCP_FIELD_FLAG_ENCRYPT_TYPE;
					res->ppp_ccp_field_encrypt_type = PPP_CCP_ENCRY_L40_BIT;
				}
				if(ccp_data.M56_bit_encrypt){
					*field_flag |= PPP_CCP_FIELD_FLAG_ENCRYPT_TYPE;
					res->ppp_ccp_field_encrypt_type = PPP_CCP_ENCRY_M56_BIT;
				}
				if(ccp_data.S128_bit_encrypt){
					*field_flag |= PPP_CCP_FIELD_FLAG_ENCRYPT_TYPE;
					res->ppp_ccp_field_encrypt_type = PPP_CCP_ENCRY_S128_BIT;
				}
				popt += 6;
				lcp_data_len -= 6;		
			}	
			break;

			default:
			{
				opt_len = popt[1];
				if((opt_len <= 0) || (opt_len > lcp_data_len)){
					return (*field_flag != 0);
				}
				popt += opt_len;
				lcp_data_len -= opt_len;
			}	
			break;
		}
	}
	
	return (*field_flag != 0);
}


int ppp_lcp_pkt_parse(const struct mesa_ppp_lcp_ack_hdr *plcp_hdr, unsigned long long *field_flag, ppp_lcp_field_data_t *res)
{
	int lcp_data_len = ntohs(plcp_hdr->length) - sizeof(struct mesa_ppp_lcp_ack_hdr); /* 减去lcp头部 */
	const unsigned char *popt = (const unsigned char *)((char *)plcp_hdr + sizeof(struct mesa_ppp_lcp_ack_hdr));
	struct ppp_lcp_link_info plcp_info;
	memset(&plcp_info, 0, sizeof(struct ppp_lcp_link_info));
	int opt_len;

	*field_flag = 0;
	
	while(lcp_data_len > 0){
		switch(*popt){
			case PPP_LCP_OPT_MAX_RCV_UNIT:
				if(popt[1] != 4){
					return (*field_flag != 0);
				}
				plcp_info.mru = ntohs(*(unsigned short *)(popt + 2));
				lcp_data_len -= 4;
				popt += 4;
			break;

			case PPP_LCP_OPT_AUTH_PRO:
			{
				opt_len = popt[1];
				if(opt_len < 4){
					return (*field_flag != 0);
				}
				plcp_info.auth_pro = ntohs(*(unsigned short *)(popt + 2));
				if((plcp_info.auth_pro != PPP_LCP_OPT_AUTH_PRO_PAP)
				&& (plcp_info.auth_pro != PPP_LCP_OPT_AUTH_PRO_CHAP)){
					return (*field_flag != 0);
				}
				/* 实际应该是认证方式, 为了和库表统一, 暂且叫"加密方式" */
				if(PPP_LCP_OPT_AUTH_PRO_PAP == plcp_info.auth_pro){
					*field_flag |= PPP_LCP_FIELD_FLAG_AUTH_PRO_TYPE;
					res->ppp_lcp_field_pro_type = PPP_LCP_OPT_AUTH_PRO_PAP;
				}else if(PPP_LCP_OPT_AUTH_PRO_CHAP == plcp_info.auth_pro){
					/* CHAP选项第5个字节表示实际算法类型 */
					if(PPP_LCP_OPT_AUTH_PRO_CHAP_ALGO_MS_CHAP_V2 == popt[4]){
						*field_flag |= PPP_LCP_FIELD_FLAG_AUTH_PRO_TYPE;
						res->ppp_lcp_field_pro_type  = PPTP_ENCRYPT_MS_CHAP;	
					}else{
						*field_flag |= PPP_LCP_FIELD_FLAG_AUTH_PRO_TYPE;
						res->ppp_lcp_field_pro_type  = PPTP_ENCRYPT_CHAP;	
					}
				}

				lcp_data_len -= opt_len;
			}	
			break;

			case PPP_LCP_OPT_PRO_FIELD_COMPRESS:
				if(popt[1] != 2){
					return (*field_flag != 0);
				}	
				plcp_info.use_pro_field_compress = 1;
				lcp_data_len -= 2;
				popt += 2;
				*field_flag |= PPP_LCP_FIELD_FLAG_PRO_FIELD_COMPRESS;
				res->ppp_lcp_filed_pro_compress = 1;
			break;

			case PPP_LCP_OPT_ADDR_CTRL_FIELD_COMPRESS:
				if(popt[1] != 2){
					return (*field_flag != 0);
				}
				plcp_info.use_addr_ctrl_field_compress= 1;
				lcp_data_len -= 2;
				popt += 2;
				*field_flag |= PPP_LCP_FIELD_FLAG_ADDR_CTRL_FIELD_COMPRESS;
				res->ppp_lcp_filed_addr_ctrl_compress = 1;				
			break;

			default:
			{
				opt_len = popt[1];
				if((opt_len <= 0) || (opt_len > lcp_data_len)){
					return (*field_flag != 0);
				}
				popt += opt_len;
				lcp_data_len -= opt_len;
			}	
			break;
		}
	}

	return (*field_flag != 0);
}

/*
	return value:
		0 : success.
		-1: internal error;
		-2: args error.
*/
int ppp_chap_pkt_parse(const struct mesa_ppp_chap_hdr *chap_hdr, char *res, int *res_len)
{
	int ret = 0;
	const char *ptr = (const char *)chap_hdr;
	int chap_data_len, hadshake_len, username_len;
	
	switch(chap_hdr->code){
		case PPP_CHAP_CHALLENGE:
		case PPP_CHAP_RESPONSE:
			chap_data_len = ntohs(chap_hdr->length);
			ptr += sizeof(struct mesa_ppp_chap_hdr); /* ptr -> value_size */
			hadshake_len = *ptr;
			ptr++; /* ptr -> handshake value */
			username_len = chap_data_len - sizeof(struct mesa_ppp_chap_hdr) - hadshake_len - 1;
			if(username_len <= 0){
				ret = -1;
				break;
			}
			if((NULL == res_len) || (username_len + 1 > *res_len)){
				ret = -2;
				break;
			}
			ptr += hadshake_len; /* ptr -> chap user name */
			memcpy(res, ptr, username_len);
			res[username_len] = '\0'; /* string EOF */
		break;

		default:
			ret = -1;
			/* 其他code类型获取不到username, 无需处理 */
		break;
	}

	return ret;
}

/*
	TODO:
	PPP协议解压缩怎么处理? 解压后相当于原始包的内容变了, 有点类似IP分片重组, 
	思路:解压之后, 当前层的底层各协议直接挂载到pfather, 但要跟新raw_pkt指针，底层的entry不会再被调用, 从当前层之上，继续调用上层协议。

	还有发送RST的问题，解压之后如何按原来算法再压缩？	
	在build_layer_ppp增加PPP压缩算法，将上层的TCP-RST内容重新压缩，同时更新datalen长度。
*/

int ppp_entry(struct streaminfo_private *pfstream_pr,const void *this_layer_hdr,
			int thread_num,unsigned char routedir, const raw_pkt_t *raw_pkt,int offset_to_raw_pkt_hdr)
{
	assert(0);
}


#ifdef __cplusplus
}
#endif

