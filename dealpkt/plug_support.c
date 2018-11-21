/*
	此文件非平台自身需要的功能和函数,
	是提供给其他业务插件的接口, 如MESA_set_stream_opt, printaddr等,
*/
#include "stream_internal.h"
#include "stream_manage.h"
#include "sysinfo.h"
#include "packet_io.h"
#include "packet_io_internal.h"
#include "project_requirement.h"
#include "project_internal.h"
#include "dictator.h"
#include <MESA/MESA_handle_logger.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/select.h>
#include <linux/version.h>

#ifdef __cplusplus
extern "C" {
#endif

int G_DICTATOR_SW = 1;
extern int g_packet_io_thread_num;

extern const raw_ipfrag_list_t *get_raw_frag_list(const struct streaminfo *stream);

int get_opt_from_rawpkt(const void *voidpkt, int type, void *void_value)
{
	int ret = 0;
	const raw_pkt_t *rawpkt = (const raw_pkt_t *)voidpkt;

	if(NULL == voidpkt || NULL == void_value){
		return -1;
	}

	if(RAW_PKT_MAGIC_NUM != rawpkt->magic_num){ /* 可能来源于papp平台, 不支持此类功能 */
		return -1;
	}
	
	switch(type){
		case RAW_PKT_GET_DATA:
		{
			void **out_value = (void **)void_value;
			*out_value = (void *)rawpkt->raw_pkt_data;
		}
		break;

		case RAW_PKT_GET_RAW_PKT_TYPE:
		{
			enum addr_type_t *out_value = (enum addr_type_t *)void_value;
			*out_value = rawpkt->low_layer_type;
		}
		break;		

		case RAW_PKT_GET_TOT_LEN:
		{
			int *out_value = (int *)void_value;
			*out_value = rawpkt->raw_pkt_len;
		}
		break;

		case RAW_PKT_GET_TIMESTAMP:
		{
			struct timeval *out_value =(struct timeval *)void_value;
			memcpy(out_value, &rawpkt->raw_pkt_ts, sizeof(struct timeval));
		}
		break;
		
		case RAW_PKT_GET_THIS_LAYER_HDR:
		{
			void **out_value = (void **)void_value;
			const char *this_layer_hdr = (const char *)rawpkt->raw_pkt_data + rawpkt->offset_to_raw_pkt_hdr;
			*out_value = (void *)this_layer_hdr;
		}
		break;

		case RAW_PKT_GET_THIS_LAYER_REMAIN_LEN:
		{
			int *out_value = (int *)void_value;
			*out_value = rawpkt->raw_pkt_len - rawpkt->offset_to_raw_pkt_hdr;
		}
		break;

		default:
			ret = -1;
		break;
	}

	return ret;
}

int get_rawpkt_opt_from_streaminfo(const struct streaminfo *pstream, int type, void *out_value)
{
	int ret = -1;
	const struct streaminfo_private *pstream_pr = (const struct streaminfo_private *)pstream;

	if(NULL == out_value){
		return -1;
	}
	
	if((RAW_PKT_GET_DATA == type) 
	&& ((PKT_TYPE_IPREBUILD & pstream->addr.pktipfragtype) != 0)){
		const raw_ipfrag_list_t *list_tmp = get_raw_frag_list(pstream);
		if(NULL == list_tmp){
			ret = -1;
		}else{
			const raw_ipfrag_list_t **out_list = (const raw_ipfrag_list_t **)out_value;
			*out_list = list_tmp;
			ret = 1;
		}
		return ret;
	}
	
	return get_opt_from_rawpkt(pstream_pr->raw_pkt, type, out_value);
}

/*Convert tuple4 to string. Format: 10.0.0.1, 1234->10.0.0.2,5678*/
const char *printaddr (const struct layer_addr *paddrinfo,int threadindex)
{
	static char maxbuf[64+1][128];
       char *buf=maxbuf[threadindex];
	char ip_str[64];
	struct stream_tuple4_v4 *paddr;
	struct stream_tuple4_v6 *paddr6;

	if(NULL == paddrinfo){
		return NULL;
	}

	switch(paddrinfo->addrtype){
		case ADDR_TYPE_IPV4:
		{
			paddr=(struct stream_tuple4_v4 *)paddrinfo->paddr;
			memset(buf,0,64);
			//strcpy (buf, int_ntoa (paddr->saddr));
			inet_ntop(AF_INET, &paddr->saddr, ip_str, 64);
			strcpy (buf, ip_str);
			sprintf (buf + strlen (buf), ".%u>", ntohs(paddr->source));
			//strcat (buf, int_ntoa (paddr->daddr));
			inet_ntop(AF_INET, &paddr->daddr, ip_str, 64);
			strcat (buf, ip_str);
			sprintf (buf + strlen (buf), ".%u", ntohs(paddr->dest));
		}	
		break;
		
		case ADDR_TYPE_IPV6:
		{
			paddr6=(struct stream_tuple4_v6 *)(paddrinfo->paddr);
			memset(buf,0,128);
			inet_ntop(AF_INET6, paddr6->saddr, ip_str, 64);
			strcpy (buf, ip_str);
			sprintf (buf + strlen (buf), ".%u>", ntohs(paddr6->source));
			inet_ntop(AF_INET6, paddr6->daddr, ip_str, 64);
			strcat (buf, ip_str);
			sprintf (buf + strlen (buf), ".%u", ntohs(paddr6->dest));
		}
		break;

		case __ADDR_TYPE_IP_PAIR_V4:
		{
			paddr=(struct stream_tuple4_v4 *)paddrinfo->paddr;
			memset(buf,0,128);
			//strcpy (buf, int_ntoa (paddr->saddr));
			inet_ntop(AF_INET, &paddr->saddr, ip_str, 64);
			strcpy (buf, ip_str);
			strcat (buf, ">");
			inet_ntop(AF_INET, &paddr->daddr, ip_str, 64);
			strcat (buf, ip_str);
		}
		break;

		case __ADDR_TYPE_IP_PAIR_V6:
		{
			paddr6=(struct stream_tuple4_v6 *)(paddrinfo->paddr);
			memset(buf,0,128);
			inet_ntop(AF_INET6, paddr6->saddr, ip_str, 64);
			strcpy (buf, ip_str);
			strcat (buf, ">");
			inet_ntop(AF_INET6, paddr6->daddr, ip_str, 64);
			strcat (buf, ip_str);
		}
		break;
		
		default:
		{
			return (const char *)"Not support layer type";
		}
		break;
	}
	
	return buf;
}

/*
    This is a reentrant version of printaddr(), 
    Convert tuple4 to string store in out_buf. 
    Format: 10.0.0.1, 1234->10.0.0.2,5678. 
*/    
const char *printaddr_r(const struct layer_addr *paddrinfo, char *out_buf, int out_buf_len)
{
#define __MIN_ADDR_STR_LEN (20) /* 最小地址字符串长度, 例如:1.1.1.1.1>2.2.2.2.2 */
	char maxbuf[128];
       char *buf=maxbuf;
	char ip_str[64];
	int addr_str_len;
	struct stream_tuple4_v4 *paddr;
	struct stream_tuple4_v6 *paddr6;

	if((NULL == paddrinfo) || (NULL == out_buf)){
		return "invalid args";
	}	

	if(paddrinfo->addrtype==ADDR_TYPE_IPV4)
	{
		paddr=(struct stream_tuple4_v4 *)paddrinfo->paddr;
		memset(buf,0,128);
		//strcpy (buf, int_ntoa (paddr->saddr));
		inet_ntop(AF_INET, &paddr->saddr, ip_str, 64);
		strcpy (buf, ip_str);
		sprintf (buf + strlen (buf), ".%u>", ntohs(paddr->source));
		//strcat (buf, int_ntoa (paddr->daddr));
		inet_ntop(AF_INET, &paddr->daddr, ip_str, 64);
		strcat (buf, ip_str);
		sprintf (buf + strlen (buf), ".%u", ntohs(paddr->dest));
	}
	//to addjust
	else	if(paddrinfo->addrtype==ADDR_TYPE_IPV6)
	{
		paddr6=(struct stream_tuple4_v6 *)(paddrinfo->paddr);
		memset(buf,0,128);
		inet_ntop(AF_INET6, paddr6->saddr, ip_str, 64);
		strcpy (buf, ip_str);
		sprintf (buf + strlen (buf), ".%u>", ntohs(paddr6->source));
		inet_ntop(AF_INET6, paddr6->daddr, ip_str, 64);
		strcat (buf, ip_str);
		sprintf (buf + strlen (buf), ".%u", ntohs(paddr6->dest));
	}
	else
	{
		return (const char *)"Not support layer type";
	}

	addr_str_len = strlen(buf) + 1; /* add EOF */ 
	if(addr_str_len > out_buf_len){
		return (const char *)"buf len not enough";
	}

	memcpy(out_buf, buf, addr_str_len);
	
	return out_buf;
}


struct layer_addr * layer_addr_dup(const struct layer_addr *stack_info)
{
	void *addr_value;
	struct layer_addr *heap_addr = (struct layer_addr *)malloc(sizeof(struct layer_addr));
	addr_value = malloc(stack_info->addrlen);
	
	memcpy(heap_addr, stack_info, sizeof(struct layer_addr));
	memcpy(addr_value, stack_info->paddr, stack_info->addrlen);
	heap_addr->paddr = addr_value;

	return heap_addr;
}

void layer_addr_free(struct layer_addr *paddrinfo)
{
	free(paddrinfo->paddr);
	free(paddrinfo);
}

int get_thread_count(void)
{
	return g_packet_io_thread_num;
}


int MESA_set_stream_opt(const struct streaminfo *pstream, enum MESA_stream_opt opt, void *opt_val, int opt_val_len)
{
	int ret = -1;

	if((NULL == opt_val) || (opt_val_len <= 0)){
		return -1;
	}
	
	switch((int)opt){
		case (int)MSO_MAX_UNORDER:
		{
			if(STREAM_TYPE_TCP != pstream->type){
				printf("MESA_set_stream_opt() error:stream type is not tcp!\n");
				ret = -1;
				break;
			}
			if(opt_val_len != sizeof(struct max_unorder_opt)){
				printf("MESA_set_stream_opt() error:opt_val_len invalid, must be sizeof(struct max_unorder_opt)\n");
				ret = -1;
				break;
			}
			struct max_unorder_opt *max_uorder = (struct max_unorder_opt *)opt_val;
			ret = tcp_set_single_stream_max_unorder(pstream, max_uorder->stream_dir, max_uorder->max_unorder_val);
		}
		break;

		case (int)MSO_NEED_ACK:
		{
			if(STREAM_TYPE_TCP != pstream->type){
				printf("MESA_set_stream_opt() error:stream type is not tcp!\n");
				ret = -1;
				break;
			}
			unsigned char nack = *((unsigned char *)opt_val);
			struct tcpdetail_private *pdetail_pr = (struct tcpdetail_private*)(pstream->pdetail);
			pdetail_pr->needackflag = nack;
			ret = 0;
		}
		break;

		case (int)MSO_TAKEOVER:
		{
			if(STREAM_TYPE_TCP != pstream->type){
				printf("MESA_set_stream_opt() error:stream type is not tcp!\n");
				ret = -1;
				break;
			}
			int takeover = *((int *)opt_val);
			struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private*)(pstream->pdetail);
			pdetail_pr->takeoverflag = takeover;
			ret = 0;
		}
		break;

		case (int)MSO_TIMEOUT:
		{
			if(sizeof(short) != opt_val_len){
				printf("MESA_set_stream_opt() error:opt_val_len invalid, must be sizeof(short)\n");
				ret = -1;
				break;
			}
			unsigned short tmout = *((unsigned short *)opt_val);
			ret = stream_set_single_stream_timeout(pstream, tmout);
		}
		break;

		case (int)MSO_IGNORE_RST_FIN:
		{
			if(STREAM_TYPE_TCP != pstream->type){
				printf("MESA_set_stream_opt() error: stream type is not tcp!\n");
				ret = -1;
				break;
			}
			unsigned char igrstfin = *((unsigned char *)opt_val);
			struct tcpdetail_private *pdetail_pr = (struct tcpdetail_private*)(pstream->pdetail);
			pdetail_pr->ignore_rst_fin = igrstfin;	
			ret = 0;
		}	
		break;

		default:
			printf("MESA_set_stream_opt() error: unsupport MESA_stream_opt type!\n");
			ret = -1;
			break;
	}

	return ret;
}


static inline int tcp_get_single_stream_max_unorder(const struct streaminfo *pstream, void *opt_val, int *opt_val_len)
{
	struct max_unorder_opt out_val;
	struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private *)pstream->pdetail;
	UINT16 out_uorder_C2S = 0, out_uorder_S2C = 0;

	memset(&out_val, 0, sizeof(struct max_unorder_opt));
	if((pdetail_pr->pserver != NULL) && (tcp_default_unorder != pdetail_pr->pserver->maxunorder)){
		out_uorder_C2S = pdetail_pr->pserver->maxunorder;
		out_val.stream_dir |= DIR_C2S;
	}
	
	if((pdetail_pr->pclient != NULL) && (tcp_default_unorder != pdetail_pr->pclient->maxunorder)){
		out_uorder_S2C = pdetail_pr->pclient->maxunorder;
		out_val.stream_dir |= DIR_S2C;
	}

	out_val.max_unorder_val = (out_uorder_C2S > out_uorder_S2C)?out_uorder_C2S: out_uorder_S2C;

	memcpy(opt_val, &out_val, sizeof(struct max_unorder_opt));

	*opt_val_len = sizeof(struct max_unorder_opt);
	
	return 0;
}


static void sapp_mac_addr_to_long(const unsigned char *mac_addr, unsigned long long *smac_integer_type)
{
	int i;
	char *ptr = (char *)smac_integer_type;

	ptr += 5; /* 指向long long 的第6个字节 */

	for(i = 0; i < 6; i++){
		*ptr-- = *mac_addr++; /* 网络数据包中mac的最低位, copy至long long整数的最高位(除去最高2个字节后) */
	}
}

static int sapp_get_vxlan_info_from_streaminfo(const struct streaminfo *pstream, struct vxlan_info *vxinfo)
{
#define GDEV_SMAC_MASK_ENCAP_TYPE  	(0x00000000000F0000)
#define GDEV_SMAC_MASK_ENTRANCE_ID  	(0x0000000000007C00)
#define GDEV_SMAC_MASK_DEV_ID  			(0x00000000000003F0)
#define GDEV_SMAC_MASK_LINK_ID  		(0x000000000000000E)
#define GDEV_SMAC_MASK_LINK_DIR  		(0x0000000000000001)


	int ret, i;
	const struct streaminfo *mim_stream = pstream->pfather;
	const struct layer_addr_mac_in_mac *mim_addr;
	const struct layer_addr_mac *mac_addr;
	unsigned char *ptr;
	unsigned long long smac_integer_type; /* 48bit mac转换为64bit的长整型数字存储, 便于操作 */

	while(mim_stream){
		if(ADDR_TYPE_MAC_IN_MAC == mim_stream->addr.addrtype || ADDR_TYPE_MAC == mim_stream->addr.addrtype){
			break;
		}else{
			mim_stream = mim_stream->pfather;
		}
	}

	if(NULL == mim_stream){
		return -1;
	}

	memset(vxinfo, 0, sizeof(struct vxlan_info));

	if(ADDR_TYPE_MAC_IN_MAC == mim_stream->addr.addrtype)
    {
        mim_addr = mim_stream->addr.mimac;
        sapp_mac_addr_to_long(mim_addr->outer_src_mac, &smac_integer_type);
    }
    else
    {
        mac_addr = mim_stream->addr.mac;
        sapp_mac_addr_to_long(mac_addr->src_mac, &smac_integer_type);
    }
	vxinfo->encap_type = (smac_integer_type & GDEV_SMAC_MASK_ENCAP_TYPE) >> 16;
	vxinfo->entrance_id = (smac_integer_type & GDEV_SMAC_MASK_ENTRANCE_ID) >> 10;
	vxinfo->dev_id = (smac_integer_type & GDEV_SMAC_MASK_DEV_ID) >> 4;
	vxinfo->link_id = (smac_integer_type & GDEV_SMAC_MASK_LINK_ID ) >> 1;
	vxinfo->link_dir = (smac_integer_type & GDEV_SMAC_MASK_LINK_DIR);

    if(ADDR_TYPE_MAC_IN_MAC == mim_stream->addr.addrtype)
    {
        ptr = vxinfo->inner_smac;
        for(i = 0; i < 6; i++, ptr += 3){
            sprintf((char *)ptr, "%02x:", mim_addr->inner_src_mac[i]);
        }
        vxinfo->inner_smac[17] = '\0'; /* 最后一位清零 */
        memcpy(vxinfo->inner_smac_hex, mim_addr->inner_src_mac, 6);

        ptr = vxinfo->inner_dmac;
        for(i = 0; i < 6; i++, ptr += 3){
            sprintf((char *)ptr, "%02x:", mim_addr->inner_dst_mac[i]);
        }
        vxinfo->inner_dmac[17] = '\0'; /* 最后一位清零 */
        memcpy(vxinfo->inner_dmac_hex, mim_addr->inner_dst_mac, 6);
    }
    else
    {
		ptr = vxinfo->inner_smac;
		for(i = 0; i < 6; i++, ptr += 3){
			sprintf((char *)ptr, "%02x:", mac_addr->src_mac[i]);
		}
		vxinfo->inner_smac[17] = '\0'; /* 最后一位清零 */
		memcpy(vxinfo->inner_smac_hex, mac_addr->src_mac, 6);

        ptr = vxinfo->inner_dmac;
        for(i = 0; i < 6; i++, ptr += 3){
            sprintf((char *)ptr, "%02x:", mac_addr->dst_mac[i]);
        }
        vxinfo->inner_dmac[17] = '\0'; /* 最后一位清零 */
        memcpy(vxinfo->inner_dmac_hex, mac_addr->dst_mac, 6);
    }
	return 0;
}

int MESA_get_stream_opt(const struct streaminfo *pstream, enum MESA_stream_opt opt, void *opt_val, int *opt_val_len)
{
	int ret = 0;
	
	if((NULL == opt_val) || (NULL == opt_val_len) || (*opt_val_len <= 0)){
		return -1;
	}

	switch((int)opt){
		case (int)MSO_MAX_UNORDER:
		{
			if(STREAM_TYPE_TCP != pstream->type){
				sapp_runtime_log(RLOG_LV_DEBUG, "MESA_get_stream_opt() error:stream type is not tcp!\n");
				ret = -1;
				break;
			}		
			if(*opt_val_len < (int)sizeof(struct max_unorder_opt)){
				sapp_runtime_log(RLOG_LV_DEBUG,"MESA_get_stream_opt() error:opt_val_len invalid, must be sizeof(struct max_unorder_opt)\n");
				ret = -1;
				break;
			}
			*opt_val_len = sizeof(struct max_unorder_opt);			
			ret = tcp_get_single_stream_max_unorder(pstream, opt_val, opt_val_len);
		}
		break;

		case (int)MSO_NEED_ACK:
		{
			if(STREAM_TYPE_TCP != pstream->type){
				sapp_runtime_log(RLOG_LV_DEBUG,"MESA_get_stream_opt() error:stream type is not tcp!\n");
				ret = -1;
				break;
			}
			unsigned char *nack = (unsigned char *)opt_val;
			struct tcpdetail_private *pdetail_pr = (struct tcpdetail_private*)(pstream->pdetail);
			*nack = pdetail_pr->needackflag;
			*opt_val_len = sizeof(char);
		}
		break;

		case (int)MSO_TAKEOVER:
		{
			if(*opt_val_len < (int)sizeof(int)){
				ret = -1;
				break;
			}
			if(STREAM_TYPE_TCP != pstream->type){
				sapp_runtime_log(RLOG_LV_DEBUG,"MESA_get_stream_opt() error:stream type is not tcp!\n");
				ret = -1;
				break;
			}
			int *takeover = (int *)opt_val;
			struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private*)(pstream->pdetail);
			*takeover = pdetail_pr->takeoverflag;
			*opt_val_len = sizeof(int);
		}
		break;

		case (int)MSO_TIMEOUT:
		{
			if(sizeof(short) != *opt_val_len){
				sapp_runtime_log(RLOG_LV_DEBUG,"MESA_get_stream_opt() error:opt_val_len invalid, must be sizeof(short)\n");
				ret = -1;
				break;
			}
			unsigned short *tmout = (unsigned short *)opt_val;
			struct streaminfo_private *pstream_pr=(struct streaminfo_private *)pstream;
			*tmout = pstream_pr->timeout;
			*opt_val_len = sizeof(short);
		}
		break;

		case (int)MSO_IGNORE_RST_FIN:
		{
			if(STREAM_TYPE_TCP != pstream->type){
				sapp_runtime_log(RLOG_LV_DEBUG,"MESA_get_stream_opt() error:stream type is not tcp!\n");
				ret = -1;
				break;
			}
			unsigned char *igrstfin = (unsigned char *)opt_val;
			struct tcpdetail_private *pdetail_pr = (struct tcpdetail_private*)(pstream->pdetail);
			*igrstfin = pdetail_pr->ignore_rst_fin;	
		}	
		break;
		
		case MSO_TCP_CREATE_LINK_MODE:
		{
			struct tcpdetail_private *pdetail_pr;
			UCHAR *out_val = (UCHAR *)opt_val;
			if(STREAM_TYPE_TCP != pstream->type){
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG,"MESA_get_stream_opt() error:stream type is not tcp!\n");
				break;
			}
			
			pdetail_pr = (struct tcpdetail_private*)(pstream->pdetail);
			*out_val = pdetail_pr->creat_mod;
			*opt_val_len = sizeof(char);
		}
		break;

		case MSO_TCP_ISN_C2S:
		{
			struct tcpdetail_private *pdetail_pr;
			UINT32 *out_val = (UINT32 *)opt_val;
			if(STREAM_TYPE_TCP != pstream->type){
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "MESA_get_stream_opt() error:stream type is not tcp!\n");
				break;
			}
 
			pdetail_pr = (struct tcpdetail_private*)(pstream->pdetail);
			if(pdetail_pr->creat_mod != TCP_CTEAT_LINK_BYSYN){
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "MESA_get_stream_opt() error: stream create mode is not by SYN!\n");
				break;
			}
			if(0 == pdetail_pr->iserverseq){
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "MESA_get_stream_opt() error: can't get SYN seq!\n");
				break;
			}
			
			*out_val = pdetail_pr->iserverseq - 1;
			*opt_val_len = sizeof(int);
		}
		break;

		case MSO_TCP_ISN_S2C:
		{
			/* TODO 1: 代码与上面重复, 待合并 */
			struct tcpdetail_private *pdetail_pr;
			UINT32 *out_val = (UINT32 *)opt_val;
			if(STREAM_TYPE_TCP != pstream->type){
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "MESA_get_stream_opt() error:stream type is not tcp!\n");
				break;
			}
			pdetail_pr = (struct tcpdetail_private*)(pstream->pdetail);
			if(pdetail_pr->creat_mod != TCP_CTEAT_LINK_BYSYN){
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "MESA_get_stream_opt() error: stream create mode is not by SYN!\n");
				break;
			}

			if(0 == pdetail_pr->iclientseq){
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "MESA_get_stream_opt() error: can't get SYN/ACK seq!\n");
				break;
			}

			*out_val = pdetail_pr->iclientseq - 1;
			*opt_val_len = sizeof(int);
		}
		break;

		case MSO_TCP_SYN_OPT:
		{
			const struct streaminfo_private *pstream_pr = (const struct streaminfo_private *)pstream;
			struct tcp_option **out_val = (struct tcp_option **)opt_val;
			if((pstream_pr->syn_opt_array != NULL) && (pstream_pr->syn_opt_num > 0)){
				*out_val = pstream_pr->syn_opt_array;
				*opt_val_len = pstream_pr->syn_opt_num; /* 此处不是长度, 表示opt_array的个数 */
				ret = 0;
			}else{
				ret = -1;
			}
		}
		break;

		case MSO_TCP_SYNACK_OPT:
		{
			const struct streaminfo_private *pstream_pr = (const struct streaminfo_private *)pstream;
			struct tcp_option **out_val = (struct tcp_option **)opt_val;
			if((pstream_pr->synack_opt_array != NULL) && (pstream_pr->synack_opt_num > 0)){
				*out_val = pstream_pr->synack_opt_array;
				*opt_val_len = pstream_pr->synack_opt_num;  /* 此处不是长度, 表示opt_array的个数 */
				ret = 0;
			}else{
				ret = -1;
			}
		}
		break;

		case MSO_STREAM_TUNNEL_TYPE:
		{
			const struct streaminfo_private *pstream_pr = (const struct streaminfo_private *)pstream;
			unsigned short *out_val = (unsigned short *)opt_val;
			*out_val = pstream_pr->stream_low_layer_tunnel_type;
			ret = 0;
		}
		break;

		case MSO_STREAM_CLOSE_REASON:
		{
			if(pstream->opstate != OP_STATE_CLOSE){
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "MESA_get_stream_opt() MSO_STREAM_CLOSE_REASON error: stream %p has not closed!\n", pstream);
				break;				
			}
			if(pstream->type != STREAM_TYPE_TCP){
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "MESA_get_stream_opt() error:unsupport stream type:%d!\n", pstream->type);
				break;
			}
			UCHAR *close_reason = (UCHAR *)opt_val;
			struct tcpdetail_private *pdetail_pr = (struct tcpdetail_private*)(pstream->pdetail);
			*close_reason = pdetail_pr->link_state;
		}
		break;

		case MSO_STREAM_VXLAN_INFO:
			if(*opt_val_len != sizeof(struct vxlan_info)){
				return -1;
			}
			ret = sapp_get_vxlan_info_from_streaminfo(pstream, (struct vxlan_info *)opt_val);
		break;
		
		default:
			sapp_runtime_log(RLOG_LV_DEBUG, "MESA_get_stream_opt() error:unsupport MESA_stream_opt type:%d!\n", opt);
			ret = -1;
			break;		
	}

	return ret;
}

int is_proxy_stream(const struct streaminfo *pstream)
{
	int ret = 0;
	
	switch(pstream->type){
		case STREAM_TYPE_SOCKS4:
		case STREAM_TYPE_SOCKS5:
		case STREAM_TYPE_HTTP_PROXY:
		case STREAM_TYPE_OPENVPN:
			ret = 1;
		break;

		default:
			ret = 0;
			break;
	}

	return ret;
}


void bind_thread_to_cpuid(int thread_id)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
#if(__GNUC__ * 100 + __GNUC_MINOR__ * 10 + __GNUC_PATCHLEVEL__ >= 440)
	cpu_set_t cpuset;
	u_long core_id;
	int res;
	int tot_cpu_num = sysconf(_SC_NPROCESSORS_ONLN);

	/* Bind this thread to a specific core */
	if(tot_cpu_num > 1) {
		core_id = (thread_id + 1) % tot_cpu_num; 

		CPU_ZERO(&cpuset);
		CPU_SET(core_id, &cpuset);
		res = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
		if (res != 0){
			fprintf(stderr, "Error while binding thread %d to core %ld: errno=%i\n", 
	     			thread_id, core_id, res);
	      }else{
			printf("[Info]Binding thread %d to core %ld success!\n", thread_id, core_id);
	      }
	}
#endif	
#endif
	return;
}


extern int project_req_terminal_tag_id;
/* For863, 用于应用层插件获取本TCP流中对应的用户标签 */
const unsigned char *get_terminal_tag(struct streaminfo *stream)
{
	unsigned char *terminal_tag;
	
	if(project_req_terminal_tag_id < 0){
		return NULL;
	}
	
	terminal_tag = (unsigned char *)project_req_get_struct(stream, project_req_terminal_tag_id);
	
	return (const unsigned char *)terminal_tag;
}

int number_is_2powerN(uint n)
{
	if(n & (n-1)){
		return 0;
	}    

	return 1;
}



void *dictator_malloc(int thread_seq,size_t size)
{	
	/*
	if(malloccount%100000==0)
	{
		printf("malloc=%d,free=%d\n",malloccount,freecount);
	}
	*/

	if(G_DICTATOR_SW){
#if USE_MEMPOOL
		return __dictator_malloc(thread_seq, size);
#endif		
	}

	return malloc(size);
}	
void dictator_free(int thread_seq,void *pbuf)
{
#if USE_MEMPOOL	
	if(G_DICTATOR_SW){
		__dictator_free(thread_seq, pbuf);
	}
	else
#endif
	{
		free(pbuf);
	}
}

void *dictator_realloc(int thread_seq, void *ptr, size_t size)
{
#if USE_MEMPOOL	
	if(G_DICTATOR_SW){
		return __dictator_realloc(thread_seq, ptr, size);
	}
#endif

	return realloc(ptr, size);
}

/* 将业务插件返回的值转换成平台定义的值, 即将PROT_STATE_xxx转换为APP_STATE_xxx */
char biz_retval_to_platform(char biz_ret)
{
	char plat_ret = 0;

	if(biz_ret & PROT_STATE_GIVEME){
		plat_ret |= APP_STATE_GIVEME;
	}

	if(biz_ret & PROT_STATE_DROPME){
		plat_ret |= APP_STATE_DROPME;
	}

	if(biz_ret & PROT_STATE_DROPPKT){
		plat_ret |= APP_STATE_DROPPKT;
	}
	
	return plat_ret;
}

/* 将平台的state值转换成业务插件的值, 即将OP_STATE_PENDING转为SESSION_STATE_PENDING */
char plat_state_to_biz(char plat_state)
{
	char biz_ret = SESSION_STATE_CLOSE;

	switch(plat_state){
		case OP_STATE_PENDING:
			biz_ret = SESSION_STATE_PENDING;
		break;

		case OP_STATE_DATA:
			biz_ret = SESSION_STATE_DATA;
		break;

		case OP_STATE_CLOSE:
			biz_ret = SESSION_STATE_CLOSE;
		break;

		default:
		break;
	}

	return biz_ret;
}


long long sapp_get_cpu_cycle(void)
{
#ifdef __x86_64
#define X86_64_ENV 1
#endif
#ifdef  __x86_64__
#define X86_64_ENV 1
#endif

#ifdef X86_64_ENV
	 long long l;
	 long long h;

	__asm__ volatile("rdtsc" : "=a"(l), "=d"(h));
	return (long long )l | ((long long )h<<32);
#else
	return 0;
#endif
}

#ifdef __cplusplus
}
#endif

