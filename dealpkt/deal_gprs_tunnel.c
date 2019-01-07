#ifdef __cplusplus
extern "C" {
#endif

#include "stream_internal.h" 
#include "stream_manage.h"
#include "mesa_net.h"
#include "sysinfo.h"
#include "MESA_htable.h"

#define GPRS_TUNNEL_PORT (2152)


MESA_htable_handle g_gtp_info_hash[MAX_THREAD_NUM];

extern int ipv4_entry(struct streaminfo_private *pfstream, const void *this_layer_data, int thread_num,
                      unsigned char routedir, const raw_pkt_t *raw_pkt, int);

extern int ipv6_entry(struct streaminfo_private *pfstream, const void *this_layer_data, int thread_num,
                      unsigned char routedir, const raw_pkt_t *raw_pkt, int);

int gtp_entry(struct streaminfo_private *pfstream_pr,void *this_layer_data,int thread_num, 
		unsigned char routedir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr)
{
	/*
		创建gtp层结构, 分别记录C2S, S2C方向的地址, 
	*/
    struct streamindex tmp_index;
    struct streamindex *ptmp=&tmp_index;
    struct streaminfo_private *pstream_pr = &ptmp->stream;
    struct streaminfo *pstream = &pstream_pr->stream_public;
    struct layer_addr_gtp gtpaddr;
    const struct gtp_hdr *p_gtd_hdr;
    int ret = PASS;
    char *next_layer_hdr;
    int next_layer_offset;
    unsigned int cur_seq = 0, seq_offset = 0;

    //针对同一回话GTP网关源端口变化的情况，强制将栈上的streaminfo中，源端口设置成0
    if(pfstream_pr->stream_public.curdir == DIR_C2S)
    {
        pfstream_pr->stream_public.addr.tuple4_v4->source = 0;
        pfstream_pr->stream_public.addr.tuple4_v4->saddr = 0;
    }
    if(pfstream_pr->stream_public.curdir == DIR_S2C)
    {
        pfstream_pr->stream_public.addr.tuple4_v4->dest = 0;
        pfstream_pr->stream_public.addr.tuple4_v4->daddr = 0;
    }
    /* 之前已经通过协议识别插件识别过, 所以在entry()里不用再次判断 */
    p_gtd_hdr = (const struct gtp_hdr *)((char *)this_layer_data + sizeof(struct mesa_udp_hdr));

    /* 仅处理T-PDU类型的数据面信息，控制面不认为是GTP隧道*/
    if(p_gtd_hdr->msg_type != GTP_MSG_TYPE_T_PDU)
    {
        sapp_runtime_log(10, "GTP layer msg_type not T_PDU, %x !\n", p_gtd_hdr->msg_type);
        return PASS;
    }
    if(p_gtd_hdr->flags != 0x30 && p_gtd_hdr->flags != 0x32)
    {
        sapp_runtime_log(20, "GTP layer flag not 0x30, %x !\n", p_gtd_hdr->flags);
        return PASS;
    }

    if(p_gtd_hdr->flags == 0x32)
    {
        cur_seq = ntohl(*(unsigned int *)(p_gtd_hdr + 1));
        seq_offset = sizeof(unsigned int);
    }

    g_SysInputInfo[thread_num][TUNNEL_GTP]++;

    memset(&tmp_index, 0, sizeof(struct streamindex));
    memset(&gtpaddr, 0, sizeof(struct layer_addr_gtp));
    /* GTP地址C2S, S2C方向独立, 无法靠当前包地址区分dir, 每次栈里的变量都存储于source方向, 即C2S方向,  
       创建流时, 如果需要reverse拷贝, 则将source, dest颠倒, 否则直接memcpy到堆里的addr.
     */
    memcpy(&gtpaddr.source, p_gtd_hdr, sizeof(struct gtp_hdr));
    gtpaddr.src_seq = cur_seq;
    pstream->curdir = DIR_C2S;

    
    pstream->addr.paddr = &gtpaddr;
    pstream->addr.addrtype = ADDR_TYPE_GPRS_TUNNEL;
    pstream->addr.addrlen = sizeof(struct layer_addr_gtp); /* 此处使用结构体长度 */

    pstream_pr->addr_use_as_hash = 0;//地址不参与hash比对，仅算层数
    pstream_pr->need_update_opposite_addr = 1;//需要更新对侧信息

    pstream_pr->offset_to_raw_pkt_hdr = (unsigned short)offset_to_raw_pkt_hdr;
    pstream_pr->raw_pkt = raw_pkt;
    pstream_pr->layer_dir = pfstream_pr->layer_dir;  

    pstream->pfather=&pfstream_pr->stream_public;
    pstream->type=STREAM_TYPE_NON;
    pstream->routedir=routedir;
    pstream->threadnum=(UCHAR)thread_num;

    next_layer_hdr = (char *)p_gtd_hdr + sizeof(struct gtp_hdr) + seq_offset;
    next_layer_offset = offset_to_raw_pkt_hdr + sizeof(struct gtp_hdr) + seq_offset;

    if((*next_layer_hdr & 0xF0) == 0x40)
    {
        int left_pkt_len = raw_pkt->raw_pkt_len - next_layer_offset;
        struct iphdr  *ip4_hdr = (struct iphdr *)next_layer_hdr;
        if(left_pkt_len < 20 || ntohs(ip4_hdr->tot_len) > left_pkt_len)
        {
            g_SysInputInfo[thread_num][PKT_UNKNOWN]++;
            g_SysInputInfo[thread_num][PKT_UNKNOWN_LEN] += raw_pkt->raw_pkt_len;
            sapp_runtime_log(20, "illegal left Ipv4 len %d, total len %d!\n", left_pkt_len, ntohs(ip4_hdr->tot_len));
            return DROP;
        }
        ret = ipv4_entry(pstream_pr,next_layer_hdr,thread_num,routedir,raw_pkt, next_layer_offset);
    }
    else if((*next_layer_hdr & 0xF0) == 0x60)
    {
        ret = ipv6_entry(pstream_pr,next_layer_hdr,thread_num,routedir,raw_pkt, next_layer_offset);
    }
    else
    {
        sapp_runtime_log(20, "GTP next layer not IPv4 or IPv6, drop pkt !\n");
        return PASS;
    }
    return ret;
}


static int identify_gtp(const struct streaminfo *pstream,const char *payload, unsigned int payload_len)
{
    if (payload_len >= sizeof(struct gtp_hdr))
    {
        unsigned int gtp_u = (2152);
        unsigned int gtp_c = (2123);
        unsigned int gtp_v0 = (3386);

        unsigned short dest = 0, source = 0;

        if (pstream->addr.addrtype == __ADDR_TYPE_IP_PAIR_V6
            || pstream->addr.addrtype == ADDR_TYPE_IPV6) {
            dest = ntohs(pstream->addr.ipv6->dest);
            source = ntohs(pstream->addr.ipv6->source);
        } else {
            dest = ntohs(pstream->addr.ipv4->dest);
            source = ntohs(pstream->addr.ipv4->source);
        }

        if ((source == gtp_u) || (dest == gtp_u) || (source == gtp_c)
            || (dest == gtp_c) || (source == gtp_v0) || (dest == gtp_v0)) {
            struct gtp_hdr *gtp =
                    (struct gtp_hdr *) payload;
            unsigned short gtp_version = (gtp->flags & 0xE0) >> 5;

            if ((gtp_version == 0) || (gtp_version == 1) || (gtp_version == 2)) {
                unsigned short message_len = ntohs(gtp->len);

                if (message_len == (payload_len - sizeof(struct gtp_hdr))) {
                    return 1;
                }
            }
        }
    }
    return 0;
}

/*
	内置插件, 
	用于识别当前UDP流是否是隧道.
	如果是隧道, 在streaminfo_private->stream_carry_up_layer_tunnel_type中设置标记.
*/
char udp_gtp_identify_entry(const struct streaminfo *pstream, const void *this_hdr, const void *raw_pkt, void **pme)
{
#if 0
	if(pstream->addr.addrtype == ADDR_TYPE_IPV4)
	{
		if(ntohs(pstream->addr.tuple4_v4->dest) == GPRS_TUNNEL_PORT && ntohs(pstream->addr.tuple4_v4->source) == GPRS_TUNNEL_PORT)
        {
            struct streaminfo_private *pstream_pr = (struct streaminfo_private *)pstream;
            pstream_pr->stream_carry_up_layer_tunnel_type |= STREAM_TUNNEL_GPRS_TUNNEL;
        }
	}
    else if(pstream->addr.addrtype == ADDR_TYPE_IPV6)
    {
        if(ntohs(pstream->addr.tuple4_v6->dest) == GPRS_TUNNEL_PORT && ntohs(pstream->addr.tuple4_v6->source) == GPRS_TUNNEL_PORT)
        {
            struct streaminfo_private *pstream_pr = (struct streaminfo_private *)pstream;
            pstream_pr->stream_carry_up_layer_tunnel_type |= STREAM_TUNNEL_GPRS_TUNNEL;
        }
    }
    else
        ;
#else
    struct streaminfo_private *pstream_pr = (struct streaminfo_private *)pstream;
    if(1 == identify_gtp(pstream, (char *)this_hdr+sizeof(struct mesa_udp_hdr), 
    					pstream_pr->raw_pkt->raw_pkt_len - ((const char *)this_hdr - (const char*)pstream_pr->raw_pkt->raw_pkt_data) - sizeof(struct mesa_udp_hdr)))
    {
        pstream_pr->stream_carry_up_layer_tunnel_type |= STREAM_TUNNEL_GPRS_TUNNEL;
    }
#endif
	return APP_STATE_DROPME; /* 每个流只看第一个包, 不管是否GTP隧道, 后续都不再处理了 */
}


#ifdef __cplusplus
}
#endif


