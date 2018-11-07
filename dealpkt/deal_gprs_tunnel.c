#ifdef __cplusplus
extern "C" {
#endif

#include "stream_internal.h" 
#include "stream_manage.h"
#include "mesa_net.h"
#include "sysinfo.h"

#define GPRS_TUNNEL_PORT (2152)

struct layer_addr_gtp
{
    unsigned char source[8];
    unsigned char dest[8];
};

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

    /* 之前已经通过协议识别插件识别过, 所以在entry()里不用再次判断 */
    p_gtd_hdr = (const struct gtp_hdr *)((char *)this_layer_data + sizeof(struct mesa_udp_hdr));

    if(p_gtd_hdr->flags != 0x30)
    {
        sapp_runtime_log(20, "GTP layer flag not 0x30, %x !\n", p_gtd_hdr->flags);
        return PASS;
    }
    if(p_gtd_hdr->msg_type != GTP_MSG_TYPE_T_PDU)
    {
        sapp_runtime_log(20, "GTP layer msg_type not T_PDU, %x !\n", p_gtd_hdr->msg_type);
        return PASS;
    }


    g_SysInputInfo[thread_num][TUNNEL_GTP]++;

    memset(&tmp_index, 0, sizeof(struct streamindex));
    if(pfstream_pr->layer_dir == 1)
    {
        memcpy(gtpaddr.source, p_gtd_hdr, sizeof(struct gtp_hdr));
        pstream->curdir = DIR_C2S;
    }
    else
    {
        memcpy(gtpaddr.dest, p_gtd_hdr, sizeof(struct gtp_hdr));
        pstream->curdir = DIR_S2C;
    }
    pstream->addr.paddr = &gtpaddr;
    pstream->addr.addrtype = ADDR_TYPE_GPRS_TUNNEL;
    pstream->addr.addrlen = sizeof(struct layer_addr_gtp); /* 此处使用结构体长度 */

    pstream_pr->addr_use_as_hash = 0;

    pstream_pr->offset_to_raw_pkt_hdr = (unsigned short)offset_to_raw_pkt_hdr;
    pstream_pr->raw_pkt = raw_pkt;
    pstream_pr->layer_dir = pfstream_pr->layer_dir; /* L2TP层不能对本层做出方向性判断, 使用父层的方向值, L2TP只能是UDP或IP承载 */

    pstream->pfather=&pfstream_pr->stream_public;
    pstream->type=STREAM_TYPE_NON;
    pstream->routedir=routedir;
    pstream->threadnum=(UCHAR)thread_num;

    next_layer_hdr = (char *)p_gtd_hdr + sizeof(struct gtp_hdr);
    next_layer_offset = offset_to_raw_pkt_hdr + sizeof(struct gtp_hdr);

    if((*next_layer_hdr & 0xF0) == 0x40)
    {
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
}


/*
	内置插件, 
	用于识别当前UDP流是否是隧道.
	如果是隧道, 在streaminfo_private->stream_carry_up_layer_tunnel_type中设置标记.
*/
char udp_gtp_identify_entry(const struct streaminfo *pstream, const void *this_hdr, const void *raw_pkt, void **pme)
{
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
	return APP_STATE_DROPME; /* 每个流只看第一个包, 不管是否GTP隧道, 后续都不再处理了 */
}


#ifdef __cplusplus
}
#endif


