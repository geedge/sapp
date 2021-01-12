#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"

static int set_vxlan_addr(const void *this_layer_hdr, struct layer_addr_vxlan *addr)
{
	unsigned short vlan_id_high, vlan_id_low;
	
	const inline_vxlan_hdr_t *vxlan_hdr = (inline_vxlan_hdr_t *)this_layer_hdr;

	addr->dir = vxlan_hdr->dir;
	addr->link_id = vxlan_hdr->link_id;
	addr->link_type = vxlan_hdr->link_layer_type;
	vlan_id_high = vxlan_hdr->vlan_id_half_high;
	vlan_id_low = vxlan_hdr->vlan_id_half_low;
	addr->vlan_id = (vlan_id_high<<8) | vlan_id_low;

	return 0;
}

int vxlan_entry(struct streaminfo_private *pfstream_pr,const void *this_layer_hdr,int thread_num, 
						unsigned char routedir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr)
{
	int ret;
	int next_layer_offset;
	const unsigned char *next_layer_data;
	struct streamindex tmp_index;
	struct streamindex *ptmp=&tmp_index;
	struct streaminfo_private *pstream_pr = &ptmp->stream;
	struct streaminfo *pstream = &pstream_pr->stream_public;	
	struct layer_addr_vxlan addr;

	memset(ptmp,0,sizeof(struct streamindex));
	
	next_layer_data = (const unsigned char *)this_layer_hdr + sizeof(inline_vxlan_hdr_t);
	next_layer_offset = offset_to_raw_pkt_hdr + sizeof(inline_vxlan_hdr_t);
	

	set_vxlan_addr(this_layer_hdr, &addr);

	pstream->addr.paddr=&addr;
	pstream->addr.addrtype = ADDR_TYPE_VXLAN;
	pstream->addr.addrlen = sizeof(struct layer_addr_vxlan);
	pstream_pr->addr_use_as_hash = 0;//vxlan地址不参与hash比对
	pstream_pr->layer_index = pfstream_pr->layer_index+1;

	pstream_pr->offset_to_raw_pkt_hdr = offset_to_raw_pkt_hdr;
	pstream_pr->raw_pkt = raw_pkt;
	
	pstream->pfather=&pfstream_pr->stream_public;
	pstream_pr->pfather_pr = pfstream_pr;
	pstream->type=STREAM_TYPE_NON;
	pstream->routedir=routedir;
	pstream->threadnum=thread_num;

	ret = eth_entry(pstream_pr,next_layer_data,thread_num,routedir,raw_pkt, next_layer_offset);

	return ret;
}

#ifdef __cplusplus
}
#endif


