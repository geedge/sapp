#include "mesa_net.h"
#include "deal_ipv6.h"
/* Linux OS std */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <dlfcn.h>
#include <linux/if_ether.h>
#include <linux/limits.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/types.h>
#include <linux/version.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/un.h>
#include <link.h>
#include <execinfo.h>
#include <pcap/pcap.h>
#include <getopt.h>
#include <sys/sysinfo.h>
#include <dirent.h>
#include <sys/syscall.h>


static int eth_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type);
static int vlan8021q_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type);
static int ipv4_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type);
static int ipv6_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type);
static int ppp_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type);

static char _g_mesa_jump_layer_last_error[PIPE_BUF];

static int __mjl_guess_mpls_with_control_word(const unsigned char *maybe_eth_hdr)
{
	const struct mesa_ethernet_hdr *ehdr = (struct mesa_ethernet_hdr *)(maybe_eth_hdr);

	/* 
	    MPLSû���ֶα�ʾ���ص�Э������, ����!!
	    
	    https://tools.ietf.org/html/rfc4623
	    https://wiki.mikrotik.com/wiki/Manual:VPLS_Control_Word
	    https://www.ciscopress.com/articles/article.asp?p=386788&seqNum=2
	    
	    ����׼��ipv4, ipv6֮��, ���п�����ethernet, ���п����Ǵ�PW Ethernet Control Word��, ��ʽ����:
	    
        0               1               2                 3
		0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|0 0 0 0| flags |frag|len(6bit) |    Sequence Number(16bit)     |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		ʵ�����֤��, ��4bit�Ƿ�==0Ϊ����, ���ǿ��ܲ´�, ���ж�һ����̫�����Ƿ�Ϊ��������.
	*/

	switch(ntohs(ehdr->ether_type)){
		case ETH_P_IP:
		case ETH_P_IPV6:
		case ETH_P_8021Q:
		case ETH_P_MPLS_UC:
		case ETH_P_PPP_SES:
			return 0; /* �Ϸ���ethernet����, ����CW */
		break;

		default:
		break;
	}

	ehdr = (struct mesa_ethernet_hdr *)(maybe_eth_hdr + 4);
	switch(ntohs(ehdr->ether_type)){
		case ETH_P_IP:
		case ETH_P_IPV6:
		case ETH_P_8021Q:
		case ETH_P_MPLS_UC:
		case ETH_P_PPP_SES:
			return 1; /* �Ϸ���ethernet����, ����CW */
		break;
		
		default:
		break;		
	}

	/* TODO: ���϶�����, �˴�Ӧ�÷��ظ�ʲôֵ? */
	return 0;
}

static int __mjl_mpls_addr_net_to_mem(const struct mesa_mpls_hdr *net_mpls_hdr, struct single_layer_mpls_addr *mem_mpls_hdr)
{
	memset(mem_mpls_hdr, 0, sizeof(struct single_layer_mpls_addr));

	mem_mpls_hdr->label = htonl( (net_mpls_hdr->mpls_label_low<<12) | (net_mpls_hdr->mpls_label_mid<<4) | net_mpls_hdr->mpls_label_high ); /* network order */
	mem_mpls_hdr->experimental = net_mpls_hdr->mpls_exp;
	mem_mpls_hdr->bottom = net_mpls_hdr->mpls_bls;
	mem_mpls_hdr->ttl = net_mpls_hdr->mpls_ttl;

	return 0;
}

static int __mjl_set_mpls_addr(struct layer_addr_mpls *addr, const unsigned char *raw_mpls_pkt_data)
{
	const struct mesa_mpls_hdr *this_mpls_hdr;
	int i;
	
    memset(addr, 0, sizeof(struct layer_addr_mpls));
	for(i = 0; i < MAX_MPLS_ADDR_LAYER; i++)
	{
		this_mpls_hdr = (const struct mesa_mpls_hdr *)raw_mpls_pkt_data;
		//memcpy(&addr->src_mpls_pkt[i], raw_mpls_pkt_data,  sizeof(struct mesa_mpls_hdr));
		__mjl_mpls_addr_net_to_mem(this_mpls_hdr, &addr->c2s_addr_array[i]); /* ����ջ��ĵ�ַ, ÿ���ݴ���c2s����, TCP/UDP���ٸ���������ת */
		
		addr->c2s_layer_num += 1;
		if(1 == this_mpls_hdr->mpls_bls){
			raw_mpls_pkt_data += sizeof(struct mesa_mpls_hdr); /* Ϊ�˺��淽���ж��Ƿ���ctrl word */
			break;
		}
		raw_mpls_pkt_data += sizeof(struct mesa_mpls_hdr);
	}

	if(1 != this_mpls_hdr->mpls_bls) /* ����MAX_MPLS_ADDR_LAYER, MPLS��û�н��� */
	{
		snprintf(_g_mesa_jump_layer_last_error, PIPE_BUF, "MPLS layer number over load, only support %d", MAX_MPLS_ADDR_LAYER);
		return -1;
	}

	if(((*raw_mpls_pkt_data & 0xF0) != 0x40) && ((*raw_mpls_pkt_data & 0xF0) != 0x60)){ //VPLS, MPLS with Control Word
		if(__mjl_guess_mpls_with_control_word(raw_mpls_pkt_data) > 0){
			memcpy(&addr->c2s_mpls_ctrl_word, raw_mpls_pkt_data,  sizeof(int));
			addr->c2s_has_ctrl_word = 1;
		}
	}

	return 0;
}

/*
  gprsͷ�����ݱ�־λ�Ĳ�ͬ, ����Ҳ��ͬ, ����ֱ����sizeof(struct gtp_hdr)��ȡ����.
*/
static int __mjl_gtp_calc_gtp_hdr_len(const struct gtp_hdr *gtph)
{
	const unsigned char *p_ext_hdr = (unsigned char *)gtph + sizeof(struct gtp_hdr);
	unsigned char next_hdr_type;
	unsigned char this_ext_field_cont_len;

	/* 
	   v0̫������, �ѱ�����;
	   ������GTPv2-UЭ��, ��LTE�е�GTP-U��ʹ��GTPv1-U, 
	   ����, sappĿǰ��֧��gtp v1�汾.
	 */
	if(((gtph->flags & GTP_HDR_VER_MASK) >> 5) != 1){
	  return -1; 
	}

	if(gtph->msg_type != 0xFF){
	  return -1;
	}

	if(ntohs(gtph->len) > 1460 || ntohs(gtph->len) < 40)
	{
		return -1;
	}

	if(gtph->flags & (GTP_HDR_FLAG_SEQ_NUM | GTP_HDR_FLAG_N_PDU | GTP_HDR_FLAG_NEXT_EXT_HDR)){
	  //todo, parse and get seq field
	  p_ext_hdr += 2; //seq field length is 2 bytes

	  //todo, parse and get N-PDU field
	  p_ext_hdr++; //N-PDU field length is 1 byte 

    /*
		����gtp��չͷ���ֶ�, 
		�ο�3GPP�ĵ���5.1, 5.2�½�,
		�Լ�wiresharkԴ��, packet-gtp.c -> dissect_gtp_common()����.
    */

	next_hdr_type = *p_ext_hdr;
	  if(gtph->flags & GTP_HDR_FLAG_NEXT_EXT_HDR){
		  while(next_hdr_type != 0){
		  	//todo, parse and get extension headers
			  p_ext_hdr++; //ָ�򳤶��ֶ�, ��4���ֽ�Ϊ��λ
			  this_ext_field_cont_len = *p_ext_hdr * 4 - 2;

			  p_ext_hdr++; //ָ�����ݲ��ֵ�һ���ֽ�
			  p_ext_hdr += this_ext_field_cont_len;

			  //ָ����һ��ͷ���ֶ�
			  next_hdr_type = *p_ext_hdr;
			  p_ext_hdr++;
		  }
	  }else{
		  p_ext_hdr++;
	  }
	}

	return (char *)p_ext_hdr - (char *)gtph;
}

static inline int check_layer_type(int layer_type)
{
	if((layer_type <= __ADDR_TYPE_INIT) || (layer_type >= __ADDR_TYPE_MAX)){
		return -1;
	}

	return 0;
}

static int arp_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type)
{
	/* arpЭ�鲻�����κ��ϲ�����Э�� */
	return -1;
}


static int gtp_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type)
{
	const struct gtp_hdr *gh = (struct gtp_hdr *)raw_data;
	const unsigned char *next_ip_layer_hdr;
	int skip_len;
	int gtp_hdr_len;

	if(ADDR_TYPE_GPRS_TUNNEL == expect_layer_type){
		return 0;
	}

	gtp_hdr_len = __mjl_gtp_calc_gtp_hdr_len(gh);
	if(gtp_hdr_len < 0){
		snprintf(_g_mesa_jump_layer_last_error, PIPE_BUF, "calc gtp hdr len error");
		return -1;
	}

	next_ip_layer_hdr = (unsigned char *)raw_data + gtp_hdr_len;

	if((*next_ip_layer_hdr & 0xF0) == 0x40){
		skip_len = ipv4_jump_to_layer((char *)next_ip_layer_hdr, __ADDR_TYPE_IP_PAIR_V4, expect_layer_type);
	}else if((*next_ip_layer_hdr & 0xF0) == 0x60){
		skip_len = ipv6_jump_to_layer((char *)next_ip_layer_hdr, __ADDR_TYPE_IP_PAIR_V6, expect_layer_type);
	}else{
		snprintf(_g_mesa_jump_layer_last_error, PIPE_BUF, "gtp_jump_to_layer() error, unsupport type in GTP, 0x%x!", (*next_ip_layer_hdr));
		return -1;
	}

	if(skip_len < 0){
		return -1;
	}

	return gtp_hdr_len + skip_len;
}

static int __mjl_guess_l2tp_ppp_layer_len(const unsigned char *maybe_l2tp_ppp_hdr)
{
	int ppp_layer_len = -1;
	const unsigned short *ppp_proto;
	if((0xFF == maybe_l2tp_ppp_hdr[0]) && (0x03 == maybe_l2tp_ppp_hdr[1])){
		ppp_proto = (unsigned short *)(maybe_l2tp_ppp_hdr + 2);

		switch(ntohs(*ppp_proto)){
			case PPP_PROTOCOL_IPv4:
			case PPP_PROTOCOL_PAP:
			case PPP_PROTOCOL_CHAP:
			case PPP_PROTOCOL_IPv6:
			case PPP_PROTOCOL_LCP:
			case PPP_PROTOCOL_CCP:
			case PPP_PROTOCOL_IPCP:
				ppp_layer_len = 4;
			break;
		}
	}else{
		if((0x21 == maybe_l2tp_ppp_hdr[0]) || (0x57 == maybe_l2tp_ppp_hdr[0])){

			ppp_layer_len = 1; /* ʡ����control, address�ֶ�, ֻ��һ���ֽڵ�Э���, �ο�: http://www2.ic.uff.br/~michael/kr1999/5-datalink/5_08-ppp.htm#[RFC%201662]  */
		}
	}

	return ppp_layer_len;
}

static int __mjl_parse_l2tpv2_ppp_hdr(const unsigned char *l2tp_ppp_hdr, struct layer_addr_l2tp *l2tpaddr)
{
	int ppp_hdr_len;
	const unsigned short *ppp_protocol;

	ppp_hdr_len = __mjl_guess_l2tp_ppp_layer_len(l2tp_ppp_hdr);
	if(ppp_hdr_len < 0){
		return -1;
	}

	if(sizeof(struct layer_compress_ppp_hdr) == ppp_hdr_len){
		l2tpaddr->l2tpun.l2tp_addr_v2.ppp_hdr_compress_enable = 1;
		l2tpaddr->l2tpun.l2tp_addr_v2.compress_ppp_hdr.protocol = l2tp_ppp_hdr[0];
	}else if(sizeof(struct layer_ppp_hdr) == ppp_hdr_len){
		l2tpaddr->l2tpun.l2tp_addr_v2.ppp_hdr_compress_enable = 0;
		l2tpaddr->l2tpun.l2tp_addr_v2.ppp_hdr.address = l2tp_ppp_hdr[0];
		l2tpaddr->l2tpun.l2tp_addr_v2.ppp_hdr.control = l2tp_ppp_hdr[1];

		ppp_protocol = (unsigned short *)&l2tp_ppp_hdr[2];
		l2tpaddr->l2tpun.l2tp_addr_v2.ppp_hdr.protocol = *ppp_protocol;
	}else{
		return -1;
	}

	return ppp_hdr_len;
}

static int __mjl_parse_l2tpv2_hdr(const struct l2tp_hdr_v2 *pl2tphdrv2, struct layer_addr_l2tp *l2tpaddr)
{
	unsigned short l2top_tot_len, offset_size;
	const char *ptr = (const char *)pl2tphdrv2 + sizeof(struct l2tp_hdr_v2);
	int l2tp_ppp_hdr_len;

	memset(l2tpaddr, 0, sizeof(struct layer_addr_l2tp));
	
	if(pl2tphdrv2->length_present){
		l2top_tot_len = ntohs(*((unsigned short *)ptr));
		ptr += sizeof(short);
		if(l2top_tot_len < sizeof(struct l2tp_hdr_v2) +  1/* compress ppp hdr len */ + sizeof(struct mesa_ip4_hdr)){
			return -1; /* ����С��Ч���� */
		}
	}

	 /* L2TP��ַC2S, S2C�������, �޷�����ǰ����ַ����dir, ÿ��ջ��ı������洢��source����, ��C2S����,  
        ������ʱ, �����Ҫreverse����, ��source, dest�ߵ�, ����ֱ��memcpy�������addr.
     */

	l2tpaddr->l2tpun.l2tp_addr_v2.tunnelid_C2S = *((unsigned short *)ptr);
	ptr += sizeof(short);
	l2tpaddr->l2tpun.l2tp_addr_v2.sessionid_C2S = *((unsigned short *)ptr);
	ptr += sizeof(short);	

	if(pl2tphdrv2->seq_present){
		ptr += sizeof(int);	
		l2tpaddr->l2tpun.l2tp_addr_v2.seq_present_C2S = 1;
	}

	if(pl2tphdrv2->offset_present){
		offset_size = ntohs(*((unsigned short *)ptr));
		if(offset_size > 1460)
		{
			return -1;
		}
		ptr += sizeof(short);	 /* 2 byte fix len offset size */
		ptr += offset_size;  /* var bytes offset value length */
	}	

	l2tp_ppp_hdr_len = __mjl_parse_l2tpv2_ppp_hdr((unsigned char *)ptr, l2tpaddr);
	if(l2tp_ppp_hdr_len < 0){
		return -1;
	}
	ptr += l2tp_ppp_hdr_len;

	l2tpaddr->version = 2; /* version, RFC2661 */

	return ptr - (char *)pl2tphdrv2;
}
static int l2tp_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type)
{
	int l2tp_hdr_len, skip_len = 0;
	
	const unsigned char *next_layer_hdr;
	struct layer_addr_l2tp tmp_l2tp_addr;

	if(ADDR_TYPE_L2TP == expect_layer_type){
		return 0;
	}
	
	l2tp_hdr_len = __mjl_parse_l2tpv2_hdr((const struct l2tp_hdr_v2 *)raw_data, &tmp_l2tp_addr);
	if(l2tp_hdr_len < 0){
		return -1;
	}

	next_layer_hdr = (unsigned char *)raw_data + l2tp_hdr_len;

	if(tmp_l2tp_addr.l2tpun.l2tp_addr_v2.ppp_hdr_compress_enable){
		if(tmp_l2tp_addr.l2tpun.l2tp_addr_v2.compress_ppp_hdr.protocol == 0x21){ 
			skip_len = ipv4_jump_to_layer((char *)next_layer_hdr, __ADDR_TYPE_IP_PAIR_V4, expect_layer_type);
		}else if(tmp_l2tp_addr.l2tpun.l2tp_addr_v2.compress_ppp_hdr.protocol == 0x57){ 
			skip_len = ipv6_jump_to_layer((char *)next_layer_hdr, __ADDR_TYPE_IP_PAIR_V6, expect_layer_type);		
		}
	}else{
		if(ntohs(tmp_l2tp_addr.l2tpun.l2tp_addr_v2.ppp_hdr.protocol) == 0x0021){ 
			skip_len = ipv4_jump_to_layer((char *)next_layer_hdr, __ADDR_TYPE_IP_PAIR_V4, expect_layer_type);
		}else if(ntohs(tmp_l2tp_addr.l2tpun.l2tp_addr_v2.ppp_hdr.protocol) == 0x57){ 
			skip_len = ipv6_jump_to_layer((char *)next_layer_hdr, __ADDR_TYPE_IP_PAIR_V6, expect_layer_type);		
		}
	}

	if(skip_len < 0){
		return -1;
	}
	
	return l2tp_hdr_len + skip_len;
}

static int teredo_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type)
{
	const char *next_layer_hdr;
	struct teredo_auth_hdr *p_teredo_hdr;
	int teredo_layer_len = 0, tmp_hdr_len = 0, skip_len = 0;

	
	/* teredoʵ��û�����ݰ�ͷ */
	next_layer_hdr = raw_data;

	while((*next_layer_hdr & 0xF0) != 0x60){
		p_teredo_hdr = (struct teredo_auth_hdr *)next_layer_hdr;
		if(p_teredo_hdr->flags == ntohs(TEREDO_AUTH_HDR_FLAG))
		{
			//rfc4380 5.1.1 teredo ����0x0001ʱΪTeredo authentication headers����Ҫ����
			tmp_hdr_len += sizeof(struct teredo_auth_hdr) + ntohs(p_teredo_hdr->au_len) + ntohs
			(p_teredo_hdr->id_len) + 8 + 1;
			next_layer_hdr += tmp_hdr_len;
			teredo_layer_len += tmp_hdr_len;
		}
		else if(p_teredo_hdr->flags == ntohs(TEREDO_INDICATION_HDR_FLAG))
		{
			//rfc4380 teredo ����0x0000ʱΪTeredo indication headers����Ҫ����
			next_layer_hdr += TEREDO_INDICATION_HDR_LEN;
			teredo_layer_len += TEREDO_INDICATION_HDR_LEN;
		}
		else
		{
			snprintf(_g_mesa_jump_layer_last_error, PIPE_BUF, "teredo_jump_to_layer(): unsupport teredo hdr:0x%u!\n", *(unsigned int *)(next_layer_hdr));
			return -1;
		}
	}
	skip_len = ipv6_jump_to_layer(next_layer_hdr, __ADDR_TYPE_IP_PAIR_V6, expect_layer_type);
	if(skip_len < 0){
		return -1;
	}
	skip_len += teredo_layer_len;

	return skip_len;
}



static int udp_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type)
{
	const struct mesa_udp_hdr *uh = (const struct mesa_udp_hdr *)raw_data;
	unsigned short usport, udport;
	int skip_len;

	if(ADDR_TYPE_UDP == expect_layer_type){
		return 0;
	}

	usport = ntohs(uh->uh_sport);
	udport = ntohs(uh->uh_dport);

	if((2152 == usport) || (2152 == udport)){
		skip_len = gtp_jump_to_layer(raw_data+sizeof(struct mesa_udp_hdr), ADDR_TYPE_UDP, expect_layer_type);
	}else if(4789 == udport){
		/* vxlanģʽ��ʱֻ֧��ethernet. TODO: �����hdlc, ppp��װ, ��Ҫʵ��һ��������vxlan_jump_to_layer()���� */
		skip_len = eth_jump_to_layer(raw_data+sizeof(struct mesa_udp_hdr)+8, ADDR_TYPE_MAC, expect_layer_type);
		if(skip_len < 0){
			return -1;
		}
		skip_len += 8; /* skip vxlan header */
	}else if((3544 == usport) || (3544 == udport)){
		skip_len = teredo_jump_to_layer(raw_data+sizeof(struct mesa_udp_hdr), 0, expect_layer_type);
	}else if((1701 == usport) || (1701 == udport)){
		skip_len = l2tp_jump_to_layer(raw_data+sizeof(struct mesa_udp_hdr), ADDR_TYPE_UDP, expect_layer_type);
	}else{
		/* ����UDP���Ͳ�֧������ת */
		snprintf(_g_mesa_jump_layer_last_error, PIPE_BUF, "MESA_jump_layer_greedy() not support layer type:%d", expect_layer_type);
		return -1;
	}
	if(skip_len < 0){
		return -1;
	}

	return skip_len + sizeof(struct mesa_udp_hdr);
}

static int udp_jump_to_layer_greedy(const char *raw_data,  int raw_layer_type, int expect_layer_type)
{
	const struct mesa_udp_hdr *uh = (const struct mesa_udp_hdr *)raw_data;
	unsigned short usport, udport;
	int skip_len;

	usport = ntohs(uh->uh_sport);
	udport = ntohs(uh->uh_dport);

	if((2152 == usport) || (2152 == udport)){
		skip_len = gtp_jump_to_layer(raw_data+sizeof(struct mesa_udp_hdr), ADDR_TYPE_UDP, expect_layer_type);
	}else if(4789 == udport){
		/* vxlanģʽ��ʱֻ֧��ethernet. TODO: �����hdlc, ppp��װ, ��Ҫʵ��һ��������vxlan_jump_to_layer()���� */
		skip_len = eth_jump_to_layer(raw_data+sizeof(struct mesa_udp_hdr)+8, ADDR_TYPE_MAC, expect_layer_type);
		if(skip_len < 0){
			return -1;
		}
		skip_len += 8; /* skip vxlan header */
	}else if((3544 == usport) || (3544 == udport)){
		skip_len = teredo_jump_to_layer(raw_data+sizeof(struct mesa_udp_hdr), 0, expect_layer_type);
	}else if((1701 == usport) || (1701 == udport)){
		skip_len = l2tp_jump_to_layer(raw_data+sizeof(struct mesa_udp_hdr), ADDR_TYPE_UDP, expect_layer_type);
	}else{
		/* ����UDP���Ͳ�֧������ת */
		snprintf(_g_mesa_jump_layer_last_error, PIPE_BUF, "udp_jump_to_layer(): unsupport udp sport:%u, dport:%u!\n", usport, udport);
		return -1;
	}
	if(skip_len < 0){
		return -1;
	}

	return skip_len + sizeof(struct mesa_udp_hdr);
}

static int set_gre_hdr_ver0(struct mesa_gre_hdr *stack_gre_addr, const struct mesa_gre_hdr *net_gre_addr)
{
	struct mesa_gre_extend_hdr *stack_gre_ext = &stack_gre_addr->gre_extend;
	const struct mesa_gre_base_hdr_v0 *net_gre_base = &net_gre_addr->gre_base;
	const char *net_ext_hdr_value = (const char *)(&net_gre_addr->gre_extend);
	//const struct gre_source_route_entry_hdr *rse_hdr;

	if(net_gre_base->checksum_flag || net_gre_base->route_flag){
		stack_gre_ext->checksum = *((unsigned short *)net_ext_hdr_value);
		net_ext_hdr_value += sizeof(short);

		/* ���checksum����, ��offsetҲ�ش��� */
		stack_gre_ext->offset = *((unsigned short *)net_ext_hdr_value);
		net_ext_hdr_value += sizeof(short);		
	}

	if(net_gre_base->key_flag){
		stack_gre_ext->key = *((unsigned int *)net_ext_hdr_value);
		net_ext_hdr_value += sizeof(int);
	}
	
	if(net_gre_base->seq_flag){
		stack_gre_ext->seq_num = *((unsigned int *)net_ext_hdr_value);
		net_ext_hdr_value += sizeof(int);
	}
	
	/* SRE��Ϣ��GREͷ�������, ��Ϊ������, �������� */
	if(net_gre_base->route_flag){
		//rse_hdr = (const struct gre_source_route_entry_hdr *)net_ext_hdr_value;
		//TODO 1, copy SRE
		snprintf(_g_mesa_jump_layer_last_error, PIPE_BUF, "found GRE SRE data, but not parse yet!");
		return -1;
	}

	return sizeof(struct mesa_gre_base_hdr_v1) + (net_ext_hdr_value - (char *)&net_gre_addr->gre_extend);	
}

static int set_gre_hdr_ver1(struct mesa_gre_hdr *stack_gre_addr, const struct mesa_gre_hdr *net_gre_addr)
{
	//struct mesa_gre_base_hdr_v1 *stack_gre_base = (struct mesa_gre_base_hdr_v1 *)&stack_gre_addr->gre_base;
	struct mesa_gre_extend_hdr *stack_gre_ext = &stack_gre_addr->gre_extend;
	const struct mesa_gre_base_hdr_v1 *net_gre_base = (struct mesa_gre_base_hdr_v1 *)&net_gre_addr->gre_base;
	//const struct mesa_gre_extend_hdr *net_gre_ext = &net_gre_addr->gre_extend;
	const char *net_ext_hdr_value = (const char *)(&net_gre_addr->gre_extend);

	if(net_gre_base->checksum_flag != 0){
		snprintf(_g_mesa_jump_layer_last_error, PIPE_BUF,"error! in gre version1, checksum flag not zero!");
		return -1;
	}

	if(net_gre_base->route_flag != 0){
		snprintf(_g_mesa_jump_layer_last_error, PIPE_BUF,"error! in gre version1, route flag not zero!");
		return -1;
	}

	if(net_gre_base->recur != 0){
		snprintf(_g_mesa_jump_layer_last_error, PIPE_BUF,"error! in gre version1, recur flag not zero!");
		return -1;
	}
	
	if(net_gre_base->strict_src_route_flag != 0){
		snprintf(_g_mesa_jump_layer_last_error, PIPE_BUF,"error! in gre version1, strict_src_route flag not zero!");
		return -1;
	}
	
	if(ntohs(net_gre_base->protocol) != GRE_PRO_PPP){
		snprintf(_g_mesa_jump_layer_last_error, PIPE_BUF,"error! in gre version1, protocol not 0x%x!", GRE_PRO_PPP);
		return -1;
	}	

	stack_gre_ext->payload_len = *((unsigned short *)net_ext_hdr_value);
	net_ext_hdr_value += sizeof(short);	
	
	stack_gre_ext->call_id = *((unsigned short *)net_ext_hdr_value);
	net_ext_hdr_value += sizeof(short);	
	
	if(net_gre_base->seq_flag){
		stack_gre_ext->seq_num = *((unsigned int *)net_ext_hdr_value);
		net_ext_hdr_value += sizeof(int);
	}
	
	/* version 1 has ack number */
	if(net_gre_base->ack_flag){
		stack_gre_ext->ack_num = *((unsigned int *)net_ext_hdr_value);
		net_ext_hdr_value += sizeof(int);
	}

	return sizeof(struct mesa_gre_base_hdr_v1) + (net_ext_hdr_value - (char *)&net_gre_addr->gre_extend);
}

extern int __mjl_set_gre_hdr(struct mesa_gre_hdr *stack_gre_addr, const void *this_layer_data)
{
	int gre_hdr_len = 0;
	const struct mesa_gre_hdr *net_gre_addr = (const struct mesa_gre_hdr *)this_layer_data;

	memcpy(&stack_gre_addr->gre_base, &net_gre_addr->gre_base, sizeof(struct mesa_gre_base_hdr_v0));
	memset(&stack_gre_addr->gre_extend, 0, sizeof(struct mesa_gre_extend_hdr));
	
	if(0 == net_gre_addr->gre_base.version){
		gre_hdr_len = set_gre_hdr_ver0(stack_gre_addr, net_gre_addr);
	}else if(1 == net_gre_addr->gre_base.version){
		gre_hdr_len = set_gre_hdr_ver1(stack_gre_addr, net_gre_addr);
	}else{
		//TODO 1, δ֪�汾
		snprintf(_g_mesa_jump_layer_last_error, PIPE_BUF,"Unknown gre hdr version:%d", net_gre_addr->gre_base.version);
		gre_hdr_len = -1;
	}

	return gre_hdr_len;
}

static int gre_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type)
{
	int skip_len = 0;
	int this_gre_layer_len;
	struct mesa_gre_hdr this_layer_hdr;
	
	if(raw_layer_type == expect_layer_type){
		return 0;
	}

	this_gre_layer_len = __mjl_set_gre_hdr(&this_layer_hdr, (void *)raw_data);
	if(this_gre_layer_len < 0){
		return -1;
	}

	switch(ntohs(this_layer_hdr.gre_base.protocol))
	{
		case GRE_PRO_IPV4:
			if(expect_layer_type == ADDR_TYPE_IPV4){
				skip_len = 0;
				break;
			}else{
				skip_len=ipv4_jump_to_layer(raw_data+this_gre_layer_len, __ADDR_TYPE_IP_PAIR_V4, expect_layer_type);
			}
		break;

		case GRE_PRO_IPV6:
			if(expect_layer_type == ADDR_TYPE_IPV4){
				skip_len = 0;
				break;
			}else{
				skip_len=ipv6_jump_to_layer(raw_data+this_gre_layer_len, __ADDR_TYPE_IP_PAIR_V6, expect_layer_type);
			}
		break;
		
		case GRE_PRO_PPP:
			if((expect_layer_type == ADDR_TYPE_PPP) || (expect_layer_type == ADDR_TYPE_PPTP)){
				skip_len = this_gre_layer_len;
				break;
			}else{
				skip_len = ppp_jump_to_layer(raw_data+this_gre_layer_len, ADDR_TYPE_PPP, expect_layer_type);
			}	
		break;
		
		default:
			snprintf(_g_mesa_jump_layer_last_error, PIPE_BUF, "gre_jump_to_layer(): unknown gre protocol:0x%x!", ntohs(this_layer_hdr.gre_base.protocol));			
			return -1;
			break;
	}

	if(skip_len < 0){
		snprintf(_g_mesa_jump_layer_last_error, PIPE_BUF, "gre_jump_to_layer() error!");	
		return -1;
	}

	return skip_len + this_gre_layer_len;
}

static int ipv4_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type)
{
	struct mesa_ip4_hdr *p_ip_hdr = (struct mesa_ip4_hdr *)raw_data;
	int skip_len = 0;
	int ip_hdr_len = p_ip_hdr->ip_hl * 4;
	//const char *next_layer_data = raw_data + ip_hdr_len;

	if(raw_layer_type == expect_layer_type){
		return 0;
	}

	if((ntohs(p_ip_hdr->ip_off) & IP_MF ) || (ntohs(p_ip_hdr->ip_off) & IP_OFFMASK)){
		/* IP��Ƭ���ټ������ڲ���ת */
		return -1;
	}
				
	switch(p_ip_hdr->ip_p){
		case IPPROTO_TCP:
			if(ADDR_TYPE_TCP == expect_layer_type){
				skip_len = 0;
				break;
			}else{
				skip_len = -1; /* tcp ��֮�ϲ���������Э�� */
			}
		break;

		case IPPROTO_UDP:
			if(ADDR_TYPE_UDP == expect_layer_type){
				skip_len = 0;
				break;
			}else{
				skip_len = udp_jump_to_layer(raw_data+ip_hdr_len, ADDR_TYPE_UDP, expect_layer_type); 
			}
		break;

		case IPPROTO_IPV6:
			if(__ADDR_TYPE_IP_PAIR_V6 == expect_layer_type){
				skip_len = 0;
				break;
			}else{
				skip_len = ipv6_jump_to_layer(raw_data+ip_hdr_len, __ADDR_TYPE_IP_PAIR_V6, expect_layer_type);
			}
		break;

		case IPPROTO_GRE:
			if((ADDR_TYPE_GRE == expect_layer_type) || (ADDR_TYPE_PPTP == expect_layer_type)){
				skip_len = 0;
				break;
			}else{
				skip_len = gre_jump_to_layer(raw_data+ip_hdr_len, ADDR_TYPE_GRE, expect_layer_type);
			}		
		break;
		
		default:
			skip_len = -1;
		break;
	}

	if(skip_len < 0){
		return -1;
	}

	return skip_len + sizeof(struct ip);
}

static int ipv6_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type)
{
	const struct mesa_ip6_hdr *a_packet = (const struct mesa_ip6_hdr *)raw_data;
	UINT8 next_hdr_type = a_packet->ip6_nxt_hdr;
	UINT8 *next_hdr_ptr = (UINT8 *)a_packet + sizeof(struct mesa_ip6_hdr);	
	int skip_len = 0;
	int offset_to_ip6 = 0;
	
	if(raw_layer_type == expect_layer_type){
		return 0;
	}

	while(1){
		offset_to_ip6 = 0;
		switch(next_hdr_type)
		{
			case NEXTHDR_HOP:
			case NEXTHDR_ROUTING:
			case NEXTHDR_AUTH:
			case NEXTHDR_DEST:
				offset_to_ip6 = (*(next_hdr_ptr + 1))*8 + 8; /* ѡ�����8�ֽ�Ϊ��λ */				
			break;

			case NEXTHDR_IPIP:
				if(__ADDR_TYPE_IP_PAIR_V4 == expect_layer_type){
					skip_len = next_hdr_ptr - (UINT8 *)raw_data;
				}else{
					skip_len = ipv4_jump_to_layer((const char *)next_hdr_ptr, __ADDR_TYPE_IP_PAIR_V4, expect_layer_type);
					if(skip_len < 0){
						return -1;
					}else{
						return skip_len + next_hdr_ptr - (UINT8 *)raw_data;
					}
				}
				goto done;
			break;

			case NEXTHDR_NONE:
				skip_len = -1;
				goto done;					
			break;

			case NEXTHDR_ICMP: /* IMCP���ٳ�������Э�� */
				skip_len = -1;
				goto done;
			break;
			
			case NEXTHDR_TCP:
				if(ADDR_TYPE_TCP == expect_layer_type){
					skip_len = next_hdr_ptr - (UINT8 *)raw_data;
				}else{
					skip_len = -1;
				}
				goto done;
			break;
				
			case NEXTHDR_UDP:
				if(ADDR_TYPE_UDP == expect_layer_type){
					skip_len = next_hdr_ptr - (UINT8 *)raw_data;
				}else{
					skip_len = udp_jump_to_layer((char *)next_hdr_ptr, ADDR_TYPE_UDP, expect_layer_type); 
					if(skip_len < 0){
						return -1;
					}else{
						return skip_len + next_hdr_ptr - (UINT8 *)raw_data;
					}					
				}
				goto done;
			break;

			case NEXTHDR_FRAGMENT:	
				/* IP��Ƭ���ټ������ڲ���ת */
				skip_len = -1;
				goto done;
			break;

			case NEXTHDR_ESP:
				skip_len = -1;
				goto done;

			default:
				snprintf(_g_mesa_jump_layer_last_error, PIPE_BUF, "ipv6_jump_to_layer(): unknown IPv6 header type:0x%x!", next_hdr_type);		
				skip_len = -1;
				goto done;
			break;
		}

		next_hdr_type = *next_hdr_ptr;
		next_hdr_ptr += offset_to_ip6;
	}	

done:
	if(skip_len < 0){
		return -1;
	}
	
	return skip_len;
}

static int ppp_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type)
{
	int skip_len = 0;
	struct mesa_ppp_hdr *ppp_data_hdr;
	char *next_hdr;
	
	if(raw_layer_type == expect_layer_type){
		return 0;
	}
	ppp_data_hdr = (struct mesa_ppp_hdr *)raw_data;
	next_hdr = (char *)raw_data + sizeof(struct mesa_ppp_hdr);

	switch(ntohs(ppp_data_hdr->protocol)){
		case PPP_PROTOCOL_IPv4:
			if(__ADDR_TYPE_IP_PAIR_V4 == expect_layer_type){
				break;
			}else{
				skip_len = ipv4_jump_to_layer(next_hdr, __ADDR_TYPE_IP_PAIR_V4, expect_layer_type);
			}
		break;

		case PPP_IPV6:
			if(__ADDR_TYPE_IP_PAIR_V6 == expect_layer_type){
				break;
			}else{
				skip_len = ipv6_jump_to_layer(next_hdr, __ADDR_TYPE_IP_PAIR_V6, expect_layer_type);
			}		
		break;

		case PPP_COMP:
		case PPP_CCP:
		case PPP_IPCP:
		case PPP_PAP:
		case PPP_CHAP:
		case PPP_LQR:
		case PPP_PROTOCOL_LCP: 
		
			/* ������Ӧ�ò�Э�� */
			skip_len = -1;
		break;

		default:
			snprintf(_g_mesa_jump_layer_last_error, PIPE_BUF, "ppp_jump_to_layer(): unsupport ppp pro:0x%x!", ntohs(ppp_data_hdr->protocol));
		break;
	}

	if(skip_len < 0){
		return -1;
	}
	
	return skip_len + sizeof(struct mesa_ppp_hdr);
}

static int pppoe_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type)
{
	int skip_len = 0;
	struct mesa_pppoe_session_hdr *pppoe_ses_hdr;
	char *next_hdr;
	
	if(raw_layer_type == expect_layer_type){
		return 0;
	}
	pppoe_ses_hdr = (struct mesa_pppoe_session_hdr *)raw_data;
	next_hdr = (char *)raw_data + sizeof(struct mesa_pppoe_session_hdr);

	switch(ntohs(pppoe_ses_hdr->ppp_protocol)){
		case PPP_PROTOCOL_IPv4:
			if(__ADDR_TYPE_IP_PAIR_V4 == expect_layer_type){
				break;
			}else{
				skip_len = ipv4_jump_to_layer(next_hdr, __ADDR_TYPE_IP_PAIR_V4, expect_layer_type);
			}
		break;

		case PPP_IPV6:
			if(__ADDR_TYPE_IP_PAIR_V6 == expect_layer_type){
				break;
			}else{
				skip_len = ipv6_jump_to_layer(next_hdr, __ADDR_TYPE_IP_PAIR_V6, expect_layer_type);
			}		
		break;

		case PPP_COMP:
		case PPP_CCP:
		case PPP_IPCP:
		case PPP_PAP:
		case PPP_CHAP:
		case PPP_LQR:
		case PPP_PROTOCOL_LCP: 
		
			/* ������Ӧ�ò�Э�� */
			skip_len = -1;
		break;

		default:
			snprintf(_g_mesa_jump_layer_last_error, PIPE_BUF, "pppoe_jump_to_layer(): unsupport ppp pro:0x%x!", ntohs(pppoe_ses_hdr->ppp_protocol));
		break;
		
	}

	if(skip_len < 0){
		return -1;
	}
	
	return skip_len + sizeof(struct mesa_pppoe_session_hdr);
}


extern int __mjl_set_mpls_addr(struct layer_addr_mpls *addr, const unsigned char *raw_mpls_pkt_data);
static int mpls_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type)
{
	int skip_len = 0;
	struct layer_addr_mpls mpls_addr = {};
	const char *next_layer_data;
	int mpls_layer_len;

	if(raw_layer_type == expect_layer_type){
		return 0;
	}

	__mjl_set_mpls_addr(&mpls_addr, (unsigned char *)raw_data);
	mpls_layer_len = mpls_addr.c2s_layer_num * sizeof(struct mesa_mpls_hdr);
	if(mpls_addr.c2s_has_ctrl_word){
		mpls_layer_len += sizeof(int);
	}

	next_layer_data = raw_data + mpls_layer_len;

	/* MPLSû���ֶα�ʶ��һ����ʲô, ���²���һ���IP���� */
	if((*next_layer_data & 0xF0) == 0x40){
		skip_len = ipv4_jump_to_layer(next_layer_data, __ADDR_TYPE_IP_PAIR_V4, expect_layer_type);
	}else if((*next_layer_data & 0xF0) == 0x60){
		skip_len = ipv6_jump_to_layer(next_layer_data, __ADDR_TYPE_IP_PAIR_V6, expect_layer_type);
	}else{	
		/* VPLS�Ͳ���control wordһ������, ��__mjl_set_mpls_addr()������, �������Control word, next_layer_data�Ѿ����������ֽڵ�control word  */
		skip_len = eth_jump_to_layer(next_layer_data, ADDR_TYPE_MAC, expect_layer_type);
		if(skip_len < 0){
			snprintf(_g_mesa_jump_layer_last_error, PIPE_BUF,"WARNING: jmp unsupport type in MPLS to Ethernet, 0x%x!",  
							(unsigned char)(*next_layer_data));
			return -1;
		}
	}

	if(skip_len < 0){
		return -1;
	}

	return skip_len + mpls_layer_len;
}

static int __common_eth_type_dispatch(UINT16 eth_type, const char *next_layer_data, int raw_layer_type, int expect_layer_type)
{
	int skip_len = 0;
	
	switch(eth_type){
		case ETH_P_ARP:
			if(ADDR_TYPE_ARP == expect_layer_type){
				break;
			}else{
				skip_len = arp_jump_to_layer(next_layer_data, ADDR_TYPE_ARP, expect_layer_type);
			}
		break;

		case ETH_P_8021Q:
		case ETH_P_8021AD:
			if(ADDR_TYPE_VLAN == expect_layer_type){
				break;
			}else{
				skip_len = vlan8021q_jump_to_layer(next_layer_data, ADDR_TYPE_VLAN, expect_layer_type);
			}
		break;
		
		case ETH_P_IP:
			if(__ADDR_TYPE_IP_PAIR_V4 == expect_layer_type){
				break;
			}else{
				skip_len = ipv4_jump_to_layer(next_layer_data, __ADDR_TYPE_IP_PAIR_V4, expect_layer_type);
			}
		break;

		case ETH_P_IPV6:
			if(__ADDR_TYPE_IP_PAIR_V6 == expect_layer_type){
				break;
			}else{
				skip_len = ipv6_jump_to_layer(next_layer_data, __ADDR_TYPE_IP_PAIR_V6, expect_layer_type);
			}
		break;

		case ETH_P_PPP_SES:
			if(ADDR_TYPE_PPPOE_SES == expect_layer_type){
				break;
			}else{
				skip_len = pppoe_jump_to_layer(next_layer_data, ADDR_TYPE_PPPOE_SES, expect_layer_type);
			}
		break;		

		case ETH_P_MPLS_UC: /* MPLS, ETH_P_MPLS_UC */
			skip_len = mpls_jump_to_layer(next_layer_data, ADDR_TYPE_MPLS, expect_layer_type);
		break;
		
		default:
			skip_len = -1;
		break;
	}

	return skip_len;
}

/* �����紫��ĵ�ַת��Ϊ�ڴ�ṹ, ����ҵ�������� */
static int __mjl_vlan_addr_net_to_mem(const struct mesa_vlan_detail_hdr *net_vlan_hdr, struct single_layer_vlan_addr *mem_vlan_hdr)
{
	mem_vlan_hdr->VID = htons(net_vlan_hdr->vlan_id_high << 8 | net_vlan_hdr->vlan_id_low);
	mem_vlan_hdr->TPID = net_vlan_hdr->type;
	mem_vlan_hdr->PCP = net_vlan_hdr->priority;
	mem_vlan_hdr->DEI = net_vlan_hdr->del_flag;

	return 0;
}

static int __mjl_set_vlan_addr(struct layer_addr_vlan *addr, const unsigned char *vlan_tag)
{
	int i;
	const struct mesa_vlan_detail_hdr *net_vhdr;
	int vlan_layer_len = 0;

	memset(addr, 0, sizeof(struct layer_addr_vlan));

	for(i = 0; i < MAX_VLAN_ADDR_LAYER; i++){
		net_vhdr = (struct mesa_vlan_detail_hdr *)vlan_tag;
		//memcpy(&addr->c2s_addr_array[i], vlan_tag, sizeof(struct mesa_vlan_hdr));

		__mjl_vlan_addr_net_to_mem(net_vhdr, &addr->c2s_addr_array[i]);
		vlan_tag += sizeof(struct mesa_vlan_detail_hdr);
		vlan_layer_len += sizeof(struct mesa_vlan_detail_hdr);
		addr->c2s_layer_num++;
		if(ETH_P_8021Q != ntohs(net_vhdr->type)){
			break;
		}
	}
	
	return vlan_layer_len;
}

static int vlan8021q_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type)
{
	int skip_len = 0;
	struct layer_addr_vlan vlan_addr;
	const char *next_layer_data;
	//const struct mesa_vlan_hdr *vhdr;
	unsigned short next_layer_type;
	int vlan_layer_len;

	if(raw_layer_type == expect_layer_type){
		return 0;
	}

	__mjl_set_vlan_addr(&vlan_addr, (const unsigned char *)raw_data);
	vlan_layer_len = sizeof(struct mesa_vlan_hdr) * vlan_addr.c2s_layer_num;
	next_layer_data = raw_data + vlan_layer_len;
	//vhdr = (struct mesa_vlan_hdr *)&vlan_addr.c2s_addr_array[vlan_addr.c2s_layer_num-1];
	next_layer_type = ntohs(vlan_addr.c2s_addr_array[vlan_addr.c2s_layer_num-1].TPID);
	
	switch(next_layer_type){
		case ETH_P_ARP:
			if(ADDR_TYPE_ARP == expect_layer_type){
				break;
			}else{
				skip_len = arp_jump_to_layer(next_layer_data, ADDR_TYPE_ARP, expect_layer_type);
			}
		break;
		
		case ETH_P_IP:
			if(__ADDR_TYPE_IP_PAIR_V4 == expect_layer_type){
				break;
			}else{
				skip_len = ipv4_jump_to_layer(next_layer_data, __ADDR_TYPE_IP_PAIR_V4, expect_layer_type);
			}
		break;

		case ETH_P_IPV6:
			if(__ADDR_TYPE_IP_PAIR_V6 == expect_layer_type){
				break;
			}else{
				skip_len = ipv6_jump_to_layer(next_layer_data, __ADDR_TYPE_IP_PAIR_V6, expect_layer_type);
			}
		break;

		case ETH_P_PPP_SES:
			if(ADDR_TYPE_PPPOE_SES == expect_layer_type){
				break;
			}else{
				skip_len = pppoe_jump_to_layer(next_layer_data, ADDR_TYPE_PPPOE_SES, expect_layer_type);
			}
		break;		

		case ETH_P_PPP_DISC: /* pppoe���ֽ׶� */
			skip_len = -1;
		break;

		/* QinQ */
		case ETH_P_8021Q:
			snprintf(_g_mesa_jump_layer_last_error, PIPE_BUF, "vlan8021q_jump_to_layer(): multiple VLAN combine to one layer!");
			skip_len = -1;
			assert(0);
		break;

		case ETH_P_MPLS_UC:
			skip_len = mpls_jump_to_layer(next_layer_data, ADDR_TYPE_MPLS, expect_layer_type);
		break;
		
		default:
			snprintf(_g_mesa_jump_layer_last_error, PIPE_BUF, "vlan8021q_jump_to_layer(): unsupport type: 0x%x!", next_layer_type);
			skip_len = -1;
	}

	if(skip_len < 0){
		return -1;
	}

	return skip_len + vlan_layer_len;
}

static int eth_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type)
{
	struct ethhdr *p_eth_hdr = (struct ethhdr *)raw_data;
	unsigned short eth_type = ntohs(p_eth_hdr->h_proto);
	//int skip_len = -1;
	const char *next_layer_data = raw_data + sizeof(struct ethhdr);
	int layer_skip_len;

	if(raw_layer_type == expect_layer_type){
		return 0;
	}
	
	layer_skip_len =  __common_eth_type_dispatch(eth_type, next_layer_data, raw_layer_type, expect_layer_type);
	if(layer_skip_len < 0){
		return -1;
	}

	return layer_skip_len + sizeof(struct ethhdr);
}


static int mac_in_mac_jump_to_layer(const char *raw_data,  int raw_layer_type, int expect_layer_type)
{
	struct ethhdr *inner_eth_hdr = (struct ethhdr *)(raw_data + sizeof(struct ethhdr ));
	unsigned short inner_eth_type = ntohs(inner_eth_hdr->h_proto);
	//int skip_len = -1;
	const char *next_layer_data = raw_data + sizeof(struct ethhdr);
	int layer_skip_len;

	if(raw_layer_type == expect_layer_type){
		return 0;
	}
	
	layer_skip_len =  __common_eth_type_dispatch(inner_eth_type, next_layer_data, raw_layer_type, expect_layer_type);
	if(layer_skip_len < 0){
		return -1;
	}

	return layer_skip_len + sizeof(struct ethhdr) * 2;
}

#ifdef __cplusplus
extern "C" {
#endif

/*
	return value:
		Non-NULL: the pointer to expect layer;
		NULL: not found expect layer.
*/
const void *MESA_jump_layer(const void *raw_data,  int raw_layer_type, int expect_layer_type)
{
	int  ret;

	if(check_layer_type(raw_layer_type) < 0){
		return NULL;
	}

	if(check_layer_type(expect_layer_type) < 0){
		return NULL;
	}

	if(ADDR_TYPE_IPV4 == raw_layer_type){
		/* ת�ɴ�IPv4��ַ���� */
		raw_layer_type = __ADDR_TYPE_IP_PAIR_V4;
	}

	if(ADDR_TYPE_IPV6 == raw_layer_type){
		/* ת�ɴ�IPv6��ַ���� */
		raw_layer_type = __ADDR_TYPE_IP_PAIR_V6;
	}

	if(ADDR_TYPE_IPV4 == expect_layer_type){
		/* ת�ɴ�IPv4��ַ���� */
		expect_layer_type = __ADDR_TYPE_IP_PAIR_V4;
	}

	if(ADDR_TYPE_IPV6 == expect_layer_type){
		/* ת�ɴ�IPv6��ַ���� */
		expect_layer_type = __ADDR_TYPE_IP_PAIR_V6;
	}

	if(raw_layer_type == expect_layer_type){
		return raw_data;
	}
	
	switch(raw_layer_type){
		case ADDR_TYPE_MAC:
			ret = eth_jump_to_layer((const char *)raw_data, raw_layer_type, expect_layer_type);
		break;
		
		case ADDR_TYPE_ARP:
			ret = arp_jump_to_layer((const char *)raw_data, raw_layer_type, expect_layer_type);
		break;
		case ADDR_TYPE_VLAN:
			ret = vlan8021q_jump_to_layer((const char *)raw_data, raw_layer_type, expect_layer_type);
		break;
		
		case __ADDR_TYPE_IP_PAIR_V4:
			ret = ipv4_jump_to_layer((const char *)raw_data, raw_layer_type, expect_layer_type);
		break;

		case __ADDR_TYPE_IP_PAIR_V6:
			ret = ipv6_jump_to_layer((const char *)raw_data, raw_layer_type, expect_layer_type);
		break;

		case ADDR_TYPE_MAC_IN_MAC:
			ret = mac_in_mac_jump_to_layer((const char *)raw_data, raw_layer_type, expect_layer_type);
		break;

		case ADDR_TYPE_UDP:
			ret = udp_jump_to_layer((const char *)raw_data, raw_layer_type, expect_layer_type);
		break;

		case ADDR_TYPE_MPLS:	
			ret = mpls_jump_to_layer((const char *)raw_data, raw_layer_type, expect_layer_type);
		break;

		case ADDR_TYPE_GRE:
			ret = gre_jump_to_layer((const char *)raw_data, raw_layer_type, expect_layer_type);
		break;
		
		case ADDR_TYPE_PPPOE_SES:	
			return NULL;
		break;
		
		default:
			snprintf(_g_mesa_jump_layer_last_error, PIPE_BUF, "MESA_jump_layer(): unsupport raw_layer_type:%d in MESA_jump_layer()!", raw_layer_type);
			return NULL;
	}

	if(ret < 0){
		return NULL;
	}

	return ((const char *)raw_data + ret);
}

const void *MESA_net_jump_to_layer(const void *raw_data,  int raw_layer_type, int expect_layer_type)
{
	return MESA_jump_layer(raw_data, raw_layer_type, expect_layer_type);
}

/*
	��MESA_jump_layer()������:
		MESA_jump_layer()������㿪ʼ, �ҵ���һ�����������Ĳ���˳�;
		MESA_jump_layer_greedy()��һֱ���������ڲ�Э��ͷ, �ʺ�����ģʽ.
	
	return value:
		Non-NULL: the pointer to expect layer;
		NULL: not found expect layer.
*/
const void *MESA_jump_layer_greedy(const void *raw_data, int raw_layer_type, int expect_layer_type)
{
	int skip_len;
	const void *expect_layer;
	const void *success_layer = NULL; /* ���һ�γɹ��ҵ��Ĳ� */
	int new_raw_layer_type = raw_layer_type; /* ����ת������, ���ܻ�����м����Ϣ */
	const char *new_next_layer_data = (char *)raw_data;

	if(ADDR_TYPE_IPV4 == raw_layer_type){
		/* ת�ɴ�IPv4��ַ���� */
		raw_layer_type = __ADDR_TYPE_IP_PAIR_V4;
	}

	if(ADDR_TYPE_IPV6 == raw_layer_type){
		/* ת�ɴ�IPv6��ַ���� */
		raw_layer_type = __ADDR_TYPE_IP_PAIR_V6;
	}

	if(ADDR_TYPE_IPV4 == expect_layer_type){
		/* ת�ɴ�IPv4��ַ���� */
		expect_layer_type = __ADDR_TYPE_IP_PAIR_V4;
	}

	if(ADDR_TYPE_IPV6 == expect_layer_type){
		/* ת�ɴ�IPv6��ַ���� */
		expect_layer_type = __ADDR_TYPE_IP_PAIR_V6;
	}

	expect_layer = MESA_jump_layer(new_next_layer_data, new_raw_layer_type, expect_layer_type);
	while(expect_layer){
		success_layer = expect_layer;

		switch(expect_layer_type){
			case __ADDR_TYPE_IP_PAIR_V4:
			{
				const struct mesa_ip4_hdr *ip4hdr = (const struct mesa_ip4_hdr *)expect_layer;
				if((ntohs(ip4hdr->ip_off) & IP_MF ) || (ntohs(ip4hdr->ip_off) & IP_OFFMASK)){
					/* IP��Ƭ���ټ������ڲ���ת */
					goto done;
				}				
				if(IPPROTO_UDP == ip4hdr->ip_p){
					new_next_layer_data = (char *)expect_layer + ip4hdr->ip_hl * 4;
					new_raw_layer_type = ADDR_TYPE_UDP; /* IP���������һ��ƫ�� */
				}else if(IPPROTO_GRE == ip4hdr->ip_p){
					new_next_layer_data = (char *)expect_layer + ip4hdr->ip_hl * 4;
					new_raw_layer_type = ADDR_TYPE_GRE; /* GRE */					
				}else{
					//TODO 2, IPIP, L2TPv3
					goto done;
				}
			}
			break;

			case __ADDR_TYPE_IP_PAIR_V6:
			{
				const struct mesa_ip6_hdr *ip6hdr = (const struct mesa_ip6_hdr *)expect_layer;		
				if(IPPROTO_UDP == ip6hdr->ip6_nxt_hdr){
					new_next_layer_data = (char *)expect_layer + sizeof(struct mesa_ip6_hdr);
					new_raw_layer_type = ADDR_TYPE_UDP; /* IP���������һ��ƫ�� */
				}else if(IPPROTO_GRE == ip6hdr->ip6_nxt_hdr){
					new_next_layer_data = (char *)expect_layer + sizeof(struct mesa_ip6_hdr);
					new_raw_layer_type = ADDR_TYPE_GRE; /* GRE */					
				}else if(IPPROTO_IPIP == ip6hdr->ip6_nxt_hdr){
					new_next_layer_data = (char *)expect_layer + sizeof(struct mesa_ip6_hdr);
					new_raw_layer_type = ADDR_TYPE_IPV4;  			
				}else if(IPPROTO_IPV6 == ip6hdr->ip6_nxt_hdr){
					new_next_layer_data = (char *)expect_layer + sizeof(struct mesa_ip6_hdr);
					new_raw_layer_type = ADDR_TYPE_IPV6;  				
				}else{
					//TODO 2, IPIP, L2TPv3
					goto done;
				}
			}
			break;

			case ADDR_TYPE_UDP:
			{
				skip_len = udp_jump_to_layer_greedy((char *)expect_layer, ADDR_TYPE_UDP, expect_layer_type);
				if(skip_len < 0){
					goto done;
				}

				success_layer = (char *)expect_layer + skip_len;
				goto done;
			}
			break;

			default:
				snprintf(_g_mesa_jump_layer_last_error, PIPE_BUF, "MESA_jump_layer_greedy() not support layer type:%d\n", expect_layer_type);
				goto done;
		}

		expect_layer = MESA_jump_layer(new_next_layer_data, new_raw_layer_type, expect_layer_type);
	}

done:
	return success_layer;
}

const void *MESA_net_jump_to_layer_greedy(const void *raw_data, int raw_layer_type, int expect_layer_type)
{
	return MESA_jump_layer_greedy(raw_data, raw_layer_type, expect_layer_type);
}

#include <netinet/tcp.h>
#include <netinet/udp.h>

/* ģ��tcpdump��ʽ:   192.168.40.137.22 > 192.168.36.40.49429  */
const char *MESA_jump_layer_ipv4_ntop(const struct ip *ip4_hdr, char *out_buf, int buf_len )
{
	unsigned char inner_ip_proto;
	const struct mesa_tcp_hdr *inner_thdr = NULL;
	const struct mesa_udp_hdr *inner_uhdr = NULL;
	unsigned short sport, dport;
	char ipsrc_str[INET6_ADDRSTRLEN];
	char ipdst_str[INET6_ADDRSTRLEN];

	inner_ip_proto = ip4_hdr->ip_p;		
	if(IPPROTO_TCP == inner_ip_proto){
		inner_thdr = (struct mesa_tcp_hdr *)((char *)ip4_hdr + ip4_hdr->ip_hl*4);
		sport = ntohs(inner_thdr->th_sport);
		dport = ntohs(inner_thdr->th_dport);
	}else if(IPPROTO_UDP == inner_ip_proto){
		inner_uhdr = (struct mesa_udp_hdr *)((char *)ip4_hdr + ip4_hdr->ip_hl*4);
		sport = ntohs(inner_uhdr->uh_sport);
		dport = ntohs(inner_uhdr->uh_dport);				
	}else{
		snprintf(_g_mesa_jump_layer_last_error, PIPE_BUF, "MESA_jump_layer_ipv4_ntop() error, unsupport ip protocol:%d", inner_ip_proto);
		return NULL;
	}
	
	inet_ntop(AF_INET, &ip4_hdr->ip_src.s_addr, ipsrc_str, sizeof(ipsrc_str));
	inet_ntop(AF_INET, &ip4_hdr->ip_dst.s_addr, ipdst_str, sizeof(ipdst_str));

	snprintf(out_buf, buf_len, "%s.%u > %s.%u", ipsrc_str, sport, ipdst_str, dport);

	return out_buf;
}


const char *MESA_jump_layer_ipv6_ntop(const struct ip6_hdr *ip6_hdr, char *out_buf, int buf_len)
{
	unsigned char inner_ip_proto;
	const struct tcphdr *inner_thdr = NULL;
	const struct udphdr *inner_uhdr = NULL;
	unsigned short sport, dport;
	char ipsrc_str[INET6_ADDRSTRLEN];
	char ipdst_str[INET6_ADDRSTRLEN];

	/* TODO: �˴��п��ܰ���ѡ�����Ƭ, ����ֱ�ӻ�ȡ��һ���Э������, ��˴��������Ͻ�! */
	inner_ip_proto = ip6_hdr->ip6_nxt;	
	if(IPPROTO_TCP == inner_ip_proto){
		inner_thdr = (struct tcphdr *)((char *)ip6_hdr + sizeof(struct ip6_hdr));
		sport = inner_thdr->source;
		dport = inner_thdr->dest;				
	}else if(IPPROTO_UDP== inner_ip_proto){
		inner_uhdr = (struct udphdr *)((char *)ip6_hdr + sizeof(struct ip6_hdr));
		sport = inner_uhdr->source;
		dport = inner_uhdr->dest;					
	}else{
		snprintf(_g_mesa_jump_layer_last_error, PIPE_BUF, "MESA_jump_layer_ipv6_ntop() error, unsupport ip6_nxt_hdr:%d", inner_ip_proto);
		return NULL;
	}	
	
	inet_ntop(AF_INET6, &ip6_hdr->ip6_src, ipsrc_str, sizeof(ipsrc_str));
	inet_ntop(AF_INET6, &ip6_hdr->ip6_dst, ipdst_str, sizeof(ipdst_str));

	snprintf(out_buf, buf_len, "%s.%u > %s.%u", ipsrc_str, sport, ipdst_str, dport);

	return out_buf;
}

const char *MESA_jump_layer_get_last_error(void)
{
	return _g_mesa_jump_layer_last_error;
}

#ifdef __cplusplus
}
#endif

