#ifndef _MESA_NET_H_
#define _MESA_NET_H_

#include <stdio.h>
#include <endian.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/in_systm.h>
#include <linux/ppp_defs.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define BYTE_ALIGNED(n)    __attribute__((packed, aligned(n)))


#define SENDPACKET_ARP_H			0x1c    /* ARP header:          28 bytes */
#define SENDPACKET_ETH_H			0xe     /* Etherner header:     14 bytes */
#define SENDPACKET_IP_H            	0x14    /* IP header:           20 bytes */
/* See sendpacket-ospf.h for OSPF related header sizes */
#define SENDPACKET_RIP_H           	0x18    /* RIP header base:     24 bytes */
#define SENDPACKET_TCP_H           	0x14    /* TCP header:          20 bytes */
#define SENDPACKET_UDP_H           	0x8     /* UDP header:           8 bytes */

/*
 *  Ethernet packet header prototype.  Too many O/S's define this differently.
 *  Easy enough to solve that and define it here.
 */
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif 
#define ETHERTYPE_PUP           		0x0200  /* PUP protocol */
#define ETHERTYPE_IP            		0x0800  /* IP protocol */
#define ETHERTYPE_IPv6          		0x86dd  /* IPv6 protocol */
#define ETHERTYPE_ARP           		0x0806  /* Addr. resolution protocol */
#define ETHERTYPE_REVARP        		0x8035  /* reverse Addr. resolution protocol */
#define ETHERTYPE_VLAN          		0x8100  /* IEEE 802.1Q VLAN tagging */
#define ETHERTYPE_LOOPBACK      	0x9000  /* used to test interfaces */

#define ETH_P_MAC_IN_MAC			0x88A8 /* pangu项目借用88a8类型, 用于回流MAC_IN_MAC数据包 */

#define ETHERTYPE_PANGU_MAC_IN_MAC 0x88A8 /* 2018-08-16 lijia add, for pangu MAC-in-MAC */

#if 0
#define ETHERTYPE_IP_NET            	0x0008  /* IP protocol network order */
#define ETHERTYPE_IPv6_NET          	0xdd86  /* IPv6 protocol network order */
#define ETHERTYPE_VLAN_NET         	0x0081  /* IEEE 802.1Q VLAN tagging network order*/
#define ETH_P_PPP_SES_NET   		0x6488  /* PPPoE session messages network order      */
#define ETH_P_MPLS_UC_NET   		0x4788  /* MPLS Unicast traffic  network order       */
#define ETH_P_ARP_NET  		      0x0608  /* Address Resolution packet network order   */
#endif

#define ETHERNET_HDR_LEN			(14)
struct mesa_ethernet_hdr
{
	u_int8_t  ether_dhost[ETHER_ADDR_LEN];    /* destination ethernet address */
	u_int8_t  ether_shost[ETHER_ADDR_LEN];    /* source ethernet address */
	u_int16_t ether_type;                     /* packet type ID */
}BYTE_ALIGNED(1);


/*
 *  IPv4 packet header prototype.
 */
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif 


#define IPPROTO_L2TPV3	(115)  /* L2TPv3, RFC3931-page17 */

struct mesa_ip4_hdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t ip_hl:4,         /* header length */
            ip_v:4;         /* version */
#elif __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t ip_v:4,          /* version */
            ip_hl:4;        /* header length */
#else
#error "Please check <endian.h>"
#endif
    u_int8_t ip_tos;          /* type of service */
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};


/*
 *  ARP packet header prototype.  Too many O/S's define this differently.
 *  Easy enough to solve that and define it here.
 */
#define ARPOP_REQUEST    1                  /* req to resolve address */
#define ARPOP_REPLY      2                  /* resp to previous request */
#define ARPOP_REVREQUEST 3                  /* req protocol address given hardware */
#define ARPOP_REVREPLY   4                  /* resp giving protocol address */
#define ARPOP_INVREQUEST 8                  /* req to identify peer */
#define ARPOP_INVREPLY   9                  /* resp identifying peer */ 


#define ARPHRD_ETHER     1                  /* ethernet hardware format */
struct mesa_arp_hdr
{
    u_short ar_hrd;                         /* format of hardware address */

    u_short ar_pro;                         /* format of protocol address */
    u_char  ar_hln;                         /* length of hardware address */
    u_char  ar_pln;                         /* length of protocol addres */
    u_short ar_op;                          /* operation type */

    /*
     *  These should implementation defined but I've hardcoded eth/IP.
     */
    u_char ar_sha[6];                         /* sender hardware address */
    u_char ar_spa[4];                         /* sender protocol address */
    u_char ar_tha[6];                         /* target hardware address */
    u_char ar_tpa[4];                         /* target protocol address */
};


/*
 *  IPv6 packet header prototype, add by LiJia 2012-03-19.
 */
struct mesa_ip6_hdr
{
    u_int8_t ip6_flags[4]; /* version, traffic-class, flow-label */
    u_int16_t ip6_payload_len;  /* payload length, not contain header */
    u_int8_t ip6_nxt_hdr;       /* next header, same as protocol in IPv4 */
    u_int8_t ip6_hop;           /* hop limit, same as TTL in IPv4 */
    struct in6_addr ip6_src;     /* source address */
    struct in6_addr ip6_dst;     /* dest address */
};


struct mesa_icmp_echo_hdr{
	unsigned char icmp_type;
	unsigned char icmp_code;
	unsigned short icmp_cksum;
	unsigned short icd_id;
	unsigned short icd_seq;
	//char echo_data[];
};


/*
 *  ICMP packet header prototype. // from libnet-headers.h
 */
struct mesa_icmp_hdr
{
    u_char icmp_type;
/*
 *  ICMP types.
 */
#ifndef     ICMP_ECHOREPLY
#define     ICMP_ECHOREPLY                  0
#endif
#ifndef     ICMP_UNREACH
#define     ICMP_UNREACH                    3
#endif
#ifndef     ICMP_SOURCEQUENCH
#define     ICMP_SOURCEQUENCH               4
#endif
#ifndef     ICMP_REDIRECT
#define     ICMP_REDIRECT                   5
#endif
#ifndef     ICMP_ECHO
#define     ICMP_ECHO                       8
#endif
#ifndef     ICMP_ROUTERADVERT
#define     ICMP_ROUTERADVERT               9
#endif
#ifndef     ICMP_ROUTERSOLICIT
#define     ICMP_ROUTERSOLICIT              10
#endif
#ifndef     ICMP_TIMXCEED
#define     ICMP_TIMXCEED                   11
#endif
#ifndef     ICMP_PARAMPROB
#define     ICMP_PARAMPROB                  12
#endif
#ifndef     ICMP_TSTAMP
#define     ICMP_TSTAMP                     13
#endif
#ifndef     ICMP_TSTAMPREPLY
#define     ICMP_TSTAMPREPLY                14
#endif
#ifndef     ICMP_IREQ
#define     ICMP_IREQ                       15
#endif
#ifndef     ICMP_IREQREPLY
#define     ICMP_IREQREPLY                  16
#endif
#ifndef     ICMP_MASKREQ
#define     ICMP_MASKREQ                    17
#endif
#ifndef     ICMP_MASKREPLY
#define     ICMP_MASKREPLY                  18
#endif
    u_char icmp_code;
/*
 *  ICMP codes.
 */
#ifndef     ICMP_UNREACH_NET
#define     ICMP_UNREACH_NET                0
#endif
#ifndef     ICMP_UNREACH_HOST
#define     ICMP_UNREACH_HOST               1
#endif
#ifndef     ICMP_UNREACH_PROTOCOL
#define     ICMP_UNREACH_PROTOCOL           2
#endif
#ifndef     ICMP_UNREACH_PORT
#define     ICMP_UNREACH_PORT               3
#endif
#ifndef     ICMP_UNREACH_NEEDFRAG
#define     ICMP_UNREACH_NEEDFRAG           4
#endif
#ifndef     ICMP_UNREACH_SRCFAIL
#define     ICMP_UNREACH_SRCFAIL            5
#endif
#ifndef     ICMP_UNREACH_NET_UNKNOWN
#define     ICMP_UNREACH_NET_UNKNOWN        6
#endif
#ifndef     ICMP_UNREACH_HOST_UNKNOWN
#define     ICMP_UNREACH_HOST_UNKNOWN       7
#endif
#ifndef     ICMP_UNREACH_ISOLATED
#define     ICMP_UNREACH_ISOLATED           8
#endif
#ifndef     ICMP_UNREACH_NET_PROHIB
#define     ICMP_UNREACH_NET_PROHIB         9
#endif
#ifndef     ICMP_UNREACH_HOST_PROHIB
#define     ICMP_UNREACH_HOST_PROHIB        10
#endif
#ifndef     ICMP_UNREACH_TOSNET
#define     ICMP_UNREACH_TOSNET             11
#endif
#ifndef     ICMP_UNREACH_TOSHOST
#define     ICMP_UNREACH_TOSHOST            12
#endif
#ifndef     ICMP_UNREACH_FILTER_PROHIB
#define     ICMP_UNREACH_FILTER_PROHIB      13
#endif
#ifndef     ICMP_UNREACH_HOST_PRECEDENCE
#define     ICMP_UNREACH_HOST_PRECEDENCE    14
#endif
#ifndef     ICMP_UNREACH_PRECEDENCE_CUTOFF
#define     ICMP_UNREACH_PRECEDENCE_CUTOFF  15
#endif
#ifndef     ICMP_REDIRECT_NET
#define     ICMP_REDIRECT_NET               0
#endif
#ifndef     ICMP_REDIRECT_HOST
#define     ICMP_REDIRECT_HOST              1
#endif
#ifndef     ICMP_REDIRECT_TOSNET
#define     ICMP_REDIRECT_TOSNET            2
#endif
#ifndef     ICMP_REDIRECT_TOSHOST
#define     ICMP_REDIRECT_TOSHOST           3
#endif
#ifndef     ICMP_TIMXCEED_INTRANS
#define     ICMP_TIMXCEED_INTRANS           0
#endif
#ifndef     ICMP_TIMXCEED_REASS
#define     ICMP_TIMXCEED_REASS             1
#endif
#ifndef     ICMP_PARAMPROB_OPTABSENT
#define     ICMP_PARAMPROB_OPTABSENT        1
#endif

    u_short icmp_sum;

    union
    {
        struct
        {
            u_short id;
            u_short seq;
        }echo;

#undef icmp_id
#undef icmp_seq
#define icmp_id     hun.echo.id
#define icmp_seq    hun.echo.seq

        u_long gateway;
        struct
        {
            u_short pad;
            u_short mtu;
        }frag;
    }hun;
    union
    {
        struct
        {
            n_time its_otime;
            n_time its_rtime;
            n_time its_ttime;
        }ts;
        struct
        {
            struct ip idi_ip;
            /* options and then 64 bits of data */
        }ip;
        u_long mask;
        char data[1];

#undef icmp_mask
#define icmp_mask    dun.mask
#undef icmp_data
#define icmp_data    dun.data

#undef icmp_otime
#define icmp_otime   dun.ts.its_otime
#undef icmp_rtime
#define icmp_rtime   dun.ts.its_rtime
#undef icmp_ttime
#define icmp_ttime   dun.ts.its_ttime
    }dun;
	
};

/*
 *  TCP packet header prototype.
 */
#ifndef TH_FIN
#define TH_FIN    0x01
#endif
#ifndef TH_SYN
#define TH_SYN    0x02
#endif
#ifndef TH_RST
#define TH_RST    0x04
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08
#endif
#ifndef TH_ACK
#define TH_ACK    0x10
#endif
#ifndef TH_URG
#define TH_URG    0x20
#endif 
struct mesa_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
#elif __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t th_off:4,        /* data offset */
           th_x2:4;         /* (unused) */
#else
#error "Please check <endian.h>"
#endif
    u_int8_t  th_flags;       /* control flags */
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};


/*
 *  UDP packet header prototype.
 */
struct mesa_udp_hdr
{
    u_int16_t uh_sport;   /* soure port */
    u_int16_t uh_dport;   /* destination port */
    u_int16_t uh_ulen;    /* length */
    u_int16_t uh_sum;     /* checksum */
};


#define PPPOE_HDR_LEN			(sizeof(struct mesa_pppoe_session_hdr))
#define PPP_PROTOCOL_PAD		(0x0001)
#define PPP_PROTOCOL_IPv4		(0x0021)
#define PPP_PROTOCOL_PAP		(0xC023)
#define PPP_PROTOCOL_CHAP	(0xC223)
#define PPP_PROTOCOL_IPv6		(0x0057)
#define PPP_COMPRESS_DATA	(0x00FD)

#define PPP_PROTOCOL_LCP		(0xC021)
#define PPP_PROTOCOL_CCP		(0x80FD)
#define PPP_PROTOCOL_IPCP		(0x8021)

struct mesa_pppoe_session_hdr{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int ver:4;   
	unsigned int type:4;  
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int type:4; 
	unsigned int ver:4; 
#else
#error "Please check <endian.h>"
#endif
  	unsigned char code;
	unsigned short session_id;
	unsigned short len;
	/* to do:
		ppp应该单独作为一层存在, 为了简化处理, 强制将其和PPPOE_SES绑在一起,
		如果需要监听PPP协商过程, 此结构需要改动.
	*/
	unsigned short ppp_protocol; 
}BYTE_ALIGNED(1);


struct mesa_ppp_hdr{
	unsigned char address;
	unsigned char control;
	unsigned short protocol;
}BYTE_ALIGNED(1);

#define PPP_LCP_CODE_REQUEST			(1)
#define PPP_LCP_CODE_ACK				(2)
#define PPP_LCP_CODE_NAK				(3)
#define PPP_LCP_CODE_REJECT			(4)
#define PPP_LCP_CODE_TERMINATE_REQ	(5)
#define PPP_LCP_CODE_TERMINATE_ACK	(6)

/* refer to RFC1661 */
#define PPP_LCP_OPT_RESERVED		(0)
#define PPP_LCP_OPT_MAX_RCV_UNIT	(1)	
#define PPP_LCP_OPT_AUTH_PRO		(3)
#define PPP_LCP_OPT_QA_PRO		(4)
#define PPP_LCP_OPT_MAGIC			(5)
#define PPP_LCP_OPT_PRO_FIELD_COMPRESS (7)
#define PPP_LCP_OPT_ADDR_CTRL_FIELD_COMPRESS (8)

#define PPP_LCP_OPT_AUTH_PRO_PAP	  	(0xC023)
#define PPP_LCP_OPT_AUTH_PRO_CHAP 	(0xC223)

#define PPP_LCP_OPT_AUTH_PRO_CHAP_ALGO_MS_CHAP_V2 	(0x81)
#define PPP_LCP_OPT_AUTH_PRO_CHAP_ALGO_CHAP_MD5	 	(0x05)


/* refer to RFC1962 Page6 */
#define PPP_CCP_OPT_OUI			(0)
#define PPP_CCP_OPT_MS_PPC		(18) 

struct mesa_ppp_lcp_ack_hdr{ /* RFC1661-Page29 */
	unsigned char code;
	unsigned char identifier;
	unsigned short length;
}BYTE_ALIGNED(1);

struct mesa_ppp_ccp_ack_hdr{ /* RFC1661-Page29 */
	unsigned char code;
	unsigned char identifier;
	unsigned short length;
}BYTE_ALIGNED(1);

#define PPP_CHAP_CHALLENGE	(1)
#define PPP_CHAP_RESPONSE		(2)
#define PPP_CHAP_SUCCESS		(3)
#define PPP_CHAP_FAILURE		(4)

struct mesa_ppp_chap_hdr{
	unsigned char code;
	unsigned char identifier;
	unsigned short length;
}BYTE_ALIGNED(1);

struct mesa_ppp_ipcp_ack_hdr{
	unsigned char code;
	unsigned char identifier;
	unsigned short length;
}BYTE_ALIGNED(1);

enum pptp_control_message_type{
	PPTP_CTRL_START_CONN_REQ		=	1,
	PPTP_CTRL_START_CONN_REPLY	=	2,
	PPTP_CTRL_STOP_CONN_REQ		=	3,
	PPTP_CTRL_STOP_CONN_REPLY	=	4,
	PPTP_CTRL_ECHO_REQ			= 	5,
	PPTP_CTRL_ECHO_REPLY			=	6,
	PPTP_CTRL_OUT_GO_REQ			=	7,
	PPTP_CTRL_OUT_GO_REPLY		=	8,
	PPTP_CTRL_IN_CALL_REQ			=	9,
	PPTP_CTRL_IN_CALL_REPLY		= 	10,
	PPTP_CTRL_IN_CALL_CONN		=	11,
	PPTP_CTRL_CALL_CLEAR_REQ		=	12,
	PPTP_CTRL_CALL_DISCONN_NOTIFY = 13,
	PPTP_CTRL_WAN_ERROR_NOTIFY	=	14,
	PPTP_CTRL_SET_LINK_INFO		= 	15,
};

struct mesa_pptp_control_hdr{
	unsigned short length; /* 全部数据长度, 包括本头部 */
	unsigned short pptp_message_type;
	unsigned int magic_cookie;
	unsigned short control_message_type;
	char ignore_bytes[0]; /* 后续字段暂不关心, 长度也不一定 */
};

struct mesa_vlan_hdr{
	unsigned short pri_cfi_id;
	unsigned short type;
};

struct mesa_vlan_detail_hdr{
	unsigned int priority:3;
	unsigned int del_flag:1;
	unsigned int vlan_id:12;
	unsigned short type;
};

/* 2018-08-28 lijia add, for pangu 项目mac_in_mac回流 */
struct mesa_mac_in_mac_net_hdr{
	unsigned int route_dir:1;
	unsigned int link_id:3;
	unsigned int dev_id:6;
	unsigned int region_id:5;
	unsigned int __pad1:1;
	unsigned int encap_type:4;
	unsigned int __pad2:20;
	unsigned int __pad3:8;
};

struct mesa_gre_base_hdr_v0{
#if __BYTE_ORDER == __LITTLE_ENDIAN 
	unsigned char recur:3;
	unsigned char strict_src_route_flag:1;
	unsigned char seq_flag:1;
	unsigned char key_flag:1;
	unsigned char route_flag:1;
	unsigned char checksum_flag:1;
	
	unsigned char version:3;
	unsigned char flags:5;	/* version 0 flags is 5 bit */
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned char checksum_flag:1;
	unsigned char route_flag:1;
	unsigned char key_flag:1;
	unsigned char seq_flag:1;
	unsigned char strict_src_route_flag:1;
	unsigned char recur:3;

	unsigned char flags:5;	/* version 0 flags is 5 bit */
	unsigned char version:3;
#else
#error "Please check <endian.h>"
#endif
	unsigned short protocol;
};

struct mesa_gre_base_hdr_v1{
#if __BYTE_ORDER == __LITTLE_ENDIAN 
	unsigned char recur:3;
	unsigned char strict_src_route_flag:1;
	unsigned char seq_flag:1;
	unsigned char key_flag:1;
	unsigned char route_flag:1;
	unsigned char checksum_flag:1;

	unsigned char version:3;
	unsigned char flags:4;	/* version 1 flags is 4 bit */
	unsigned char ack_flag:1;

#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned char checksum_flag:1;
	unsigned char route_flag:1;
	unsigned char key_flag:1;
	unsigned char seq_flag:1;
	unsigned char strict_src_route_flag:1;
	unsigned char recur:3;
	
	unsigned char ack_flag:1;
	unsigned char flags:4;	/* version 1 flags is 4 bit */
	unsigned char version:3;
#else
#error "Please check <endian.h>"
#endif
	unsigned short protocol;
};

#define GRE_SRE_MAX_LEN		(256) /* 长度最长为一个字节, 256 */
struct gre_source_route_entry_hdr{
	unsigned short address_family;
	unsigned char sre_offset;
	unsigned char sre_length;
	unsigned char sre_entry_list[GRE_SRE_MAX_LEN];
};

/* 所有可能的值均在, 需要根据mesa_gre_base_hdr各个bit的值, 判断是否含有如下值 */
struct mesa_gre_extend_hdr{
	unsigned short checksum; //version0
	unsigned short offset;	//version0, if checksum present, then offset also present 
	unsigned short payload_len; //version1
	unsigned short call_id; 	//version1
	unsigned int key;		//version0
	unsigned int seq_num;	//version0 and version1
	unsigned int ack_num;	//version1
	//struct gre_source_route_entry_hdr sre_list;
};

struct mesa_gre_hdr{
	/* version0和version1的头部中, version字段时一致的, 其他有小区别, 默认使用v0方式解析 */
	struct mesa_gre_base_hdr_v0 gre_base;
	struct mesa_gre_extend_hdr gre_extend;
};


#define MPLS_LABEL_MASK	(0xFFFFF000)
#define MPLS_EXP_MASK		(0x00000E00)
#define MPLS_BLS_MASK	(0x00000100)
#define MPLS_TTL_MASK		(0x000000FF)
struct mesa_mpls_hdr{
#if __BYTE_ORDER == __LITTLE_ENDIAN 
	unsigned short mpls_label_low;
	unsigned char mpls_bls:1;	/* bottom of label stack */
	unsigned char mpls_exp:3;
	unsigned char mpls_label_high:4;
	unsigned char mpls_ttl;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned char mpls_ttl;
	unsigned char mpls_label_high:4;
	unsigned char mpls_exp:3;
	unsigned char mpls_bls:1;	/* bottom of label stack */
	unsigned short mpls_label_low;
#else
#error "Please check <endian.h>"
#endif
};

#define L2TP_REGISTERED_IP_PRO		(115)
#define L2TP_REGISTERED_PORT		(1701)

#define L2TP_HDR_TYPE_DATA		(0)
#define L2TP_HDR_TYPE_CONTROL		(1)

struct l2tp_hdr_v2{
#if __BYTE_ORDER == __LITTLE_ENDIAN 
	unsigned char priority:1;
	unsigned char offset_present:1;
	unsigned char reserved2:1;
	unsigned char seq_present:1;
	unsigned char reserved1:2;
	unsigned char length_present:1;
	unsigned char type:1; 
	
	unsigned char version:4;
	unsigned char reserved3:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned char reserved3:4;
	unsigned char version:4;

	unsigned char type:1; 
	unsigned char length_present:1;
	unsigned char reserved1:2;
	unsigned char seq_present:1;
	unsigned char reserved2:1;
	unsigned char offset_present:1;
	unsigned char priority:1;
#else
#error "Please check <endian.h>"
#endif
};

/* refer to RFC2661-Page12 */
#define L2TP_CTRL_MSG_RESERVED0	(0)
#define L2TP_CTRL_MSG_SCCRQ		(1)
#define L2TP_CTRL_MSG_SCCRP		(2)
#define L2TP_CTRL_MSG_SCCCN		(3)
#define L2TP_CTRL_MSG_STOP_CCN	(4)
#define L2TP_CTRL_MSG_RESERVED5	(5)
#define L2TP_CTRL_MSG_HELLO		(6)
#define L2TP_CTRL_MSG_OCRQ		(7)
#define L2TP_CTRL_MSG_OCRP		(8)
#define L2TP_CTRL_MSG_OCCN		(9)
#define L2TP_CTRL_MSG_ICRQ		(10)
#define L2TP_CTRL_MSG_ICRP		(11)
#define L2TP_CTRL_MSG_ICCN		(12)
#define L2TP_CTRL_MSG_RESERVED13	(13)
#define L2TP_CTRL_MSG_CDN			(14)
#define L2TP_CTRL_MSG_WEN		(15)
#define L2TP_CTRL_MSG_SLI			(16)

#define L2TP_AVP_GET_LEN(u)  (ntohs(u) & 0x3F)
struct l2tp_avp{
	unsigned short M_H_rsvd_len_union;
	unsigned short vendor_id;
	unsigned short attribute_type;
}BYTE_ALIGNED(1);

/* RFC2408-Page23 */
#define ISAKMP_PAYLOAD_TYPE_NONE		(0)
#define ISAKMP_PAYLOAD_TYPE_SA		(1)
#define ISAKMP_PAYLOAD_TYPE_PROPOSAL 	(2)
#define ISAKMP_PAYLOAD_TYPE_TRANSFORM (3)
#define ISAKMP_PAYLOAD_TYPE_KEY_EXCHANGE (4)
#define ISAKMP_PAYLOAD_TYPE_ID		(5)
#define ISAKMP_PAYLOAD_TYPE_CERT		(6)
#define ISAKMP_PAYLOAD_TYPE_CR		(7)
#define ISAKMP_PAYLOAD_TYPE_HASH		(8)
#define ISAKMP_PAYLOAD_TYPE_SIG		(9)
#define ISAKMP_PAYLOAD_TYPE_NONCE		(10)
#define ISAKMP_PAYLOAD_TYPE_NOTIFY	(11)
#define ISAKMP_PAYLOAD_TYPE_DELETE	(12)
#define ISAKMP_PAYLOAD_TYPE_VENDOR_ID (13)
#define ISAKMP_PAYLOAD_TYPE_RESERVED_BEGIN	(14) /* 14 - 127 */
#define ISAKMP_PAYLOAD_TYPE_RESERVED_END		(127) /* 14 - 127 */
#define ISAKMP_PAYLOAD_TYPE_PRIVATE_USE_BEGIN	(128) /* 128-255 */
#define ISAKMP_PAYLOAD_TYPE_PRIVATE_USE_END	(255) /* 128-255 */

/* RFC2408-Page23 */
#define ISAKMP_EXCHANGE_TYPE_NONE		(0)
#define ISAKMP_EXCHANGE_TYPE_BASE		(1)
#define ISAKMP_EXCHANGE_TYPE_ID_PROT	(2) /* RFC-2409 page8, main mode is instantiation os ISAKMP Identity Protect Exchange  */
#define ISAKMP_EXCHANGE_TYPE_AUTH		(3)
#define ISAKMP_EXCHANGE_TYPE_AGGRESS	(4)/* RFC-2409 page8, Aggressive mode is instantiation os ISAKMP Aggressive Exchange  */
#define ISAKMP_EXCHANGE_TYPE_INFO		(5)
#define ISAKMP_EXCHANGE_TYPE_FEATURE_USE_BEGIN	(6) /* 6-31的值暂不可用 */
#define ISAKMP_EXCHANGE_TYPE_FEATURE_USE_END	(31) /* 6-31的值暂不可用 */

struct mesa_isakmp_hdr{ /* RFC2408-Page22 */
	unsigned long long init_cookie;
	unsigned long long resp_cookie;	
	unsigned char next_payload;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char minor_version:4;
	unsigned char major_version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned char major_version:4;
	unsigned char minor_version:4;
#else
#error "Please check <endian.h>"
#endif	
	
	unsigned char exchange_type;
	unsigned char flags;
	unsigned int message_id;
	unsigned int length;
};

struct mesa_isakmp_payload_hdr{ /* RFC2408-Page22 */
	unsigned char next_payload;
	unsigned char reserver;
	unsigned short payload_len;
};

#define GTP_MSG_TYPE_T_PDU (0xFF)

struct gtp_hdr{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char flags;
	unsigned char msg_type;
    unsigned short len;
	unsigned int teid;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int teid;
    unsigned short len;
	unsigned char msg_type;
	unsigned char flags;
#else
#error "Please check <endian.h>"
#endif
};

#define MAX_ADDR_TYPE_STRING_LEN	(64)
#define MAX_ADDR_LIST_STRING_LEN	(2048)
#define MAX_ADDR_EMBED_LAYER_NUM (20) /* 最大地址嵌套层数 */
#define MAX_ADDR_BIN_VALUE_LEN	(40) /* paddr实际内容最大长度, 目前是tuple4v6最长 */

/* 串联模式下, 记录MAC地址用于发包 */
struct packet_io_mac_addr{
	struct mesa_ethernet_hdr eth_hdr;
	char route_dir;
	char __pad__;	 /* 整体结构8字节对齐 */
};

unsigned char net_layer_to_ipv4_protocol(int addr_type);
unsigned char net_layer_to_ipv6_protocol(int addr_type);
unsigned short net_layer_to_ethernet_protocol(int addr_type);
int net_common_build_send_mac(unsigned char *buf, const struct mesa_ethernet_hdr *raw_eth_hdr, int addr_type, int dir_reverse, int net_topology_mode);
int net_common_adjust_forward_mac(struct mesa_ethernet_hdr *raw_eth_hdr,int net_topology_mode);
const void *MESA_net_jump_to_layer(const void *raw_data,  int raw_layer_type, int expect_layer_type);
const void *MESA_net_jump_to_layer_greedy(const void *raw_data, int raw_layer_type, int expect_layer_type);
char MESA_ascii_to_hex(char ascii);

#ifdef __cplusplus
}
#endif

#endif

