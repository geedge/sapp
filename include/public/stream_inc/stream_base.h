#ifndef _APP_STREAM_BASE_H_
#define _APP_STREAM_BASE_H_ 

#define STREAM_BASE_H_VERSION		(20210621)

#include <sys/types.h>
#include <netinet/in.h>            
#include <linux/if_ether.h>   

#ifndef UINT8
typedef unsigned char		UINT8;
#endif
#ifndef UCHAR
typedef unsigned char		UCHAR;
#endif
#ifndef UINT16
typedef unsigned short		UINT16;
#endif

#ifndef UINT32
typedef unsigned int		UINT32;
#endif
#ifndef UINT64
typedef unsigned long long	UINT64;
#endif

/* CHN : ���ķ����� */
/* ENG : stream direction definition*/
#define DIR_C2S 			0x01
#define DIR_S2C 			0x02
#define DIR_DOUBLE 			0x03

/* CHN : ����ײ㴫�䷽����,����ģʽ������ */
/* ENG : network topology route direction, is valid in serial mode */
#define DIR_ROUTE_UP		0x00
#define DIR_ROUTE_DOWN 		0x01

/* CHN : ���������Ͷ��� */
/* ENG : single packet type definition */
#define PKT_TYPE_NORMAL  			(0x0)	/* normal, common */
#define PKT_TYPE_IPREBUILD 			(1<<0)  /* ip frag reassembled packet;  ip��Ƭ���鱨�� */
#define PKT_TYPE_TCPUNORDER 		(1<<1)  /* TCP out of order packet;  TCP������ */
#define PKT_TYPE_TCPREORDER 		(1<<2)  /* TCP sequential packet;  TCP��������õ����ݰ� */ 
#define PKT_TYPE_TCPRETRANS 		(1<<3)  /* TCP retransmit packet;  TCP�ش����� */
#define PKT_TYPE_IP_FRAG			(1<<4)  /* IP frag packet;  IP��Ƭ�� */
#define PKT_TYPE_IP_FRAG_LAST		(1<<5)  /* last IP frag packet;  ͬ����һ��ԭʼ����IP�������һ��IP��Ƭ�� */

/* CHN : ��ַ���Ͷ���, ��ͨ������ addr_type_to_string() ת���ַ�����ʽ. */
/* ENG : address type, transform to string mode by call addr_type_to_string(). */
enum addr_type_t{
	__ADDR_TYPE_INIT = 0,
	ADDR_TYPE_IPV4,				/* 1, struct stream_tuple4_v4 */
	ADDR_TYPE_IPV6,				/* 2, struct stream_tuple4_v6 */
	ADDR_TYPE_VLAN,				/* 3, 802.1Q */
	ADDR_TYPE_MAC,				/* 4 */
	ADDR_TYPE_ARP = 5,			/* 5 */
	ADDR_TYPE_GRE,				/* 6 */
	ADDR_TYPE_MPLS,				/* 7 */
	ADDR_TYPE_PPPOE_SES,		/* 8 */
	ADDR_TYPE_TCP,				/* 9 */
	ADDR_TYPE_UDP = 10,			/* 10 */
	ADDR_TYPE_L2TP,				/* 11 */
	__ADDR_TYPE_IP_PAIR_V4,		/* 12, ipv4 layer in tunnel mode */
	__ADDR_TYPE_IP_PAIR_V6,		/* 13, ipv6 layer in tunnel mode */
	ADDR_TYPE_PPP,				/* 14 */
	ADDR_TYPE_PPTP,			/* 15 */
	ADDR_TYPE_MAC_IN_MAC,		/* 16 */
	ADDR_TYPE_GPRS_TUNNEL,      /* 17 */
	ADDR_TYPE_VXLAN,			/* 18 */
	__ADDR_TYPE_MAX,			/* 19 */
};

#define TCP_TAKEOVER_STATE_FLAG_OFF	0
#define TCP_TAKEOVER_STATE_FLAG_ON	1


/* CHN : Ӧ�ò㿴��������״̬���� */
/* ENG : stream state for protocol or business plug*/
#define OP_STATE_PENDING   0
#define OP_STATE_TIMED 1  /* is obsolete */
#define OP_STATE_CLOSE     2
#define OP_STATE_DATA      3

/* CHN : Ӧ�ò㷵�ؽ������ */
/* ENG : return value of plug */
#define APP_STATE_GIVEME   0x00
#define APP_STATE_FAWPKT   0x00

#define APP_STATE_DROPME   0x01
#define APP_STATE_GIVESTATE   0x02


#define APP_STATE_DROPPKT  0x10

#define APP_STATE_KILL_FOLLOW 0x40 /* ǿ��CLOSE��ǰ������������в�� */
#define APP_STATE_KILL_OTHER  0x80 /* ǿ��CLOSE����ǰ���������в�� */


/* CHN : �������Ͷ��� */
/* ENG : stream type */
enum stream_type_t{
	STREAM_TYPE_NON = 0, /* No stream concept indeed, such as vlan, IP, etc.;  �����ĸ���, ��VLAN, IP��� */
	STREAM_TYPE_TCP,
	STREAM_TYPE_UDP,	 /* there is no stream of UDP in RFC, but in MESA platform, we build a UDP stream with same tuple4 packet */
	STREAM_TYPE_VLAN,
	STREAM_TYPE_SOCKS4,
	STREAM_TYPE_SOCKS5,
	STREAM_TYPE_HTTP_PROXY,
	STREAM_TYPE_PPPOE,
	STREAM_TYPE_L2TP,
	STREAM_TYPE_OPENVPN,
	STREAM_TYPE_PPTP,	
	STREAM_TYPE_ISAKMP,
};

/*
   CHN: ���ĵײ������������, 
   	   ��ͬ��stream_type_t, ���統ǰ��ΪSTREAM_TYPE_TCP, ���ײ��������Ϳ�����STREAM_TUNNLE_PPTP.
        ��Ϊ���������Ƕ��ֲ�ͬ����Ƕ�����, ֻ��¼��ײ�(��MAC�������)��������.
*/
enum stream_carry_tunnel_t{
	STREAM_TUNNLE_NON 		= 0, 	/* default is 0, not tunnel; Ĭ��Ϊ0, ������; */
	STREAM_TUNNLE_6OVER4 	= 1 << 0,
	STREAM_TUNNLE_4OVER6	= 1 << 1,
	STREAM_TUNNLE_GRE		= 1 << 2,
	STREAM_TUNNLE_IP_IN_IP	= 1 << 3,
	STREAM_TUNNLE_PPTP		= 1 << 4,
	STREAM_TUNNLE_L2TP		= 1 << 5,
	STREAM_TUNNLE_TEREDO	= 1 << 6,
	STREAM_TUNNEL_GPRS_TUNNEL = 1 << 7,
	STREAM_TUNNEL_MULTI_MAC = 1 << 8, /* is obsoulte */
};

typedef struct raw_ipfrag_list{
    void *frag_packet; /* ��ip��ͷ, �ӵײ�������ȡ��ԭʼ��ͷ */
    int pkt_len;
    int type; /* IPv4 or IPv6 */
    struct raw_ipfrag_list *next;
}raw_ipfrag_list_t;


#ifndef STRUCT_TUPLE4_DEFINED
#define STRUCT_TUPLE4_DEFINED (1)
/* compat for start, papp;  ����start, papp */
struct tuple4 {
  u_int saddr;
  u_int daddr;
  u_short source;
  u_short dest;
};
#endif

struct tuple6
{
	UCHAR saddr[16] ;
	UCHAR daddr[16] ;
	UINT16 source;
	UINT16 dest;
};

/* network-order */
struct stream_tuple4_v4{
	UINT32 saddr;	/* network order */
	UINT32 daddr;	/* network order */
	UINT16 source;	/* network order */
	UINT16 dest;	/* network order */
};


#ifndef IPV6_ADDR_LEN
#define IPV6_ADDR_LEN	(sizeof(struct in6_addr))
#endif

struct stream_tuple4_v6
{
	UCHAR saddr[IPV6_ADDR_LEN] ;
	UCHAR daddr[IPV6_ADDR_LEN] ;
	UINT16 source;	/* network order */
	UINT16 dest;	/* network order */
};


#define GRE_TAG_LEN 		(4)
struct layer_addr_gre
{
	UINT16 call_id; /* network order */
};


#define VLAN_ID_MASK		(0x0FFF)
#define VLAN_TAG_LEN 		(4)
#define MAX_VLAN_ADDR_LAYER (8)


struct single_layer_vlan_addr{     /* refer to https://en.wikipedia.org/wiki/IEEE_802.1Q */
	unsigned short TPID; /* Tag protocol identifier, network order */
	unsigned char PCP; /* Priority code point */
	unsigned char DEI; /* Drop eligible indicator  */
	unsigned short VID;  /* VLAN identifier, network order */
};


struct layer_addr_vlan
{
	struct single_layer_vlan_addr c2s_addr_array[MAX_VLAN_ADDR_LAYER];
	struct single_layer_vlan_addr s2c_addr_array[MAX_VLAN_ADDR_LAYER];
	UCHAR c2s_layer_num;
	UCHAR s2c_layer_num;
};


struct layer_addr_pppoe_session
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int ver:4;   
	unsigned int type:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int type:4; 
	unsigned int ver:4; 
#endif
  	unsigned char code;
	unsigned short session_id;
};

#ifndef MAC_ADDR_LEN
#define MAC_ADDR_LEN		(6)
#endif

struct layer_addr_mac
{
	/* 
	   C2S��S2C�������Բ�ͬ����·���豸, �ᵼ�����������mac��ַȫ��һ��, ����ע��ʱ�����ô�ͳ��ʽ, ���򵥵ĵߵ�src��dst,
	   �޸Ķ�������, mirrorģʽ��, ���Ǵ洢��src_addr��,
	   API��ͬ��, ABI������ǰ���ݵ�, �ṹ���ڴ�ֲ���֮ǰ��һ��. 
	*/
	struct ethhdr src_addr;
	struct ethhdr dst_addr;
	
	//UCHAR dst_mac[MAC_ADDR_LEN]; /* network order */
	//UCHAR src_mac[MAC_ADDR_LEN]; /* network order */
};

struct layer_addr_ipv4
{
	UINT32 saddr; 	/* network order */
	UINT32 daddr; 	/* network order */
	/* 2014-04-21 lijia add, 
	   Ϊ�˽�Լ�ڴ�ռ䡢�ʹ���Ч��, ��ǿ�ư�Э���δ���,
	   IP���TCP����Ϊһ����,
	   �����������IP, �˿���ϢΪ0;
	*/
	UINT16 source;	/* network order */
	UINT16 dest;		/* network order */
};

struct layer_addr_ipv6
{
	UCHAR saddr[IPV6_ADDR_LEN] ; /* network order */
	UCHAR daddr[IPV6_ADDR_LEN] ; /* network order */
	/* 2014-04-21 lijia add, 
	   Ϊ�˽�Լ�ڴ�ռ䡢�ʹ���Ч��, ��ǿ�ư�Э���δ���,
	   IP���TCP����Ϊһ����,
	   �����������IP, �˿���ϢΪ0;
	*/
	UINT16 source;/* network order */
	UINT16 dest;/* network order */
};

struct layer_addr_tcp
{
	UINT16 source; /* network order */
	UINT16 dest;    /* network order */
};

struct layer_addr_udp
{
	UINT16 source; /* network order */
	UINT16 dest;    /* network order */
};


struct layer_ppp_hdr{
	unsigned char address;
	unsigned char control;
	unsigned short protocol;	/* network order */ 		
}__attribute__((packed));

/* һ�������, address,control���ǹ̶������,����0xFF,0x03, ppp hdr�ǿ���ѹ���Խ�Լ����,ֻ����һ���ֽڵ�protocol�ֶ� */
struct layer_compress_ppp_hdr{
	unsigned char protocol;		
};	


struct layer_addr_l2tp_v2_t{
	UINT16 tunnelid_C2S; /* network order, �Դ���㴴�����ķ���Ϊ׼ */
	UINT16 tunnelid_S2C; /* network order, �Դ���㴴�����ķ���Ϊ׼ */
	UINT16 sessionid_C2S; /* network order, �Դ���㴴�����ķ���Ϊ׼ */
	UINT16 sessionid_S2C; /* network order, �Դ���㴴�����ķ���Ϊ׼ */
	unsigned char seq_present_C2S;
	unsigned char seq_present_S2C;
	unsigned char ppp_hdr_compress_enable;
	union{
		struct layer_ppp_hdr ppp_hdr;
		struct layer_compress_ppp_hdr compress_ppp_hdr;
	};
};

struct layer_addr_l2tp_v3_t{
	UINT32 sessionlid; /* network order */
};
		
struct layer_addr_l2tp
{
	UCHAR version; /* v2 or v3 */
	union
	{	
 		struct layer_addr_l2tp_v2_t l2tp_addr_v2;
		struct layer_addr_l2tp_v3_t l2tp_addr_v3;
	}l2tpun;
};

#define MAX_MPLS_ADDR_LAYER 4

struct single_layer_mpls_addr{ /* refer to RFC3032 */
	unsigned int label; /* network order */
	unsigned char experimental;
	unsigned char bottom;
	unsigned char ttl;
};

/* 
    MPLS�п����Ƕ��Ƕ��, sapp�Ѷ��ϲ�����, Ŀǰ���֧��4��, ���������⵽������, 0��ʾ�����, 3��ʾ���ڲ� 
    ����һ���ڲ�TCP/UDP����˵, �ײ�MPLS��������ĵ�ַ���ܲ�һ��, �ֱ��Ϊcs2_addr, s2c_addr.
*/
struct layer_addr_mpls
{
	struct single_layer_mpls_addr c2s_addr_array[MAX_MPLS_ADDR_LAYER]; 
	struct single_layer_mpls_addr s2c_addr_array[MAX_MPLS_ADDR_LAYER]; 
    char c2s_layer_num; /* ʵ��mpls���� */
    char s2c_layer_num; /* ʵ��mpls���� */
	char c2s_has_ctrl_word;
	char s2c_has_ctrl_word;
    unsigned int c2s_mpls_ctrl_word; /* refer to RFC4623 */
    unsigned int s2c_mpls_ctrl_word; /* refer to RFC4623 */
};


struct layer_addr_pptp
{
	UINT16 C2S_call_id;	/* C2S�Դ����Э�鷽��Ϊ׼, TCP SYNΪC2S, UDPԴ�˿ڴ��ΪC2S, callid, network order */
	UINT16 S2C_call_id;	/* S2Ck�Դ����Э�鷽��Ϊ׼, TCP SYN/ACKΪS2C, UDPĿ�Ķ˿ڴ��ΪS2C, callid, network order */
};

struct layer_addr_gtp
{
	unsigned int teid_c2s; /* network order */
	unsigned int teid_s2c; /* network order */
}__attribute__ ((aligned (1)));

#define MAC_IN_MAC_HDR_LEN	(sizeof(struct mesa_ethernet_hdr) +  sizeof(struct mesa_ethernet_hdr))
struct layer_addr_mac_in_mac
{
	UCHAR outer_dst_mac[MAC_ADDR_LEN]; /* �����mac��ַ, network order */
	UCHAR outer_src_mac[MAC_ADDR_LEN]; /* �����mac��ַ, network order */
	UCHAR inner_dst_mac[MAC_ADDR_LEN]; /* �ڲ�mac��ַ, network order */
	UCHAR inner_src_mac[MAC_ADDR_LEN]; /* �ڲ�mac��ַ, network order */
};

struct single_layer_addr_vxlan
{
	UINT16 vlan_id; /* network order */
	UCHAR flag;
	UCHAR dir;
	UCHAR link_id;
	UCHAR link_type;
};


struct layer_addr_vxlan
{
	struct single_layer_addr_vxlan C2S_vxlan_addr;
	struct single_layer_addr_vxlan S2C_vxlan_addr;
};


struct layer_addr
{
	UCHAR addrtype; /*  definition in enum addr_type_t */
	UCHAR addrlen;	
	UCHAR pkttype;	   	/* packet special features, definition in MACRO PKT_TYPE_xxx */
	UCHAR pktipfragtype;	/* ip frag packetfeatures, definition in MACRO PKT_TYPE_xxx */
	
	UCHAR __pad[4]; /* pad for alignment */
	union
	{
		struct stream_tuple4_v4 *tuple4_v4;
		struct stream_tuple4_v6 *tuple4_v6;
		struct layer_addr_ipv4	*ipv4;
		struct layer_addr_ipv6	*ipv6;
		struct layer_addr_vlan	*vlan;
		struct layer_addr_mac	*mac;
		struct layer_addr_gre	*gre;
		struct layer_addr_tcp	*tcp;
		struct layer_addr_udp	*udp;
		struct layer_addr_pppoe_session *pppoe_ses;		
		struct layer_addr_l2tp	*l2tp;
		struct layer_addr_pptp	*pptp;
		struct layer_addr_mac_in_mac *mimac;
        struct layer_addr_gtp *gtp;
        struct layer_addr_mpls *mpls;
		struct layer_addr_vxlan *vxlan;
        void 					*paddr;
	};

};

/* CHN : �����˽ṹ���ں�papp����, ����ָ��ʱ, ����struct layer_addrǿת */
/* ENG : compat for papp, can be transform to struct layer_addr pointer */
struct ipaddr
{
	UCHAR addrtype; /*  definition in enum addr_type_t */
	UCHAR addrlen;
	UCHAR  pkttype;	  /* packet special features, definition in MACRO PKT_TYPE_xxx */
	UCHAR  pktipfragtype;	   		/* ip frag packetfeatures, definition in MACRO PKT_TYPE_xxx */
	UCHAR __pad[4]; /* pad for alignment */
	union
	{
		struct stream_tuple4_v4 *v4;
		struct stream_tuple4_v6 *v6;
		void *paddr;
	};

};

struct tcpdetail
{
	void  *pdata;		 
	UINT32 datalen;		
	UINT32 lostlen;		/* lost data len, not accumulated, current procedure */
	UINT32 serverpktnum; 	/* C2S, this value indicate TCP-ALL packet, include syn, ack, rst, if want get tcp data status, use stream_project.h : struct tcp_flow_stat */
	UINT32 clientpktnum;  	/* S2C, this value indicate TCP-ALL packet, include syn, ack, rst, if want get tcp data status, use stream_project.h : struct tcp_flow_stat */
	UINT32 serverbytes;   	/* C2S, this value indicate TCP-ALL packet, include syn, ack, rst, if want get tcp data status, use stream_project.h : struct tcp_flow_stat */
	UINT32 clientbytes;     /* S2C, this value indicate TCP-ALL packet, include syn, ack, rst, if want get tcp data status, use stream_project.h : struct tcp_flow_stat */
	UINT64 createtime; 
	UINT64 lastmtime;
};

struct udpdetail
{
 	void *pdata;		     
 	UINT32 datalen;			 
	UINT32 pad;			
	UINT32 serverpktnum; 	 /* C2S, you should better use stream_project.h : struct udp_flow_stat */
	UINT32 clientpktnum;	/* S2C, you should better use stream_project.h : struct udp_flow_stat */
	UINT32 serverbytes;	/* C2S, you should better use stream_project.h : struct udp_flow_stat */
	UINT32 clientbytes;	/* S2C, you should better use stream_project.h : struct udp_flow_stat */
	UINT64 createtime; 
	UINT64 lastmtime;
};

struct streaminfo
{
	struct layer_addr addr;      
	struct streaminfo *pfather; /* this stream's carry layer stream; �ϲ����ṹ�� */
	UCHAR type;			/* stream type, definition in enum stream_type_t */
	UCHAR threadnum;	     
	UCHAR  dir;           	/*  valid in all stream life, current stream direction state, 0x01:c-->s; 0x02:s-->c; 0x03 c<-->s; */
	UCHAR  curdir;         /* valid in current procedure, current packet direction, 0x01:c-->s;  0x02:s-->c */
	UCHAR  opstate;		/* stream state, definition in MACRO OP_STATE_xxx */
	UCHAR  pktstate;	/* for TCPALL plug, stream state, definition in MACRO OP_STATE_xxx */
	UCHAR  routedir;	     /* network topology route direction, is valid in serial mode */
	UCHAR  stream_state;	/* stream management state, for example, in TCP stream, maybe SYN, DATA, NOUSE */
	UINT32 hash_index;		/* stream hash index, maybe reduplicate with other stream when hash algorithm collide */      
	UINT32 stream_index;    /* stream global index per thread  */	
	union
	{
		struct tcpdetail *ptcpdetail;
		struct udpdetail *pudpdetail;
		void   *pdetail;
	};
 };


typedef struct {
	unsigned int type;
	unsigned int length;
	union{
		char	char_value;
		short	short_value;
		int	int_value;
		long	long_value;
		char	array_value[8];
		void	*ptr_value; /* more than 8bytes data, or complex struct. */
	};
}SAPP_TLV_T;

#ifdef __cplusplus
extern "C" {
#endif

/* CHN : �ڴ������غ���, ����ƽ̨�Ĳ������ʹ�ô��ຯ��������ͷ��ڴ� */
/* ENG : memory management function, plugs must call these functions instead of malloc, free in <stdlib.h> */
void *dictator_malloc(int thread_seq,size_t size);
void dictator_free(int thread_seq,void *pbuf);
void *dictator_realloc(int thread_seq, void* pbuf, size_t size);

/* CHN : ��ȡ��ǰϵͳ���еĲ��������߳����� */
/* ENG : get current total thread of platfomr */
int get_thread_count(void);

time_t get_timestamp_s(void);
long long get_timestamp_ms(void);

//if return -1, it means caller not in worker thread context
int get_current_worker_thread_id();

/* CHN : ����enum addr_type_tַ����ת���ɿɴ�ӡ���ַ�����ʽ */
/* ENG : transform binary addr_type_t to string mode */
const char *addr_type_to_string(enum addr_type_t type);

/*
	ENG : transform tuple4 to string mode, must used in packet process thread context;
	CHN : ��layer_addr��ַת�����ַ�����ʽ, �������ڰ������߳�.
*/
const char *printaddr (const struct layer_addr *paddrinfo, int threadindex);

/*
	ENG : a reentrant version of printaddr, thread safe;
	CHN : printaddr�Ŀ�����汾, ���̰߳�ȫ��.
*/
const char *printaddr_r(const struct layer_addr *paddrinfo, char *out_buf, int out_buf_len);


/*
	ENG : transform layer address to string mode, must used in packet process thread context, 
	      the return value is read-only, user can't free it;
	CHN : ��layer_addr��ַת�����ַ�����ʽ, �������ڰ������߳�, ���ص�ָ��Ϊֻ��, ʹ���߲���free.
*/
const char *layer_addr_ntop(const struct streaminfo *pstream);

/*
	ENG : a reentrant version of layer_addr_ntop, thread safe, return a pointer to the destination string 'out_buf';
	CHN : layer_addr_ntop_r�Ŀ�����汾, ���̰߳�ȫ��, ���ص�ָ��ִ��ʹ�����ṩ��out_buf, ���ڴ�����֯.
*/
char *layer_addr_ntop_r(const struct streaminfo *pstream, char *out_buf, int out_buf_len);

/*
	ENG : transform layer type to abbr string mode, is reentrant, the return value is read-only, user can't free it;.
	CHN : ��layer_addr��ַ����ת������д�ַ�����ʽ, �������̰߳�ȫ, ���ص�ָ��Ϊֻ��, ʹ���߲���free..
*/
const char *layer_addr_prefix_ntop(const struct streaminfo *pstream);


/* 
	ENG : duplicate a same layer_addr struct, memory obtained with malloc(3);
	CHN : ����һ����ȫ��ͬ��layer_addr�ṹ��, �ڴ�ͨ��malloc(3)��ȡ.
*/
struct layer_addr * layer_addr_dup(const struct layer_addr *paddrinfo);

/* 
	ENG: used to free all memory of paddrinfo;
	CHN: �����ͷ�paddrinfo�ڴ�.
*/
void layer_addr_free(struct layer_addr *paddrinfo);


/* 
	ENG : duplicate a same streaminfo list, memory obtained with malloc(3);
	CHN : ����һ����ȫ��ͬ��streaminfo�ṹ�弰�����ṹ, �ڴ�ͨ��malloc(3)��ȡ.
*/
struct streaminfo *streaminfo_dup(const struct streaminfo *stream);

/* 
	ENG: used to free all memory of streaminfo;
	CHN: �����ͷŽṹ�弰�����ṹ���ڴ�.
*/
void streaminfo_free(struct streaminfo *stream);


/* 
	addr list transform function, like inet_ntop(), inet_pton(),
	use '<' as delimitation between layer,
	if direction is double, for ip, port, use '-' as delimitation between source and destination,
	
	for example:
		"T4T:6005-1673<IP4:61.147.112.53-11.215.62.23<MAC:0000ea60040d-0200000003b6"

	args:
		pstream	: stream info;
		dst		: buf to store result;
		size		: dst buf's size;
		addr_list_str: addr list string;
		thread_index : thread index;

	����ֵ:
		>0:ת����Ľ��ʵ��ռ���ڴ泤��, stream_addr_list_ntop()�������ַ���ĩβ��'\0';
		-1:dst����ռ䳤�Ȳ���;
		-2:��ʽ����;
		-3:��������;
*/
int stream_addr_list_ntop(const struct streaminfo *pstream, char *dst, int size);
int stream_addr_list_pton(const char *addr_list_str, void *dst, int size, int thread_index);

/*
	TCP,UDP��ģʽ��, ��ȡ��ǰIP����ԭʼ��Ƭ��.
*/
const raw_ipfrag_list_t *get_raw_frag_list(const struct streaminfo *stream);

/*
	IP���ģʽ��, ��ȡ��ǰIP����ԭʼ��Ƭ��.
*/
const raw_ipfrag_list_t *ip_plug_get_raw_ipfrag_list(int thread_num, enum addr_type_t addr_type);


/*
	��Ϊ������Ƕ��Э���ԭ��, ����һ������Ԫ��, ʵ���п��ܲ�ѯ�����streaminfo,
	��������������:
		(1) tuple4->gtp->ip->udp->ethernet;
		(2) tuple4->l2tp->ip->udp->ethernet;
	��������ڲ�ʹ��˽�е�ַ, ��һЩ���˴��ɵ������, ��1����2���ڲ�tuple4������һ����, ��sapp�ᴴ��������ͬ��streaminfo.

	�������:
		thread_index: �߳�id;
		tuple4v4 or tuple4v6: ��Ԫ���ַ, Դ��Ŀ�ĵ�ַ˳����Ҫ��, C2S, S2c�������;
		streamtype: ֻ֧����������, STREAM_TYPE_TCP or STREAM_TYPE_UDP;
		array_max_num: ����streaminfo_array�����Ԫ�ظ���.

	�������: 
		streaminfo_array: ��ѯ���ķ���������Ԫ���ַ��streaminfo�ṹ��ָ��.

	����ֵ:
	    -1: error;
		 0: û�ж�Ӧ��streaminfo�ṹ;
		>0: ʵ���ҵ�streaminfo�ṹ������;
*/
int find_streaminfo_by_addrv4(int thread_index, const struct stream_tuple4_v4 *tuplev4, enum stream_type_t streamtype, struct streaminfo *streaminfo_array[], int array_max_num);
int find_streaminfo_by_addrv6(int thread_index, const struct stream_tuple4_v6 *tuplev6, enum stream_type_t streamtype, struct streaminfo *streaminfo_array[], int array_max_num);


#ifdef __cplusplus
}
#endif

#endif

