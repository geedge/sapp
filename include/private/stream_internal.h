#ifndef _APP_STREAM_INTERNAL_H_
#define _APP_STREAM_INTERNAL_H_ 

#include "mesa_net.h"
#include "private/mesa_net.h"
#include "mesa_pkt_dump.h"
#include "sapp_limits.h"
#include "stream.h"

//#define STREAM_BASE_MD5_CHECK		"dd09b3b11993cc835200db477dad7d4b"
//#define STREAM_CONTROL_MD5_CHECK 	"75aab0821e489b84355fa22ad02a2e78"
//#define STREAM_ENTRY_MD5_CHECK		"7dab86d65114ebe5438e85e0d008645d"
//#define STREAM_INJECT_MD5_CHECK		"1e25b7a8cd812db2ad261264b6783d64"
//#define STREAM_PROJECT_MD5_CHECK		"fc2b981f7e2c99e73d8857e206cb4977"
//#define STREAM_PROXY_MD5_CHECK		"25cec664c9b44a8cac29f6e3e117eaa6"
//#define STREAM_RAWPKT_MD5_CHECK		"48fdc3294bced1c74a853e197db8fd67"
//#define STREAM_TUNNEL_MD5_CHECK		"d20aa6b4f5683b7b0040676547997be0"

#define IP_PORT_UNION_VERSION			(1) /* �Ƿ�IP-PORT�ϲ� */
#define COMPAT_PAPP_FOR_BENCHMARK	(0) /* 2015-01-07 lijia add, ͬpapp�ԱȽ��ʱ, ��ʱ�ر�Ƕ�ס���������Э��, ����һ�� */
#define USE_RBTREE_INSTEAD_LIST		(0) /* ��HASH��ͻʱ, ʹ�ú������������, ������������±��� */
//#define USE_LINUX_KERNEL_HASH_ALGO	(1) /* ʹ��LINUX�ں�HASH�㷨 */

#define SAPP_INSECTICIDE				(0) /* ɱ��(DEBUG)��ʱ����, ������Ī�������BUGʱ��ʱ����, ���緢������, �����糬�� */

//#define CYCLE_PKT_DUMP				(1 && DEBUG) /* 2015-04-16 lijia add, ������������޹�coredump, ���Ҳ���ԭ�� */
#define CYCLE_PKT_DUMP				(1) /* 2015-04-16 lijia add, ������������޹�coredump, ���Ҳ���ԭ�� */

#define PCAP_CAP_FROM_IP				(0) /* Ϊ��ģ��pag�����߻���, ��pcapҲģ���IPv4ͷ����ʼ��ȡ */

//#define NON_PKT_THREAD_SEND_QUEUE		(64) /* �����������߳�����Ͷ������� */

#define IKNOW_ENABLE					(0)

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))
#endif

#define sapp_get_struct_header(ptr, type, member)  container_of(ptr, type, member)

#define RAW_PKT_MAGIC_NUM		(0xF1E2D3C4) /* 1:���ڼ��ݾ���Ŀ, ��call_old��������ݽṹʱ,ʶ��ԭʼ������Դ; 2:��ȫ�Լ�� */

#define SAPP_DESTROY_DONE_FLAG  (0x7FFFFFFF)


#ifdef __cplusplus
extern "C" {
#endif

struct detain_pkt;

struct rawpkt_metadata;


/* ԭʼ���ṹ */
typedef struct {
	/* ---8 bytes-- */
	unsigned int magic_num; 
	int offset_to_raw_pkt_hdr;			/* ����ص���Ӧ��������raw_pkt_data��ƫ���� */
	/* ===8 bytes=== */

	/* ---8 bytes-- */
	enum addr_type_t low_layer_type;	/* ԭʼ����ײ�Э�������, ������MAC(pcap����), Ҳ������IPv4(pag����) */
	int __lib_raw_pkt_len;		/* �ײ㲶�����ṩ�İ���ʵԭʼ���� */
	/* ===8 bytes=== */

	/* ---8 bytes-- */
	int raw_pkt_len;			/* ���ϲ�Ӧ�ÿ���ԭʼ���ܳ���, �п��ܲ�����ʵ��, ����������Ethernet�� */
	unsigned int hd_hash; /* ����Ӳ���������Ԫ��HASH, ����ƽ̨CPU�������� */
	/* ===8 bytes=== */

	const void *__lib_raw_pkt_data; /* �ײ㲶�����ṩ����ʵԭʼ��ָ�� */
	const void *raw_pkt_data;	/* ���ϲ�Ӧ�ÿ���ԭʼ��ͷָ��, �п���������Ethernet��, ����low_layer_type�ж�Э������ */

	struct timeval raw_pkt_ts;	/* ԭʼ������ʱ���, ���ȫΪ0��֧�ִ˹���(��pagģʽ) */
	//2*8 Bytes
	const void *io_lib_pkt_reference; /* ���õײ�I/O���ԭʼ�������ṹ, ����:����marsio��˵, ���ײ��mbuf�ṹ */

	/* ---8 bytes-- */
	int payload_len; /* ���س��� */
	int device_index;/* �ж������ʱ, Ҫ��֤���ĸ������ʹ��ĸ����� */
	/* ===8 bytes=== */

	/* ---8 bytes-- */
	unsigned char route_dir:1;
	unsigned char is_overlay_pkt:1; /* ��ʾ����ʵ��·�е����ݰ�, Ҫ��������ע, ��������������һ������; ����Ҫ���� */
	unsigned char is_ctrl_pkt:1;
	unsigned char diagnose_error_to_dump:1; /* ��ĳ�ִ������ݰ�, ����pkt_dump�洢��udp socket���͸�tcpdump_mesa */
	unsigned char drop_current_pkt_flag:1; /* �������MSO_DROP_CURRENT_PKT���ö�����ǰ��, ÿ�δ�����Ҫ��� */
	unsigned char mac_flipping_enable:1;
	unsigned char padding_flags:2;
			//1 Bytes
	unsigned char padding[2];
	unsigned char overlay_layer_bytes; /* ������װ�㳤��, ����vxlanģʽ����50�ֽ� */
			//3 Bytes
		//4 Bytes
	unsigned short vlan_flipping_couple[2]; /*2020-09-28 lijia add, in host order, vlan flipping for adev, index0��ʾ�յ���ǰ����vlan_id, index1��ʾԭ��ת����vlan_id */
		//4Bytes
	/* ===8 bytes=== */


	struct detain_pkt *d_pkt;
	struct rawpkt_metadata *meta_route_dir[2];// ���������metadata, �����ڵ���low_level_sendʱ, ���marsio 4.6����Ҫ����Ϣ.
	struct segment_id_list *append_list;
	struct segment_id_list *prepend_list;
	unsigned long long stream_trace_id;
}raw_pkt_t; 

enum retained_rawpkt_mark
{
	RETAIN_RAWPKT = 0,
	FORWARD_RAWPKT = 1,
	FREE_RAWPKT = 2,
};

struct detain_pkt
{
	const raw_pkt_t *original;
	raw_pkt_t replica;	
	enum retained_rawpkt_mark mark;
	int tid;
};


struct buf_unorder
{
	struct buf_unorder *next;
	struct buf_unorder *prev;
	//void *data; 
	//UINT32 len;	
	void *this_ip_hdr; /* ������Դ����ʵԭʼ��, Ҳ������Դ�������IP��Ƭ��,��'ip_reassemble_pkt'���� */
	struct mesa_tcp_hdr *this_tcp_hdr;
	void *tcpdata; /* TCP�����ݲ���ָ��, ����TCPͷ */
	UINT16 tcpdatalen; /* TCP�����ݲ��ֳ��� */
	UINT16 urg_ptr;
	char fin;
	char urg;
	char rst;   
	unsigned char ip_reassemble_pkt;
	UINT32 seq;
	UINT32 ack;
	raw_ipfrag_list_t *ipfrag_list; /* �����ǰ����IP��Ƭ����İ�, ��Ҫ�洢����IP��Ƭ������ */
	raw_pkt_t raw_pkt; /* ������洢ԭʼ�� */
};

/*�����ṹ�嶨�壺*/
struct half_tcpstream
{
  UCHAR *data;
  UINT32 offset;           /*data�е�һ���ֽ���TCP�������е�ƫ����*/
  UINT32 count;           /*�����ӽ���������Ϊֹ������������ܳ����ֽ���*/
  UINT32 count_new;        /*�����µ��������ֽ���*/
  UINT32 count_ideal;      /*�����ӽ���������Ϊֹ��������Ӧ�õ���������ܳ���*/
  UINT32 pktcout;          /*�����ۼƵ���İ�����, �����ش���, ACK, ������SYN */
  UINT32 totallost;        /*�����ۼƶ�������*/
  UINT32 seq;              /*���������ڴ���seq���*/
  UINT32 first_data_seq;   /*����������ʼ�ĵ�seq���*/
  
  //UINT32 ack_seq;          /*�����������ʹ�õ�Ӧ���, 2017-08-02 lijia modify , �ƶ���struct tcpdetail_private */
  
  UINT16 window;           /*�������ݻ������ڴ�С*/
  UCHAR __pad__;
  UCHAR finstate;		    /*fin״̬*/
  UINT16 unorder_cnt;/* 2014-11-27 lijia modify, ĳЩ���������޴�, UCHAR�Ͳ���, ��չΪUINT16 */
  UINT16 maxunorder; /* 2014-11-27 lijia modify, ĳЩ���������޴�, UCHAR�Ͳ���, ��չΪUINT16 */
  struct buf_unorder *unorderlist;	/*�����������*/
  struct buf_unorder *unorderlisttail;	/*�����������β��ָ��*/
};

/* ����ÿ�������������һ����, ����polling entry����ʹ�� */
typedef struct {
	const raw_pkt_t *raw_pkt_stream_dir[2];
	struct rawpkt_metadata* meta_stream_dir[2];// ÿ������metadata��[0:c2s, 1:s2c]����洢��polling_inject_context��, update_raw_pkt��������ʱ����������䵽���ص�rawpkt��
}polling_inject_context_t;

struct streaminfo_private
{
	/* ����ṹ�����ڽṹ����ǰ, ָ���ַ���Ի���ǿת */
	struct streaminfo stream_public;
	struct streaminfo_private *pfather_pr; /* ��ʵ�������ϲ���ָ��, ������vxlan�ȷ�װ��, stream_public.pfather�Ǹ�ҵ��������,������vxlan��� */
	/* ���±���Ϊƽ̨�ڲ�˽��, ���ⲻ�ɼ� */
	void *cur_plugin_cb_func;
	void   *pproject;		//ÿ�����̿����Զ���ʹ�ã�

	/* ---8 bytes-- */
	UCHAR  layer_dir:2;   /* ������Ч, ��ǰ��ĵ�ַ�Ƿ��Ĭ�Ϲ���"��˿��ǿͻ���"��ͬ */	
	UCHAR  stream_dir:1; /* ��������������Ч, ���Ĵ洢�ĵ�ַ�Ƿ��Ĭ�Ϲ���"��˿��ǿͻ���"��ͬ  */		
	UCHAR  stream_c2s_route_dir:1; /* c2s����İ�, ��Ӧ����·route dir����, ���ڻ�ȡinbound, outbound���� */
	UCHAR  addr_use_as_hash:1; /* �����addr�Ƿ���ΪHASH����ͱȽϵĲ���, ��:MAC��ַ��������� */
	UCHAR  set_special_timeout:1;
	UCHAR  need_update_opposite_addr:1;/*�����addr�Ƿ��ڶԲ�����ʱ���£��磺MPLS��ǩ�ǶԳ�ʱ��Ҫ��S2C���һ������¼�����ǩ,��ֵĬ��Ϊ0��������Ҫ����*/
	UCHAR  stream_killed_flag:1; /* 2014-08-22 lijia add, ����ģʽ��, �Ѿ������Kill, ֮�������ֱ��Drop��Kill, �����ٸ��ϲ��� */
	UCHAR  dirreverse;	     /* ��������ʱ�Ƿ������ip��ַ��ת, ����"��˿��ǿͻ���"�����෴ */
	UINT16 timeout;/* ÿ�����ӵĶ��г�ʱʱ��, ��ֵ��������;, 1:���ھ�����̭��ʱ���ް��������, �Խ�Լ�ڴ�; 2:���ڱ�����ʱ���ް�����, ����IM�೤ʱ���ް������Ӳ�δ����, �����ýϴ��timeout */
	unsigned short offset_to_raw_pkt_hdr; /* ����ͷ�����ԭʼ������ʼ��ַ��ƫ���� */
	unsigned short offset_to_ip_hdr; /* 2015-12-07 lijia add, UDP/TCP ��ͷ����ڳ��ص�IP��ͷƫ���� */
	/* ===8 bytes=== */
	const raw_pkt_t *raw_pkt; /* 2014-12-30 lijia add, ��Щ�ص�������֧��ԭʼ��, ����������Ҫ, �洢��private�ṹ�� */

	/* ---8 bytes-- */
	unsigned int hash_slave; /* 2015-12-14 lijia add, ʹ��linux_jhash����ʱ, ����ͬʱ�õ��������ϵ�HASHֵ, ��HASH����ȷ����HASH����SLOTλ��, slave_HASH���ڿ��ٱȽϵ�ַ�Ƿ���� */
	unsigned char hash_not_head_times;/* 2015-12-15 lijia add, ��ǰindex����HASH SLOT�ĵ�һλ�Ĵ��� */
	unsigned char cur_layer_raw_hdr_len; /* 2017-10-31 lijia add, ��ǰ���ԭʼ����ַ����, ��pppͷ��ѹ��, ԭ���汾�޷��������״̬, ����ʱҲ�޷���֪��ַ������ */
	unsigned char __pad:1;
	unsigned char packet_process_context:1;
	unsigned char is_ctrl_pkt:1;
	unsigned char plugin_process_context:1; /* 2019-09-07 lijia add, for polling entry send packet */
	unsigned char stream_close_reason:4; /* 2019-02-14 lijia add, ����TCPʹ��tcpdetail_private��link_state����, ����UDP֮ǰû��, ���pad�����˱��� */
	unsigned char gdev_block_timer;
	/* ===8 bytes=== */

	/* ---8 bytes-- */
	unsigned short stream_low_layer_tunnel_type; /* 2016-07-25 lijia add, ��¼�����ײ���������, 0Ϊ������, �������:enum stream_carry_tunnel_t */
	unsigned short stream_carry_up_layer_tunnel_type; /* ��ǰ���ϲ����������, ���統ǰ��ΪUDP, ���صĿ�����teredo������L2TP���� */
	/* 2016-07-08 lijia add, for janus hijack, ��Ӧ�ô洢��half_stream, �����յ�SYNʱ, ��û�д���half_streamʵ��, �����ݴ���streaminfo_private */
	unsigned short syn_opt_num;
	unsigned short synack_opt_num;
	/* ===8 bytes=== */

	unsigned long long stream_trace_id;
	
	struct tcp_option *syn_opt_array;
	struct tcp_option *synack_opt_array;

	polling_inject_context_t *polling_inject_context;

	struct segment_id_list *sid_append_list;
	struct segment_id_list *sid_prepend_list;

	/* ȫ����id, stream_index��ʷ���Ѿ���ʾ������Ψһid, �˴�Ҫ��֤��Ⱥ���л������ظ�, �����½�����;  
		��λ --- ��λ
		1 |  12bit device_id | 8bit thread_id | 28bit timestamp in sec | 15bit sequence per thread
	*/
	unsigned long long global_stream_id; 
	unsigned long long stream_create_timestamp_ms; 
	unsigned long long stream_lastupdate_timestamp_ms; 
	/* ---8 bytes-- */
	unsigned char layer_index:4; /* ��ʾ��ǰ��ļ���, ����ײ㿪ʼ,һ����ethernet��ʼ, ��0��ʼ����, 4bit���֧��15��Ƕ��, Ҳ�ܷ�ֹ����Ƕ�׹���(Ŀǰ��û��������) */
	unsigned char create_dir_by_well_known_port:1;  /* UDP��TCP��data������, ����well_known_port����, �����ǰ���˿��ǿͻ���ԭ�򴴽��� */
	char __pad2:3;
	char has_duplicate_pkt; /* ��ǰ�������й��ظ����ݰ�, ����������Ӧ��ÿ������� */
	char under_ddos_bypass;
	char __pad3[3];
	/* ===8 bytes=== */
	
	unsigned char ip_ttl_c2s;
	unsigned char ip_ttl_s2c;
	void   *stream_bridge;	/* 20210425 lijia add, ����project����, ֧��ͬ�����첽����ģʽ, ԭ��project�����첽ģʽ */
};

struct tcpdetail_private
{
	/* ����ṹ�����ڽṹ����ǰ, ָ���ַ���Ի���ǿת */
	struct tcpdetail tcpdetail_public;
	
	/* ---8 bytes-- */
	UCHAR  multisynflag:2;	  // multi syn
	UCHAR  ignore_rst_fin:1;  //������rst, fin����, ֻ����ʱ��lru����
	UCHAR  drop_stream_flag:1; //2019-11-20 lijia add, ����ͬDROPPKT, ֻ����������������stream
	UCHAR  auto_remedy_flag:1;	  //�Ƿ�����FD����
	UCHAR  needackflag:1;	  //��Ҫ�ϴ�ack����
	UCHAR  takeoverflag:1;
	UCHAR  has_lost_pkt_flag:1;		//2020-08-23 lijia add, ����������������־λ
	UCHAR  tcpstateflag;	   // ���ڼ�¼tcp�ĻỰSYN���״̬
	UCHAR  link_state;		   // ���ӵ�״̬
	UCHAR  creat_mod;
	UINT16 tcpoverlen;		// modify by lqy 20150225, ��¼��ǰ������һ�������ص�tcp���ȣ�	
	UCHAR  offload_stream_flag; //2022-04-13 liuxueli add, ������������stream
	UCHAR  pad;			
	/* ===8 bytes=== */
	time_t offload_stream_timestamp_s;
	
	struct half_tcpstream *pclient;  //��client��TCP������Ϣ
	struct half_tcpstream *pserver;  //�� server��TCP������Ϣ
	UINT32 iserverseq;	  //���ӽ���ʱ��ʱ�洢seq, ��ֵ��C2S->SYN+1
	UINT32 iclientseq;	  //���ӽ���ʱ��ʱ�洢seq, ��ֵ��S2C->SYN+1
	/* NOTE:
		Ϊ��first_ack_seq������half_tcpstream��?
		��half_tcpstream�����յ���һ�����и��صİ��ŷ����, 
		�����tcp_deal_ack()����������, �����S2C����, ��ô��һ��S2C���ݰ�����ʱ, �Ѿ�����first_ack_seq��.
		�����Է�ֹDDOS����.
	*/
	UINT32 C2S_first_ack_seq; /* 2017-08-02 lijia modify, C2S���һ��ACK��, ��half_tcpstream->ack_seqһ����Լ�����������Բ���������� */
	UINT32 C2S_ack_seq;  /* 2017-08-02 lijia add, C2S�൱ǰ��ACK�� */ 
	UINT32 S2C_first_ack_seq; /* 2017-08-02 lijia modify, C2S���һ��ACK��, ��half_tcpstream->ack_seqһ����Լ�����������Բ���������� */
	UINT32 S2C_ack_seq;  /* 2017-08-02 lijia add, S2C�൱ǰ��ACK�� */ 
	void   *apme;		  //Ӧ�ò�������
	void   *pAllpktpme;   //��״̬��tcp����������
	struct tcp_flow_stat *flow_stat; /* 2016-07-14 lijia add, ���ڼ�¼TCP��data���ļ���, ʵ���ڴ������ͷ���projectģ�����, ����ΪNULL,  */
	struct tcp_flow_stat *deduce_flow_stat; /* 2018-10-30 lijia add, ���ڼ�¼������ƶϳ������ϴ��������, ���������ĳ���; �Լ������������, �Զ�Ӧ���յ�������  */
	unsigned short rtt_csc;
	unsigned short rtt_scs;
	long long last_c2s_pkt_rcv_time;
	long long last_s2c_pkt_rcv_time;
};

struct udpdetail_private
{
	/* ����ṹ�����ڽṹ����ǰ, ָ���ַ���Ի���ǿת */
	struct udpdetail udpdetail_public;
	void   *apme;		  //Ӧ�ò�������
	struct udp_flow_stat *flow_stat; /* 2015-12-28 lijia add, udpdetail�е���ϸ����(64bit), ʵ���ڴ������ͷ���projectģ�����, ����ΪNULL */
	UCHAR  drop_stream_flag; //2020-06-02 lijia add, ����ͬDROPPKT, ֻ����������������stream	
	UCHAR  offload_stream_flag; //2022-04-13 liuxueli add, ������������stream
	UCHAR pad[6];
	time_t offload_stream_timestamp_s;
};	

/* 2015-02-26 lijia add, for stream-addr-list ntop, pton */
typedef struct{
	struct streaminfo stream;
	char addr_value[MAX_ADDR_BIN_VALUE_LEN]; /* Ϊ��paddr������malloc, �������, ��stream����׷��һ�黺�� */
}addr_continuous_bin_t;

typedef struct{
	enum addr_type_t addr_type_bin;
	UCHAR stream_type;/* ����ʶ��ADDR_TYPE_IPV4��TCP����UDP */
	const char *addr_type_str;
	const char *addr_type_prefix;
	const char *addr_type_prefix_with_delim; /* ���ָ�����ǰ׺, ���ڱȽ��ַ���, ��ֹIPv4��IPv4_TCP�ַ����Ƚ�ʱ����, �����IPv4:, IPv4_TCP:�Ͳ����ڻ������� */
	int (*addr_n2p_fun)(const struct layer_addr *paddr, char *buf, int buf_len);
	int (*addr_p2n_fun)(char *addr_str, addr_continuous_bin_t *addr_bin_val);
	const char *addr_type_string_abbreviation;
}addr_convert_t;

struct pptp_stream_key{
	UINT32 sip;	/* TCP-SYN����ԴIP, ����ǰ�data������, ����pptp->message_type�ж�, REQ���������ԴIP��Ϊ��sip */
	UINT32 dip;   /* sip,dip are network order */
	UINT16 sip_side_call_id; /* �������ݰ�����sip������GRE����callid, ʵ�������ʾpeer call id, network order */
	UINT16 dip_side_call_id; /* �������ݰ�����dip������GRE����callid, ʵ�������ʾpeer call id, network order */
	//struct streaminfo_private *stream_pr;  /* TODO 1, ���ڱ����ַ����, Ŀǰ��������ײ��IP��call_id */
};

/* PPTPЭ�����������ṹ, sapp�ڲ�ʹ�� */
struct pptp_info_pri{
	struct MESA_tunnel_info tunnel_context;
	struct pptp_stream_key pptp_key;
	stSessionInfo ssinfo; /* ����ҵ�����������Ϣ */
	void *biz_pme; /* ҵ����Զ������� */
	struct streaminfo *my_stream; /* pptp�ײ�UDP�� */
	unsigned char threadnum; 
	char insert_hash_flag; /* ���������ѽ�key����HASH�� */
	char content_notify_biz_flag; /* �Ƿ��Ѿ����ù�ҵ����, ��֮content_type */	
};

/* ˽��pptp��ַ, pptp_addr�ṩ��ҵ����, ����gre_layer_len����FDʱ����ʶ�𱾲�ͷ������ */
struct layer_addr_pptp_pri{
	struct layer_addr_pptp pptp_addr;
	int gre_layer_len;
};

struct l2tp_stream_key{
	UINT32 sip;	/* L2TP�����������𷽵�IP, ����������SCCRQ, ICRQ, SCCCN�Ȱ���ԴIP, network order */
	UINT32 dip;   /* L2TP�����������˵�IP, network order */
	UINT16 sport; /* network order */
	UINT16 dport; /* network order */
	UINT16 sip_side_tunnel_id; /* sip�ⷢ������tunnelid, network order */
	UINT16 sip_side_session_id; /* sip�ⷢ������tunnelid, network order */
	UINT16 dip_side_tunnel_id; /* dip�ⷢ������tunnelid, network order */
	UINT16 dip_side_session_id; /* dip�ⷢ������tunnelid, network order */
	//struct streaminfo_private *stream_pr;  /* TODO 1, ���ڱ����ַ����, Ŀǰ��������ײ��IP��call_id */
};

struct l2tp_info_pri{
	struct MESA_tunnel_info tunnel_context;
	struct l2tp_stream_key l2tp_key;
	stSessionInfo ssinfo; /* ����ҵ��������� */
	void *biz_pme;
	const struct streaminfo *my_stream; /* l2tp�ײ�UDP�� */
	unsigned char thread_seq;
	char content_notify_biz_flag; /* �Ƿ��Ѿ����ù�ҵ����, ��֮content_type */	
};

#define STATSD_SEND_MSS	(1472)
/* ȫ��Ψһ��ȫ�ֱ���, ͨ���ǿ�����������, �򲻳��仯��ȫ�ֱ���, ����������, ������ֻ�� */
struct sapp_global_single_t{
	int signal_take_over_sw; /* �Ƿ�ӹܳ���ϵͳ�ź�, ��SIGSEGV, SIGABRT�ȵ� */
	int ipentry_priority_over_ipfrag; /* IP_entry���ȼ�����IP_frag_entry, Ĭ��Ϊ0, ��ӦWY�����ض����� */
	//int kill_tcp_with_gdev; /* FDδ��Чʱ, ����gdev�������� */
	int cfg_send_tcp_offload_sw; /* ��������MTUʱ, ������Ƭ�ɶ��С��MTU�İ����� */
	//int cfg_kill_tcp_rst_num; /* kill_tcp����rst������ */
	//int cfg_kill_tcp_rst_signature; /* kill_tcp���͵�rst�Ƿ���Ҫָ����Ϣ, ����ʶ�� */
    //int tuple4_reuse_time_interval; /* ��Ԫ�����õ���С���ʱ�� */
	//void *fs2_handle;
	const char *fs2_server_ip;
	unsigned short fs2_server_port_host;
	short __pad1;

	//int send_fake_pkt_mode; /* 2018-10-26 lijia add, for PanGu, ����ȱ��FD·��, ����ô���GDEV����rst��, DNS-fake����,mode 0�� Э��ջ���㷢���� 1��Э��ջ���㷢����3��gdevע�뷢������ģʽ��send_fake_pkt_gdev_sport��Ч */
	//int send_fake_pkt_gdev_sport;  /* 2018-10-26 lijia add, for PanGu, ����ѡ��vxlanԴ�˿� */
	int send_fake_pkt_sip;	
};

#define TIMESTAMP_SINGLE_PKT_REGION 		(4) /* ������ʱͳ������ */
#define TIMESTAMP_SINGLE_PKT_REGION_MAX     (5) /* ��������ͳ�������ֵ */
typedef struct{
	unsigned int runtime_pkt_max_delay; /* �����������ʱ */
	unsigned long long pkt_total_num[TIMESTAMP_SINGLE_PKT_REGION_MAX]; /* ��¼��������ʱ���ܰ���, ������ͳ�� */
	unsigned long long pkt_total_time; /* ���һ��ʱ�������ʱ, ���ڼ���ƽ������������ʱ */
}timestamp_record_region_t;


/* ���߳�ȫ�ֱ���, �������ݰ�ͳ����Ϣ, ͨ��ֵ��ʵʱ�仯 */
struct sapp_global_mthread_t{
	int ipv6_pkt_type_flag; /* ipv6 packet type, normal, or rebuild */
	int pptp_hash_max_search_times;
	int l2tp_hash_max_search_times;
	char __pad1[4];
	double pptp_hash_avg_search_times;
	double l2tp_hash_avg_search_times;
	int tcp_stream_special_timeout_num; /* ���õ�����ʱʱ�����, Ĭ�ϲ�����������������10% */
	int udp_stream_special_timeout_num;/* ���õ�����ʱʱ�����, Ĭ�ϲ�����������������10% */
	timestamp_record_region_t runtime_record;
	timestamp_record_region_t runtime_record_driver; /* �����������õ���, ��ƽ̨�õ�������ʱ */
}__attribute__ ((aligned (64)));

typedef struct{
#ifdef DEBUG
	unsigned int magic; /* malloc�����0x4D4D4D4D,  ��MMMM ��16����; free�����0xFEFEFEFE */
#endif	
	unsigned int user_buf_size;
}sapp_private_mem_t;


/*
	vxlan ppp��hdlc�ֶλ�������, ����ethernet, �漰�����򷢰�, Ҫ��mac��ַ�ߵ�����.
	���Բ��ٴ���һ���µ�streaminfo�ṹ, �˷��ڴ�Ҳ�ķ�CPU, ���岻��,
	��hdlc, ppp���ֶκ�vxlan�ϲ�, ����ip���tcp/udp�Ĺ�ϵһ��.
*/
struct layer_addr_vxlan_private{
	struct layer_addr_vxlan addr_public;
	unsigned char actual_total_len; /* ���������紫���е�vxlanͷ����ַ����, ��������׷�ӵ�hdlc, ppp�ֶ�  */
	union{
		struct hdlc_net_hdr inner_hdlc;
		struct layer_ppp_hdr inner_ppp;
	};
};



extern struct sapp_global_single_t sapp_global_single;
extern struct sapp_global_mthread_t sapp_global_mthread[MAX_THREAD_NUM];
extern int g_overlay_layer_set[__ADDR_TYPE_MAX][SAPP_SUPPORT_LAYER_NUM_MAX]; 
int MESA_kill_tcp_remedy(struct streaminfo *stream, const void *ext_raw_pkt);

long long sapp_get_cpu_cycle(void);

int get_stream_carry_tunnel_type(const struct streaminfo *this_stream, const struct streaminfo *upper_stream, unsigned short *tunnel_type);

void cycle_pkt_dump(int thread_seq, const raw_pkt_t *p_raw_pkt);
void cycle_diagnose_pkt_dump(int thread_seq, const raw_pkt_t *p_raw_pkt);
void cycle_pkt_dump_by_classify(int thread_seq, const raw_pkt_t *p_raw_pkt, enum _pkt_classify class_val);

char biz_retval_to_platform(char biz_ret);
char plat_state_to_biz(char plat_state);

void idle_polling_call(int thread_seq);
int gdev_block_send_rule(const struct streaminfo *pstream);
int gdev_block_init(void);
int sapp_identify_broad_multicast_pkt(const void *this_layer_data, const raw_pkt_t *raw_pkt);
int sapp_identify_tunnel_inner_pkt(const raw_pkt_t *raw_pkt);
int sapp_metric_init(void);
int sapp_metric_start(void);
void sapp_fs2_fuzzy_latency_update_per_entry(int thead_seq, int entry_id, long long time_cost);
int save_polling_inject_context(int mem_used_type, struct streaminfo_private *pstream_pr, const raw_pkt_t *raw_pkt);
void free_polling_inject_context(int mem_used_type, struct streaminfo_private *pstream_pr);
int update_polling_inject_context(int mem_used_type, struct streaminfo_private *pstream_pr, const raw_pkt_t *raw_pkt);
unsigned long long get_global_stream_id(unsigned long long thread_seq);
enum sapp_state_t sapp_get_current_state(void);
extern struct streaminfo_private *copy_stream_info_to_heap(int mem_used_type, const struct streaminfo_private *stack_stream, int reverse);
enum addr_type_t addr_type_abbreviation_pton(const char *addr_type_abbreviation);
const char *addr_type_abbreviation_ntop(enum addr_type_t addrtype);

int plugin_manage_init(void);
void plugin_manage_destroy(void);
void  *plugin_get_plug_entry(const char *plug_name, const char *plug_entry_type);
int libsapp_setup_env(int argc, char *argv[]);
void *stream_bridge_create_per_stream(int mem_used_type, int thread_num);
void stream_bridge_destroy_per_stream(int mem_used_type, const struct streaminfo *stream, void *pbridge);
char *sapp_strdup(const char *raw_s);
int MESA_mkdir_p(const char *pathname, mode_t mode);
int sapp_get_secondary_file_path(void);
void sapp_update_config_root_dir(const char *cfg_root_dir);
void sapp_update_data_root_dir(const char *data_root_dir);
int sapp_is_absolute_path(const char *filename);
char *sapp_memmove_for_blank_table(char *data, int max_len);
void del_last_rn(char *data, int max_len);
void sapp_printf_colorful(int level, const char *format, ...);
int set_transport_addr(struct streaminfo *this_stream, int enable_well_known_port, UINT16 sport, UINT16 dport);
long long sapp_random(void);
int sapp_usleep(int usec);
void set_current_thread_cpu_affinity(int);
int get_current_thread_cpu_affinity_id(void);
void sapp_metric_destroy(void);
void sapp_gval_destroy(void);
char *byte_convert_human(unsigned long long bytes, int interval, int multiple, char * byte_str);
void cycle_pkt_dump_destroy(void);
void stream_destroy_plugin(void);
void stream_bridge_destroy(void);
void global_project_req_destroy(void);
void raw_ip_frag_list_v4_destroy(void);
void raw_ip_frag_list_v6_destroy(void);
void global_stream_destroy(void);
void global_sapp_timer_destroy(void);
void gdev_keepalive_plug_destroy(void);
void packet_io_device_alias_destroy(void);
void sapp_dup_pkt_destroy(void);
const char *stream_bridge_id_to_name(int bridge_id);
void sapp_printf(const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif

