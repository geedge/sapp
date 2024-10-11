#ifndef _SAPP_PKT_STAT_H_
#define _SAPP_PKT_STAT_H_ 1

/*
	ʹ��enum����, ����ԭ��sysinfo.h���ú궨��̶�ֵ��ʽ,
	��Ϊ��Щ���������⿪��, ���������Ҫ����������, ������λ�ö����������±���,
	���±��뼴��!
*/

typedef enum __sapp_sys_stat_type{
	SAPP_STAT_FETCH_PKT,  /* sapp���Դ�pcap, marsio��ȡ���ݰ��Ĵ���, �����Ľ��, ��Ҫ����������� */
	
	/* 
		LINE����overlay������, ���²���LINE�Ķ��������е���ʵͨ��˫��������, ����vxlan�ȷ�װ���ֽ���,
		����һ��vxlan���ܳ�����1000�ֽ�, vxlan overlay�����ethernet,ipv4,udp,vxlan, �ܳ�����50�ֽ�,
		��SAPP_STAT_RCV_LINE��1000�ֽ�, SAPP_STAT_RCV_RAW��950�ֽ�.
	*/
	SAPP_STAT_RCV_LINE, 
	
	/*************  receive packet  ****************/
	SAPP_STAT_RCV_RAW, /* �յ�����ʵԭʼ������, ��һ������ethernet, ethernet����mac-in-mac, vpls��ԭ��Ҳ���ܻ��ظ����� */
	
	SAPP_STAT_RCV_ETHERNET,
	SAPP_STAT_RCV_IPV4,		 /* ������SAPP_STAT_RCV_IPV4_FRAG */
	SAPP_STAT_RCV_IPV4_FRAG, /* ������SAPP_STAT_RCV_IPV4֮��,  ��������   */
	SAPP_STAT_RCV_IPV6,		 /* ������SAPP_STAT_RCV_IPV6_FRAG */
	SAPP_STAT_RCV_IPV6_FRAG, /* ������SAPP_STAT_RCV_IPV6֮��,  ��������   */
	SAPP_STAT_RCV_TCP,
	SAPP_STAT_RCV_UDP,

	SAPP_STAT_RCV_DUP_TCP, /* �ظ����� */
	SAPP_STAT_RCV_DUP_UDP, /* �ظ����� */

	SAPP_STAT_DUP_IDENTIFY_ERR, /* �ظ�����ʶ��key���Ӵ��� */

	SAPP_STAT_RCV_UNKNOWN,
	
	/*************  send packet  *******************/

	SAPP_STAT_RAW_INBOUND,
	SAPP_STAT_RAW_OUTBOUND,

	SAPP_STAT_ETH_INBOUND,  /* ����ģʽ��, �ǵ�ǰ������I/O����, ��������ڵ�ǰ�豸��������λ��, ���뾳�������� */
	SAPP_STAT_ETH_OUTBOUND, /* ����ģʽ��, �ǵ�ǰ������I/O����, ��������ڵ�ǰ�豸��������λ��, ���뾳�������� */

	SAPP_STAT_IPV4_INBOUND,		 /* ������SAPP_STAT_RCV_IPV4_FRAG */
	SAPP_STAT_IPV4_FRAG_INBOUND, /* ������SAPP_STAT_RCV_IPV4֮��,  ��������   */
	SAPP_STAT_IPV6_INBOUND,		 /* ������SAPP_STAT_RCV_IPV6_FRAG */
	SAPP_STAT_IPV6_FRAG_INBOUND, /* ������SAPP_STAT_RCV_IPV6֮��,  ��������   */
	SAPP_STAT_TCP_INBOUND,
	SAPP_STAT_UDP_INBOUND,	

	SAPP_STAT_IPV4_OUTBOUND,		 /* ������SAPP_STAT_RCV_IPV4_FRAG */
	SAPP_STAT_IPV4_FRAG_OUTBOUND, /* ������SAPP_STAT_RCV_IPV4֮��,  ��������   */
	SAPP_STAT_IPV6_OUTBOUND,		 /* ������SAPP_STAT_RCV_IPV6_FRAG */
	SAPP_STAT_IPV6_FRAG_OUTBOUND, /* ������SAPP_STAT_RCV_IPV6֮��,  ��������   */
	SAPP_STAT_TCP_OUTBOUND,
	SAPP_STAT_UDP_OUTBOUND,	

	SAPP_STAT_UNKNOWN_INBOUND,
	SAPP_STAT_UNKNOWN_OUTBOUND,


	SAPP_STAT_SND_ETHERNET, /* ����������͵�����, ������������������ */
	SAPP_STAT_SND_IPV4,
	SAPP_STAT_SND_IPV6,
	SAPP_STAT_SND_TCP,
	SAPP_STAT_SND_TCP_RST,
	SAPP_STAT_SND_TCP_SYNACK,
	SAPP_STAT_SND_UDP,
	SAPP_STAT_SND_CTRL,

	SAPP_STAT_BUILD_LAYER_ERR,
	SAPP_STAT_BUILD_CTRL_ERR,

	SAPP_STAT_SND_ERROR,

	/*************  special condition  *************/
	SAPP_STAT_DROP_ETHERNET,
	SAPP_STAT_DROP_IPV4,
	SAPP_STAT_DROP_IPV6,

	SAPP_POLLING_WORK,
	SAPP_POLLING_IDLE,
	
	/*************  tunnel stat  *******************/
	SAPP_STAT_TUNNEL_4OVER6,
	SAPP_STAT_TUNNEL_6OVER4,
	SAPP_STAT_TUNNEL_IPIP,
	SAPP_STAT_TUNNEL_TEREDO,
	SAPP_STAT_TUNNEL_L2TP,
	SAPP_STAT_TUNNEL_PPTP,
	SAPP_STAT_TUNNEL_GTP,
	SAPP_STAT_TUNNEL_GRE,
	
	/*************  stream stat  *******************/
	SAPP_STAT_TCP_STREAM_SYN,
	SAPP_STAT_TCP_STREAM_DATA,
	SAPP_STAT_TCP_STREAM_NOUSE,

	SAPP_STAT_TCP_STREAM_C2S, /* ��������������ͳ��  (total pkt num > m and total byte > n) */
	SAPP_STAT_TCP_STREAM_S2C,/*  ��������������ͳ��(total pkt num > m and total byte > n) */
	SAPP_STAT_TCP_STREAM_DOUBLE,/*  ��������������ͳ��  (total pkt num > m and total byte > n) */

	SAPP_STAT_TCP_STREAM_C2S_PKTS, /* ��������������ͳ��  (total pkt num > m and total byte > n) */
	SAPP_STAT_TCP_STREAM_S2C_PKTS,/*  ��������������ͳ��(total pkt num > m and total byte > n) */
	SAPP_STAT_TCP_STREAM_DOUBLE_PKTS,/*  ��������������ͳ��  (total pkt num > m and total byte > n) */

	SAPP_STAT_TCP_STREAM_C2S_BYTES, /* ��������������ͳ��  (total pkt num > m and total byte > n) */
	SAPP_STAT_TCP_STREAM_S2C_BYTES,/*  ��������������ͳ��(total pkt num > m and total byte > n) */
	SAPP_STAT_TCP_STREAM_DOUBLE_BYTES,/*  ��������������ͳ��  (total pkt num > m and total byte > n) */

	SAPP_STAT_TCP_STREAM_NEW,
	SAPP_STAT_TCP_STREAM_DEL,
	SAPP_STAT_TCP_STREAM_RESET,

	SAPP_STAT_UDP_STREAM_ONE,
	SAPP_STAT_UDP_STREAM_TWO,
	SAPP_STAT_UDP_STREAM_MORE,
	SAPP_STAT_UDP_STREAM_NEW,
	SAPP_STAT_UDP_STREAM_DEL,
	SAPP_STAT_UDP_STREAM_RESET,

	SAPP_STAT_TCP_STREAM_TOTAL_C2S, /* ȫ��TCP��ͳ�� ������*/
	SAPP_STAT_TCP_STREAM_TOTAL_S2C,/* ȫ��TCP��ͳ�� ������*/
	SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE,	/* ȫ��TCP��ͳ�� ������*/

	SAPP_STAT_TCP_STREAM_TOTAL_C2S_PKTS, /* ȫ��TCP��ͳ�� ���� */
	SAPP_STAT_TCP_STREAM_TOTAL_S2C_PKTS,/* ȫ��TCP��ͳ�� ����*/
	SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE_PKTS,	/* ȫ��TCP��ͳ�� ����*/

	SAPP_STAT_TCP_STREAM_TOTAL_C2S_BYTES, /* ȫ��TCP��ͳ�� �ֽ��� */
	SAPP_STAT_TCP_STREAM_TOTAL_S2C_BYTES,/* ȫ��TCP��ͳ�� �ֽ���*/
	SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE_BYTES,	/* ȫ��TCP��ͳ�� �ֽ���*/

	SAPP_STAT_TCP_LOST_PKT_STREAM_NUM, /* ���������������� */
	SAPP_STAT_TCP_LOST_PKT, /* �����ֽ��ܼ��� */

	SAPP_STAT_UDP_STREAM_C2S, /* ��������������ͳ��  (total pkt num > m and total byte > n) */
	SAPP_STAT_UDP_STREAM_S2C,/*  ��������������ͳ��(total pkt num > m and total byte > n) */
	SAPP_STAT_UDP_STREAM_DOUBLE,/*  ��������������ͳ��  (total pkt num > m and total byte > n) */
	

	SAPP_STAT_UDP_STREAM_C2S_PKTS, /* ��������������ͳ��  (total pkt num > m and total byte > n) */
	SAPP_STAT_UDP_STREAM_S2C_PKTS,/*  ��������������ͳ��(total pkt num > m and total byte > n) */
	SAPP_STAT_UDP_STREAM_DOUBLE_PKTS,/*  ��������������ͳ��  (total pkt num > m and total byte > n) */

	SAPP_STAT_UDP_STREAM_C2S_BYTES, /* ��������������ͳ��  (total pkt num > m and total byte > n) */
	SAPP_STAT_UDP_STREAM_S2C_BYTES,/*  ��������������ͳ��(total pkt num > m and total byte > n) */
	SAPP_STAT_UDP_STREAM_DOUBLE_BYTES,/*  ��������������ͳ��  (total pkt num > m and total byte > n) */

	SAPP_STAT_UDP_STREAM_TOTAL_C2S, /* ȫ��UDP��ͳ�� */
	SAPP_STAT_UDP_STREAM_TOTAL_S2C,/* ȫ��UDP��ͳ�� */
	SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE,	/* ȫ��UDP��ͳ�� */	

	SAPP_STAT_UDP_STREAM_TOTAL_C2S_PKTS, /* ȫ��UDP��ͳ�� */
	SAPP_STAT_UDP_STREAM_TOTAL_S2C_PKTS,/* ȫ��UDP��ͳ�� */
	SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE_PKTS,	/* ȫ��UDP��ͳ�� */	

	SAPP_STAT_UDP_STREAM_TOTAL_C2S_BYTES, /* ȫ��UDP��ͳ�� */
	SAPP_STAT_UDP_STREAM_TOTAL_S2C_BYTES,/* ȫ��UDP��ͳ�� */
	SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE_BYTES,	/* ȫ��UDP��ͳ�� */	

	SAPP_STAT_TCP_HASH_LIST_MAX,
	SAPP_STAT_UDP_HASH_LIST_MAX,

	SAPP_STAT_TCP_CLOSE_BY_FIN,     /* ���������TCP_ALL���, ��ʵû���״̬, ���ǳ�ʱ���Ǳ�ǿ���߳� */
	SAPP_STAT_TCP_CLOSE_BY_RST,     /* ���������TCP_ALL���, ��ʵû���״̬, ���ǳ�ʱ���Ǳ�ǿ���߳� */
	SAPP_STAT_TCP_CLOSE_BY_TIMEOUT, /* ��ʱ����̭ */
	SAPP_STAT_TCP_CLOSE_BY_KICKOUT, /* ������������̭ */
	SAPP_STAT_TCP_CLOSE_BY_REUSE,   /* ����Ԫ�����ñ���̭ */
	SAPP_STAT_TCP_CLOSE_BY_DUMPFILE_END, /* ��pcap dumpfileģʽ��Ч, ��ʵ��������»�û�н���, ��pcap��������ǿ��������е������˳� */
	SAPP_STAT_TCP_SHOULD_CLOSE_BUT_TCPALL, /* ���������tcp�����Ѿ�������, ����Ϊ��TCP_ALL���, ����ʵ�ʻ�����free, ���������ջ���TIMEOUT��KICKOUT���� */
	
	SAPP_STAT_UDP_CLOSE_BY_TIMEOUT,
	SAPP_STAT_UDP_CLOSE_BY_KICKOUT,
	SAPP_STAT_UDP_CLOSE_BY_DUMPFILE_END,


	/* under ddos bypass  */
	SAPP_STAT_GLOBAL_BYPASS, /* �����߳�cpu����, ��������ȫ��bypass��־ */
	SAPP_STAT_TCP_BYPASS_STREAM,
	SAPP_STAT_TCP_BYPASS_PKTS,
	SAPP_STAT_TCP_BYPASS_BYTES,
	SAPP_STAT_UDP_BYPASS_STREAM,
	SAPP_STAT_UDP_BYPASS_PKTS,
	SAPP_STAT_UDP_BYPASS_BYTES,	

	SAPP_STAT_TCP_OFFLOAD_STREAM,
	SAPP_STAT_TCP_OFFLOAD_PKTS,
	SAPP_STAT_TCP_OFFLOAD_BYTES,
	SAPP_STAT_UDP_OFFLOAD_STREAM,
	SAPP_STAT_UDP_OFFLOAD_PKTS,
	SAPP_STAT_UDP_OFFLOAD_BYTES,	

	SAPP_STAT_UDP_DUP_KICK_STREAM,

	SAPP_STAT_TCP_OPENING_OVERSPEED,
	SAPP_STAT_UDP_OPENING_OVERSPEED,

	SAPP_STAT_TCP_TIMEOUTS_OVERSPEED,
	SAPP_STAT_UDP_TIMEOUTS_OVERSPEED,

	SAPP_STAT_TCP_TRY_TIMEOUTS,
	SAPP_STAT_UDP_TRY_TIMEOUTS,
	
	/*************  memory stat  *******************/

	/*************  bloom filter stat  *******************/
	SAPP_STAT_BM_HASH_NUM,
	SAPP_STAT_BM_EXPAND_NUM,
	SAPP_STAT_BM_SLICE_NUM_NEW,
	SAPP_STAT_BM_SLICE_NUM_FREE,
	SAPP_STAT_BM_CUR_SLICE_NUM,
	SAPP_STAT_APBM_EXPAND_MAX_MULTIPLE,
	SAPP_STAT_DABM_RESIZE_MAX_RATIO,
	/************** Maximum Value Definition *******/
	SAPP_STAT_NUM_MAX,
}sapp_sys_stat_type_t;

#endif

