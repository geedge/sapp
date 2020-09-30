#ifndef _SAPP_PKT_STAT_H_
#define _SAPP_PKT_STAT_H_ 1

/*
	ʹ��enum����, ����ԭ��sysinfo.h���ú궨��̶�ֵ��ʽ,
	��Ϊ��Щ���������⿪��, ���������Ҫ����������, ������λ�ö����������±���,
	���±��뼴��!
*/

typedef enum __sapp_sys_stat_type{
	/*************  receive packet  ****************/
	SAPP_STAT_RCV_RAW, /* �յ�����ʵԭʼ������, ethernet����mac-in-mac, vpls��ԭ��Ҳ���ܻ��ظ����� */
	
	SAPP_STAT_RCV_ETHERNET,
	SAPP_STAT_RCV_IPV4,		 /* ������SAPP_STAT_RCV_IPV4_FRAG */
	SAPP_STAT_RCV_IPV4_FRAG, /* ������SAPP_STAT_RCV_IPV4֮��,  ��������   */
	SAPP_STAT_RCV_IPV6,		 /* ������SAPP_STAT_RCV_IPV6_FRAG */
	SAPP_STAT_RCV_IPV6_FRAG, /* ������SAPP_STAT_RCV_IPV6֮��,  ��������   */
	SAPP_STAT_RCV_TCP,
	SAPP_STAT_RCV_UDP,

	SAPP_STAT_RCV_UNKNOWN,
	
	/*************  send packet  *******************/

	SAPP_STAT_RAW_INBOUND,  /* ����ģʽ��, �ǵ�ǰ������I/O����, ��������ڵ�ǰ�豸��������λ��, ���뾳�������� */
	SAPP_STAT_RAW_OUTBOUND, /* ����ģʽ��, �ǵ�ǰ������I/O����, ��������ڵ�ǰ�豸��������λ��, ���뾳�������� */

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

	SAPP_STAT_HASH_LIST_MAX,
	
	/*************  memory stat  *******************/

	/************** Maximum Value Definition *******/
	SAPP_STAT_NUM_MAX,
}sapp_sys_stat_type_t;

#endif

