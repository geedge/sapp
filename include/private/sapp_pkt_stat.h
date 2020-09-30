#ifndef _SAPP_PKT_STAT_H_
#define _SAPP_PKT_STAT_H_ 1

/*
	使用enum定义, 代替原来sysinfo.h中用宏定义固定值方式,
	因为这些变量不对外开放, 如果后期需要增加新类型, 在任意位置都可以增加新变量,
	重新编译即可!
*/

typedef enum __sapp_sys_stat_type{
	/*************  receive packet  ****************/
	SAPP_STAT_RCV_RAW, /* 收到的真实原始包数量, ethernet由于mac-in-mac, vpls等原因也可能会重复计算 */
	SAPP_STAT_RCV_ETHERNET,
	SAPP_STAT_RCV_IPV4,		 /* 不包括SAPP_STAT_RCV_IPV4_FRAG */
	SAPP_STAT_RCV_IPV4_FRAG, /* 不含在SAPP_STAT_RCV_IPV4之内,  独立计数   */
	SAPP_STAT_RCV_IPV6,		 /* 不包括SAPP_STAT_RCV_IPV6_FRAG */
	SAPP_STAT_RCV_IPV6_FRAG, /* 不含在SAPP_STAT_RCV_IPV6之内,  独立计数   */
	SAPP_STAT_RCV_TCP,
	SAPP_STAT_RCV_UDP,

	SAPP_STAT_RCV_UNKNOWN,
	
	/*************  send packet  *******************/

	SAPP_STAT_RAW_INBOUND,  /* 串联模式下, 非当前网卡的I/O流量, 而是相对于当前设备所在物理位置, 出入境方向流量 */
	SAPP_STAT_RAW_OUTBOUND, /* 串联模式下, 非当前网卡的I/O流量, 而是相对于当前设备所在物理位置, 出入境方向流量 */

	SAPP_STAT_ETH_INBOUND,  /* 串联模式下, 非当前网卡的I/O流量, 而是相对于当前设备所在物理位置, 出入境方向流量 */
	SAPP_STAT_ETH_OUTBOUND, /* 串联模式下, 非当前网卡的I/O流量, 而是相对于当前设备所在物理位置, 出入境方向流量 */

	SAPP_STAT_IPV4_INBOUND,		 /* 不包括SAPP_STAT_RCV_IPV4_FRAG */
	SAPP_STAT_IPV4_FRAG_INBOUND, /* 不含在SAPP_STAT_RCV_IPV4之内,  独立计数   */
	SAPP_STAT_IPV6_INBOUND,		 /* 不包括SAPP_STAT_RCV_IPV6_FRAG */
	SAPP_STAT_IPV6_FRAG_INBOUND, /* 不含在SAPP_STAT_RCV_IPV6之内,  独立计数   */
	SAPP_STAT_TCP_INBOUND,
	SAPP_STAT_UDP_INBOUND,	

	SAPP_STAT_IPV4_OUTBOUND,		 /* 不包括SAPP_STAT_RCV_IPV4_FRAG */
	SAPP_STAT_IPV4_FRAG_OUTBOUND, /* 不含在SAPP_STAT_RCV_IPV4之内,  独立计数   */
	SAPP_STAT_IPV6_OUTBOUND,		 /* 不包括SAPP_STAT_RCV_IPV6_FRAG */
	SAPP_STAT_IPV6_FRAG_OUTBOUND, /* 不含在SAPP_STAT_RCV_IPV6之内,  独立计数   */
	SAPP_STAT_TCP_OUTBOUND,
	SAPP_STAT_UDP_OUTBOUND,	

	SAPP_STAT_UNKNOWN_INBOUND,
	SAPP_STAT_UNKNOWN_OUTBOUND,


	SAPP_STAT_SND_ETHERNET, /* 插件主动发送的流量, 不包括串联回流流量 */
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

	SAPP_STAT_TCP_STREAM_C2S, /* 满足以下条件的统计  (total pkt num > m and total byte > n) */
	SAPP_STAT_TCP_STREAM_S2C,/*  满足以下条件的统计(total pkt num > m and total byte > n) */
	SAPP_STAT_TCP_STREAM_DOUBLE,/*  满足以下条件的统计  (total pkt num > m and total byte > n) */

	SAPP_STAT_TCP_STREAM_C2S_PKTS, /* 满足以下条件的统计  (total pkt num > m and total byte > n) */
	SAPP_STAT_TCP_STREAM_S2C_PKTS,/*  满足以下条件的统计(total pkt num > m and total byte > n) */
	SAPP_STAT_TCP_STREAM_DOUBLE_PKTS,/*  满足以下条件的统计  (total pkt num > m and total byte > n) */

	SAPP_STAT_TCP_STREAM_C2S_BYTES, /* 满足以下条件的统计  (total pkt num > m and total byte > n) */
	SAPP_STAT_TCP_STREAM_S2C_BYTES,/*  满足以下条件的统计(total pkt num > m and total byte > n) */
	SAPP_STAT_TCP_STREAM_DOUBLE_BYTES,/*  满足以下条件的统计  (total pkt num > m and total byte > n) */

	SAPP_STAT_TCP_STREAM_NEW,
	SAPP_STAT_TCP_STREAM_DEL,
	SAPP_STAT_TCP_STREAM_RESET,

	SAPP_STAT_UDP_STREAM_ONE,
	SAPP_STAT_UDP_STREAM_TWO,
	SAPP_STAT_UDP_STREAM_MORE,
	SAPP_STAT_UDP_STREAM_NEW,
	SAPP_STAT_UDP_STREAM_DEL,
	SAPP_STAT_UDP_STREAM_RESET,

	SAPP_STAT_TCP_STREAM_TOTAL_C2S, /* 全部TCP流统计 连接数*/
	SAPP_STAT_TCP_STREAM_TOTAL_S2C,/* 全部TCP流统计 连接数*/
	SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE,	/* 全部TCP流统计 连接数*/

	SAPP_STAT_TCP_STREAM_TOTAL_C2S_PKTS, /* 全部TCP流统计 包数 */
	SAPP_STAT_TCP_STREAM_TOTAL_S2C_PKTS,/* 全部TCP流统计 包数*/
	SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE_PKTS,	/* 全部TCP流统计 包数*/

	SAPP_STAT_TCP_STREAM_TOTAL_C2S_BYTES, /* 全部TCP流统计 字节数 */
	SAPP_STAT_TCP_STREAM_TOTAL_S2C_BYTES,/* 全部TCP流统计 字节数*/
	SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE_BYTES,	/* 全部TCP流统计 字节数*/

	SAPP_STAT_TCP_LOST_PKT_STREAM_NUM, /* 曾经丢包的流计数 */
	SAPP_STAT_TCP_LOST_PKT, /* 丢包字节总计数 */

	SAPP_STAT_UDP_STREAM_C2S, /* 满足以下条件的统计  (total pkt num > m and total byte > n) */
	SAPP_STAT_UDP_STREAM_S2C,/*  满足以下条件的统计(total pkt num > m and total byte > n) */
	SAPP_STAT_UDP_STREAM_DOUBLE,/*  满足以下条件的统计  (total pkt num > m and total byte > n) */
	

	SAPP_STAT_UDP_STREAM_C2S_PKTS, /* 满足以下条件的统计  (total pkt num > m and total byte > n) */
	SAPP_STAT_UDP_STREAM_S2C_PKTS,/*  满足以下条件的统计(total pkt num > m and total byte > n) */
	SAPP_STAT_UDP_STREAM_DOUBLE_PKTS,/*  满足以下条件的统计  (total pkt num > m and total byte > n) */

	SAPP_STAT_UDP_STREAM_C2S_BYTES, /* 满足以下条件的统计  (total pkt num > m and total byte > n) */
	SAPP_STAT_UDP_STREAM_S2C_BYTES,/*  满足以下条件的统计(total pkt num > m and total byte > n) */
	SAPP_STAT_UDP_STREAM_DOUBLE_BYTES,/*  满足以下条件的统计  (total pkt num > m and total byte > n) */

	SAPP_STAT_UDP_STREAM_TOTAL_C2S, /* 全部UDP流统计 */
	SAPP_STAT_UDP_STREAM_TOTAL_S2C,/* 全部UDP流统计 */
	SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE,	/* 全部UDP流统计 */	

	SAPP_STAT_UDP_STREAM_TOTAL_C2S_PKTS, /* 全部UDP流统计 */
	SAPP_STAT_UDP_STREAM_TOTAL_S2C_PKTS,/* 全部UDP流统计 */
	SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE_PKTS,	/* 全部UDP流统计 */	

	SAPP_STAT_UDP_STREAM_TOTAL_C2S_BYTES, /* 全部UDP流统计 */
	SAPP_STAT_UDP_STREAM_TOTAL_S2C_BYTES,/* 全部UDP流统计 */
	SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE_BYTES,	/* 全部UDP流统计 */	

	SAPP_STAT_HASH_LIST_MAX,
	
	/*************  memory stat  *******************/

	/************** Maximum Value Definition *******/
	SAPP_STAT_NUM_MAX,
}sapp_sys_stat_type_t;

#endif

