#ifndef __SYSINFO_H__
#define __SYSINFO_H__


#ifndef MAX_THREAD_NUM
#define MAX_THREAD_NUM 	128
#endif

#define SYS_COUNTER_ON 
#define COUNTER_NUM (4096)   /*newly added  ---LiLei*/


#define COUNTER_PKT         	240
#define COUNTER_PKTLEN        241
#define COUNTER_DROP_PKT    242
#define COUNTER_DROP_PKTLEN 243
#define COUNTER_DROPLINK    244  //2??üê?±e??1?±?μ?á′?ó
#define COUNTER_CLOSELINK   245  //?ü1?ê?±e?aó|ó?2?D-òé￡?μ?ê?D-òé′?ê??úèY2?Dèòa′|àí￡??ò??′|àí1y3ì?D3?′í￡??ü?Dμ?á′?ó


//---pkt info

#define PKTINFO_BASE	    0
#define PKT_ETHERNET	    0
#define PKT_IP_FRAG		    1    
#define PKT_IP       		    2   
#define PKT_TCP	 		    3   
#define PKT_UDP			    4
#define PKT_IPLEN		    5
#define PKT_TCPLEN		    6
#define PKT_UDPLEN		    8
#define PKT_TCP_DROP	    11  //2?Dèòatcp2?′|àíμ?°ü??êy
#define PKT_TCP_DROPLEN    12  //2?Dèòatcp2?′|àíμ?°ü3¤?è
#define PKT_TCP_UNORDER    13  //?òDò°üμ???êy
#define PKT_TCP_APP	 	     14
#define PKT_TCP_APP_LEN		15
#define HTTP_CON_NOGZ	   16
#define HTTP_CON_GZ	   17
#define HTTP_CON_NO_GZAV   18
#define HTTP_CON_GZAV      19

//---link info
#define LINKINFO_BASE       20
#define LINK_TATAL		  20
#define LINK_TATAL_DROP  21
#define LINK_APPTATAL	  22
#define LINK_DROP_NOUSE 23 //2??üê?±e??1?±?μ?á′?ó
#ifndef PLATFORM_NSDPF_PAPP /* 2013-02-25 lijia modify,  LINK_CLOSEó?stream_manage.h?D3?í?￡????? */		
#define LINK_CLOSE            24 //?ü1?ê?±e?aó|ó?2?D-òé￡?μ?ê?D-òé′?ê??úèY2?Dèòa′|àí￡??ò??′|àí1y3ì?D3?′í￡??ü?Dμ?á′?ó
#else
#define NIDS_LINK_CLOSE		24
#endif
#define LINK_SINGLE_C2S          25 //  μ￥?òá′?ó
#define LINK_SINGLE_S2C          26 //  μ￥?òá′?ó
#define LINK_DOUBLE        	 27 //
#define LINK_KILL         	 28 //

/* 2014-12-02 lijia add */
#define PKT_IPV6       		31   
#define PKT_IPV6LEN		    32
#define PKT_ETHERNET_LEN    	33

#define SYS_TCP_LINK_SYN		(34)
#define SYS_TCP_LINK_DATA		(35)
#define SYS_TCP_LINK_NOUSE		(36)
#define SYS_TCP_LINK_NEW		(37)
#define SYS_TCP_LINK_DEL		(38)
#define SYS_TCP_LINK_RESET		(39) /* tcp???a×é??ó?êy */

#define SYS_UDP_LINK_ONE		(40)
#define SYS_UDP_LINK_TWO		(41)
#define SYS_UDP_LINK_MORE		(42)
#define SYS_UDP_LINK_NEW		(43)
#define SYS_UDP_LINK_DEL		(44)
#define SYS_UDP_LINK_RESET		(45) /* udp???a×é??ó?êy */

#define SYS_HASH_LIST_MAX		(46)

/* 2014-12-02 lijia add */
#define TCPV4_LINK_TOTAL		(47)
#define TCPV4_LINK_NEW_CREATE	(48)
#define TCPV4_LINK_CLOSE		(49)
#define TCPV6_LINK_TOTAL		(50)
#define TCPV6_LINK_NEW_CREATE	(51)
#define TCPV6_LINK_CLOSE		(52)

#define UDPV4_LINK_TOTAL		(53)
#define UDPV4_LINK_NEW_CREATE	(54)
#define UDPV4_LINK_CLOSE		(55)
#define UDPV6_LINK_TOTAL		(56)
#define UDPV6_LINK_NEW_CREATE	(57)
#define UDPV6_LINK_CLOSE		(58)

#define TUNNEL_6OVER4			(59)


#define TUNNEL_6OVER4_LEN		(61)
#define TUNNEL_4OVER6			(62)
#define TUNNEL_4OVER6_LEN		(63)
#define TUNNEL_TEREDO			(64)
#define TUNNEL_TEREDO_LEN		(65)
#define TUNNEL_IP_IN_IP			(66)

#define SEND_IP_RAW_PKT		(70) /* 调用MESA_sendpacket_iplayer()发送构造好的IP完整包 */
#define SEND_IP_RAW_PKT_LEN	(71)
#define SEND_IP_PKT			(72)
#define SEND_IP_PKT_LEN		(73)
#define SEND_TCP_PKT			(74) /* MESA_fakepacket_send_tcp()发送TCP数据包 */
#define SEND_TCP_PKT_LEN		(75)
#define SEND_TCP_RST			(76)
#define SEND_TCP_RST_LEN		(77)
#define SEND_TCP_SYN_ACK		(78)
#define SEND_TCP_SYN_ACK_LEN	(79)
#define SEND_UDP_PKT			(80) /* MESA_fakepacket_send_udp()发送UDP数据包 */
#define SEND_UDP_PKT_LEN		(81)

#define SEND_PKT_ERR			(82)
#define SEND_PKT_ERR_LEN		(83) /* sendto error */

/* 2014-12-02 lijia add */
#define PKT_UNKNOWN			(98)
#define PKT_UNKNOWN_LEN		(99)


//group info

#define PKT_APP_BASE	  		1000
//--app count (30)
#define LINK_APP_BASE	  		1500
#define IP_FRAG_GROUP_BASE	    2000
#define TCP_UNORDER_GROUP_BASE	3000



#ifdef __cplusplus
extern "C" {
#endif
extern volatile unsigned int  g_aiSysCounter[COUNTER_NUM]; /*newly modified   ---LiLei*/

extern volatile unsigned long long g_SysInputInfo[MAX_THREAD_NUM][COUNTER_NUM];

#ifdef __cplusplus
}
#endif

#endif
