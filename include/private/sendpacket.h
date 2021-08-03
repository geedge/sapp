/************************************************************************************
Filename   : sendpacket.h
Author     : liuqingyun
Time       : 2007-05
实现说明：
（1）参照libnet1.02a版本实现如下函数，基本未变
    	sendpacket_build_ip
        sendpacket_build_ipv4
	sendpacket_build_tcp
	sendpacket_build_udp
	sendpacket_do_checksum
	sendpacket_init_packet
	sendpacket_destroy_packet
功能说明：
（1）能够发送tcp,udp,ipv4数据包；
（2）能够统计每个socket上面发送的包数，字节数；
（3）可以全局公用sendpacketTool，不用每次调用时分配长度，
（4）如果全局使用sendpacketTool,为了安全起见，每次调用前应该先检测要发送的长度，不超过初始化分配的长度；
（5）不支持选项字段，不支持其它协议报文；




*************************************************************************************/

#ifndef __SENDPACKET_H_
#define __SENDPACKET_H_

/*
 * Data-link level type codes.
 */
#define DLT_NULL        0       /* no link-layer encapsulation */
#define DLT_EN10MB      1       /* Ethernet (10Mb) */
#define DLT_EN3MB       2       /* Experimental Ethernet (3Mb) */
#define DLT_AX25        3       /* Amateur Radio AX.25 */
#define DLT_PRONET      4       /* Proteon ProNET Token Ring */
#define DLT_CHAOS       5       /* Chaos */
#define DLT_IEEE802     6       /* IEEE 802 Networks */
#define DLT_ARCNET      7       /* ARCNET */
#define DLT_SLIP        8       /* Serial Line IP */
#define DLT_PPP         9       /* Point-to-point Protocol */
#define DLT_FDDI        10      /* FDDI */
#define DLT_ATM_RFC1483 11      /* LLC/SNAP encapsulated atm */
#define DLT_RAW         12      /* raw IP */
#ifndef DLT_SLIP_BSDOS
#define DLT_SLIP_BSDOS  13      /* BSD/OS Serial Line IP */
#endif
#ifndef DLT_PPP_BSDOS
#define DLT_PPP_BSDOS   14      /* BSD/OS Point-to-point Protocol */
#endif

#define SENDPACKET_LIL_ENDIAN 1
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#if defined(HAVE_SYS_SOCKIO_H) && !defined(SIOCGIFADDR)
#include <sys/sockio.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <net/if.h>
#if !(__linux__)
#include <netinet/ip_var.h>
#else   /* __linux__ */
#if (HAVE_NET_ETHERNET_H)
#include <net/ethernet.h>
#endif  /* HAVE_NET_ETHERNET_H */
#endif  /* __linux__ */
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#if (__linux__) && !(__GLIBC__)
/*
 *  We get multiple definitions of IGMP_AGE_THRESHOLD if we include netinet.
 */
#include <linux/igmp.h>
#else
#include <netinet/igmp.h>
#endif
#include <arpa/inet.h>
#include <sys/time.h>
#include <netdb.h>
#include <errno.h>
#include <assert.h>

#ifdef CAPTURE_MODE_PFRING
#include <pfring.h>
#endif


#define SENDPACKET_ARP_H			0x1c    /* ARP header:          28 bytes */
#define SENDPACKET_ETH_H			0xe     /* Etherner header:     14 bytes */
#define SENDPACKET_IP_H            0x14    /* IP header:           20 bytes */
/* See sendpacket-ospf.h for OSPF related header sizes */
#define SENDPACKET_RIP_H           0x18    /* RIP header base:     24 bytes */
#define SENDPACKET_TCP_H           0x14    /* TCP header:          20 bytes */
#define SENDPACKET_UDP_H           0x8     /* UDP header:           8 bytes */

/*  
 *  Standard (IPv4) header sizes in bytes. 
 */

#define SENDPACKET_ICMP_H          0x4     /* ICMP header base:     4 bytes */
#define SENDPACKET_ICMP_ECHO_H     0x8     /* ICMP_ECHO header:     8 bytes */
#define SENDPACKET_ICMP_MASK_H     0xc     /* ICMP_MASK header:    12 bytes */
#define SENDPACKET_ICMP_UNREACH_H  0x8     /* ICMP_UNREACH header:  8 bytes */
#define SENDPACKET_ICMP_TIMXCEED_H 0x8     /* ICMP_TIMXCEED header: 8 bytes */
#define SENDPACKET_ICMP_REDIRECT_H 0x8     /* ICMP_REDIRECT header: 8 bytes */
#define SENDPACKET_ICMP_TS_H       0x14    /* ICMP_TIMESTAMP headr:20 bytes */


/*
 *  IPv4 packet header prototype.
 */
struct sendpacket_ip_hdr
{
#if (SENDPACKET_LIL_ENDIAN)
    u_int8_t ip_hl:4,         /* header length */
            ip_v:4;         /* version */
#endif
#if (SENDPACKET_BIG_ENDIAN)
    u_int8_t ip_v:4,          /* version */
            ip_hl:4;        /* header length */
#endif
    u_int8_t ip_tos;          /* type of service */
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
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
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};


/*
 *  Ethernet packet header prototype.  Too many O/S's define this differently.
 *  Easy enough to solve that and define it here.
 */
struct sendpacket_ethernet_hdr
{
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination ethernet address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source ethernet address */
    u_short ether_type;                     /* packet type ID */
};

#define ETHERTYPE_PUP           0x0200  /* PUP protocol */
#define ETHERTYPE_IP            0x0800  /* IP protocol */
#define ETHERTYPE_IPv6          0x86dd  /* IPv6 protocol */
#define ETHERTYPE_ARP           0x0806  /* Addr. resolution protocol */
#define ETHERTYPE_REVARP        0x8035  /* reverse Addr. resolution protocol */
#define ETHERTYPE_VLAN          0x8100  /* IEEE 802.1Q VLAN tagging */
#define ETHERTYPE_LOOPBACK      0x9000  /* used to test interfaces */

/*
 *  Low level packet interface struct
 */
struct sendpacket_link_int
{
    int fd;             /* link layer file descriptor */
    int linktype;       /* link type */
    int linkoffset;     /* link header size (offset till network layer) */
    u_char *device;     /* device name */
};


/*
 *  ICMP packet header prototype. // from libnet-headers.h
 */
struct libnet_icmp_hdr
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
 *  Some BSD variants have this endianess problem.
 */
#if (SENDPACKET_BSD_BYTE_SWAP)
#define FIX(n)      ntohs(n)
#define UNFIX(n)    htons(n)
#else
#define FIX(n)      (n)
#define UNFIX(n)    (n)
#endif


//add by lqy 20070517
#define SENDPACKET_PACKET_SIZE 2*1024
#define SENDPACKET_MAX_PACKET_SIZE 64*1024



#define SENDPACKET_MAX_ERRNO          12
#define SEND_PACKET_SUCCESS             0           
#define SEND_PACKET_OPEN_SOCK_ERR 1 
#define SEND_PACKET_INI_PKT_ERR      2
#define SEND_PACKET_IP_ERR			 3
#define SEND_PACKET_TCP_ERR		 4
#define SEND_PACKET_UDP_ERR		 5
#define SEND_PACKET_CHECKSUM_ERR  5
#define SEND_PACKET_SEND_LESS_ERR 7
#define SEND_PACKET_SEND_NONE_ERR 8
#define SEND_PACKET_CLOSE_SOCK_ERR 9 
#define SEND_PACKET_FREE_PKT_ERR      10
#define SEND_PACKET_SIZELIMIT_ERR     11


#ifdef __cplusplus
extern "C"  int g_UseSendpktCard;
#else
extern int g_UseSendpktCard;
#endif
#ifdef PLATFORM_NSDPF_PAPP
#define SENDBUF_LOCATION_TOOL			(0) /* 已经COPY到sendpacketTool结构中的数据 */
#define SENDBUF_LOCATION_APP			(1) /* 应用层程序自己申请的内存 */
typedef struct _sendpacketTool
{
    int send_fd;
    int send_raw_eth_fd; /* 2013-11-08 LiJia add, 并联模式下发送eth包 */
    short threadnum;//add by lqy 20090313
    short sendtype;
    int errflag;
    int sendbuflen;
    u_int64_t pkt_send;
    u_int64_t bytes_send;
    u_int64_t pkt_senderr;
	unsigned char *__raw_send_buf; /* add by LiJia 2012-04-10，全部缓存区，包含以太网帧头 */
	unsigned char *send_buf; /* modify by LiJia 2012-04-10，使用方式改变，IP层及应用层缓存区，为了和之前接口保持兼容性 */
	unsigned char *send_ptr; /* 指向待发送的数据，根据工作模式和发包方式，可能是__raw_send_buf, send_buf, 或者是应用层自己申请的内存 */
	//char device_name[IFNAMSIZ];//add by LiJia 2012-04-10，网卡名称
	struct sockaddr sa; /* 2012-07-17 LiJia add, RAW_LINK模式发包时使用 */
	struct sockaddr sa2; /* 2012-07-17 LiJia add, 基于双网卡，RAW_LINK模式发包时使用 */
	struct sockaddr sa_raw_eth;  /* 2013-11-08 LiJia add, 并联模式下发送eth包 */
    int protocol;//add by LiJia 2012-04-10，协议类型
    int send_buf_location; /* 待发送的数据所在内存空间，0:已经COPY到sendpacketTool结构中的数据; 1:应用层程序自己申请的内存 */
    unsigned char linktype;
    unsigned char linkoffset;
#ifdef CAPTURE_MODE_PFRING
	pfring *pf_handle;
	pfring_pkt_buff *pkt_handle;
	int pfring_if_index;
	int pfring_if_index2;
#endif
}sendpacketTool;
#ifdef __cplusplus
extern "C" {
#endif
int sendpacket_build_ip(u_int16_t len, u_char tos, u_int16_t id, u_int16_t frag, u_int8_t ttl,
            u_int8_t prot, u_int32_t src, u_int32_t dst, const char *payload,
            int payload_s, unsigned char *buf);
int sendpacket_build_ipv4(u_int16_t len, u_int8_t tos, u_int16_t id, u_int16_t frag,
            u_int8_t ttl, u_int8_t prot, u_int32_t src, u_int32_t dst,
            const char *payload, int payload_s, unsigned char *buf);
int sendpacket_build_tcp(u_int16_t sp, u_int16_t dp, u_int32_t seq, u_int32_t ack, u_int8_t control,
            u_int16_t win, u_int16_t urg, const char *payload, int payload_s,unsigned char *buf);
int sendpacket_build_tcp_with_option(u_int16_t sp, u_int16_t dp, u_int32_t seq, u_int32_t ack, u_int8_t control,
            u_int16_t win, u_int16_t urg, const char *option, int option_len, const char *payload, int payload_s,
            unsigned char *buf);
int sendpacket_build_udp_dual_stack(u_int16_t sp, u_int16_t dp, const char *payload, int payload_s,int, unsigned char *buf);
int sendpacket_build_ethernet(u_char *dst, u_char *src, u_short type,
            const u_char *payload, int payload_s, u_char *buf);
int sendpacket_build_arp(u_short hrd, u_short pro, u_char hln, u_char pln, u_short op,
            u_char *sha, u_char *spa, u_char *tha, u_char *tpa,
            const u_char *payload, int payload_s, u_char *buf);
int sendpacket_do_checksum(unsigned char *buf, int protocol, int len);
int sendpacket_init_packet(int p_size, unsigned char **buf);
int sendpacket_tool_init(void);
extern int sendpacket_write_new( sendpacketTool *pTool,int sendlen, char dir);
int sendpacket_build_icmpv4_echo(u_int8_t type, u_int8_t code, u_int16_t sum,
	u_int16_t id, u_int16_t seq, u_int8_t *payload, u_int32_t payload_s, unsigned char *buf);

#ifdef __cplusplus
}
#endif
#else // #ifdef PLATFORM_PAPP
typedef struct _sendpacketTool
{
    int send_fd;
    short threadnum;//add by lqy 20090313
    short sendtype;
    int errflag;
    int sendbuflen;
    __uint64_t pkt_send;
    __uint64_t bytes_send;
    __uint64_t pkt_senderr;
    char *send_buf;
}sendpacketTool;
#ifdef __cplusplus
extern "C" {
#endif
int sendpacket_build_ip(u_int16_t len, u_char tos, u_int16_t id, u_int16_t frag, u_int8_t ttl,
            u_int8_t prot, u_int32_t src, u_int32_t dst, const char *payload,
            int payload_s, char *buf);
int sendpacket_build_ipv4(u_int16_t len, u_int8_t tos, u_int16_t id, u_int16_t frag,
            u_int8_t ttl, u_int8_t prot, u_int32_t src, u_int32_t dst,
            const char *payload, int payload_s, unsigned char *buf);
int sendpacket_build_icmpv4_echo(u_int8_t type, u_int8_t code, u_int16_t sum,
	u_int16_t id, u_int16_t seq, u_int8_t *payload, u_int32_t payload_s, unsigned char *buf);            
int sendpacket_build_tcp(u_int16_t sp, u_int16_t dp, u_int32_t seq, u_int32_t ack, u_int8_t control,
            u_int16_t win, u_int16_t urg, const char *payload, int payload_s,
            char *buf);
int sendpacket_build_udp_dual_stack(u_int16_t sp, u_int16_t dp, const char *payload, int payload_s,int,unsigned char *buf);
int sendpacket_build_ethernet(u_char *dst, u_char *src, u_short type,
            const u_char *payload, int payload_s, u_char *buf);
int sendpacket_build_arp(u_short hrd, u_short pro, u_char hln, u_char pln, u_short op,
            u_char *sha, u_char *spa, u_char *tha, u_char *tpa,
            const u_char *payload, int payload_s, u_char *buf);
int sendpacket_do_checksum(unsigned char *buf, int protocol, int len);
int sendpacket_init_packet(int p_size, char **buf);
#ifdef __cplusplus
}
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

int sendpacket_destroy_packet(char **buf);
//int MESA_sendpacket_ethlayer(int thread_index,const char *buf, int buf_len,unsigned char compat_no_use);
int sendpacket_write_link_layer(struct sendpacket_link_int *l, const char *device,u_char *buf, int len);
struct sendpacket_link_int *sendpacket_open_link_interface(char *device, char *ebuf);


int sendpacket_init(sendpacketTool *pTool,int pktsize);
int sendpacket_reset(sendpacketTool *pTool);

char * sendpacket_geterr(sendpacketTool *pTool);
int sendpacket_write(sendpacketTool *pTool,int sendlen);
int sendpacket_checkbufsize(sendpacketTool *pTool,int sendlen);

#ifdef CAPTURE_MODE_PFRING
void pfring_set_ifindex(sendpacketTool *pTool, u_char dir);
int pfring_get_sendbuf(sendpacketTool *pTool);
void pfring_release_sendbuf(sendpacketTool *pTool);
#endif


#ifdef __cplusplus
}
#endif

#endif




    
