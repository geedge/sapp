#ifdef __cplusplus
extern "C" {
#endif

#include "sysinfo.h"
#include "mesa_net.h"
#include "stream_internal.h"
#include "packet_io_internal.h"
#include "packet_io.h"
#include <MESA/MESA_handle_logger.h>
#include <MESA/MESA_htable.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>


//#define KILL_TCP_RST_NUM				(3)
#define KILL_TCP_SYN_ACK_NUM			(1) /* 虚假SYN/ACK只发送一个即可 */

typedef struct{
	UINT32 gateway_ip;	/* network order */
	UINT8 gateway_mac[ETHER_ADDR_LEN];
	char to_gateway_device_name[DEV_NAME_STR_LEN];
}sys_route_t;

//static sys_route_t g_sys_route_info;
MESA_send_handle g_send_handle[MAX_THREAD_NUM];
static volatile UINT64 g_rand_seed = 0x013579ABCDEF;

/* 兼容老平台计算rand值的算法, 用于校验RST包是否为本系统发送 */
static int randgroup[MAX_THREAD_NUM];
static int g_iRandKey=13;
static int g_iMaxRandVal=65535;

typedef struct{
	unsigned char ip_ttl;
	unsigned short ip_id_host_order;
	char __cache_align_pad_[60]; /* 多线程全局变量, 保证64字节cache对齐边界 */
}bulid_layer_ipv4_args_t;

typedef struct{
	int to_do;
}bulid_layer_ipv6_args_t;

typedef struct{
	unsigned char tcp_flags;
	unsigned short tcp_win_host_order;
	unsigned int tcp_seq;
	char __cache_align_pad_[56]; /* 多线程全局变量, 保证64字节cache对齐边界 */
}bulid_layer_tcp_args_t;


typedef struct{
	unsigned char ip_ttl;
	unsigned short ip_id_host_order;
	unsigned short tcp_win_host_order;
	char __cache_align_pad_[58]; /* 多线程全局变量, 保证64字节cache对齐边界 */
}tcp_rst_finger_mark_t;

static bulid_layer_ipv4_args_t g_build_ipv4_args[MAX_THREAD_NUM];
//static bulid_layer_ipv6_args_t g_build_ipv6_args[MAX_THREAD_NUM];
static bulid_layer_tcp_args_t g_build_tcp_args[MAX_THREAD_NUM];
static layer_args_t g_build_pkt_args[MAX_THREAD_NUM];

static tcp_rst_finger_mark_t g_tcp_rst_finger[MAX_THREAD_NUM];

extern void *g_packet_dl_send_handle[MAX_THREAD_NUM];
extern dl_io_fun_list_t dl_io_fun_list;
extern char g_send_dev_name[DEV_NAME_STR_LEN];
extern int g_packet_io_ipv6_switch;
extern int g_packet_io_ipv6_raw_socket;
extern int g_app_send_rst_type ;
extern int g_packet_io_cap_level;
extern int calc_l2tp_hdr_len(const struct l2tp_hdr_v2 *l2tp_hdr);
extern int packet_io_send_fake_pkt(MESA_send_handle *send_handle,int datalen,int send_type, 
					int low_layer_type, int dir,int thread_num,
					char *feedback_buf, int *feedback_buf_len);					
static inline int dir_check(unsigned char raw_dir);

extern MESA_htable_handle g_gtp_info_hash[MAX_THREAD_NUM];

typedef struct gtp_cache_addr_t
{
	unsigned char addr_type;
	union
	{
		unsigned int v4[2];
		unsigned int v6[32];
	};
}mpls_cache_addr_t;

struct gtp_cache_addr_t g_addr_register_for_gtp_cache[MAX_THREAD_NUM];

extern MESA_htable_handle g_mpls_info_hash[MAX_THREAD_NUM];
mpls_cache_addr_t g_mpls_cache_key[MAX_THREAD_NUM];
struct layer_addr_mpls g_mpls_register_addr[MAX_THREAD_NUM];

/*
	根据收到的字节数、与上个包的长度差、及数据包的地址部分, 得到计算随机数的种子.
*/
#if 0
void random_seed(int pkt_len, UINT64 *pkt_rand)
{
	static int last_pkt_len = 0x1234567;
	int diff = (pkt_len >= last_pkt_len)?(pkt_len-last_pkt_len):(last_pkt_len-pkt_len);
	
	g_rand_seed += (UINT64)pkt_len + (UINT64)diff + *pkt_rand;

	last_pkt_len = pkt_len;
}
#endif


UINT64 MESA_rand(void)
{
	return g_rand_seed ^ (UINT64)random();
}

/* return value: [start, end] */
UINT64 MESA_rand_range(UINT64 start, UINT64 end)
{
	UINT64 rand_num = MESA_rand();

	if(start > end){
		return end + rand_num % (start - end + 1);
	}

	return start + rand_num % (end - start + 1);
}


int set_rst_rand_key(int rnd_key)
{
	g_iRandKey = rnd_key;
	return 0;
}

int set_rst_max_rnd_val(int max_rnd_val)
{
	g_iMaxRandVal = max_rnd_val;
	return 0;
}

/*
	为了兼容老版系统, 可追踪本系统发出的RST包.
	IN ARG:
		sip, dip: network order;
		
	OUT ARG:
		ipid, win: host order;
*/
static void trick_algo_getrandval(int thread_id,unsigned sip,unsigned dip,unsigned short *ipid,unsigned short *win,u_char *ttl)
{
	int val=randgroup[thread_id];

	if(val*g_iRandKey>g_iMaxRandVal) 
	{
		randgroup[thread_id]=128;
	}
	else
	{
		randgroup[thread_id]++;
	}
	*win= (unsigned short)(val+dip%g_iRandKey);
	if(*win==0) *win=1;
	*ipid=(unsigned short)(g_iMaxRandVal-val*g_iRandKey+sip%(*win));
	*ttl=(u_char)(val % 200 + 48);

   	return;
}

/* 2014-08-26 lijia add, 可追踪本系统发出的RST包.*/
static tcp_rst_finger_mark_t *make_tcp_rst_finger_mark(int thread_id,  const raw_pkt_t *raw_pkt)
{
	tcp_rst_finger_mark_t *rst_finger;
	const struct mesa_ip4_hdr *ip4_hdr;

	rst_finger = &g_tcp_rst_finger[thread_id];

	/* NOTE, 只有IPv4能在ip_id上做些标记, IPv6暂不支持RST指纹 */
	/* TODO 2, 此处如果有隧道, 靠jump_to_layer不知道跳到哪一层, 应该用stream_private->offset_to_ip_hdr偏移到本层的IP头部 */
	ip4_hdr = (const struct mesa_ip4_hdr *)MESA_net_jump_to_layer(raw_pkt->raw_pkt_data, raw_pkt->low_layer_type, __ADDR_TYPE_IP_PAIR_V4);
	if((NULL == ip4_hdr) || (0 == sapp_global_single.cfg_kill_tcp_rst_signature)){ /* 随机填充, 无指纹信息 */
		rst_finger->ip_id_host_order = (unsigned short)MESA_rand();
		rst_finger->ip_ttl = (unsigned short)MESA_rand_range(48, 120);
		rst_finger->tcp_win_host_order = (unsigned short)MESA_rand_range(1000, 1460);
	}else{
		trick_algo_getrandval(thread_id, 
							  ip4_hdr->ip_src.s_addr, /* 2015-10-27 lijia modify */
							  ip4_hdr->ip_dst.s_addr,  /* 2015-10-27 lijia modify */
							  &rst_finger->ip_id_host_order,
							  &rst_finger->tcp_win_host_order,
							  &rst_finger->ip_ttl);
	}

	return rst_finger;
}


/*
 *  Checksum stuff
 */
#define SENDPACKET_CKSUM_CARRY(x) \
    (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))


/* 2012-04-10 LiJia add, 获取网卡IPv4地址
参数:
	device: 网卡名称
	ip_add: 存储IP地址的指针，结果为网络序.
返回值:
	0: 正常
	-1:错误
*/
int MESA_get_dev_ipv4(const char *device, int *ip_add)
{
    struct ifreq ifr;
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0)
    {
        return -1;
    }

    memset(ifr.ifr_ifrn.ifrn_name, 0, sizeof(ifr.ifr_ifrn.ifrn_name));
    strncpy(ifr.ifr_ifrn.ifrn_name, device, sizeof(ifr.ifr_ifrn.ifrn_name));
    if(ioctl(fd, SIOCGIFADDR, &ifr) == -1) 
    {
        //perror("Cann't get ip addr:");
        goto err_exit;
    }

    *ip_add = ((struct sockaddr_in*)&ifr.ifr_ifru.ifru_addr)->sin_addr.s_addr;

    close(fd);

    return 0;

err_exit:
    close(fd);
    return -1;
}


/* 2012-04-10 LiJia add, 获取网卡MAC地址
参数:
	device: 网卡名称
	mac: 存储MAC地址的数组,结果为网络序,
		 如网卡MAC地址为11:22:33:44:55:66,则mac[0]为0x11,mac[5]为0x66.
返回值:
	0: 正常
	-1:错误
*/
int MESA_get_dev_mac(const char *device, unsigned char mac[6])
{
    struct ifreq ifr;
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0)
    {
        return -1;
    }

    memset(ifr.ifr_ifrn.ifrn_name, 0, sizeof(ifr.ifr_ifrn.ifrn_name));
    strncpy(ifr.ifr_ifrn.ifrn_name, device, sizeof(ifr.ifr_ifrn.ifrn_name));
    if(ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) 
    {
        printf("Cann't get hwaddr of %s:%s\n", device, strerror(errno));
        goto err_exit;
    }

    if(ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
    {
		printf("'%s' is not ethernet interface!\n", device);
		goto err_exit;
    }

    memcpy(mac, ifr.ifr_ifru.ifru_addr.sa_data, 6);

    close(fd);

    return 0;

err_exit:
    close(fd);
    return -1;
}


/*  2012-04-11 LiJia add,将MAC字符串形式转换为16进制MAC地址.
参数:
	str:   MAC地址字符串
	delim: 字符串分隔符，常见为':', '-'等,如: xx:xx:xx:xx:xx:xx
			如果字符串无分隔符，delim设为-1.
	mac:   存储MAC地址的数组(指针),结果为网络序,
		   如网卡MAC地址为11:22:33:44:55:66,则mac[0]为0x11,mac[5]为0x66.
返回值:
	0: 正常
	-1:错误
*/
int MESA_mac_pton(const char *str, int delim, char *mac)
{
#define MAC_STR_LEN_DELIM		(17) /* length of "11:22:33:44:55:66" */
#define MAC_STR_LEN_NODELIM		(12) /* length of "112233445566" */
	const char *s = str;
	int i; 

	/* 检查输入合法性 */
	if(delim != -1)
	{
		if(strlen(str) != MAC_STR_LEN_DELIM) 
		{
			printf("MAC string length error!\n");
			return -1;
		}
	}
	else
	{
		if(strlen(str) != MAC_STR_LEN_NODELIM) 
		{
			printf("MAC string length error!\n");
			return -1;
		}
	}

	/* 检查输入合法性，同时转换成16进制值 */
	for(i = 0; i < 6; i++)
	{
		mac[i] = 0; /* 先清零，赋值语句都是或操作 */
		if(isxdigit(*s)==0)
		{
			printf("MAC string type error!\n");
			return -1;
		}
		mac[i] |= MESA_ascii_to_hex(*s) << 4;
		s++;
		
		if(isxdigit(*s)==0)
		{
			printf("MAC string type error!\n");
			return -1;
		}
		mac[i] |= MESA_ascii_to_hex(*s);
		s++;
		
		if((delim != -1) && i<5 && (*s++ != (char)delim))
		{
			printf("MAC string type error!\n");
			return -1;
		}
	}

	return 0;
}




int
sendpacket_in_cksum(u_int16_t *addr, int len)
{
    int sum;
    int nleft;
    u_int16_t ans;
    u_int16_t *w;

    sum = 0;
    ans = 0;
    nleft = len;
    w = addr;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1)
    {
        *(char *)(&ans) = *(char *)w;
        sum += ans;
    }
    return (sum);
}


int sendpacket_do_checksum(unsigned char *buf, int protocol, int len)
{
    struct mesa_ip4_hdr *iph_p;
    struct mesa_ip6_hdr *ip6h_p;
    int ip_hl;
    int sum;
    int is_ipv6 = 0;

    sum = 0;
    iph_p = (struct mesa_ip4_hdr *)buf;

    if(4 == iph_p->ip_v)  /* IP版本号字段，IPv4和IPv6格式是相同的 */
    {
        ip_hl = iph_p->ip_hl << 2;
        ip6h_p = NULL;
    }
    else if(6 == iph_p->ip_v)
    {
        ip6h_p = (struct mesa_ip6_hdr *)buf;
        iph_p = NULL;
        ip_hl = sizeof(struct mesa_ip6_hdr);
        is_ipv6 = 1;
    }
    else
    {
        return (-1);
    }

    /*
     *  Dug Song came up with this very cool checksuming implementation
     *  eliminating the need for explicit psuedoheader use.  Check it out.
     */
    switch (protocol)
    {
        /*
         *  Style note: normally I don't advocate declaring variables inside
         *  blocks of control, but it makes good sense here. -- MDS
         */
        case IPPROTO_TCP:
        {
            struct mesa_tcp_hdr *tcph_p =
                (struct mesa_tcp_hdr *)(buf + ip_hl);

#if (STUPID_SOLARIS_CHECKSUM_BUG)
            tcph_p->th_sum = tcph_p->th_off << 2;
            return (1);
#endif /* STUPID_SOLARIS_CHECKSUM_BUG */

            tcph_p->th_sum = 0;
            /* 2012-03-19 LiJia add, for IPv6 */
            if(is_ipv6)
            {
                sum = sendpacket_in_cksum((u_int16_t *)&ip6h_p->ip6_src, 32);
            }
            else
            {
                sum = sendpacket_in_cksum((u_int16_t *)&iph_p->ip_src, 8);
            }    
            sum += ntohs(IPPROTO_TCP + len);
            sum += sendpacket_in_cksum((u_int16_t *)tcph_p, len);
            tcph_p->th_sum = SENDPACKET_CKSUM_CARRY(sum);
            break;
        }
        
        case IPPROTO_UDP:
        {
            struct mesa_udp_hdr *udph_p =
                (struct mesa_udp_hdr *)(buf + ip_hl);

            udph_p->uh_sum = 0;
            /* 2012-03-19 LiJia add, for IPv6 */
            if(is_ipv6)
            {
                sum = sendpacket_in_cksum((u_int16_t *)&ip6h_p->ip6_src, 32);
            }
            else
            {
                sum = sendpacket_in_cksum((u_int16_t *)&iph_p->ip_src, 8);
            }   
            sum += ntohs(IPPROTO_UDP + len);
            sum += sendpacket_in_cksum((u_int16_t *)udph_p, len);
            udph_p->uh_sum = SENDPACKET_CKSUM_CARRY(sum);
            break;
        }
        
        case IPPROTO_IP: /* Dummy protocol for TCP.  */
        {
            iph_p->ip_sum = 0;
            sum = sendpacket_in_cksum((u_int16_t *)iph_p, len);
            iph_p->ip_sum = SENDPACKET_CKSUM_CARRY(sum);
            break;
        }

        case IPPROTO_ICMP:
        {
            struct mesa_icmp_hdr *icmph_p =
                (struct mesa_icmp_hdr *)(buf + ip_hl);

            icmph_p->icmp_sum = 0;
            sum = sendpacket_in_cksum((u_short *)icmph_p, len);
            icmph_p->icmp_sum = SENDPACKET_CKSUM_CARRY(sum);
            break;
        }
        
        default:
        {
            return (-1);
        }
    }
    return (1);
}

int sendpacket_build_ipv4(u_int16_t carry_layer_len, u_int8_t tos, u_int16_t id, u_int16_t frag, 
		u_int8_t ttl, u_int8_t prot, u_int32_t src, u_int32_t dst, const char *payload,
		int payload_s, unsigned char *buf)
{
	struct mesa_ip4_hdr *ip_hdr;

	if (!buf){
	    return (-1);
	}

	ip_hdr = (struct mesa_ip4_hdr *)buf;

	ip_hdr->ip_v    = 4;                             /* version 4 */
	ip_hdr->ip_hl   = 5;                             /* 20 byte header */
	ip_hdr->ip_tos  = tos;                           /* IP tos */
	ip_hdr->ip_len  = htons(SENDPACKET_IP_H + carry_layer_len);      /* total length */
	ip_hdr->ip_id   = htons(id);                     /* IP ID */
	ip_hdr->ip_off  = htons(frag);                   /* fragmentation flags */
	ip_hdr->ip_ttl  = ttl;                           /* time to live */
	ip_hdr->ip_p    = prot;                          /* transport protocol */
	ip_hdr->ip_sum  = 0;                             /* do this later */
	ip_hdr->ip_src.s_addr = src; /* 为什么地址用网络序? 历史遗留原因, 改动太多,只能这么继续了 */
	ip_hdr->ip_dst.s_addr = dst; /* 为什么地址用网络序? 历史遗留原因, 改动太多,只能这么继续了 */
	if (payload && payload_s){
	    /*
	     *  Unchecked runtime error for buf + IP_H + payload to be greater than
	     *  the allocated heap memory.
	     */
		memcpy(buf + SENDPACKET_IP_H, payload, payload_s);
	}
	//memcpy((char *)buf, (char *)&ip_hdr, sizeof(ip_hdr));
	
	return (0);
}


/* TODO 2: 带扩展头部的IPv6包 */
int sendpacket_build_ipv6(u_int8_t traffic_class, u_int32_t flow_lable,
                              u_int16_t len, u_int8_t next_header, u_int8_t hop,
                              const struct in6_addr *src, const struct in6_addr *dst,
                              const char *payload, int payload_s, unsigned char *buf)
{
	struct mesa_ip6_hdr *ip6_h;

	if(!buf){
		return -1;
	}

	ip6_h = (struct mesa_ip6_hdr *)buf;

	memset(ip6_h, 0, sizeof(struct mesa_ip6_hdr));

	ip6_h->ip6_flags[0]      = 0x60 | ((traffic_class & 0xF0) >> 4);
	ip6_h->ip6_flags[1]      = ((traffic_class & 0x0F) << 4) | ((flow_lable & 0xF0000) >> 16);
	ip6_h->ip6_flags[2]      = flow_lable & 0x0FF00 >> 8;
	ip6_h->ip6_flags[3]      = flow_lable & 0x000FF;
	ip6_h->ip6_payload_len   = htons(len);
	ip6_h->ip6_nxt_hdr       = next_header;
	ip6_h->ip6_hop           = hop;
	memcpy(&ip6_h->ip6_src, src, sizeof(struct in6_addr));
	memcpy(&ip6_h->ip6_dst, dst, sizeof(struct in6_addr));

	if(payload && payload_s)
	{
	    /*
	     *  Unchecked runtime error for buf + IP_H + payload to be greater than
	     *  the allocated heap memory.
	    */
		memcpy(buf + sizeof(struct mesa_ip6_hdr), payload, payload_s);
	}

	//memcpy(buf, &ip6_h, sizeof(struct mesa_ip6_hdr));

	return 0;
}

/* 2012-04-10 LiJia add, 用于构建ICMP-ECHO-REQUEST, ICMP-ECHO-REPLAY包 */
int sendpacket_build_icmpv4_echo(u_int8_t type, u_int8_t code, u_int16_t sum,
	u_int16_t id, u_int16_t seq, u_int8_t *payload, u_int32_t payload_s, unsigned char *buf)
{
	struct mesa_icmp_echo_hdr icmp_hdr;

	icmp_hdr.icmp_type = type;
	icmp_hdr.icmp_code = code;
	icmp_hdr.icmp_cksum = 0; /* checksum done in userland */ 
	icmp_hdr.icd_id = htons(id);
	icmp_hdr.icd_seq = htons(seq);

	if(payload && payload_s){
		/*
		 *  Unchecked runtime error for buf + IP_H + payload to be greater than
		 *  the allocated heap memory.
		*/
		memcpy(buf + sizeof(struct mesa_icmp_echo_hdr), payload, payload_s);
	}

	memcpy(buf, &icmp_hdr, sizeof(struct mesa_icmp_echo_hdr));

	return 0;
}


int sendpacket_build_tcp(u_int16_t sp, u_int16_t dp, u_int32_t seq, u_int32_t ack, 
						u_int8_t th_flags, u_int16_t win, u_int16_t urg, 
						const char *payload, int payload_s, unsigned char *buf)
{
	struct mesa_tcp_hdr *tcp_hdr;

	if (!buf){
	    return (-1);
	}

	tcp_hdr = (struct mesa_tcp_hdr *)buf;

	tcp_hdr->th_sport   = htons(sp);    /* source port */
	tcp_hdr->th_dport   = htons(dp);    /* destination port */
	tcp_hdr->th_seq     = htonl(seq);   /* sequence number */
	tcp_hdr->th_ack     = htonl(ack);   /* acknowledgement number */
	tcp_hdr->th_flags   = th_flags;      /* control flags */
	tcp_hdr->th_x2      = 0;            /* UNUSED */
	tcp_hdr->th_off     = 5;            /* 20 byte header */
	tcp_hdr->th_win     = htons(win);   /* window size */
	tcp_hdr->th_sum     = 0;            /* checksum done in userland */ 
	tcp_hdr->th_urp     = urg;          /* urgent pointer */

	if (payload && payload_s){
	    /*
	     *  Unchecked runtime error for buf + TCP_H + payload to be greater
	     *  than the allocated heap memory.
	     */
	    memcpy(buf + SENDPACKET_TCP_H, payload, payload_s);
	}
	//memcpy((char *)buf, (char *)&tcp_hdr, sizeof(tcp_hdr));
	
	return (0);
}

int sendpacket_build_tcp_with_option(u_int16_t sp, u_int16_t dp, u_int32_t seq, 
					u_int32_t ack, u_int8_t control,u_int16_t win, u_int16_t urg, 
					const char *option, int option_len, const char *payload, int payload_s,
            				unsigned char *buf)
{
	struct mesa_tcp_hdr tcp_hdr;

	if (!buf){
	    return (-1);
	}
	if((option_len % 4) != 0){
		return (-2);
	}

	tcp_hdr.th_sport   = htons(sp);    /* source port */
	tcp_hdr.th_dport   = htons(dp);    /* destination port */
	tcp_hdr.th_seq     = htonl(seq);   /* sequence number */
	tcp_hdr.th_ack     = htonl(ack);   /* acknowledgement number */
	tcp_hdr.th_flags   = control;      /* control flags */
	tcp_hdr.th_x2      = 0;            /* UNUSED */
	tcp_hdr.th_off     = 5 + option_len/4;            /* 20 byte header + option_len */
	tcp_hdr.th_win     = htons(win);   /* window size */
	tcp_hdr.th_sum     = 0;            /* checksum done in userland */ 
	tcp_hdr.th_urp     = urg;          /* urgent pointer */

	if(option && option_len){
		memcpy(buf + SENDPACKET_TCP_H, option, option_len);
	}

	if (payload && payload_s){
	    /*
	     *  Unchecked runtime error for buf + TCP_H + payload to be greater
	     *  than the allocated heap memory.
	     */
	    memcpy(buf + SENDPACKET_TCP_H + option_len, payload, payload_s);
	}
	memcpy((char *)buf, (char *)&tcp_hdr, sizeof(struct mesa_tcp_hdr));
	return (0);
}

int sendpacket_build_udp(u_int16_t sp, u_int16_t dp, const char *payload, int payload_s,
            unsigned char *buf)
{
    struct mesa_udp_hdr udp_hdr;

    if (!buf)
    {
        return (-1);
    }

    udp_hdr.uh_sport   = htons(sp);                /* source port */
    udp_hdr.uh_dport   = htons(dp);                /* destination port */
    udp_hdr.uh_ulen    = htons(SENDPACKET_UDP_H + payload_s);   /* total length */
    udp_hdr.uh_sum     = 0;                        /* checksum */

    if (payload && payload_s)
    {
        /*
         *  Unchecked runtime error for buf + UDP_H + payload to be greater
         *  than the allocated heap memory.
         */
        memcpy(buf + SENDPACKET_UDP_H, payload, payload_s);
    } 
    memcpy(buf, &udp_hdr, sizeof(udp_hdr));
    return (1);
}

/* lijia add carry_layer_len args, 
	在嵌套、隧道模式下构造数据包, 没有payload, 但实际还有上层协议, 如teredo, 等协议时使用.
*/
int sendpacket_build_udp_dual_stack(u_int16_t sp, u_int16_t dp, const char *payload, 
					int payload_s, int carry_layer_len, unsigned char *buf)
{
	struct mesa_udp_hdr *udp_hdr;

	if (!buf){
	    return (-1);
	}

	udp_hdr = (struct mesa_udp_hdr *)buf;

	udp_hdr->uh_sport   = htons(sp);                /* source port */
	udp_hdr->uh_dport   = htons(dp);                /* destination port */
	udp_hdr->uh_ulen    = htons(SENDPACKET_UDP_H + carry_layer_len);   /* total length */
	udp_hdr->uh_sum     = 0;                        /* checksum */

	if (payload && payload_s){
	    /*
	     *  Unchecked runtime error for buf + UDP_H + payload to be greater
	     *  than the allocated heap memory.
	     */
	    memcpy(buf + SENDPACKET_UDP_H, payload, payload_s);
	} 
	//memcpy(buf, &udp_hdr, sizeof(udp_hdr));
	return (0);
}

int sendpacket_build_arp(u_short hrd, u_short pro, u_char hln, u_char pln, u_short op,
	            u_char *sha, u_char *spa, u_char *tha, u_char *tpa,
	            const u_char *payload, int payload_s, u_char *buf)
{
	struct mesa_arp_hdr arp_hdr;

	if (!buf){
	    return (-1);
	}

	arp_hdr.ar_hrd = htons(hrd);       /* hardware address type */
	arp_hdr.ar_pro = htons(pro);       /* protocol address type */
	arp_hdr.ar_hln = hln;              /* hardware address length */
	arp_hdr.ar_pln = pln;              /* protocol address length */
	arp_hdr.ar_op  = htons(op);        /* opcode command */
	memcpy(arp_hdr.ar_sha, sha, hln);  /* sender hardware address */
	memcpy(arp_hdr.ar_spa, spa, pln);  /* sender protocol (IP) address */
	memcpy(arp_hdr.ar_tha, tha, hln);  /* target hardware address */
	memcpy(arp_hdr.ar_tpa, tpa, pln);  /* target protocol (IP) address */

	if (payload && payload_s){
	    /*
	     *  Unchecked runtime error for buf + LIBNET_ARP_H payload to be
	     *  greater than the allocated heap memory.
	     */
	    memcpy(buf + SENDPACKET_ARP_H, payload, payload_s);
	}
	memcpy(buf, &arp_hdr, sizeof(arp_hdr));
	return (0);
}


/*
	if playload2 is not NULL, it means that there is ip spice, it must be copied first, then 
	playload is copied
	otherwise, only payload is copied and it includes ip header
*/
int sendpacket_build_ethernet(u_char *dst, u_char *src, u_short type,
            				const u_char *payload, int payload_s, u_char *buf)
{
	struct mesa_ethernet_hdr eth_hdr;

	if (!buf){
	    return (-1);
	}

	memcpy(eth_hdr.ether_dhost, dst, ETHER_ADDR_LEN);  /* destination address */
	memcpy(eth_hdr.ether_shost, src, ETHER_ADDR_LEN);  /* source address */
	eth_hdr.ether_type = htons(type);                  /* packet type */

	if (payload && payload_s)
	{
	    /*
	     *  Unchecked runtime error for buf + ETH_H payload to be greater than
	     *  the allocated heap memory.
	     */
	    memcpy(buf + SENDPACKET_ETH_H, payload, payload_s);
	}
	memcpy(buf, &eth_hdr, sizeof(eth_hdr));
	return (0);
}

#if 0
static int __do_kill_tcp(sendpacketTool *pSend, int thread_num, char CtoS_dir, char StoC_dir,
		u_int32_t sip,ushort sid,ushort sport,u_int32_t sseq,u_int32_t sack,
		u_int32_t dip,ushort did,ushort dport,u_int32_t dseq,u_int32_t dack)
{
	u_char sttl, dttl;
	ushort swin, dwin, nouse;
	int i, n_rst;
	  int sendnum=0;
#ifdef USE_TIME_TEST
         struct timeval tv;
        long begintime,endtime;
        gettimeofday(&tv, 0);
        begintime = tv.tv_sec* 1000*1000 + tv.tv_usec;

#endif

	sip = htonl(sip);
#if 1	
	dip = htonl(dip);
#else /* test  */	
	dip = htonl(0x0A00069A);
#endif
	if((0 == rst_whom || 2 == rst_whom) && (0!=sseq)) {	/* rst server */
		if(0 == sip || 0 == sport) return -1;

		 //如果使用发包，那么每次需要重新得到缓冲区
        if(g_UseSendpktCard)
    	{
			pSend->send_buf=(char *)getbuffrompag(thread_num);
    	}

		//if(0 != param->n_rst) n_rst = param->n_rst;
		//else	n_rst=num_of_rst_tos_send;
		n_rst = num_of_rst_to_send;
		for(i = 0; i < n_rst; i ++) 
		{
		    getrandval(thread_num,sip,dip,&nouse,&swin,&sttl);
		    if(-1 == sendpacket_build_ip(SENDPACKET_TCP_H, 0, sid, 0x4000, sttl,
			IPPROTO_TCP, sip, dip, NULL, 0, pSend->send_buf))
		    {
				pSend->errflag=SEND_PACKET_IP_ERR;
				return -1;
		    }
		    if(-1 == sendpacket_build_tcp(sport,dport,sseq,sack,
				TH_RST|TH_ACK, swin, 0,NULL, 0,
				pSend->send_buf + SENDPACKET_IP_H))
		     {
			  pSend->errflag=SEND_PACKET_TCP_ERR;
			  return -1;
		      }
			if(-1 == sendpacket_do_checksum(pSend->send_buf,
				IPPROTO_TCP, SENDPACKET_TCP_H))
			{
			  pSend->errflag=SEND_PACKET_CHECKSUM_ERR;
			  return -1;
		      }
		      sendpacket_do_checksum(pSend->send_buf, IPPROTO_IP, SENDPACKET_IP_H);
			pSend->send_buf_location = 1;
			pSend->send_ptr = pSend->send_buf;		      
			sendnum=sendpacket_write_new(pSend, SENDPACKET_TCP_H + SENDPACKET_IP_H, CtoS_dir);
			if(sendnum==-1)
			{
			  return -1;
			}
			
			g_OutInfo.rstnum[thread_num]++;
			sseq += 1460 * (i + 1);
			//如果使用重新获得缓冲区
			if(g_UseSendpktCard)
			{
			   if(i<n_rst-1)
			   pSend->send_buf=(char *)regetbuffrompag(thread_num,pSend->send_buf,0,SENDPACKET_IP_H);
			}
		}
		 //如果使用发包，那么每次需要重新得到缓冲区
        if(g_UseSendpktCard)
    	{
            	pag_freesendbuf(thread_num);
    	}

	}
	if ((0 == rst_whom || 1 == rst_whom)&&(0!=dseq)) {	/* rst client */
		if(0 == dip || 0 == dport) return -1;
		  //如果使用发包，那么每次需要重新得到缓冲区
                if(g_UseSendpktCard)
                {
                        pSend->send_buf=(char *)getbuffrompag(thread_num);
                }


		//if(0 != param->n_rst) n_rst = param->n_rst;
		//else	n_rst=num_of_rst_toc_send;
		n_rst = num_of_rst_to_send;
		for(i = 0; i < n_rst; i ++) {
		
			getrandval(thread_num,sip,dip,&nouse,&dwin,&dttl);
			
			if(-1 == sendpacket_build_ip(SENDPACKET_TCP_H, 0, did, 0x4000, dttl,
				IPPROTO_TCP, dip, sip, NULL, 0, pSend->send_buf))
			{
				pSend->errflag=SEND_PACKET_IP_ERR;
				return -1;
			}
			if(-1 == sendpacket_build_tcp(dport,sport,dseq,dack,
				TH_RST|TH_ACK, dwin, 0, NULL, 0,
				pSend->send_buf + SENDPACKET_IP_H))
			{
			  pSend->errflag=SEND_PACKET_TCP_ERR;
			  return -1;
		      }
			if(-1 == sendpacket_do_checksum(pSend->send_buf,
				IPPROTO_TCP, SENDPACKET_TCP_H))
		      {
			  pSend->errflag=SEND_PACKET_CHECKSUM_ERR;
			  return -1;
		      }
		      	sendpacket_do_checksum(pSend->send_buf, IPPROTO_IP, SENDPACKET_IP_H);

			pSend->send_buf_location = 1;
			pSend->send_ptr = pSend->send_buf;	
			sendnum=sendpacket_write_new(pSend, SENDPACKET_TCP_H + SENDPACKET_IP_H, StoC_dir);
			if(sendnum==-1)
			{
			   return -1;
			}

			g_OutInfo.rstnum[thread_num]++;
			dseq += 1460 * (i + 1);
			//如果使用,重新获得缓冲区
			if(g_UseSendpktCard)
			{
			   if(i<n_rst-1)
			   pSend->send_buf=(char *)regetbuffrompag(thread_num,pSend->send_buf,0,SENDPACKET_IP_H);
			}
		}
		  //如果使用发包，那么每次需要重新得到缓冲区
            if(g_UseSendpktCard)
            {
                    pag_freesendbuf(thread_num);
            }
	}
	
#ifdef USE_TIME_TEST
        gettimeofday(&tv, 0);
        endtime = tv.tv_sec* 1000*1000 + tv.tv_usec;
        killcount++;
        killtime+=endtime-begintime;
        if(killcount%10000==0)
        {
           fprintf(stderr,"killcount=%lu,average usetime is %lu\n",killcount,(killtime-oldtime)/10000);
	  MESA_runtime_log(RLOG_LV_INFO, "KILL TCP COUNT:", "killcount=%lu,average usetime is %lu\n",killcount,(killtime-oldtime)/10000);
           oldtime=killtime;
        }
#endif	
	return 0;
}


int MESA_kill_tcp(struct streaminfo *stream)
{
	u_int32_t sip, sseq, sack, dip, dseq, dack, payload;
	u_int16_t sid, sport, did, dport;
	struct tcphdr *thdr;
	sendpacketTool *pTool;
	unsigned char C2S_dir, S2C_dir;

	thdr = (struct tcphdr*)((u_int8_t *)a_packet + (a_packet->ip_hl << 2) );

	payload = ntohs(a_packet->ip_len) - ((a_packet->ip_hl) << 2) - ((thdr->th_off) << 2);
	if(0 != (TH_SYN & thdr->th_flags))
	       payload ++;
	
	sip = ntohl((a_packet->ip_src).s_addr);
	sseq = ntohl(thdr->th_seq) + payload;
	sack = ntohl(thdr->th_ack);
	dip = ntohl((a_packet->ip_dst).s_addr);
	dseq = ntohl(thdr->th_ack);
	dack = ntohl(thdr->th_seq) + payload;
#if 1	
	sid = a_packet->ip_id;	/* sender host byte order */
	did = 128;
#else /* test  */
	sid = 0x1234;
	did = 0xdddd;
#endif

	sport = ntohs(thdr->th_sport);
	dport = ntohs(thdr->th_dport);

	pTool = &g_SendPacketTools[stream->threadnum];

	if(1 == stream->curdir)
	{
		C2S_dir = stream->routedir;
		S2C_dir = stream->routedir ^ 0x80;
	}
	else
	{
		S2C_dir = stream->routedir;
		C2S_dir = stream->routedir ^ 0x80;
	}
	
	return __do_kill_tcp(pTool, stream->threadnum, (char)C2S_dir, (char)S2C_dir,
					     sip, sid, sport, sseq, sack,
		                 dip, did, dport, dseq, dack);
}
#endif

static int calc_mpls_hdr_len(int reverse, struct streaminfo_private * stream_pr)
{
	int hdr_len = 0;
    const struct layer_addr_mpls *mpls_addr = stream_pr->stream_public.addr.mpls;
    int threadnum = stream_pr->stream_public.threadnum;
    struct layer_addr_mpls *cache_mpls_addr, *tmp_mpls_addr = &g_mpls_register_addr[threadnum];
    void *mpls_hash_key = (g_mpls_cache_key[threadnum].addr_type == ADDR_TYPE_IPV4)?g_mpls_cache_key[threadnum].v4:g_mpls_cache_key[threadnum].v6;
    int mpls_hash_key_len = (g_mpls_cache_key[threadnum].addr_type == ADDR_TYPE_IPV4)?sizeof(g_mpls_cache_key[threadnum].v4):sizeof(g_mpls_cache_key[threadnum].v6);
    const void *raw_mpls_hdr = (const char *)stream_pr->raw_pkt->raw_pkt_data + stream_pr->offset_to_raw_pkt_hdr;

    memset(tmp_mpls_addr, 0, sizeof(struct layer_addr_mpls));

    if(mpls_addr->dest_mpls_layer_num == 0 && mpls_addr->src_mpls_layer_num == 0)
    {
            if(g_mpls_info_hash[threadnum])
            {
                cache_mpls_addr = (struct layer_addr_mpls *)MESA_htable_search(g_mpls_info_hash[threadnum], (unsigned char*)mpls_hash_key, mpls_hash_key_len);
                memcpy(tmp_mpls_addr->src_mpls_pkt, cache_mpls_addr->src_mpls_pkt, cache_mpls_addr->src_mpls_layer_num*sizeof(struct mesa_mpls_hdr));
                hdr_len = cache_mpls_addr->src_mpls_layer_num*sizeof(struct mesa_mpls_hdr);
            }
    }
    else if(mpls_addr->dest_mpls_layer_num > 0 && mpls_addr->src_mpls_layer_num > 0)
    {
        if(reverse == 0)
        {
            if(0 == memcmp(mpls_addr->src_mpls_pkt, raw_mpls_hdr, sizeof(struct mesa_mpls_hdr)*(mpls_addr->src_mpls_layer_num)))
            {
                memcpy(tmp_mpls_addr->src_mpls_pkt, mpls_addr->src_mpls_pkt, mpls_addr->src_mpls_layer_num*sizeof(struct mesa_mpls_hdr));
                hdr_len = sizeof(struct mesa_mpls_hdr)*mpls_addr->src_mpls_layer_num;
            }
            else
            {
                memcpy(tmp_mpls_addr->src_mpls_pkt, mpls_addr->dest_mpls_pkt, mpls_addr->dest_mpls_layer_num*sizeof(struct mesa_mpls_hdr));
                hdr_len = sizeof(struct mesa_mpls_hdr)*mpls_addr->dest_mpls_layer_num;
            }
        }
        else
        {
            if(0 == memcmp(mpls_addr->src_mpls_pkt, raw_mpls_hdr, sizeof(struct mesa_mpls_hdr)*(mpls_addr->src_mpls_layer_num)))
            {
                memcpy(tmp_mpls_addr->src_mpls_pkt, mpls_addr->dest_mpls_pkt, mpls_addr->dest_mpls_layer_num*sizeof(struct mesa_mpls_hdr));
                hdr_len = sizeof(struct mesa_mpls_hdr)*mpls_addr->dest_mpls_layer_num;
            }
            else
            {
                memcpy(tmp_mpls_addr->src_mpls_pkt, mpls_addr->src_mpls_pkt, mpls_addr->src_mpls_layer_num*sizeof(struct mesa_mpls_hdr));
                hdr_len = sizeof(struct mesa_mpls_hdr)*mpls_addr->src_mpls_layer_num;
            }
        }
    }
    else if(mpls_addr->src_mpls_layer_num > 0)
    {
        if(reverse == 0)
        {
            if(0 == memcmp(mpls_addr->src_mpls_pkt, raw_mpls_hdr, sizeof(struct mesa_mpls_hdr)*(mpls_addr->src_mpls_layer_num)))
            {
                memcpy(tmp_mpls_addr->src_mpls_pkt, mpls_addr->src_mpls_pkt, mpls_addr->src_mpls_layer_num*sizeof(struct mesa_mpls_hdr));
                hdr_len = sizeof(struct mesa_mpls_hdr)*mpls_addr->src_mpls_layer_num;
            }
            else
            {
                if(g_mpls_info_hash[threadnum])
                {
                    cache_mpls_addr = (struct layer_addr_mpls *)MESA_htable_search(g_mpls_info_hash[threadnum], (unsigned char*)mpls_hash_key, mpls_hash_key_len);
                    memcpy(tmp_mpls_addr->src_mpls_pkt, cache_mpls_addr->src_mpls_pkt, cache_mpls_addr->src_mpls_layer_num*sizeof(struct mesa_mpls_hdr));
                    hdr_len = cache_mpls_addr->src_mpls_layer_num*sizeof(struct mesa_mpls_hdr);
                }
            }
        }
        else
        {
            if(0 == memcmp(mpls_addr->src_mpls_pkt, raw_mpls_hdr, sizeof(struct mesa_mpls_hdr)*(mpls_addr->src_mpls_layer_num)))
            {
                if(g_mpls_info_hash[threadnum])
                {
                    cache_mpls_addr = (struct layer_addr_mpls *)MESA_htable_search(g_mpls_info_hash[threadnum], (unsigned char*)mpls_hash_key, mpls_hash_key_len);
                    memcpy(tmp_mpls_addr->src_mpls_pkt, cache_mpls_addr->src_mpls_pkt, cache_mpls_addr->src_mpls_layer_num*sizeof(struct mesa_mpls_hdr));
                    hdr_len = cache_mpls_addr->src_mpls_layer_num*sizeof(struct mesa_mpls_hdr);              }
            }
            else
            {
                memcpy(tmp_mpls_addr->src_mpls_pkt, mpls_addr->src_mpls_pkt, mpls_addr->src_mpls_layer_num*sizeof(struct mesa_mpls_hdr));
                hdr_len = sizeof(struct mesa_mpls_hdr)*mpls_addr->src_mpls_layer_num;
            }
        }
    }
    else
    {
        if(reverse == 0)
        {
            if(0 == memcmp(mpls_addr->dest_mpls_pkt, raw_mpls_hdr, sizeof(struct mesa_mpls_hdr)*(mpls_addr->dest_mpls_layer_num)))
            {
                memcpy(tmp_mpls_addr->src_mpls_pkt, mpls_addr->dest_mpls_pkt, mpls_addr->dest_mpls_layer_num*sizeof(struct mesa_mpls_hdr));
                hdr_len = sizeof(struct mesa_mpls_hdr)*mpls_addr->dest_mpls_layer_num;
            }
            else
            {
                if(g_mpls_info_hash[threadnum])
                {
                    cache_mpls_addr = (struct layer_addr_mpls *)MESA_htable_search(g_mpls_info_hash[threadnum], (unsigned char*)mpls_hash_key, mpls_hash_key_len);
                    memcpy(tmp_mpls_addr->src_mpls_pkt, cache_mpls_addr->src_mpls_pkt, cache_mpls_addr->src_mpls_layer_num*sizeof(struct mesa_mpls_hdr));
                    hdr_len = cache_mpls_addr->src_mpls_layer_num*sizeof(struct mesa_mpls_hdr);
                }
            }
        }
        else
        {
            if(0 == memcmp(mpls_addr->dest_mpls_pkt, raw_mpls_hdr, sizeof(struct mesa_mpls_hdr)*(mpls_addr->dest_mpls_layer_num)))
            {
                if(g_mpls_info_hash[threadnum])
                {
                    cache_mpls_addr = (struct layer_addr_mpls *)MESA_htable_search(g_mpls_info_hash[threadnum], (unsigned char*)mpls_hash_key, mpls_hash_key_len);
                    memcpy(tmp_mpls_addr->src_mpls_pkt, cache_mpls_addr->src_mpls_pkt, cache_mpls_addr->src_mpls_layer_num*sizeof(struct mesa_mpls_hdr));
                    hdr_len = cache_mpls_addr->src_mpls_layer_num*sizeof(struct mesa_mpls_hdr);
                }
            }
            else
            {
                memcpy(tmp_mpls_addr->src_mpls_pkt, mpls_addr->dest_mpls_pkt, mpls_addr->dest_mpls_layer_num*sizeof(struct mesa_mpls_hdr));
                hdr_len = sizeof(struct mesa_mpls_hdr)*mpls_addr->dest_mpls_layer_num;
            }
        }
    }

	return hdr_len;
}

static int calc_gtp_hdr_len(const struct gtp_hdr *gtp_hdr)
{
	int hdr_len = sizeof(struct gtp_hdr);

	if(gtp_hdr->flags&0x02)
	{
		hdr_len += sizeof(unsigned int);
        sapp_runtime_log(RLOG_LV_FATAL, "%s:%d: MESA_kill_tcp() calc_gtp_hdr_len include GTP not support correct SEQ!", __FILE__, __LINE__);
    }
	return hdr_len;
}

/*
	1-计算所有包头的长度, 用于预留空间. 计算到最底层协议, 如果有MAC也包含MAC头空间;
	2-递归过程中获取Ethernet层承载的协议类型.
*/
static int calc_reserved_hdr_len(struct streaminfo *stream, int *net_layer_type)
{
	int  reserved_hdr_len = 0;
    struct streaminfo_private *stream_pr = (struct streaminfo_private *)stream;
    const raw_pkt_t *raw_pkt;

	if(NULL == stream){ /* 递归计算终结条件! */
		return 0;
	}
    raw_pkt = (const raw_pkt_t *)stream_pr->raw_pkt;
	if(is_proxy_stream(stream)){ /* 代理流结构为虚拟结构, 实际构造包时跳过不处理 */
		reserved_hdr_len = 0;
		goto done;
	}
	
	switch(stream->addr.addrtype){
		case ADDR_TYPE_IPV4:
			/* 2015-12-30 lijia modify, IP和端口同时存储于此结构 */
			if(STREAM_TYPE_TCP == stream->type){
				reserved_hdr_len = sizeof(struct mesa_tcp_hdr) + sizeof(struct mesa_ip4_hdr);
			}else if (STREAM_TYPE_UDP == stream->type){
				reserved_hdr_len = sizeof(struct mesa_udp_hdr) + sizeof(struct mesa_ip4_hdr);
			}else{
				printf("addr type is tuple4v4, but stream type is not TCP or UDP!\n");
				sapp_runtime_log(RLOG_LV_FATAL, "%s:%d: addr type is tuple4v4, but stream type is :%d, not TCP or UDP.\n", __FILE__, __LINE__, stream->type);		
				return -1;
				//assert(0);
			}
            if(stream->pfather != NULL &&
               stream->pfather->addr.addrtype == ADDR_TYPE_MPLS &&
               g_mpls_info_hash[stream->threadnum] != NULL)
            {
                struct mesa_ip4_hdr *raw_ip4_hdr = (struct mesa_ip4_hdr *)(stream_pr->offset_to_raw_pkt_hdr + (char *)raw_pkt->raw_pkt_data);
                g_mpls_cache_key[stream->threadnum].addr_type = ADDR_TYPE_IPV4;
                g_mpls_cache_key[stream->threadnum].v4[0] = raw_ip4_hdr->ip_dst.s_addr;
                g_mpls_cache_key[stream->threadnum].v4[1] = raw_ip4_hdr->ip_src.s_addr;
            }
		break;
		
		case ADDR_TYPE_IPV6:
			/* 2015-12-30 lijia modify, IP和端口同时存储于此结构 */
			if(STREAM_TYPE_TCP == stream->type){
				reserved_hdr_len = sizeof(struct mesa_tcp_hdr) + sizeof(struct mesa_ip6_hdr);;
			}else if (STREAM_TYPE_UDP == stream->type){
				reserved_hdr_len = sizeof(struct mesa_udp_hdr) + sizeof(struct mesa_ip6_hdr);;
			}else{
				printf("addr type is tuple4v6, but stream type is not TCP or UDP!\n");
				sapp_runtime_log(RLOG_LV_FATAL, "%s:%d: addr type is tuple4v6, but stream type is :%d, not TCP or UDP.\n", __FILE__, __LINE__, stream->type);		
				return -1;
				//assert(0);
			}
            if(stream->pfather != NULL &&
               stream->pfather->addr.addrtype == ADDR_TYPE_MPLS &&
               g_mpls_info_hash[stream->threadnum] != NULL)
            {
                struct mesa_ip6_hdr *raw_ip6_hdr = (struct mesa_ip6_hdr *)(stream_pr->offset_to_raw_pkt_hdr + (char *)raw_pkt->raw_pkt_data);
                g_mpls_cache_key[stream->threadnum].addr_type = ADDR_TYPE_IPV6;
                memcpy(g_mpls_cache_key[stream->threadnum].v6, &raw_ip6_hdr->ip6_dst, sizeof(struct in6_addr));
                memcpy((char *)(g_mpls_cache_key[stream->threadnum].v6) + sizeof(struct in6_addr), &raw_ip6_hdr->ip6_src, sizeof(struct in6_addr));
            }
		break;

		case ADDR_TYPE_VLAN:
			reserved_hdr_len = VLAN_TAG_LEN;
		break;

		case ADDR_TYPE_MAC:
			reserved_hdr_len = sizeof(struct mesa_ethernet_hdr);
		break;

		case ADDR_TYPE_ARP:
			printf("Sendpacket use ARP!\n");
			sapp_runtime_log(RLOG_LV_FATAL, "%s:%d: Sendpacket use ARP.\n", __FILE__, __LINE__);		
			return -1;
			//assert(0);
		break;

		case ADDR_TYPE_GRE:
		{
			reserved_hdr_len = calc_gre_hdr_len(
						   (const struct mesa_gre_hdr *)((const char *)stream_pr->raw_pkt->raw_pkt_data + stream_pr->offset_to_raw_pkt_hdr));
		}
		break;

		case ADDR_TYPE_MPLS:
			reserved_hdr_len = calc_mpls_hdr_len(1, stream_pr);
		break;
		
		case ADDR_TYPE_PPPOE_SES:
			reserved_hdr_len = sizeof(struct mesa_pppoe_session_hdr);
		break;
		
		case ADDR_TYPE_TCP:
			/* to do, 如果发送带选项的包, 而且和原始包不一样的话, 怎么计算? 
				先预留最大长度, 然后根据实际选项长度, 用memmove移动已构造的负载.
			*/
			reserved_hdr_len = sizeof(struct mesa_tcp_hdr);
		break;
		
		case ADDR_TYPE_UDP:
			reserved_hdr_len = sizeof(struct mesa_udp_hdr);
		break;

		case ADDR_TYPE_L2TP:
		{
			stream_pr = (struct streaminfo_private *)stream;
			reserved_hdr_len = calc_l2tp_hdr_len(
						   (const struct l2tp_hdr_v2 *)((const char *)stream_pr->raw_pkt->raw_pkt_data + stream_pr->offset_to_raw_pkt_hdr));
		}
		break;
		case ADDR_TYPE_GPRS_TUNNEL:
		{
			stream_pr = (struct streaminfo_private *)stream;
			reserved_hdr_len = calc_gtp_hdr_len(
					(const struct gtp_hdr *)((const char *)stream_pr->raw_pkt->raw_pkt_data + stream_pr->offset_to_raw_pkt_hdr));
		}
			break;

		case __ADDR_TYPE_IP_PAIR_V4:
			/* to do, 如果构造带选项的包, 怎么计算? */
			reserved_hdr_len = sizeof(struct mesa_ip4_hdr);
		break;
		
		case __ADDR_TYPE_IP_PAIR_V6:
			/* to do, 如果构造带选项的包, 怎么计算? */
			reserved_hdr_len = sizeof(struct mesa_ip6_hdr);
		break;

		case ADDR_TYPE_PPP:
			assert(0); /* 不再单独设PPP层, 和L2TP, PPTP共为一层 */
			reserved_hdr_len = sizeof(struct mesa_ppp_hdr);
		break;

		case ADDR_TYPE_PPTP:
		{			
			stream_pr = (struct streaminfo_private *)stream;
			reserved_hdr_len = stream_pr->cur_layer_raw_hdr_len;
		}
		break;
		
		case ADDR_TYPE_MAC_IN_MAC:
			reserved_hdr_len = sizeof(struct mesa_ethernet_hdr) + sizeof(struct mesa_ethernet_hdr);
		break;
		
		default:
			/* to do */
			printf("calc_reserved_hdr_len(): Not support addrtype:%d\n", stream->addr.addrtype);
			reserved_hdr_len = -1;
			break;
	}

	if(reserved_hdr_len < 0){
		return -1;
	}

#if 0 /* 2014-10-24 lijia modify, pag, ppf等捕包方式从IPv4开始 */
	if(stream->pfather && (ADDR_TYPE_MAC == stream->pfather->addr.addrtype)){
#else
	if(CAP_LEVEL_MAC == g_packet_io_cap_level) {
		if(stream->pfather 
		 && ((ADDR_TYPE_MAC_IN_MAC == stream->pfather->addr.addrtype) || (ADDR_TYPE_MAC == stream->pfather->addr.addrtype))){
			/* 记录MAC层之上的协议地址类型, 用于填充Ethernet->type字段, 对于MAC-in-MAC的inner_eth, 记录上层协议类型 */
			*net_layer_type = (int)stream->addr.addrtype;
		}
	}else{
		/* to do:
			如果捕包库自动屏蔽了ethernet层, 甚至剥掉了vlan等层而且还要发包怎么办?
		*/
		if(NULL == stream->pfather){
			if(g_packet_io_cap_level == stream->addr.addrtype){
				*net_layer_type = (int)stream->addr.addrtype;
			}
			if((CAP_LEVEL_IPV4 == g_packet_io_cap_level)
			 && (ADDR_TYPE_IPV4 == stream->addr.addrtype)){
				*net_layer_type = CAP_LEVEL_IPV4;
			}			
		}
	}
#endif

done:
	return reserved_hdr_len + calc_reserved_hdr_len(stream->pfather, net_layer_type);
}

static void set_build_layer_ipv4_args(int thread_num, unsigned char ip_ttl, unsigned short ip_id_host_order)
{
	layer_args_t *thread_args;
	bulid_layer_ipv4_args_t *build_ip4_args;

	thread_args = &g_build_pkt_args[thread_num];
	build_ip4_args = &g_build_ipv4_args[thread_num];

	memset(build_ip4_args, 0, sizeof(bulid_layer_ipv4_args_t));
	build_ip4_args->ip_ttl = ip_ttl;
	build_ip4_args->ip_id_host_order = ip_id_host_order;

	thread_args->layer_args[__ADDR_TYPE_IP_PAIR_V4] = build_ip4_args;

	return;
}

static void set_build_layer_tcp_args( int thread_num,unsigned char tcp_flags,
						unsigned short tcp_win_host_order, unsigned int tcp_seq)
{
	layer_args_t *thread_args;
	bulid_layer_tcp_args_t *build_tcp_args;

	thread_args = &g_build_pkt_args[thread_num];
	build_tcp_args = &g_build_tcp_args[thread_num];

	memset(build_tcp_args, 0, sizeof(bulid_layer_tcp_args_t));
	build_tcp_args->tcp_flags = tcp_flags;
	build_tcp_args->tcp_win_host_order = tcp_win_host_order;
	build_tcp_args->tcp_seq = tcp_seq;

	thread_args->layer_args[ADDR_TYPE_TCP] = build_tcp_args;

	return;
}

static inline void detach_build_layer_ipv4_args(int thread_num)
{
	g_build_pkt_args[thread_num].layer_args[__ADDR_TYPE_IP_PAIR_V4] = NULL;
}

static inline void detach_build_layer_ipv6_args(int thread_num)
{
	g_build_pkt_args[thread_num].layer_args[__ADDR_TYPE_IP_PAIR_V6] = NULL;
}

static inline void detach_build_layer_tcp_args(int thread_num)
{
	g_build_pkt_args[thread_num].layer_args[ADDR_TYPE_TCP] = NULL;
}

#if 0
static int __get_tcp_network_addr(struct streaminfo *stream, void *src_addr, void *dst_addr)
{
	struct streaminfo *father = stream->pfather;
	int f_addr_type = __ADDR_TYPE_INIT;

	if(NULL == father){
		return f_addr_type;
	}

	if(ADDR_TYPE_IPV4 == father->addr.addrtype){
		struct stream_tuple4_v4 *t4 = father->addr.tuple4_v4;
		memcpy(src_addr, &t4->saddr, sizeof(int));
		memcpy(dst_addr, &t4->daddr, sizeof(int));
		f_addr_type = ADDR_TYPE_IPV4;
	}else if(__ADDR_TYPE_IP_PAIR_V6 == father->addr.addrtype){
		struct stream_tuple4_v6 *t6 = father->addr.tuple4_v6;
		memcpy(src_addr, &t6->saddr, IPV6_ADDR_LEN);
		memcpy(dst_addr, &t6->daddr, IPV6_ADDR_LEN);
		f_addr_type = __ADDR_TYPE_IP_PAIR_V6;
	}else{
		;
	}	

	return f_addr_type;
}
#endif

static int build_net_layer_tcp(struct streaminfo_private *stream_pr, int carry_layer_type,
			int carry_layer_len, unsigned char *buf, int reverse, const raw_pkt_t *raw_pkt)
{
	struct mesa_tcp_hdr *raw_tcp_hdr;
	struct tcpdetail *a_tcp = (struct tcpdetail *)(stream_pr->stream_public.pdetail);
	UINT16 tcp_win, tcp_flags;
	UINT32 tcp_seq;
	int tcp_data_len = a_tcp->datalen;
	bulid_layer_tcp_args_t *build_tcp_args;

#if 0 /* 2015-12-30 lijia modify, IP和端口存储在一层 */
	raw_tcp_hdr = (struct mesa_tcp_hdr *)(stream_pr->offset_to_raw_pkt_hdr + (char *)raw_pkt->raw_pkt_data);
#else
	raw_tcp_hdr = (struct mesa_tcp_hdr *)(stream_pr->offset_to_raw_pkt_hdr + stream_pr->offset_to_ip_hdr + (char *)raw_pkt->raw_pkt_data);
#endif

	build_tcp_args = (bulid_layer_tcp_args_t *)g_build_pkt_args[stream_pr->stream_public.threadnum].layer_args[ADDR_TYPE_TCP];

	if(raw_tcp_hdr->th_flags & TH_SYN){
		tcp_data_len++;
	}
	
	if(NULL == build_tcp_args){
		tcp_flags = TH_ACK;
		tcp_win = (UINT16)MESA_rand_range(1000, 1460);
		tcp_seq = (UINT32)MESA_rand();
	}else{
		tcp_flags = build_tcp_args->tcp_flags;
		tcp_win = build_tcp_args->tcp_win_host_order;
		if(0 == build_tcp_args->tcp_seq){
			if(reverse){
				tcp_seq = ntohl(raw_tcp_hdr->th_ack);
			}else{
				tcp_seq = ntohl(raw_tcp_hdr->th_seq)+tcp_data_len;
			}
		}else{
			tcp_seq = build_tcp_args->tcp_seq;
		}
	}
	
	if(reverse){
		sendpacket_build_tcp(ntohs(raw_tcp_hdr->th_dport),
						    ntohs(raw_tcp_hdr->th_sport),
						    tcp_seq,
						    ntohl(raw_tcp_hdr->th_seq)+tcp_data_len,
						    tcp_flags,
						    tcp_win,
						    0,
						    NULL,
						    0,
						    (unsigned char *)buf);			    
	}else{
		sendpacket_build_tcp(ntohs(raw_tcp_hdr->th_sport),
						    ntohs(raw_tcp_hdr->th_dport),
						    tcp_seq,
						    ntohl(raw_tcp_hdr->th_ack),
						    tcp_flags,
						    tcp_win,
						    0,
						    NULL,
						    0,
						    (unsigned char *)buf);		
	}

	return sizeof(struct mesa_tcp_hdr);
}

static int build_net_layer_udp(struct streaminfo_private *stream_pr, int carry_layer_type,
			int carry_layer_len, unsigned char *buf, int reverse, const raw_pkt_t *raw_pkt)
{
	struct mesa_udp_hdr *raw_udp_hdr;

#if 0
	raw_udp_hdr = (struct mesa_udp_hdr *)(stream_pr->offset_to_raw_pkt_hdr + (char *)raw_pkt->raw_pkt_data);
#else
	raw_udp_hdr = (struct mesa_udp_hdr *)(stream_pr->offset_to_raw_pkt_hdr + stream_pr->offset_to_ip_hdr + (char *)raw_pkt->raw_pkt_data);
#endif

	if(reverse){
		sendpacket_build_udp_dual_stack(ntohs(raw_udp_hdr->uh_dport),
							ntohs(raw_udp_hdr->uh_sport),
							NULL,
							0,
							carry_layer_len,
							buf);
	}else{
		sendpacket_build_udp_dual_stack(ntohs(raw_udp_hdr->uh_sport),
							ntohs(raw_udp_hdr->uh_dport),
							NULL,
							0,
							carry_layer_len,
							buf);
	}

	return sizeof(struct mesa_udp_hdr);
}


static int build_net_layer_ipv4(struct streaminfo_private *stream_pr, int carry_layer_type,
			int carry_layer_len, unsigned char *buf, int reverse, const raw_pkt_t *raw_pkt)
{
	struct mesa_ip4_hdr *raw_ip4_hdr;
	UINT16 ip_id;
	UINT8 ip_ttl;
	bulid_layer_ipv4_args_t *build_ip4_args;
	int threadnum = (int)stream_pr->stream_public.threadnum;

	raw_ip4_hdr = (struct mesa_ip4_hdr *)(stream_pr->offset_to_raw_pkt_hdr + (char *)raw_pkt->raw_pkt_data);
	build_ip4_args = (bulid_layer_ipv4_args_t *)g_build_pkt_args[stream_pr->stream_public.threadnum].layer_args[__ADDR_TYPE_IP_PAIR_V4];

	if(NULL == build_ip4_args){
		ip_id = (UINT16)MESA_rand();
		ip_ttl = (UINT8)MESA_rand_range(48, 127);
	}else{
		ip_id = build_ip4_args->ip_id_host_order;
		ip_ttl = build_ip4_args->ip_ttl;
	}

	if(reverse){
		sendpacket_build_ipv4(carry_layer_len, 
							0, 
							ip_id, 
							IP_DF, 
							ip_ttl, 
							net_layer_to_ipv4_protocol(carry_layer_type), 
							raw_ip4_hdr->ip_dst.s_addr,
							raw_ip4_hdr->ip_src.s_addr,
							NULL,
							0, 
							(unsigned char *)buf);
		if(stream_pr->stream_public.pfather != NULL &&
			stream_pr->stream_public.pfather->addr.addrtype == ADDR_TYPE_GPRS_TUNNEL &&
			g_gtp_info_hash[threadnum] != NULL)
		{
			g_addr_register_for_gtp_cache[threadnum].addr_type = ADDR_TYPE_IPV4;
			g_addr_register_for_gtp_cache[threadnum].v4[0] = raw_ip4_hdr->ip_dst.s_addr;
			g_addr_register_for_gtp_cache[threadnum].v4[1] = raw_ip4_hdr->ip_src.s_addr;
		}
	}else{
		sendpacket_build_ipv4(carry_layer_len, 
							0, 
							ip_id, 
							IP_DF, 
							ip_ttl, 
							net_layer_to_ipv4_protocol(carry_layer_type), 
							raw_ip4_hdr->ip_src.s_addr,
							raw_ip4_hdr->ip_dst.s_addr,
							NULL,
							0, 
							(unsigned char *)buf);
	}

	sendpacket_do_checksum(buf, IPPROTO_IP, sizeof(struct mesa_ip4_hdr));

	return sizeof(struct mesa_ip4_hdr);
}

static int build_net_layer_ipv6(struct streaminfo_private *stream_pr, int carry_layer_type,
			int carry_layer_len, unsigned char *buf, int reverse, const raw_pkt_t *raw_pkt)
{
	struct mesa_ip6_hdr *raw_ip6_hdr;
	UINT8 hop = (UINT8)MESA_rand_range(64, 128);
	int threadnum = (int)stream_pr->stream_public.threadnum;

	if(0 == g_packet_io_ipv6_switch){
		printf("IPv6 module is not support! Please set 'IPv6_module_enable=1' in main.conf.\n");
		return -1;
	}

	raw_ip6_hdr = (struct mesa_ip6_hdr *)(stream_pr->offset_to_raw_pkt_hdr + (char *)raw_pkt->raw_pkt_data);

	if(reverse){
		sendpacket_build_ipv6(0,
							0,
							carry_layer_len,
							net_layer_to_ipv6_protocol(carry_layer_type),
							hop,
							&raw_ip6_hdr->ip6_dst,
							&raw_ip6_hdr->ip6_src,
							NULL,
							0,
							(unsigned char *)buf);
		if(stream_pr->stream_public.pfather != NULL &&
		   stream_pr->stream_public.pfather->addr.addrtype == ADDR_TYPE_GPRS_TUNNEL &&
		   g_gtp_info_hash[threadnum] != NULL)
		{
			g_addr_register_for_gtp_cache[threadnum].addr_type = ADDR_TYPE_IPV6;
			memcpy(g_addr_register_for_gtp_cache[threadnum].v6, &raw_ip6_hdr->ip6_dst, sizeof(struct in6_addr));
			memcpy((char *)(g_addr_register_for_gtp_cache[threadnum].v6) + sizeof(struct in6_addr), &raw_ip6_hdr->ip6_src, sizeof(struct in6_addr));
		}
	}else{
		sendpacket_build_ipv6(0,
							0,
							carry_layer_len,
							net_layer_to_ipv6_protocol(carry_layer_type),
							hop,
							&raw_ip6_hdr->ip6_src,
							&raw_ip6_hdr->ip6_dst,
							NULL,
							0,
							(unsigned char *)buf);
	}

	return sizeof(struct mesa_ip6_hdr);
}

static int build_net_layer_pppoe_ses(struct streaminfo_private *stream_pr, int carry_layer_type,
			int carry_layer_len, unsigned char *buf, int reverse, const raw_pkt_t *raw_pkt)
{
	struct mesa_pppoe_session_hdr *raw_hdr;
	struct mesa_pppoe_session_hdr *send_hdr =  (struct mesa_pppoe_session_hdr *)buf;

	raw_hdr = (struct mesa_pppoe_session_hdr *)(stream_pr->offset_to_raw_pkt_hdr + (char *)raw_pkt->raw_pkt_data);
	
	/* PPPOE无方向性, 将原始报文copy即可 */
	(void)reverse;
	memcpy(send_hdr, raw_hdr, sizeof(struct mesa_pppoe_session_hdr));

	/* lijia comment:
		此处为何要加sizeof(send_hdr->ppp_protocol)?
		因为PPPOE_SES包头本来是不含PPP协议类型字段的, 是为了方便处理, 把两层2合1了.
	*/
	send_hdr->len = htons(carry_layer_len + sizeof(send_hdr->ppp_protocol));

	return sizeof(struct mesa_pppoe_session_hdr);
}

static int build_net_layer_vlan(struct streaminfo_private *stream_pr, int carry_layer_type,
			int carry_layer_len, unsigned char *buf, int reverse, const raw_pkt_t *raw_pkt)
{
	struct mesa_vlan_hdr *raw_hdr;
	struct mesa_vlan_hdr *send_hdr =  (struct mesa_vlan_hdr *)buf;

	raw_hdr = (struct mesa_vlan_hdr *)(stream_pr->offset_to_raw_pkt_hdr + (char *)raw_pkt->raw_pkt_data);

	/* VLAN无方向性, 将原始报文copy即可 */
	(void)reverse;
	memcpy(send_hdr, raw_hdr, sizeof(struct mesa_vlan_hdr));

	return sizeof(struct mesa_vlan_hdr);
}

static int build_net_layer_gerv0_exthdr(const struct mesa_gre_hdr *parsed_hdr, struct mesa_gre_hdr *send_hdr)
{
	const struct mesa_gre_extend_hdr *parsed_ext_hdr = (const struct mesa_gre_extend_hdr *)&parsed_hdr->gre_extend;
	char *send_ext_value = (char *)&send_hdr->gre_extend;


	if(parsed_hdr->gre_base.checksum_flag != 0){
		memcpy(send_ext_value, &parsed_ext_hdr->checksum, sizeof(short));
		send_ext_value += sizeof(short);
		memcpy(send_ext_value, &parsed_ext_hdr->offset, sizeof(short));
		send_ext_value += sizeof(short);	
	}

	if(parsed_hdr->gre_base.key_flag != 0){
		memcpy(send_ext_value, &parsed_ext_hdr->key, sizeof(int));
		send_ext_value += sizeof(int);
	}	

	if(parsed_hdr->gre_base.seq_flag != 0){
		unsigned tmp_int = htons(ntohs(parsed_ext_hdr->seq_num) + 1); /* seq + 1 */
		memcpy(send_ext_value, &tmp_int, sizeof(int));
		send_ext_value += sizeof(int);
	}

	return 0;
}

static int build_net_layer_gerv1_exthdr(const struct mesa_gre_hdr *parsed_hdr, 
				struct mesa_gre_hdr *send_hdr, int carry_layer_len, UINT16 send_call_id, int reverse)
{
	const struct mesa_gre_base_hdr_v1*parsed_base_hdr = (const struct mesa_gre_base_hdr_v1*)&parsed_hdr->gre_base;
	const struct mesa_gre_extend_hdr *parsed_ext_hdr = (const struct mesa_gre_extend_hdr *)&parsed_hdr->gre_extend;
	char *send_ext_value = (char *)&(send_hdr->gre_extend);
	struct mesa_gre_base_hdr_v1 *send_grev1_hdr = (struct mesa_gre_base_hdr_v1 *)send_hdr;

	unsigned short payload_len = (unsigned short)carry_layer_len;
	payload_len = htons(payload_len);

	memcpy(send_ext_value, &payload_len, sizeof(short)); /* GREv1 必定有length字段 */
	send_ext_value += sizeof(short);	

	memcpy(send_ext_value, &send_call_id, sizeof(short)); /* GREv1 必定有callid字段 */
	send_ext_value += sizeof(short);		

	if(0 == reverse){
		if(parsed_base_hdr->seq_flag != 0){
			unsigned tmp_int = htonl(ntohl(parsed_ext_hdr->seq_num) + 1); /* seq + 1 */
			memcpy(send_ext_value, &tmp_int, sizeof(int));
			send_ext_value += sizeof(int);
			send_grev1_hdr->seq_flag = 1;
		}else{
			send_grev1_hdr->seq_flag = 0;
		}
		
		if(parsed_base_hdr->ack_flag != 0){
			memcpy(send_ext_value, &parsed_ext_hdr->ack_num, sizeof(int));
			send_ext_value += sizeof(int);
			send_grev1_hdr->ack_flag = 1;
		}else{
			send_grev1_hdr->ack_flag = 0;
		}
	}else{
		if(parsed_base_hdr->ack_flag != 0){
			unsigned tmp_int = htonl(ntohl(parsed_ext_hdr->ack_num) + 1); /* seq  = opposite_ack + 1 */
			memcpy(send_ext_value, &tmp_int, sizeof(int));
			send_ext_value += sizeof(int);
			send_grev1_hdr->seq_flag = 1;
		}else{
			send_grev1_hdr->seq_flag = 0;
		}
		
		if(parsed_base_hdr->seq_flag != 0){
			memcpy(send_ext_value, &parsed_ext_hdr->seq_num, sizeof(int)); /* ack  = opposite_seq */
			send_ext_value += sizeof(int);
			send_grev1_hdr->ack_flag = 1;
		}else{
			send_grev1_hdr->ack_flag = 0;
		}
	}
	
	return 0;
}

static int build_net_layer_gre(struct streaminfo_private *stream_pr, int carry_layer_type,
			int carry_layer_len, unsigned char *buf, int reverse, const raw_pkt_t *raw_pkt)
{
	const struct mesa_gre_hdr *raw_hdr;
	struct mesa_gre_hdr stack_hdr;
	struct mesa_gre_hdr *send_hdr = (struct mesa_gre_hdr *)buf;
	int gre_hdr_len, ret;
	const struct layer_addr_pptp *raw_pptp_addr = stream_pr->stream_public.addr.pptp;
#if 0	
	/* NOTE: BUGFIX, 当前流的curdir可能并没有设置, 因为只在TCP层设置了curdir, 所以不能取本层流的curdir值 */
	UCHAR curdir = stream_pr->stream_public.curdir;
#endif
	UINT16 send_call_id;

	raw_hdr = (const struct mesa_gre_hdr *)(stream_pr->offset_to_raw_pkt_hdr + (char *)raw_pkt->raw_pkt_data);
	gre_hdr_len = set_gre_hdr(&stack_hdr, (const void *)raw_hdr);
	if(gre_hdr_len < 0){
		return -1;
	}
	
	if((reverse != 0)
	    && ((0 == raw_pptp_addr->C2S_call_id) || (0 == raw_pptp_addr->S2C_call_id))){
	    	/* 有任意一个方向没有获取到callid, 反向发送无法填充 */
	    	sapp_runtime_log(20, "in gre layer, send dir is reverse, but haven't get opposite single stream info!\n");
		return -1;
	}

	if(0 == reverse){
		if(stack_hdr.gre_extend.call_id == raw_pptp_addr->C2S_call_id){
			/* 同向发包, 和当前来包一样 */
			send_call_id = raw_pptp_addr->C2S_call_id;
		}else{
			send_call_id = raw_pptp_addr->S2C_call_id;
		}
	}else{
		/* 反向发包, 使用对端的callid */
		if(stack_hdr.gre_extend.call_id == raw_pptp_addr->C2S_call_id){
			send_call_id = raw_pptp_addr->S2C_call_id;
		}else{
			send_call_id = raw_pptp_addr->C2S_call_id;
		}
	}

	memcpy(&send_hdr->gre_base, &raw_hdr->gre_base, sizeof(struct mesa_gre_base_hdr_v0));
	
	if(0 == stack_hdr.gre_base.version){
		ret = build_net_layer_gerv0_exthdr(&stack_hdr, send_hdr);
	}else if(1 == stack_hdr.gre_base.version){
		ret = build_net_layer_gerv1_exthdr(&stack_hdr, send_hdr, carry_layer_len, send_call_id, reverse);
	}else{
		return -1;
	}
	
	if(ret < 0){
		return -1;
	}

	return gre_hdr_len;
}

static int build_net_layer_mpls(struct streaminfo_private *stream_pr, int carry_layer_type,
			int carry_layer_len, unsigned char *buf, int reverse, const raw_pkt_t *raw_pkt)
{
	struct mesa_mpls_hdr *raw_hdr;

	raw_hdr = (struct mesa_mpls_hdr *)(stream_pr->offset_to_raw_pkt_hdr + (char *)raw_pkt->raw_pkt_data);

	/* MPLS无方向性, 将原始报文copy即可 */
	(void)reverse;
	memcpy(buf, raw_hdr, sizeof(struct mesa_mpls_hdr));

	return sizeof(struct mesa_mpls_hdr);
}

static int build_net_layer_gtp(struct streaminfo_private *stream_pr, int carry_layer_type,
								int carry_layer_len, unsigned char *buf, int reverse, const raw_pkt_t *raw_pkt)
{
	struct gtp_hdr *raw_hdr;
	int layer_len = sizeof(struct gtp_hdr);
	raw_hdr = (struct gtp_hdr *)(stream_pr->offset_to_raw_pkt_hdr + (char *)raw_pkt->raw_pkt_data);
	void *gtp_hash_key;
	int gtp_hash_key_len;
	if(reverse == 0){
		memcpy(buf, raw_hdr, sizeof(struct gtp_hdr));
		if(raw_hdr->flags&0x02){
			//TODO: 目前不支持带序号的GTP发包，seq未更新
		    memcpy(buf+sizeof(struct gtp_hdr), raw_hdr+1, sizeof(unsigned int));
            *(unsigned int *)(buf+sizeof(struct gtp_hdr)) = htonl(ntohl(*(unsigned int *)(raw_hdr+1)) + 1);
            layer_len+=sizeof(unsigned int);
		}
	} else{
		if(stream_pr->stream_public.addr.gtp->source == 0 || stream_pr->stream_public.addr.gtp->dest == 0)
		{
			if(g_gtp_info_hash[stream_pr->stream_public.threadnum])
			{
				gtp_hash_key = (g_addr_register_for_gtp_cache[stream_pr->stream_public.threadnum].addr_type == ADDR_TYPE_IPV4)?g_addr_register_for_gtp_cache[stream_pr->stream_public.threadnum].v4:g_addr_register_for_gtp_cache[stream_pr->stream_public.threadnum].v6;
				gtp_hash_key_len = (g_addr_register_for_gtp_cache[stream_pr->stream_public.threadnum].addr_type == ADDR_TYPE_IPV4)?sizeof(g_addr_register_for_gtp_cache[stream_pr->stream_public.threadnum].v4):sizeof(g_addr_register_for_gtp_cache[stream_pr->stream_public.threadnum].v6);
				raw_hdr = (struct gtp_hdr *)MESA_htable_search(g_gtp_info_hash[stream_pr->stream_public.threadnum], (unsigned char*)gtp_hash_key, gtp_hash_key_len);
				if(raw_hdr == NULL)
				{
					layer_len = 0;
				}
				else
				{
					memcpy(buf, raw_hdr, sizeof(struct gtp_hdr));
				}
			}
		}
		else
		{
			if(0 == memcmp(raw_hdr, &stream_pr->stream_public.addr.gtp->source, sizeof(struct gtp_hdr))) {
				memcpy(buf, &stream_pr->stream_public.addr.gtp->dest, sizeof(struct gtp_hdr));
				if (raw_hdr->flags & 0x02) {
					*(unsigned int *)(buf+sizeof(struct gtp_hdr)) = htonl(stream_pr->stream_public.addr.gtp->dest_seq + 1);
					layer_len+=sizeof(unsigned int);
				}
			}
			else{
				memcpy(buf, &stream_pr->stream_public.addr.gtp->source, sizeof(struct gtp_hdr));
				if (raw_hdr->flags & 0x02) {
					*(unsigned int *)(buf+sizeof(struct gtp_hdr)) = htonl(stream_pr->stream_public.addr.gtp->src_seq + 1);
					layer_len+=sizeof(unsigned int);
				}
			}
		}
	}
	return layer_len;
}

static void checksum_for_carry_layer(unsigned char *buf, int this_layer_type, int carry_layer_type, int payload_len)
{
	if((ADDR_TYPE_TCP != carry_layer_type) && (ADDR_TYPE_UDP != carry_layer_type)){
		return;
	}
	
	if(__ADDR_TYPE_IP_PAIR_V4 == this_layer_type){
		sendpacket_do_checksum(buf, net_layer_to_ipv4_protocol(carry_layer_type), payload_len);
	}else if(__ADDR_TYPE_IP_PAIR_V6 == this_layer_type){
		sendpacket_do_checksum(buf, net_layer_to_ipv6_protocol(carry_layer_type), payload_len);
	}else{
		return;
	}
}

static int build_net_layer_ppp(struct streaminfo_private *stream_pr, int carry_layer_type,
			int carry_layer_len, unsigned char *buf, int reverse, const raw_pkt_t *raw_pkt, int ppp_hdr_len)
{

	/* PPP无方向性, 将原始报文copy即可 */
	(void)reverse;
	memcpy(buf, stream_pr->offset_to_raw_pkt_hdr + (char *)raw_pkt->raw_pkt_data, ppp_hdr_len);		

	return ppp_hdr_len;
}

static int build_net_layer_l2tp(struct streaminfo_private *stream_pr, int carry_layer_type,
			int carry_layer_len, unsigned char *buf, int reverse, const raw_pkt_t *raw_pkt, int l2tp_raw_hdr_len)
{
	const struct l2tp_hdr_v2 *raw_hdr;
	const char *raw_hdr_ptr;
	unsigned char *send_ptr = buf;
	unsigned short int16_tmp;
	
	if(reverse != 0){
		/* TODO 2:
			L2TP包c2s和s2c方向TUNNEL-ID不一样, 目前没有形成L2TP流, 无法保存另一个方向的信息 ,
			所以, 暂时只能单向KILL.
		*/
		return -1;
	}

	raw_hdr = (const struct l2tp_hdr_v2 *)(stream_pr->offset_to_raw_pkt_hdr + (char *)raw_pkt->raw_pkt_data);
	raw_hdr_ptr = (const char *)raw_hdr;
	memcpy(send_ptr, raw_hdr, sizeof(struct l2tp_hdr_v2));
	send_ptr += sizeof(struct l2tp_hdr_v2);
	raw_hdr_ptr += sizeof(struct l2tp_hdr_v2);

	if(raw_hdr->length_present){
		int16_tmp = carry_layer_len + l2tp_raw_hdr_len;
		int16_tmp = ntohs(int16_tmp);
		memcpy(send_ptr, &int16_tmp, sizeof(short));
		send_ptr += sizeof(short);
		raw_hdr_ptr += sizeof(short);
	}

	memcpy(send_ptr, raw_hdr_ptr, sizeof(short)); /* 2 byte tunnel id */
	send_ptr += sizeof(short);
	raw_hdr_ptr += sizeof(short);

	memcpy(send_ptr, raw_hdr_ptr, sizeof(short)); /* 2 byte session id */
	send_ptr += sizeof(short);
	raw_hdr_ptr += sizeof(short);	

	if(raw_hdr->seq_present){
		memcpy(send_ptr, raw_hdr_ptr, sizeof(short)); /* 2 byte Ns */
		send_ptr += sizeof(short);
		raw_hdr_ptr += sizeof(short);

		memcpy(send_ptr, raw_hdr_ptr, sizeof(short)); /* 2 byte Nr */
		send_ptr += sizeof(short);
		raw_hdr_ptr += sizeof(short);	
	}

	if(raw_hdr->offset_present){
		int16_tmp = ntohs(*(unsigned short *)raw_hdr_ptr); /* offset size */
		memcpy(send_ptr, raw_hdr_ptr, sizeof(short)); /* 2 byte offset */
		send_ptr += sizeof(short);
		raw_hdr_ptr += sizeof(short);			

		memcpy(send_ptr, raw_hdr_ptr, int16_tmp);
		send_ptr += int16_tmp;
		raw_hdr_ptr += int16_tmp;			
	}

	return l2tp_raw_hdr_len;
}

/* 
	buf: 执向应用层负载地址, skip hdr.
	reverse: 对于有方向性的地址, 需反向.
*/
static int build_net_layer_pkt(struct streaminfo_private *stream_pr, int carry_layer_type,
			int carry_layer_len, unsigned char *buf, int reverse, const raw_pkt_t *raw_pkt)
{
	int this_layer_len = 0, ret;
	int transport_layer_len;
	struct streaminfo *stream;
	
	if(NULL == stream_pr){
		return carry_layer_len;
	}

	stream = &stream_pr->stream_public;

	if(is_proxy_stream(stream)){ /* 代理流结构为虚拟结构, 实际的包不存在此层, 构造包时跳过不处理 */
		this_layer_len = 0;
		goto done;
	}

	switch(stream->addr.addrtype){
		case ADDR_TYPE_IPV4:
			/* 2015-12-30 lijia modify, IP和端口存储于一个结构, 先构造TCP/UDP层 */
			if(STREAM_TYPE_TCP == stream->type){
				transport_layer_len = sizeof(struct mesa_tcp_hdr);
				buf -= sizeof(struct mesa_tcp_hdr);
				build_net_layer_tcp(stream_pr, carry_layer_type, carry_layer_len, buf, reverse, raw_pkt);
				carry_layer_type = ADDR_TYPE_TCP;
			}else{
				transport_layer_len = sizeof(struct mesa_udp_hdr);
				buf -= sizeof(struct mesa_udp_hdr);
				build_net_layer_udp(stream_pr, carry_layer_type, carry_layer_len, buf, reverse, raw_pkt);
				carry_layer_type = ADDR_TYPE_UDP;	
			}

			/* 2015-12-30 lijia modify, IP和端口存储于一个结构, 继续构造IPv4层 */
			this_layer_len += sizeof(struct mesa_ip4_hdr) + transport_layer_len;
			buf -= sizeof(struct mesa_ip4_hdr);
			build_net_layer_ipv4(stream_pr, carry_layer_type, carry_layer_len + transport_layer_len, buf, reverse, raw_pkt);
			
			/* TCP层校验和需要IP地址信息, 所以要在构造完IP层信息后, 再计算checksum */
			checksum_for_carry_layer(buf, __ADDR_TYPE_IP_PAIR_V4, carry_layer_type, carry_layer_len+transport_layer_len);
			carry_layer_type = __ADDR_TYPE_IP_PAIR_V4;
			
		break;
		
		case ADDR_TYPE_IPV6:
			/* 2015-12-30 lijia modify, IP和端口存储于一个结构, 先构造TCP/UDP层 */
			if(STREAM_TYPE_TCP == stream->type){
				transport_layer_len = sizeof(struct mesa_tcp_hdr);
				buf -= sizeof(struct mesa_tcp_hdr);
				build_net_layer_tcp(stream_pr, carry_layer_type, carry_layer_len, buf, reverse, raw_pkt);
				carry_layer_type = ADDR_TYPE_TCP;
			}else{
				transport_layer_len = sizeof(struct mesa_udp_hdr);
				buf -= sizeof(struct mesa_udp_hdr);
				build_net_layer_udp(stream_pr, carry_layer_type, carry_layer_len, buf, reverse, raw_pkt);
				carry_layer_type = ADDR_TYPE_UDP;	
			}

			/* 2015-12-30 lijia modify, IP和端口存储于一个结构, 继续构造IPv6层 */
			this_layer_len += sizeof(struct mesa_ip6_hdr) + transport_layer_len;
			buf -= sizeof(struct mesa_ip6_hdr);
			build_net_layer_ipv6(stream_pr, carry_layer_type, carry_layer_len + transport_layer_len, buf, reverse, raw_pkt);
			
			/* TCP层校验和需要IP地址信息, 所以要在构造完IP层信息后, 再计算checksum */
			checksum_for_carry_layer(buf, __ADDR_TYPE_IP_PAIR_V6, carry_layer_type, carry_layer_len+transport_layer_len);
			carry_layer_type = __ADDR_TYPE_IP_PAIR_V6;
		break;
		
		case __ADDR_TYPE_IP_PAIR_V4:
			/* to do, 如果构造带选项的包, 怎么计算? */
			this_layer_len = sizeof(struct mesa_ip4_hdr);
			buf -= sizeof(struct mesa_ip4_hdr);
			build_net_layer_ipv4(stream_pr, carry_layer_type, carry_layer_len, buf, reverse, raw_pkt);
			
			/* TCP层校验和需要IP地址信息, 所以要在构造完IP层信息后, 再计算checksum */
			checksum_for_carry_layer(buf, __ADDR_TYPE_IP_PAIR_V4, carry_layer_type, carry_layer_len);
			carry_layer_type = __ADDR_TYPE_IP_PAIR_V4;
		break;
		
		case __ADDR_TYPE_IP_PAIR_V6:
			this_layer_len = sizeof(struct mesa_ip6_hdr);
			buf -= sizeof(struct mesa_ip6_hdr);
			build_net_layer_ipv6(stream_pr, carry_layer_type, carry_layer_len, buf, reverse, raw_pkt);
			checksum_for_carry_layer(buf, __ADDR_TYPE_IP_PAIR_V6, carry_layer_type, carry_layer_len);
			carry_layer_type = __ADDR_TYPE_IP_PAIR_V6;
		break;
		
		case ADDR_TYPE_VLAN:
			this_layer_len = VLAN_TAG_LEN;
			buf -= sizeof(struct mesa_vlan_hdr);
			build_net_layer_vlan(stream_pr, carry_layer_type, carry_layer_len, buf, reverse, raw_pkt);
			carry_layer_type = ADDR_TYPE_VLAN;
		break;

		case ADDR_TYPE_MAC:
		{
			buf -= sizeof(struct mesa_ethernet_hdr); 
			/* 此处可以不构造mac地址, 仅告知packet_io_send_fake_pkt函数底层类型, MAC还是MAC_IN_MAC */
			struct mesa_ethernet_hdr * ehdr = (struct mesa_ethernet_hdr *)buf;
			ehdr->ether_type = htons(net_layer_to_ethernet_protocol(carry_layer_type));
			this_layer_len = 0; 
			//this_layer_len = build_net_layer_ethernet(stream, payload, payload_len, buf, reverse, net_layer);
			//net_layer = NET_LAYER_ETHERNET;
			/* 并联模式下, 可以直接靠系统sendto发送, 所以MAC地址不在build系列函数中添加, 在dl_io中填充 */
			return carry_layer_len;
		}
		break;

		/* TODO 2: GRE v1有callid, 分别存储于C2S, S2C两个方向的数据包, 发送双向RST需要记录另一方向的值 */
		case ADDR_TYPE_GRE:
			this_layer_len = calc_gre_hdr_len(
						 (const struct mesa_gre_hdr *)((const char *)stream_pr->raw_pkt->raw_pkt_data + stream_pr->offset_to_raw_pkt_hdr));
			buf -= this_layer_len;
			ret = build_net_layer_gre(stream_pr, carry_layer_type, carry_layer_len, buf, reverse, raw_pkt);
			if(ret < 0){
				return -1;
			}
			carry_layer_type = ADDR_TYPE_GRE;
		break;

		case ADDR_TYPE_MPLS:
			this_layer_len = g_mpls_register_addr[stream_pr->stream_public.threadnum].src_mpls_layer_num*sizeof(struct mesa_mpls_hdr);
			if(this_layer_len > 0)
			{
                buf -= this_layer_len;
				//build_net_layer_mpls(stream_pr, carry_layer_type, carry_layer_len, buf, reverse, raw_pkt);
				memcpy(buf, g_mpls_register_addr[stream_pr->stream_public.threadnum].src_mpls_pkt, this_layer_len);
				carry_layer_type = ADDR_TYPE_MPLS;
			}
		break;

		case ADDR_TYPE_GPRS_TUNNEL:
			this_layer_len = calc_gtp_hdr_len((const struct gtp_hdr *)((const char *)stream_pr->raw_pkt->raw_pkt_data + stream_pr->offset_to_raw_pkt_hdr));
			buf -= this_layer_len;
			build_net_layer_gtp(stream_pr, carry_layer_type, carry_layer_len, buf, reverse, raw_pkt);
			carry_layer_type = ADDR_TYPE_GPRS_TUNNEL;
			break;

		case ADDR_TYPE_PPPOE_SES:
			this_layer_len = sizeof(struct mesa_pppoe_session_hdr);
			buf -= sizeof(struct mesa_pppoe_session_hdr);
			build_net_layer_pppoe_ses(stream_pr, carry_layer_type, carry_layer_len, buf, reverse, raw_pkt);
			carry_layer_type = ADDR_TYPE_PPPOE_SES;
		break;
	
		case ADDR_TYPE_TCP:
			/* to do, 如果构造带选项的包, 怎么计算? */
			this_layer_len = sizeof(struct mesa_tcp_hdr);
			buf -= sizeof(struct mesa_tcp_hdr);
			build_net_layer_tcp(stream_pr, carry_layer_type, carry_layer_len, buf, reverse, raw_pkt);
			carry_layer_type = ADDR_TYPE_TCP;
		break;
			
		case ADDR_TYPE_UDP:
			this_layer_len = sizeof(struct mesa_udp_hdr);
			buf -= sizeof(struct mesa_udp_hdr);
			build_net_layer_udp(stream_pr, carry_layer_type, carry_layer_len, buf, reverse, raw_pkt);
			carry_layer_type = ADDR_TYPE_UDP;
		break;
		
		case ADDR_TYPE_L2TP:
			this_layer_len = calc_l2tp_hdr_len(
						 (const struct l2tp_hdr_v2 *)((const char *)stream_pr->raw_pkt->raw_pkt_data + stream_pr->offset_to_raw_pkt_hdr));
			if(this_layer_len < 0){
				return -1;
			}
			buf -= this_layer_len;
			ret = build_net_layer_l2tp(stream_pr, carry_layer_type, carry_layer_len, buf, reverse, raw_pkt, this_layer_len);
			if(ret < 0){
				return -1;
			}
			carry_layer_type = ADDR_TYPE_L2TP;
		break;

		case ADDR_TYPE_PPP:
			assert(0); /* PPTP隧道将gre和ppp合并为一层, 代码不会再执行到此处 */
			this_layer_len = sizeof(struct mesa_ppp_hdr);
			buf -= sizeof(struct mesa_ppp_hdr);
			build_net_layer_ppp(stream_pr, carry_layer_type, carry_layer_len, buf, reverse, raw_pkt, 0);
			carry_layer_type = ADDR_TYPE_PPP;		
		break;
		
		case ADDR_TYPE_PPTP:
		{
			int gre_layer_len;
			int ppp_hdr_len;

			gre_layer_len = calc_gre_hdr_len(
						 (const struct mesa_gre_hdr *)((const char *)stream_pr->raw_pkt->raw_pkt_data + stream_pr->offset_to_raw_pkt_hdr));
			if(gre_layer_len < 0){
				return -1;
			}						 
			ppp_hdr_len = stream_pr->cur_layer_raw_hdr_len - gre_layer_len;
			if(ppp_hdr_len < 1){
				return -1;
			}

			buf -= ppp_hdr_len;
			build_net_layer_ppp(stream_pr, carry_layer_type, carry_layer_len, buf, reverse, raw_pkt, ppp_hdr_len);	
			
			/* 直接copy ppp头部即可 */
			memcpy(buf, (char *)raw_pkt->raw_pkt_data + stream_pr->offset_to_raw_pkt_hdr + gre_layer_len, ppp_hdr_len);
			
			buf -= gre_layer_len;
			ret = build_net_layer_gre(stream_pr, ADDR_TYPE_PPP, carry_layer_len, buf, reverse, raw_pkt);
			if(ret < 0){ 
				return -1;
			}
			carry_layer_type = ADDR_TYPE_GRE;
			this_layer_len = gre_layer_len + ppp_hdr_len;
		}	
		break;
		
		case ADDR_TYPE_MAC_IN_MAC:
		{
			this_layer_len = 0;
			buf -= MAC_IN_MAC_HDR_LEN; 
			struct mesa_ethernet_hdr * outer_ehdr = (struct mesa_ethernet_hdr *)buf;
			outer_ehdr->ether_type = htons(ETHERTYPE_PANGU_MAC_IN_MAC);		

			struct mesa_ethernet_hdr * inner_ehdr = (struct mesa_ethernet_hdr *)(buf + sizeof(struct mesa_ethernet_hdr));
			inner_ehdr->ether_type = htons(net_layer_to_ethernet_protocol(carry_layer_type));
			
			/* 此处可以不构造mac地址, 仅告知packet_io_send_fake_pkt函数底层类型, MAC还是MAC_IN_MAC */
		
			/* 并联模式下, 与MAC类似, 可以直接靠系统sendto发送, 所以MAC地址不在build系列函数中添加, 在dl_io中填充 */
			return carry_layer_len;
		}	
		break;
		
		default:
			printf("build_net_layer_pkt(): unsupport protocol:%d! TODO!\n", stream->addr.addrtype);
			goto err;
			break;
	}

done:	
	return build_net_layer_pkt((struct streaminfo_private *)stream->pfather,carry_layer_type, 
							this_layer_len+carry_layer_len, 
							buf, reverse, raw_pkt);

err:
	return -1;
}


static int __do_kill_tcp(struct streaminfo *stream, const void *ext_raw_pkt, int kill_num,
								char *feedback_buf, int *feedback_buf_len)
{
	int i, ret = -1, reserved_hdr_len, send_len = 0;
	MESA_send_handle *send_handle;
	int thread_num = stream->threadnum;
	int low_net_layer_type = -1;
	tcp_rst_finger_mark_t *tcp_rst_finger;
	const raw_pkt_t *raw_pkt = NULL;
	struct streaminfo_private *stream_pr;

	(void)ext_raw_pkt;

	if(NULL == stream){
		return -1;
	}

	stream_pr = (struct streaminfo_private *)stream;
	send_handle = &g_send_handle[thread_num];

	/* 因改变了某些回调函数的原始包类型为IP包头(兼容之前papp平台), 所以不需要插件传输原始包, 信息都存储于私有流结构体内 */
	raw_pkt = (const raw_pkt_t *)stream_pr->raw_pkt;

	if((NULL == raw_pkt) || (RAW_PKT_MAGIC_NUM != raw_pkt->magic_num)){
		return -1;
	}

	reserved_hdr_len = calc_reserved_hdr_len(stream, &low_net_layer_type);
	if((reserved_hdr_len < 0) || (-1 == low_net_layer_type)){
		sapp_runtime_log(RLOG_LV_INFO, "%s:%d: MESA_kill_tcp() calc_reserved_hdr_len error !", __FILE__, __LINE__);
		ret = -1;
		goto fun_exit;
	}

    //if(sapp_global_single.send_fake_pkt_mode != SEND_PKT_MODE_STACK_3_LAYER)
    //{
	    send_handle->user_arg = (void *)stream;
    //}

	if(sapp_global_single.send_fake_pkt_mode == SEND_PKT_MODE_GDEV){ /* gdev注入模式时预留底层封装vxlan包的空间, 避免再二次copy */
		reserved_hdr_len += sizeof(vxlan_header_t);
	}

	tcp_rst_finger = make_tcp_rst_finger_mark(thread_num, (const raw_pkt_t *)raw_pkt);
	set_build_layer_ipv4_args(thread_num, tcp_rst_finger->ip_ttl, tcp_rst_finger->ip_id_host_order);

	if(0 == sapp_global_single.cfg_kill_tcp_rst_signature){
		set_build_layer_tcp_args(thread_num, TH_RST, tcp_rst_finger->tcp_win_host_order, 0);
	}else{
		set_build_layer_tcp_args(thread_num, TH_RST|TH_ACK, tcp_rst_finger->tcp_win_host_order, 0);
	}
	
	for(i = 0; i < kill_num; i++){
		send_handle->send_buf = packet_io_get_sendbuf(SEND_TYPE_LINK_INJECT, thread_num);
		
		send_len = build_net_layer_pkt(stream_pr, ADDR_TYPE_TCP, 0, send_handle->send_buf + reserved_hdr_len, 0, raw_pkt);
		if(send_len < 0){
			ret = -1;
			goto fun_exit;
		}
		ret = packet_io_send(send_handle, reserved_hdr_len, SEND_TYPE_LINK_INJECT, 
							low_net_layer_type, stream->routedir, thread_num,
							feedback_buf, feedback_buf_len);		
		if(ret < 0){
			send_handle->tot_send_err++;
		}else{
			send_handle->tot_send_pkt++;
			send_handle->tot_send_byte += send_len;
		}
		
		packet_io_free_sendbuf(SEND_TYPE_LINK_INJECT, thread_num);	

		g_SysInputInfo[thread_num][SEND_TCP_RST]++;
		g_SysInputInfo[thread_num][SEND_TCP_RST_LEN]+=send_len;
		
 /* 并联模式下, 两个方向各发一个, 总计三次, 
    而不是先发C2S三次、再发S2C三次,
    防止因RST包延时问题, 另一方迟迟没有包; 
 */			

		send_handle->send_buf = packet_io_get_sendbuf(SEND_TYPE_LINK_INJECT, thread_num);
		send_len = build_net_layer_pkt(stream_pr, ADDR_TYPE_TCP, 0, send_handle->send_buf + reserved_hdr_len, 1, raw_pkt);
		if(send_len < 0){
			ret = -1;
			goto fun_exit;
			break;
		}
		ret = packet_io_send(send_handle, reserved_hdr_len, SEND_TYPE_LINK_INJECT, 
							low_net_layer_type, stream->routedir ^ 1, thread_num,
							feedback_buf, feedback_buf_len);	
		if(ret < 0){
			send_handle->tot_send_err++;
		}else{
			send_handle->tot_send_pkt++;
			send_handle->tot_send_byte += send_len;
		}
		packet_io_free_sendbuf(SEND_TYPE_LINK_INJECT, thread_num);	
		g_SysInputInfo[thread_num][SEND_TCP_RST]++;
		g_SysInputInfo[thread_num][SEND_TCP_RST_LEN]+=send_len;		
	}

fun_exit:

	detach_build_layer_ipv4_args(thread_num);
	detach_build_layer_tcp_args(thread_num);

	stream_pr->stream_killed_flag = 1;

	return ret;
}



/*
	LiJia note, to do:
	如果因为丢包乱序, 1,2,3,4,x,6, 第5个包丢了, 第6个包被缓存,
	假设第6个包内有特殊信息, 需要kill_tcp,
	当第5个包到来时, streaminfo里存储的都是第5个包的信息,
	然后再处理缓存中第6个包的数据, 此时调用kill_tcp, 相关参数是不对的,
	实际的seq和ack使用的是第5个包的!
	应该使用buf_unorder中的seq和ack, 而不是当前流的原始包.
*/
int MESA_kill_tcp(struct streaminfo *stream, const void *ext_raw_pkt)
{
	/* 外部调用, 第一次FD, 发送KILL_TCP_RST_NUM次. */
	return __do_kill_tcp(stream, ext_raw_pkt, sapp_global_single.cfg_kill_tcp_rst_num, (char *)KILL_TCP_PHONY_POINTER, (int *)KILL_TCP_PHONY_POINTER);
}

int MESA_kill_tcp_feedback(struct streaminfo *stream, const void *raw_pkt, char *feedback_buf, int *feedback_buf_len)
{
	if((NULL == feedback_buf) || (NULL == feedback_buf_len)){
		return -2;
	}
	if(*feedback_buf_len <= 0){
		return -2;
	}
	return __do_kill_tcp(stream, raw_pkt, sapp_global_single.cfg_kill_tcp_rst_num, feedback_buf, feedback_buf_len);
}

/* 2016-06-15 lijia add  */
int MESA_kill_tcp_remedy(struct streaminfo *stream, const void *ext_raw_pkt)
{
	struct streaminfo_private *stream_pr = (struct streaminfo_private *)stream;
	int last_send_time = g_CurrentTime % 255;

	if((sapp_global_single.kill_tcp_with_gdev != 0 ) && (stream_pr->gdev_block_timer < last_send_time)){
		/* 防止FD不生效频繁调用c3接口, 对于一个流, 每隔1秒调用一次C3 */
		stream_pr->gdev_block_timer =  last_send_time;
		gdev_block_send_rule(stream);
	}
	
	/* FD补救, RST固定只发送1次. */
	return __do_kill_tcp(stream, ext_raw_pkt, 1, (char *)KILL_TCP_PHONY_POINTER, (int *)KILL_TCP_PHONY_POINTER);
}

static int __do_kill_tcp_synack(struct streaminfo *stream, const void *ext_raw_pkt, 
							char *feedback_buf, int *feedback_buf_len)
{
	int i, ret, reserved_hdr_len, send_len = 0;
	MESA_send_handle *send_handle;
	int thread_num = stream->threadnum;
	int low_net_layer_type;
	tcp_rst_finger_mark_t *tcp_rst_finger;
	const raw_pkt_t *raw_pkt = NULL;
	struct streaminfo_private *stream_pr;

	(void)ext_raw_pkt;
	
	if(NULL == stream){
		return -1;
	}

	stream_pr = (struct streaminfo_private *)stream;
	send_handle = &g_send_handle[thread_num];
	raw_pkt = (const raw_pkt_t *)stream_pr->raw_pkt;
	if((NULL == raw_pkt) || (RAW_PKT_MAGIC_NUM != raw_pkt->magic_num)){
		return -1;
	}
	
	reserved_hdr_len = calc_reserved_hdr_len(stream, &low_net_layer_type);
	if((reserved_hdr_len < 0) || (-1 == low_net_layer_type)){
		ret = -1;
		goto fun_exit;
	}
	tcp_rst_finger = make_tcp_rst_finger_mark(thread_num, (const raw_pkt_t *)raw_pkt);
	set_build_layer_ipv4_args(thread_num, tcp_rst_finger->ip_ttl, tcp_rst_finger->ip_id_host_order);
	set_build_layer_tcp_args(thread_num, TH_SYN|TH_ACK, tcp_rst_finger->tcp_win_host_order, MESA_rand());

	for(i = 0; i < KILL_TCP_SYN_ACK_NUM; i++){
		send_handle->send_buf = packet_io_get_sendbuf(SEND_TYPE_LINK_INJECT, thread_num);
		
		send_len = build_net_layer_pkt(stream_pr, ADDR_TYPE_TCP, 0, send_handle->send_buf + reserved_hdr_len, 1, raw_pkt);
		if(send_len < 0){
			ret = -1;
			goto fun_exit;		
		}
		ret = packet_io_send(send_handle, reserved_hdr_len, SEND_TYPE_LINK_INJECT, 
							low_net_layer_type, stream->routedir ^ 1, thread_num,
							feedback_buf, feedback_buf_len);		
		if(ret < 0){
			send_handle->tot_send_err++;
		}else{
			send_handle->tot_send_pkt++;
			send_handle->tot_send_byte += send_len;
		}
		
		packet_io_free_sendbuf(SEND_TYPE_LINK_INJECT, thread_num);	
		g_SysInputInfo[thread_num][SEND_TCP_SYN_ACK]++;
		g_SysInputInfo[thread_num][SEND_TCP_SYN_ACK_LEN]+=send_len;				
	}
fun_exit:
	detach_build_layer_ipv4_args(thread_num);
	detach_build_layer_tcp_args(thread_num);

	stream_pr->stream_killed_flag = 1;

	return ret;
}

int MESA_kill_tcp_synack(struct streaminfo *stream, const void *ext_raw_pkt)
{
	return __do_kill_tcp_synack(stream, ext_raw_pkt, (char *)KILL_TCP_PHONY_POINTER, (int *)KILL_TCP_PHONY_POINTER);
}

int MESA_kill_tcp_synack_feedback(struct streaminfo *stream, const void *ext_raw_pkt,
								char *feedback_buf, int *feedback_buf_len)
{
	if((NULL == feedback_buf) || (NULL == feedback_buf_len)){
		return -2;
	}
	if(*feedback_buf_len <= 0){
		return -2;
	}

	return __do_kill_tcp_synack(stream, ext_raw_pkt, feedback_buf, feedback_buf_len);
}


/* 2014-11-15 lijia add, for drop NO-TCP protocol in serial mode. 
    return value:
    >= 0: success.
    -1  : error.
*/
int MESA_kill_connection(struct streaminfo *stream, const void *ext_raw_pkt)
{
	int ret;
	struct streaminfo_private *stream_pr;

	(void)ext_raw_pkt;
	
	if(NULL == stream){
		return -1;
	}
	stream_pr = (struct streaminfo_private *)stream;
	
	switch(stream->type){
		case STREAM_TYPE_TCP:
			//ret = MESA_kill_tcp(stream, ext_raw_pkt);
			/* 因改变了某些回调函数的原始包类型为IP包头, 所以不需要插件传输原始包, 信息都存储于私有流结构体内 */
			ret = MESA_kill_tcp(stream, stream_pr->raw_pkt);
		break;
		case STREAM_TYPE_UDP:
			stream_pr->stream_killed_flag = 1;
			ret = 0;
		break;
		
		case STREAM_TYPE_SOCKS4:
		case STREAM_TYPE_SOCKS5:
		case STREAM_TYPE_HTTP_PROXY:
		case STREAM_TYPE_PPPOE:
			printf("stream type: %d, not support kill_connection!\n", stream->type);
			return -1;
			//assert(0);
		break;

		default:
			ret = -1;
			break;
	}

	return ret;
}

int MESA_kill_connection_feedback(struct streaminfo *stream, const void *ext_raw_pkt,
							char *feedback_buf, int *feedback_buf_len)
{
	int ret;
	struct streaminfo_private *stream_pr;

	(void)ext_raw_pkt;

	if((NULL == feedback_buf) || (NULL == feedback_buf_len)){
		return -2;
	}
	if(*feedback_buf_len <= 0){
		return -2;
	}	
	
	if(NULL == stream){
		return -1;
	}
	stream_pr = (struct streaminfo_private *)stream;
	
	switch(stream->type){
		case STREAM_TYPE_TCP:
			//ret = MESA_kill_tcp(stream, ext_raw_pkt);
			/* 因改变了某些回调函数的原始包类型为IP包头, 所以不需要插件传输原始包, 信息都存储于私有流结构体内 */
			ret = MESA_kill_tcp_feedback(stream, stream_pr->raw_pkt, feedback_buf, feedback_buf_len);
		break;
		case STREAM_TYPE_UDP:
			stream_pr->stream_killed_flag = 1;
			ret = 0;
		break;
		
		case STREAM_TYPE_SOCKS4:
		case STREAM_TYPE_SOCKS5:
		case STREAM_TYPE_HTTP_PROXY:
		case STREAM_TYPE_PPPOE:
			printf("stream type: %d, not support kill_connection!\n", stream->type);
			return -1;
			//assert(0);
		break;

		default:
			ret = -1;
			break;
	}

	return ret;
}

static int __do_inject_pkt(struct streaminfo *stream, const char *payload, int payload_len, 
						const void *ext_raw_pkt, UCHAR snd_routedir,
						char *feedback_buf, int *feedback_buf_len)
{
	int ret = -1, reserved_hdr_len, send_len = 0;
	MESA_send_handle *send_handle;
	int thread_num = stream->threadnum;
	int low_net_layer_type;
	int snd_dir_reverse;
	const raw_pkt_t *raw_pkt;
	struct streaminfo_private *stream_pr;

	(void)ext_raw_pkt;
	
	if(NULL == stream){
		return -1;
	}
	
	if(dir_check(snd_routedir) < 0){
		return -1;
	}
	
	stream_pr = (struct streaminfo_private *)stream;
	/* 因改变了某些回调函数的原始包类型为IP包头, 所以不需要插件传输原始包, 信息都存储于私有流结构体内 */
	raw_pkt = (const raw_pkt_t *)stream_pr->raw_pkt;
	if((NULL == raw_pkt) || (RAW_PKT_MAGIC_NUM != raw_pkt->magic_num)){
		return -1;
	}
	
	snd_dir_reverse = ((snd_routedir == stream->routedir) ? 0: 1);
	
	send_handle = &g_send_handle[thread_num];

	reserved_hdr_len = calc_reserved_hdr_len(stream, &low_net_layer_type);
	if((reserved_hdr_len < 0) || (-1 == low_net_layer_type)){
		ret = -1;
		goto fun_exit;
	}
	
	if(payload_len + reserved_hdr_len > MTU_MAX){
		sapp_runtime_log(RLOG_LV_FATAL, "%s:%d: MESA_inject_pkt() error! payload_len too long:%d.\n", __FILE__, __LINE__, payload_len + reserved_hdr_len);	
		return -1;
		//assert(0);
	}

	if((ADDR_TYPE_IPV4 == stream->addr.addrtype)
	 || (ADDR_TYPE_TCP == stream->addr.addrtype)){
		set_build_layer_tcp_args(thread_num, TH_PUSH|TH_ACK, MESA_rand_range(1000, 1460), 0);
	}

	send_handle->send_buf = packet_io_get_sendbuf(SEND_TYPE_LINK_INJECT, thread_num);

	memcpy(send_handle->send_buf + reserved_hdr_len, payload, payload_len);
	
	send_len = build_net_layer_pkt(stream_pr, stream->addr.addrtype, payload_len, 
							   send_handle->send_buf + reserved_hdr_len, snd_dir_reverse, raw_pkt);
	if(send_len < 0){
		ret = -1;
		goto err;
	}
	ret = packet_io_send(send_handle, reserved_hdr_len+payload_len, SEND_TYPE_LINK_INJECT, 
						low_net_layer_type, stream->routedir, thread_num,
						feedback_buf, feedback_buf_len);		
	if(ret < 0){
		send_handle->tot_send_err++;
	}else{
		send_handle->tot_send_pkt++;
		send_handle->tot_send_byte += send_len;
	}

	if(STREAM_TYPE_TCP == stream->type){
		g_SysInputInfo[thread_num][SEND_TCP_PKT]++;
		g_SysInputInfo[thread_num][SEND_TCP_PKT_LEN]+=send_len;	
	}else{
		g_SysInputInfo[thread_num][SEND_UDP_PKT]++;
		g_SysInputInfo[thread_num][SEND_UDP_PKT_LEN]+=send_len;	
	}

err:	
	packet_io_free_sendbuf(SEND_TYPE_LINK_INJECT, thread_num);	

fun_exit:
	if((ADDR_TYPE_IPV4 == stream->addr.addrtype)
	 || (ADDR_TYPE_TCP == stream->addr.addrtype)){
		detach_build_layer_tcp_args(thread_num);
	}

	return ret;
}

int MESA_inject_pkt(struct streaminfo *stream, const char *payload, int payload_len, 
						const void *ext_raw_pkt, UCHAR snd_routedir)
{
	return __do_inject_pkt(stream, payload, payload_len, ext_raw_pkt, snd_routedir, 
				(char *)KILL_TCP_PHONY_POINTER, (int *)KILL_TCP_PHONY_POINTER);
}


int MESA_inject_pkt_feedback(struct streaminfo *stream, const char *payload, int payload_len, 
						const void *ext_raw_pkt, UCHAR snd_routedir,
						char *feedback_buf, int *feedback_buf_len)
{
	if((NULL == feedback_buf) || (NULL == feedback_buf_len)){
		return -2;
	}
	if(*feedback_buf_len <= 0){
		return -2;
	}
	
	return __do_inject_pkt(stream, payload, payload_len, ext_raw_pkt, snd_routedir, 
						feedback_buf, feedback_buf_len);
}

unsigned long packet_io_get_send_pkt_num(int thread_num)
{
	MESA_send_handle *send_handle = &g_send_handle[thread_num];

	return send_handle->tot_send_pkt;
}

unsigned long packet_io_get_send_pkt_err(int thread_num)
{
	MESA_send_handle *send_handle = &g_send_handle[thread_num];

	return send_handle->tot_send_err;
}

unsigned long packet_io_get_send_pkt_byte(int thread_num)
{
	MESA_send_handle *send_handle = &g_send_handle[thread_num];

	return send_handle->tot_send_byte;
}

int packet_io_set_max_rand_value(int rand_max)
{
	g_iMaxRandVal = rand_max;
	return 0;
}

int packet_io_set_rand_key(int rand_key)
{
	g_iRandKey = rand_key;
	return 0;
}

static int send_handle_init(int tot_thread_num)
{
	int i, ret;

	for(i = 0; i < tot_thread_num; i++){
		g_send_handle[i].raw_ipv4_fd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
		if(g_send_handle[i].raw_ipv4_fd < 0){
			printf("socket v4 error, %s\n", strerror(errno));
			return -1;
		}
		g_send_handle[i].raw_udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
		if(g_send_handle[i].raw_udp_fd < 0){
			printf("socket udp error, %s\n", strerror(errno));
			return -1;
		} else
		{
			int opt_value = 1;
			setsockopt(g_send_handle[i].raw_udp_fd, SOL_SOCKET, SO_REUSEADDR, &opt_value, sizeof(int));
			struct sockaddr_in listen_addr;
			bzero(&listen_addr, sizeof(listen_addr));
			listen_addr.sin_family = AF_INET;
			listen_addr.sin_port = htons((unsigned short)sapp_global_single.send_fake_pkt_gdev_sport); /* 根据配置文件填写vxlan源端口 */
			if(bind(g_send_handle[i].raw_udp_fd, (struct sockaddr *) &listen_addr, sizeof(listen_addr)) != 0){
				printf("socket bind udp error");
				return -1;
			}
		}
		if(g_packet_io_ipv6_raw_socket){
			g_send_handle[i].raw_ipv6_fd = socket(PF_INET6, SOCK_RAW, IPPROTO_RAW);
			if(g_send_handle[i].raw_ipv6_fd < 0){
				printf("socket v6 error, %s\n", strerror(errno));
				printf("Please disable IPv6 module, then try again!\n");
				return -1;
			}
		}
		if(g_send_dev_name[0] != '\0'){
			ret = g_send_handle[i].raw_eth_fd =  socket(PF_INET, SOCK_PACKET, htons(ETH_P_ALL));
			if(g_send_handle[i].raw_eth_fd < 0){
				printf("socket raw eth error, %s\n", strerror(errno));
				return -1;
			}
			ret = snprintf(g_send_handle[i].saddr_raw_eth.sa_data, sizeof(g_send_handle[i].saddr_raw_eth.sa_data), 
						"%s", g_send_dev_name);
			if(ret >= 	(int)sizeof(g_send_handle[i].saddr_raw_eth.sa_data)){
				printf("send device name is too long!\n");
				return -1;
			}
			g_send_handle[i].saddr_raw_eth.sa_family = PF_INET;
		}
		g_send_handle[i].threadnum = i;

		g_send_handle[i].low_level_send_handle = dl_io_fun_list.dl_io_get_send_handle(i);
		if(NULL == g_send_handle[i].low_level_send_handle){
			printf("dl_io_get_send_handle error !\n");
			return -1;
		}

		g_packet_dl_send_handle[i] = g_send_handle[i].low_level_send_handle; /* 20161117 lijia move from packet_io_init() */
	}

	return 0;
}

/* 2015-01-04 lijia add, 从papp平台迁移到sapp平台, 底层发包接口不同 */
int MESA_sendpacket_ethlayer(int thread_num,const char *data, int data_len, unsigned int target_id)
{
	int ret;

	if(data_len > MTU_MAX)
	{
		printf("data length is more than MTU, %d\n", data_len);
		return -1;
	}

#if 0 /* for debug! */
	char send_buf[MTU_MAX];
	char debug_smac[6] = {0x74, 0x86, 0x7A, 0xD0, 0x12, 0xFC};
	char debug_dmac[6] = {0x00, 0x01, 0x6c, 0x53, 0xa9, 0x94};
	struct mesa_ethernet_hdr *eth_hdr = (struct mesa_ethernet_hdr *)data;
	eth_hdr->ether_type = ntohs(ETHERTYPE_IP);
	memcpy(eth_hdr->ether_shost, debug_smac, 6);
	memcpy(eth_hdr->ether_dhost, debug_dmac, 6);
#endif

	ret = packet_io_send_raw(thread_num, (char *)data, data_len, target_id);

	return (ret);	
}

int sendpacket_init_new(int tot_thread_num)
{
	srand(time(NULL));

	g_rand_seed = random();

	if(send_handle_init(tot_thread_num) < 0){
		return -1;
	}

	/* to do, TODO 1,
		//get_gateway_info();
	
		创建一个线程, 动态获取默认网关的MAC地址, 发包目标如果是IPv4地址而且是内网IP,发送arp请求,
		pthread_create(sendpacket_keepalive_with_gateway);
	*/

	return 0;
}


#define DIR_BIT_USE_MASK		(0x81)
#define DIR_BIT_UNUSE_MASK		(0x7E)


/*************************************************************************************** 	
	NOTE:
	MESA_sendpacket_xxx和MESA_fakepacket_send_xxx系列函数中, dir与sapp中的routedir定义不同,
	papp平台中的dir使用最高位bit表示方向, 如上行为0x00, 下行为0x80,
	而sapp中的routedir用最低位表示方向, 如上行为0x00, 下行为0x01.
	为了同时兼容此两类平台和插件, 新增MESA_dir_reverse()函数, 用于反向发包.
****************************************************************************************/
unsigned char MESA_dir_reverse(unsigned char raw_dir)
{
	raw_dir ^= DIR_BIT_USE_MASK; /* 同时兼容sapp和旧版WY插件, 最高和最低bit位同时反向 */

	return raw_dir;
}

static inline int dir_check(unsigned char raw_dir)
{
	if(raw_dir & DIR_BIT_UNUSE_MASK){ /* 方向只使用了最高和最低位bit, 如果出现其他值,说明插件在转换dir时出了错误 */
		printf("dir = 0x%x,  is invalid, only the most or least significant bit can be used!", raw_dir);
		//assert(0);
		return -1;
	}

	return 0;
}

int MESA_sendpacket_iplayer(int thread_index,const char *data,  int data_len, u_int8_t dir)
{
	MESA_send_handle *send_handle;
	int ret, offset = 0;

	send_handle = &g_send_handle[thread_index];

	send_handle->send_buf = packet_io_get_sendbuf(SEND_TYPE_LINK_INJECT, thread_index);

	switch(g_packet_io_cap_level){
		case CAP_LEVEL_IPV4:
			offset = 0;
		break;
		case CAP_LEVEL_MAC:
			offset =  sizeof(struct mesa_ethernet_hdr);
		break;

		default:
		    printf("MESA_sendpacket_iplayer: Invalid cap_mode:%d\n", g_packet_io_cap_level);
		    //exit(1);
		return -1;
	}	

	if(data_len > (int)MTU_MAX-(int)sizeof(struct mesa_ethernet_hdr)){
		printf("TODO: MESA_sendpacket_iplayer error! datalen is more than MTU, need ip fragment!\n");
		return -1;
	}

	memcpy(send_handle->send_buf + offset, data, data_len);
	
	ret = packet_io_send_fake_pkt(send_handle, data_len+sizeof(struct mesa_ethernet_hdr), SEND_TYPE_LINK_INJECT, 
							   __ADDR_TYPE_IP_PAIR_V4, dir, thread_index,
							   (char *)KILL_TCP_PHONY_POINTER, (int *)KILL_TCP_PHONY_POINTER);

	packet_io_free_sendbuf(SEND_TYPE_LINK_INJECT, thread_index);	

	g_SysInputInfo[thread_index][SEND_IP_RAW_PKT]++;
	g_SysInputInfo[thread_index][SEND_IP_RAW_PKT_LEN]+=ret;	
	
	return ret;
}

int MESA_fakepacket_send_ipv4(int thread_index,u_int8_t ttl,
							u_int8_t protocol,u_int32_t sip, u_int32_t dip, const char *payload,
							int payload_len,u_int8_t dir)
{
	MESA_send_handle *send_handle;
	int ret, offset = 0;
	u_int16_t ipid;

	send_handle = &g_send_handle[thread_index];

	send_handle->send_buf = packet_io_get_sendbuf(SEND_TYPE_LINK_INJECT, thread_index);
	switch(g_packet_io_cap_level){
		case CAP_LEVEL_IPV4:
			offset = 0;
		break;
		case CAP_LEVEL_MAC:
			offset =  sizeof(struct mesa_ethernet_hdr);
		break;

		default:
		    printf("MESA_fakepacket_send_ipv4: Invalid cap_mode:%d\n", g_packet_io_cap_level);
		    //exit(1);
		return -1;
	}	

	if(payload_len > (int)MTU_MAX-(int)sizeof(struct mesa_ethernet_hdr)-(int)sizeof(struct mesa_ip4_hdr)){
		printf("TODO: MESA_fakepacket_send_ipv4 error! datalen is more than MTU, need ip fragment!\n");
		return -1;
	}
	
	ipid = MESA_rand() % 65535;
	sendpacket_build_ipv4(payload_len, 0, ipid, 0 , ttl, protocol, 
						htonl(sip), htonl(dip), payload, payload_len, send_handle->send_buf+offset);

	sendpacket_do_checksum(send_handle->send_buf+offset, IPPROTO_IP, SENDPACKET_IP_H);

	ret = packet_io_send_fake_pkt(send_handle, payload_len+sizeof(struct mesa_ip4_hdr)+sizeof(struct mesa_ethernet_hdr), 
								SEND_TYPE_LINK_INJECT, __ADDR_TYPE_IP_PAIR_V4, dir, thread_index,
								(char *)KILL_TCP_PHONY_POINTER, (int *)KILL_TCP_PHONY_POINTER);
							   
	packet_io_free_sendbuf(SEND_TYPE_LINK_INJECT, thread_index);	

	g_SysInputInfo[thread_index][SEND_IP_PKT]++;
	g_SysInputInfo[thread_index][SEND_IP_PKT_LEN]+=ret;	
		
	return ret;	
}

int MESA_fakepacket_send_tcp(int thread_index,u_int sip_host_order,u_int dip_host_order,
							u_short sport_host_order,u_short dport_host_order,
							u_int sseq_host_order,u_int sack_host_order,
							u_char control,const char* payload,int payload_len, u_int8_t dir)
{
	MESA_send_handle *send_handle;
	int ret, offset = 0;
	u_int16_t tcp_win, ipid;

	send_handle = &g_send_handle[thread_index];

	send_handle->send_buf = packet_io_get_sendbuf(SEND_TYPE_LINK_INJECT, thread_index);
	switch(g_packet_io_cap_level){
		case CAP_LEVEL_IPV4:
			offset = 0;
		break;
		case CAP_LEVEL_MAC:
			offset =  sizeof(struct mesa_ethernet_hdr);
		break;

		default:
		    printf("MESA_fakepacket_send_tcp: Invalid cap_mode:%d\n", g_packet_io_cap_level);
		    //exit(1);
		return -1;
	}	

	if(payload_len > (int)MTU_MAX- (int)sizeof(struct mesa_ethernet_hdr)- (int)sizeof(struct mesa_ip4_hdr)- (int)sizeof(struct mesa_tcp_hdr)){
		printf("TODO: MESA_fakepacket_send_tcp error! datalen is more than MTU, need ip fragment!\n");
		return -1;
	}

	tcp_win = MESA_rand_range(1460, 65500);
	ipid = MESA_rand() % 65535;

	sendpacket_build_tcp(sport_host_order, dport_host_order, sseq_host_order, sack_host_order,
						control, tcp_win, 0, payload, payload_len, send_handle->send_buf+offset+sizeof(struct mesa_ip4_hdr));
						
	sendpacket_build_ipv4(payload_len+SENDPACKET_TCP_H, 0, ipid, 0, 64, IPPROTO_TCP, 
						htonl(sip_host_order), htonl(dip_host_order), NULL, 0, send_handle->send_buf+offset);

	sendpacket_do_checksum(send_handle->send_buf+offset, IPPROTO_TCP, SENDPACKET_TCP_H+payload_len);
	
	sendpacket_do_checksum(send_handle->send_buf+offset, IPPROTO_IP, SENDPACKET_IP_H);

	ret = packet_io_send_fake_pkt(send_handle, payload_len+sizeof(struct mesa_tcp_hdr)+sizeof(struct mesa_ip4_hdr)+sizeof(struct mesa_ethernet_hdr), 
								SEND_TYPE_LINK_INJECT, __ADDR_TYPE_IP_PAIR_V4, dir, thread_index,
								(char *)KILL_TCP_PHONY_POINTER, (int *)KILL_TCP_PHONY_POINTER);
							   
	packet_io_free_sendbuf(SEND_TYPE_LINK_INJECT, thread_index);	

	g_SysInputInfo[thread_index][SEND_TCP_PKT]++;
	g_SysInputInfo[thread_index][SEND_TCP_PKT_LEN]+=ret;	
		
	return ret;	
}

int MESA_fakepacket_send_udp(int thread_index, u_int sip_host_order, u_int dip_host_order, 
							u_short sport_host_order,u_short dport_host_order, 
							const char *payload, int payload_len,u_int8_t dir)
{
	MESA_send_handle *send_handle;
	int ret, offset = 0;
	u_int16_t  ipid;

	send_handle = &g_send_handle[thread_index];

	send_handle->send_buf = packet_io_get_sendbuf(SEND_TYPE_LINK_INJECT, thread_index);
	switch(g_packet_io_cap_level){
		case CAP_LEVEL_IPV4:
			offset = 0;
		break;
		case CAP_LEVEL_MAC:
			offset =  sizeof(struct mesa_ethernet_hdr);
		break;

		default:
		    printf("MESA_fakepacket_send_udp: Invalid cap_mode:%d\n", g_packet_io_cap_level);
		    //exit(1);
		return -1;
	}	

	if(payload_len > (int)MTU_MAX- (int)sizeof(struct mesa_ethernet_hdr)- (int)sizeof(struct mesa_ip4_hdr)- (int)sizeof(struct mesa_tcp_hdr)){
		printf("TODO: MESA_fakepacket_send_udp error! datalen is more than MTU, need ip fragment!\n");
		return -1;
	}

	ipid = MESA_rand() % 65535;

	sendpacket_build_udp_dual_stack(sport_host_order, dport_host_order, payload, payload_len, payload_len,
						send_handle->send_buf+offset+sizeof(struct mesa_ip4_hdr));
						
	sendpacket_build_ipv4(payload_len+SENDPACKET_UDP_H, 0, ipid, 0, 64, IPPROTO_UDP, 
						htonl(sip_host_order), htonl(dip_host_order), NULL, 0, send_handle->send_buf+offset);

	sendpacket_do_checksum(send_handle->send_buf+offset, IPPROTO_UDP, SENDPACKET_UDP_H+payload_len);
	
	sendpacket_do_checksum(send_handle->send_buf+offset, IPPROTO_IP, SENDPACKET_IP_H);

	ret = packet_io_send_fake_pkt(send_handle, payload_len+sizeof(struct mesa_udp_hdr)+sizeof(struct mesa_ip4_hdr)+sizeof(struct mesa_ethernet_hdr), 
								SEND_TYPE_LINK_INJECT, __ADDR_TYPE_IP_PAIR_V4, dir, thread_index,
								(char *)KILL_TCP_PHONY_POINTER, (int *)KILL_TCP_PHONY_POINTER);
							   
	packet_io_free_sendbuf(SEND_TYPE_LINK_INJECT, thread_index);	

	g_SysInputInfo[thread_index][SEND_UDP_PKT]++;
	g_SysInputInfo[thread_index][SEND_UDP_PKT_LEN]+=ret;	
	
	return ret;	
}

#ifdef __cplusplus
}
#endif

