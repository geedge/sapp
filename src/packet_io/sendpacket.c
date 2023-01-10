#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"
#include "sapp_declaration.h"


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
//static int g_iRandKey=13;
//static int g_iMaxRandVal=65535;

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

static int get_eth_carry_layer_type(struct streaminfo *stream, UCHAR send_stream_dir);

extern void *g_packet_dl_send_handle[MAX_THREAD_NUM];
extern dl_io_fun_list_t dl_io_fun_list;
extern int g_app_send_rst_type ;
extern int calc_l2tp_hdr_len_by_net_pkt(const struct l2tp_hdr_v2 *l2tp_hdr);
extern int packet_io_send_fake_pkt(MESA_send_handle *send_handle,int datalen,int send_type, 
					int low_layer_type, int dir,int thread_num,
					char *feedback_buf, int *feedback_buf_len, const raw_pkt_t *raw_pkt);					
static inline int dir_check(unsigned char raw_dir);
extern int set_mpls_addr(struct layer_addr_mpls *addr, const unsigned char *raw_mpls_pkt_data);

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

//extern MESA_htable_handle g_mpls_info_hash[MAX_THREAD_NUM];
//mpls_cache_addr_t g_mpls_cache_key[MAX_THREAD_NUM];
//struct layer_addr_mpls g_mpls_register_addr[MAX_THREAD_NUM];

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
	struct timespec curtime;
	clock_gettime (CLOCK_THREAD_CPUTIME_ID, &curtime);
	return g_rand_seed ^ (UINT64)curtime.tv_nsec;
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

static void trick_algo_getrandval_with_seed(int thread_id,unsigned sip,unsigned dip,unsigned short *ipid,
			unsigned short *win,u_char *ttl, int seed_key, int seed_max_val)
{
	int val=randgroup[thread_id];

	if(val*seed_key>seed_max_val) 
	{
		randgroup[thread_id]=128;
	}
	else
	{
		randgroup[thread_id]++;
	}
	*win= (unsigned short)(val+dip%seed_key);
	if(*win==0) *win=1;
	*ipid=(unsigned short)(seed_max_val-val*seed_key+sip%(*win));
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
	ip4_hdr = (const struct mesa_ip4_hdr *)MESA_jump_layer(raw_pkt->raw_pkt_data, raw_pkt->low_layer_type, __ADDR_TYPE_IP_PAIR_V4);
	if((NULL == ip4_hdr) || (0 == ABBR_INJECT_RST_SIGN)){ /* 随机填充, 无指纹信息 */
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
        //printf("Cann't get hwaddr of %s:%s\n", device, strerror(errno));
        goto err_exit;
    }

    if(ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
    {
		//printf("'%s' is not ethernet interface!\n", device);
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


int sendpacket_in_cksum(u_int16_t *addr, int len)
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

#if 0
	if (!buf){
	    return (-1);
	}
#else
	assert(buf);
#endif

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

#if 0
	if (!buf){
	    return (-1);
	}
#else
	assert(buf);
#endif
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
	struct mesa_tcp_hdr *tcp_hdr;

	if (!buf){
	    return (-1);
	}
	
	if((option_len % 4) != 0){
		return (-2);
	}
	tcp_hdr = (struct mesa_tcp_hdr *)buf;

	tcp_hdr->th_sport   = htons(sp);    /* source port */
	tcp_hdr->th_dport   = htons(dp);    /* destination port */
	tcp_hdr->th_seq     = htonl(seq);   /* sequence number */
	tcp_hdr->th_ack     = htonl(ack);   /* acknowledgement number */
	tcp_hdr->th_flags   = control;      /* control flags */
	tcp_hdr->th_x2      = 0;            /* UNUSED */
	tcp_hdr->th_off     = 5 + option_len/4;            /* 20 byte header + option_len */
	tcp_hdr->th_win     = htons(win);   /* window size */
	tcp_hdr->th_sum     = 0;            /* checksum done in userland */ 
	tcp_hdr->th_urp     = urg;          /* urgent pointer */

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
	//memcpy((char *)buf, (char *)&tcp_hdr, sizeof(struct mesa_tcp_hdr));
	return (0);
}

int sendpacket_build_udp(u_int16_t sp, u_int16_t dp, const char *payload, int payload_s,
            unsigned char *buf)
{
    struct mesa_udp_hdr *udp_hdr;

#if 0
    if (!buf)
    {
        return (-1);
    }
#else
	assert(buf);
#endif
    udp_hdr = (struct mesa_udp_hdr *)buf;

    udp_hdr->uh_sport   = htons(sp);                /* source port */
    udp_hdr->uh_dport   = htons(dp);                /* destination port */
    udp_hdr->uh_ulen    = htons(SENDPACKET_UDP_H + payload_s);   /* total length */
    udp_hdr->uh_sum     = 0;                        /* checksum */

    if (payload && payload_s)
    {
        /*
         *  Unchecked runtime error for buf + UDP_H + payload to be greater
         *  than the allocated heap memory.
         */
        memcpy(buf + SENDPACKET_UDP_H, payload, payload_s);
    } 

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


static int calc_mpls_hdr_len(struct streaminfo_private * stream_pr, UCHAR send_stream_dir)
{
	int mpls_layer_len;
	struct layer_addr_mpls *mpls_addr = stream_pr->stream_public.addr.mpls;

	if(g_asymmetric_addr_layer_set.layer_type_index[ADDR_TYPE_MPLS][stream_pr->layer_index] != 0){
		if(send_stream_dir == DIR_C2S){
			mpls_layer_len = sizeof(struct mesa_mpls_hdr) * mpls_addr->c2s_layer_num;
			if(mpls_addr->c2s_has_ctrl_word){
				mpls_layer_len += sizeof(int);
			}
		}else{
			mpls_layer_len = sizeof(struct mesa_mpls_hdr) * mpls_addr->s2c_layer_num;
			if(mpls_addr->s2c_has_ctrl_word){
				mpls_layer_len += sizeof(int);
			}		
		}
	}else{
		/* 如果不强制要求非对称地址, 如果本侧没有地址, 先使用对侧地址信息 */
		if(send_stream_dir == DIR_C2S){
			if(mpls_addr->c2s_layer_num > 0){
				mpls_layer_len = sizeof(struct mesa_mpls_hdr) * mpls_addr->c2s_layer_num;
				if(mpls_addr->c2s_has_ctrl_word){
					mpls_layer_len += sizeof(int);
				}
			}else{
				mpls_layer_len = sizeof(struct mesa_mpls_hdr) * mpls_addr->s2c_layer_num;
				if(mpls_addr->s2c_has_ctrl_word){
					mpls_layer_len += sizeof(int);
				}
			}
		}else{
			if(mpls_addr->s2c_layer_num > 0){
				mpls_layer_len = sizeof(struct mesa_mpls_hdr) * mpls_addr->s2c_layer_num;
				if(mpls_addr->s2c_has_ctrl_word){
					mpls_layer_len += sizeof(int);
				}		
			}else{
				mpls_layer_len = sizeof(struct mesa_mpls_hdr) * mpls_addr->c2s_layer_num;
				if(mpls_addr->c2s_has_ctrl_word){
					mpls_layer_len += sizeof(int);
				}	
			}
		}			
	}

	return mpls_layer_len;
}

static int calc_vlan_hdr_len(struct streaminfo_private * stream_pr, UCHAR send_stream_dir)
{
	int vlan_layer_len;
	struct layer_addr_vlan *vlan_addr = stream_pr->stream_public.addr.vlan;

	if(g_asymmetric_addr_layer_set.layer_type_index[ADDR_TYPE_VLAN][stream_pr->layer_index] != 0){
		if(send_stream_dir == DIR_C2S){
			vlan_layer_len = sizeof(struct mesa_vlan_hdr) * vlan_addr->c2s_layer_num;
		}else{
			vlan_layer_len = sizeof(struct mesa_vlan_hdr) * vlan_addr->s2c_layer_num;		
		}
	}else{
		/* 如果不强制要求非对称地址, 如果本侧没有, 先使用对侧地址信息 */
		if(send_stream_dir == DIR_C2S){
			if(vlan_addr->c2s_layer_num != 0){
				vlan_layer_len = sizeof(struct mesa_vlan_hdr) * vlan_addr->c2s_layer_num;
			}else{
				vlan_layer_len = sizeof(struct mesa_vlan_hdr) * vlan_addr->s2c_layer_num;
			}
		}else{
			if(vlan_addr->s2c_layer_num != 0){
				vlan_layer_len = sizeof(struct mesa_vlan_hdr) * vlan_addr->s2c_layer_num;
			}else{
				vlan_layer_len = sizeof(struct mesa_vlan_hdr) * vlan_addr->c2s_layer_num;
			}	
		}			
	}

	return vlan_layer_len;
}


static int calc_gtp_hdr_len(struct streaminfo_private * stream_pr, UCHAR send_stream_dir)
{
	int hdr_len = sizeof(struct gtp_hdr);
	const struct layer_addr_gtp *p_gtp_layer_addr = stream_pr->stream_public.addr.gtp;
	const struct gtp_hdr *raw_net_gtp_hdr;
	 
	raw_net_gtp_hdr = (const struct gtp_hdr *)((const char *)stream_pr->raw_pkt->raw_pkt_data + stream_pr->offset_to_raw_pkt_hdr);
	/* 
	    暂不支持带序号的GTP隧道, 
		一个GTP隧道可能承载多个内部四元组, 按内层二元组分流还不一定分到同一个线程上, 
		怎么保证多个内层TCP/UDP连接之间的GTP序号同步??
	    太复杂了!  
	    TODO吧!!
	*/
	if(raw_net_gtp_hdr->flags & (GTP_HDR_FLAG_SEQ_NUM | GTP_HDR_FLAG_N_PDU | GTP_HDR_FLAG_NEXT_EXT_HDR))
	{
		if(0 == sapp_global_val->config.protocol_feature.skip_gtp_S_PN_E_field_for_inject){
			sapp_global_val->mthread_volatile[stream_pr->stream_public.threadnum]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
        	sapp_runtime_log(RLOG_LV_INFO, "calc_gtp_hdr_len error, inject GTP pkt not support SEQ or N-PDU or Extension header, you should set 'skip_gtp_S_PN_E_field_for_inject' to avoid this!");
        	return -1;
        }
    }

	if(g_asymmetric_addr_layer_set.layer_type_index[ADDR_TYPE_GPRS_TUNNEL][stream_pr->layer_index] != 0){
		/* 如果GTP设置了非对称标记, 必须保证当前注入方向之前曾经有数据包 */
		if(send_stream_dir == DIR_C2S){
			if(0 == p_gtp_layer_addr->teid_c2s){
				sapp_global_val->mthread_volatile[stream_pr->stream_public.threadnum]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
				 sapp_runtime_log(RLOG_LV_INFO, "inject dir:%d packet error, GTP addr is asymmetric, but stream dir is:%d", send_stream_dir, stream_pr->stream_public.dir);
				 return -1;
			}
		}else{
			if(0 == p_gtp_layer_addr->teid_s2c){
				 sapp_global_val->mthread_volatile[stream_pr->stream_public.threadnum]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
				 sapp_runtime_log(RLOG_LV_INFO, "inject dir:%d packet error, GTP addr is asymmetric, but stream dir is:%d", send_stream_dir, stream_pr->stream_public.dir);
				 return -1;
			}		
		}
	}else{
		/* 不强制GTP地址非对称, sapp发包肯定是可以的, 但是可能对端不接受 */
	}
	
	return hdr_len;
}

/*
	1-计算所有包头的长度, 用于预留空间. 计算到最底层协议, 如果有MAC也包含MAC头空间;
	2-递归过程中获取Ethernet层承载的协议类型.

	2020-09-25 lijia add args send_stream_dir, 
	send_stream_dir: 因MPLS协议只有单向地址, 可能层数还是非对称的, 需要知道发包方向, 才能确定预留头部长度. 
*/
static int calc_reserved_hdr_len(struct streaminfo *stream, int *net_layer_type, UCHAR send_stream_dir)
{
	int  reserved_hdr_len = 0;
    struct streaminfo_private *stream_pr = (struct streaminfo_private *)stream;
    const raw_pkt_t *raw_pkt;
    int pfather_hdr_len;

	if(NULL == stream){ /* 递归计算终结条件! */
		return 0;
	}
    
	if(is_proxy_stream(stream)){ /* 代理流结构为虚拟结构, 实际构造包时跳过不处理 */
		return calc_reserved_hdr_len((struct streaminfo *)stream->pfather, net_layer_type, send_stream_dir);
	}
	raw_pkt = (const raw_pkt_t *)stream_pr->raw_pkt;
	
	switch(stream->addr.addrtype){
		case ADDR_TYPE_IPV4:
			/* 2015-12-30 lijia modify, IP和端口同时存储于此结构 */
			if(STREAM_TYPE_TCP == stream->type){
				reserved_hdr_len = sizeof(struct mesa_tcp_hdr) + sizeof(struct mesa_ip4_hdr);
			}else if (STREAM_TYPE_UDP == stream->type){
				reserved_hdr_len = sizeof(struct mesa_udp_hdr) + sizeof(struct mesa_ip4_hdr);
			}else{
				//printf("addr type is tuple4v4, but stream type is not TCP or UDP!\n");
				sapp_runtime_log(RLOG_LV_FATAL, "calc_reserved_hdr_len(): addr type is tuple4v4, but stream type is :%d, not TCP or UDP.\n", stream->type);		
				return -1;
				//assert(0);
			}
		break;
		
		case ADDR_TYPE_IPV6:
			/* 2015-12-30 lijia modify, IP和端口同时存储于此结构 */
			if(STREAM_TYPE_TCP == stream->type){
				reserved_hdr_len = sizeof(struct mesa_tcp_hdr) + sizeof(struct mesa_ip6_hdr);;
			}else if (STREAM_TYPE_UDP == stream->type){
				reserved_hdr_len = sizeof(struct mesa_udp_hdr) + sizeof(struct mesa_ip6_hdr);;
			}else{
				//printf("addr type is tuple4v6, but stream type is not TCP or UDP!\n");
				sapp_runtime_log(RLOG_LV_FATAL, "calc_reserved_hdr_len(): addr type is tuple4v6, but stream type is :%d, not TCP or UDP.\n", stream->type);		
				return -1;
				//assert(0);
			}
		break;

		case ADDR_TYPE_VLAN:
			reserved_hdr_len = calc_vlan_hdr_len(stream_pr, send_stream_dir);
		break;

		case ADDR_TYPE_MAC:
			reserved_hdr_len = sizeof(struct mesa_ethernet_hdr);
		break;

		case ADDR_TYPE_ARP:
			//printf("Sendpacket use ARP!\n");
			sapp_runtime_log(RLOG_LV_FATAL, "calc_reserved_hdr_len(): Sendpacket use ARP.\n");		
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
			reserved_hdr_len = calc_mpls_hdr_len(stream_pr, send_stream_dir);
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
			reserved_hdr_len = calc_l2tp_hdr_len(stream_pr, send_stream_dir);
		}
		break;
		
		case ADDR_TYPE_GPRS_TUNNEL:
		{
			reserved_hdr_len = calc_gtp_hdr_len(stream_pr, send_stream_dir);
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
			reserved_hdr_len = sizeof(struct mesa_ethernet_hdr);
		break;

		case ADDR_TYPE_VXLAN:
		{
			const struct layer_addr_vxlan_private *vxaddr_pr = (struct layer_addr_vxlan_private *)stream_pr->stream_public.addr.paddr;
			reserved_hdr_len = vxaddr_pr->actual_total_len;
		}
		break;
		
		default:
			/* to do */
			sapp_runtime_log(30, "calc_reserved_hdr_len(): Not support addrtype:%d\n", stream->addr.addrtype);
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
		if(stream_pr->pfather_pr 
		 && ((ADDR_TYPE_MAC_IN_MAC == stream_pr->pfather_pr->stream_public.addr.addrtype) || (ADDR_TYPE_MAC == stream_pr->pfather_pr->stream_public.addr.addrtype))){
			/* 记录MAC层之上的协议地址类型, 用于填充Ethernet->type字段, 对于MAC-in-MAC的inner_eth, 记录上层协议类型 */
			*net_layer_type = (int)stream->addr.addrtype;
		}
	}else{
		/* to do:
			如果捕包库自动屏蔽了ethernet层, 甚至剥掉了vlan等层而且还要发包怎么办?
		*/
		if(NULL == stream_pr->pfather_pr){
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
	pfather_hdr_len = calc_reserved_hdr_len((struct streaminfo *)stream_pr->pfather_pr, net_layer_type, send_stream_dir);
	if(pfather_hdr_len < 0){
		return -1;
	}
	
	return reserved_hdr_len + pfather_hdr_len;
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

static int build_net_layer_ethernet(const struct streaminfo *top_stream, struct streaminfo_private *stream_pr, unsigned short eth_type_host,
			int carry_layer_len, unsigned char *buf, UCHAR send_stream_dir, const raw_pkt_t *raw_pkt)
{
	/* 
	   注意此处不能使用原始包中的地址, 因为涉及到两侧地址不对称, 不像ip地址和端口, 颠倒src和dst即可,
	   如果C2S和S2C流量分别来自两条链路, C2S和S2C方向的mac全部不一样, 一共会有四个MAC地址, 而不是两个!
	   如果是反向发包, 即使颠倒src, dst也是错误的!!
	*/
	const struct layer_addr_mac *in_stream_addr;
	in_stream_addr = (struct layer_addr_mac *)(stream_pr->stream_public.addr.mac);
	struct mesa_ethernet_hdr *send_hdr = (struct mesa_ethernet_hdr *)buf;

	send_hdr->ether_type = htons(eth_type_host);

	/* 并联模式下,最底层无需构建ethernet地址,
	   无论inject_pkt_mode是什么模式, sys_route还是raw_ethernet_single_gateway等等, 最外层mac实际都不是原始包中的mac地址,
	   此时也不关心配置文件etc/asymmetric_addr_layer.conf的ethernet[0]是否开启, 从而导致单向流的反向发包无效.
	*/
	if((NULL == stream_pr->pfather_pr)  
	 && (DEPOLYMENT_MODE_MIRROR == sapp_global_val->config.packet_io.depolyment_mode_bin)){
		return sizeof(struct mesa_ethernet_hdr);
	}

	if(g_asymmetric_addr_layer_set.layer_type_index[ADDR_TYPE_MAC][stream_pr->layer_index] == 0){
		if(DIR_C2S == send_stream_dir){
			memcpy(send_hdr->ether_shost, in_stream_addr->src_addr.h_source, ETHER_ADDR_LEN);
			memcpy(send_hdr->ether_dhost, in_stream_addr->src_addr.h_dest, ETHER_ADDR_LEN);
		}else{
			memcpy(send_hdr->ether_shost, in_stream_addr->src_addr.h_dest, ETHER_ADDR_LEN);
			memcpy(send_hdr->ether_dhost, in_stream_addr->src_addr.h_source, ETHER_ADDR_LEN);
		}		
	}else{
		if((top_stream->dir & send_stream_dir) == 0){
			sapp_global_val->mthread_volatile[stream_pr->stream_public.threadnum]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
			sapp_runtime_log(RLOG_LV_FATAL, "build_net_layer_ethernet() error! ethernet[%d] asymmetric_addr_layer is enabled, but has not recv this dir packet!\n", stream_pr->layer_index);
			return -1;
		}
		if(DIR_C2S == send_stream_dir){
			memcpy(send_hdr->ether_shost, in_stream_addr->src_addr.h_source, ETHER_ADDR_LEN); /* 地址同向copy */
			memcpy(send_hdr->ether_dhost, in_stream_addr->src_addr.h_dest, ETHER_ADDR_LEN);
		}else{
			memcpy(send_hdr->ether_shost, in_stream_addr->dst_addr.h_source, ETHER_ADDR_LEN); /* 地址同向copy */
			memcpy(send_hdr->ether_dhost, in_stream_addr->dst_addr.h_dest, ETHER_ADDR_LEN);
		}
	}

	return sizeof(struct mesa_ethernet_hdr);
}


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

	if((reverse)
	&& (g_overlay_layer_set[ADDR_TYPE_UDP][stream_pr->layer_index] == 0)){ /* vxlan等overlay层不翻转端口 */
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
		if((stream_pr->pfather_pr != NULL) 
		 && (stream_pr->pfather_pr->stream_public.addr.addrtype == ADDR_TYPE_GPRS_TUNNEL)
		 && (g_gtp_info_hash[threadnum] != NULL))
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

	if(0 == g_ipv6_decapsulation_enabled){
		sapp_runtime_log(30, "IPv6 module is not support! Please set 'ipv6_decapsulation_enabled=1' in sapp.toml.\n");
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
		if((stream_pr->pfather_pr != NULL) 
		&& (stream_pr->pfather_pr->stream_public.addr.addrtype == ADDR_TYPE_GPRS_TUNNEL)
		&& (g_gtp_info_hash[threadnum] != NULL))
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

/* 把网络传输的地址转换为内存结构, 方便业务插件处理 */
int vlan_addr_net_to_mem(const struct mesa_vlan_detail_hdr *net_vlan_hdr, struct single_layer_vlan_addr *mem_vlan_hdr)
{
	mem_vlan_hdr->VID = htons(net_vlan_hdr->vlan_id_high << 8 | net_vlan_hdr->vlan_id_low);
	mem_vlan_hdr->TPID = net_vlan_hdr->type;
	mem_vlan_hdr->PCP = net_vlan_hdr->priority;
	mem_vlan_hdr->DEI = net_vlan_hdr->del_flag;

	return 0;
}

/* 把内存地址结构转换为RFC标准头部格式, 发送到网络中 */
int vlan_addr_mem_to_net(const struct single_layer_vlan_addr *mem_vlan_hdr, struct mesa_vlan_detail_hdr *net_vlan_hdr)
{
	net_vlan_hdr->vlan_id_high = (ntohs(mem_vlan_hdr->VID) & 0xF00) >> 8;
	net_vlan_hdr->vlan_id_low = (ntohs(mem_vlan_hdr->VID) & 0xFF);
	net_vlan_hdr->type = mem_vlan_hdr->TPID;
	net_vlan_hdr->priority = mem_vlan_hdr->PCP;
	net_vlan_hdr->del_flag = mem_vlan_hdr->DEI;

	return 0;
}


static int build_net_multilayer_vlan(const struct single_layer_vlan_addr *layer_array, int layer_num, struct mesa_vlan_detail_hdr *net_vlan_hdr)
{
	int i;
	
	for( i = 0; i < layer_num; i++){
		vlan_addr_mem_to_net(&layer_array[i], net_vlan_hdr);
		net_vlan_hdr++;
	}

	return 0;
}


static int build_net_layer_vlan(struct streaminfo_private *stream_pr, int carry_layer_type,
			int carry_layer_len, unsigned char *buf, UCHAR send_stream_dir, const raw_pkt_t *raw_pkt)
{
	const struct layer_addr_vlan *in_stream_addr;
	int layer_len = 0;

	in_stream_addr = (struct layer_addr_vlan *)(stream_pr->stream_public.addr.vlan);

	if(DIR_C2S == send_stream_dir){
		if(in_stream_addr->c2s_layer_num > 0){
			layer_len = sizeof(struct mesa_vlan_hdr) * in_stream_addr->c2s_layer_num;
			//memcpy(buf, in_stream_addr->c2s_addr_array, layer_len);
			build_net_multilayer_vlan(in_stream_addr->c2s_addr_array, in_stream_addr->c2s_layer_num, (struct mesa_vlan_detail_hdr *)buf);
		}else{ 
			/* 本侧没有地址, 取决于配置文件asymmetric_addr_layer是否可以用对侧地址 */
			if(0 == g_asymmetric_addr_layer_set.layer_type_index[ADDR_TYPE_VLAN][stream_pr->layer_index]){
				layer_len = sizeof(struct mesa_vlan_hdr) * in_stream_addr->s2c_layer_num;
				build_net_multilayer_vlan(in_stream_addr->s2c_addr_array, in_stream_addr->s2c_layer_num, (struct mesa_vlan_detail_hdr *)buf);
				///memcpy(buf, in_stream_addr->s2c_addr_array, layer_len);
			}else{
				sapp_global_val->mthread_volatile[stream_pr->stream_public.threadnum]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
				sapp_runtime_log(RLOG_LV_INFO, "build_net_layer_vlan() error, no c2s vlan addr, but asymmetric_addr_layer is set!\n");
				return -1;
			}
		}
	}else{
		if(in_stream_addr->s2c_layer_num > 0){
			layer_len = sizeof(struct mesa_vlan_hdr) * in_stream_addr->s2c_layer_num;
			//memcpy(buf, in_stream_addr->s2c_addr_array, layer_len);
			build_net_multilayer_vlan(in_stream_addr->s2c_addr_array, in_stream_addr->s2c_layer_num, (struct mesa_vlan_detail_hdr *)buf);
		}else{
			/* 本侧没有地址, 取决于配置文件asymmetric_addr_layer是否可以用对侧地址 */
			if(0 == g_asymmetric_addr_layer_set.layer_type_index[ADDR_TYPE_VLAN][stream_pr->layer_index]){
				layer_len = sizeof(struct mesa_vlan_hdr) * in_stream_addr->c2s_layer_num;
				//memcpy(buf, in_stream_addr->c2s_addr_array, layer_len);
				build_net_multilayer_vlan(in_stream_addr->c2s_addr_array, in_stream_addr->c2s_layer_num, (struct mesa_vlan_detail_hdr *)buf);
			}else{
				sapp_global_val->mthread_volatile[stream_pr->stream_public.threadnum]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
				sapp_runtime_log(RLOG_LV_INFO, "build_net_layer_vlan() error, no s2c vlan addr, but asymmetric_addr_layer is set!\n");
				return -1;
			}
		}
	}

	return layer_len;	
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

static int build_net_layer_gre(const struct streaminfo *top_stream, struct streaminfo_private *stream_pr, int carry_layer_type,
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
	
	if((reverse != 0) && (top_stream->dir != DIR_DOUBLE)){
	    	/* 反方向没有收到过包, 反向发送无法填充 */
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

/* 把网络传输的地址转换为内存结构, 方便业务插件处理 */
int mpls_addr_net_to_mem(const struct mesa_mpls_hdr *net_mpls_hdr, struct single_layer_mpls_addr *mem_mpls_hdr)
{
	memset(mem_mpls_hdr, 0, sizeof(struct single_layer_mpls_addr));

	mem_mpls_hdr->label = htonl( (net_mpls_hdr->mpls_label_low<<12) | (net_mpls_hdr->mpls_label_mid<<4) | net_mpls_hdr->mpls_label_high ); /* network order */
	mem_mpls_hdr->experimental = net_mpls_hdr->mpls_exp;
	mem_mpls_hdr->bottom = net_mpls_hdr->mpls_bls;
	mem_mpls_hdr->ttl = net_mpls_hdr->mpls_ttl;

	return 0;
}

/* 把内存地址结构转换为RFC标准头部格式, 发送到网络中 */
int mpls_addr_mem_to_net(const struct single_layer_mpls_addr *mem_mpls_hdr, struct mesa_mpls_hdr *net_mpls_hdr)
{
	memset(net_mpls_hdr, 0, sizeof(struct mesa_mpls_hdr));

	net_mpls_hdr->mpls_label_low = (ntohl(mem_mpls_hdr->label) & 0xFF000) >> 12;  
	net_mpls_hdr->mpls_label_mid = (ntohl(mem_mpls_hdr->label) & 0xFF0) >> 4;
	net_mpls_hdr->mpls_label_high = ntohl(mem_mpls_hdr->label) & 0xF;
	net_mpls_hdr->mpls_exp = mem_mpls_hdr->experimental;
	net_mpls_hdr->mpls_bls = mem_mpls_hdr->bottom;
	net_mpls_hdr->mpls_ttl = mem_mpls_hdr->ttl;

	return 0;
}


static int build_net_multilayer_mpls(const struct single_layer_mpls_addr *layer_array, int layer_num, struct mesa_mpls_hdr *net_mpls_hdr)
{
	int i;
	
	for( i = 0; i < layer_num; i++){
		mpls_addr_mem_to_net(&layer_array[i], net_mpls_hdr);
		net_mpls_hdr++;
	}

	return 0;
}


static int build_net_layer_mpls(struct streaminfo_private *stream_pr, int carry_layer_type,
			int carry_layer_len, unsigned char *buf, UCHAR send_stream_dir, const raw_pkt_t *raw_pkt)
{
	const struct layer_addr_mpls *in_stream_addr;
	int layer_len = 0;

	in_stream_addr = (struct layer_addr_mpls *)(stream_pr->stream_public.addr.mpls);

	if(DIR_C2S == send_stream_dir){
		if(in_stream_addr->c2s_layer_num > 0){
			layer_len = sizeof(struct mesa_mpls_hdr) * in_stream_addr->c2s_layer_num;
			//memcpy(buf, in_stream_addr->src_mpls_pkt, layer_len);
			build_net_multilayer_mpls(in_stream_addr->c2s_addr_array, in_stream_addr->c2s_layer_num, (struct mesa_mpls_hdr *)buf);
			
			if(in_stream_addr->c2s_has_ctrl_word){
				memcpy(buf + layer_len, &in_stream_addr->c2s_mpls_ctrl_word, sizeof(int));
				layer_len += sizeof(int);
			}
		}else{
			/* 本侧没有地址, 取决于配置文件asymmetric_addr_layer是否可以用对侧地址 */
			if(0 == g_asymmetric_addr_layer_set.layer_type_index[ADDR_TYPE_MPLS][stream_pr->layer_index]){
				layer_len = sizeof(struct mesa_mpls_hdr) * in_stream_addr->s2c_layer_num;
				//memcpy(buf, in_stream_addr->dest_mpls_pkt, layer_len);
				build_net_multilayer_mpls(in_stream_addr->s2c_addr_array, in_stream_addr->s2c_layer_num, (struct mesa_mpls_hdr *)buf);
				if(in_stream_addr->s2c_has_ctrl_word){
					memcpy(buf + layer_len, &in_stream_addr->s2c_mpls_ctrl_word, sizeof(int));
					layer_len += sizeof(int);
				}				
			}else{
				sapp_global_val->mthread_volatile[stream_pr->stream_public.threadnum]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
				sapp_runtime_log(RLOG_LV_INFO, "build_net_layer_mpls() error, no c2s mpls addr, but asymmetric_addr_layer is set!\n");
				return -1;
			}
		}
	}else{
		if(in_stream_addr->s2c_layer_num > 0){
			layer_len = sizeof(struct mesa_mpls_hdr) * in_stream_addr->s2c_layer_num;
			//memcpy(buf, in_stream_addr->dest_mpls_pkt, layer_len);
			build_net_multilayer_mpls(in_stream_addr->s2c_addr_array, in_stream_addr->s2c_layer_num, (struct mesa_mpls_hdr *)buf);
			if(in_stream_addr->s2c_has_ctrl_word){
				memcpy(buf + layer_len, &in_stream_addr->s2c_mpls_ctrl_word, sizeof(int));
				layer_len += sizeof(int);
			}
		}else{
			/* 本侧没有地址, 取决于配置文件asymmetric_addr_layer是否可以用对侧地址 */
			if(0 == g_asymmetric_addr_layer_set.layer_type_index[ADDR_TYPE_MPLS][stream_pr->layer_index]){
				layer_len = sizeof(struct mesa_mpls_hdr) * in_stream_addr->c2s_layer_num;
				//memcpy(buf, in_stream_addr->src_mpls_pkt, layer_len);
				build_net_multilayer_mpls(in_stream_addr->c2s_addr_array, in_stream_addr->c2s_layer_num, (struct mesa_mpls_hdr *)buf);
				if(in_stream_addr->c2s_has_ctrl_word){
					memcpy(buf + layer_len, &in_stream_addr->c2s_mpls_ctrl_word, sizeof(int));
					layer_len += sizeof(int);
				}
			}else{
				sapp_global_val->mthread_volatile[stream_pr->stream_public.threadnum]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
				sapp_runtime_log(RLOG_LV_INFO, "build_net_layer_mpls() error, no s2c mpls addr, but asymmetric_addr_layer is set!\n");
				return -1;
			}
		}
	}	

	return layer_len;
}

static int build_net_layer_gtp(struct streaminfo_private *stream_pr, int carry_layer_type,
								int carry_layer_len, unsigned char *buf, UCHAR send_stream_dir, const raw_pkt_t *raw_pkt)
{
	const struct gtp_hdr *raw_hdr;
	struct gtp_hdr *gtp_send_hdr;
	int gtp_net_layer_len = sizeof(struct gtp_hdr);
	void *gtp_hash_key;
	int gtp_hash_key_len;
	const struct layer_addr_gtp *p_gtp_layer_addr = stream_pr->stream_public.addr.gtp;
	unsigned int this_pkt_teid;
	
	raw_hdr = (const struct gtp_hdr *)(stream_pr->offset_to_raw_pkt_hdr + (char *)raw_pkt->raw_pkt_data);
	gtp_send_hdr  = (struct gtp_hdr *)buf;

	if(DIR_C2S == send_stream_dir){
		if(0 == p_gtp_layer_addr->teid_c2s){
			if(g_asymmetric_addr_layer_set.layer_type_index[ADDR_TYPE_GPRS_TUNNEL][stream_pr->layer_index] != 0){
				sapp_global_val->mthread_volatile[stream_pr->stream_public.threadnum]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
				sapp_runtime_log(RLOG_LV_INFO, "build_net_layer_gtp() error, no c2s gtp addr, but asymmetric_addr_layer is set!\n");
				return -1;				
			}else{
				this_pkt_teid = p_gtp_layer_addr->teid_s2c;
			}
		}else{
			this_pkt_teid = p_gtp_layer_addr->teid_c2s;
		}
	}else{
		if(0 == p_gtp_layer_addr->teid_s2c){
			if(g_asymmetric_addr_layer_set.layer_type_index[ADDR_TYPE_GPRS_TUNNEL][stream_pr->layer_index] != 0){
				sapp_global_val->mthread_volatile[stream_pr->stream_public.threadnum]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
				sapp_runtime_log(RLOG_LV_INFO, "build_net_layer_gtp() error, no s2c gtp addr, but asymmetric_addr_layer is set!\n");
				return -1;				
			}else{
				this_pkt_teid = p_gtp_layer_addr->teid_c2s;
			}
		}else{
			this_pkt_teid = p_gtp_layer_addr->teid_s2c;
		}
	}

	gtp_send_hdr->flags = 0x30; /* 暂时只支持v1版本, 不含seq */
	gtp_send_hdr->msg_type = 0xFF; /* T-PDU */
	gtp_send_hdr->len = htons(carry_layer_len);
	gtp_send_hdr->teid = this_pkt_teid;
	
	return gtp_net_layer_len;
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

#if 0
static int build_net_layer_vxlan(struct streaminfo_private *stream_pr, int carry_layer_type,
			int carry_layer_len, unsigned char *buf, UCHAR send_stream_dir, const raw_pkt_t *raw_pkt, const struct layer_addr_vxlan_private *raw_vxlan_hdr)
{
	inline_vxlan_hdr_t *send_vxlan_hdr = (inline_vxlan_hdr_t *)buf;

	//vlan_id = htons((vlan_id_high<<4) | vlan_id_low);
	
	memset(send_vxlan_hdr, 0, sizeof(inline_vxlan_hdr_t));
	send_vxlan_hdr->flags = 0x08;
	send_vxlan_hdr->vlan_id_half_high = ntohs(raw_vxlan_hdr->addr_public.vlan_id) >> 4;
	send_vxlan_hdr->vlan_id_half_low = ntohs(raw_vxlan_hdr->addr_public.vlan_id) & 0xF;
	send_vxlan_hdr->link_layer_type = raw_vxlan_hdr->addr_public.link_type;
	send_vxlan_hdr->link_id = raw_vxlan_hdr->addr_public.link_id;

	if(DIR_C2S == send_stream_dir){
		send_vxlan_hdr->dir = stream_pr->stream_c2s_route_dir;
	}else{
		send_vxlan_hdr->dir = stream_pr->stream_c2s_route_dir ^ 1;
	}

	if(VXLAN_ENCAP_HDLC == raw_vxlan_hdr->addr_public.link_type){
		struct hdlc_net_hdr *snd_hdlc_hdr = (struct hdlc_net_hdr *)(buf + sizeof(inline_vxlan_hdr_t));
		snd_hdlc_hdr->address = raw_vxlan_hdr->inner_hdlc.address;
		snd_hdlc_hdr->control = raw_vxlan_hdr->inner_hdlc.control;
		snd_hdlc_hdr->protocol = raw_vxlan_hdr->inner_hdlc.protocol;
	}else if(VXLAN_ENCAP_PPP == raw_vxlan_hdr->addr_public.link_type){
		struct layer_ppp_hdr *snd_ppp_hdr = (struct layer_ppp_hdr *)(buf + sizeof(inline_vxlan_hdr_t));
		snd_ppp_hdr->address = raw_vxlan_hdr->inner_ppp.address;
		snd_ppp_hdr->control = raw_vxlan_hdr->inner_ppp.control;
		snd_ppp_hdr->protocol = raw_vxlan_hdr->inner_ppp.protocol;
	}else{
		;//ethernet, do nothing!
	}

	return raw_vxlan_hdr->actual_total_len;
}
#else

static void build_net_single_layer_vxlan(struct streaminfo_private *stream_pr, inline_vxlan_hdr_t *send_vxlan_hdr, const struct layer_addr_vxlan_private *raw_vxlan_hdr, UCHAR send_stream_dir)
{
	const struct single_layer_addr_vxlan *single_addr;

	if(DIR_C2S == send_stream_dir){
		single_addr = &raw_vxlan_hdr->addr_public.C2S_vxlan_addr;
	}else{
		single_addr = &raw_vxlan_hdr->addr_public.S2C_vxlan_addr;
	}
	
	memset(send_vxlan_hdr, 0, sizeof(inline_vxlan_hdr_t));
	send_vxlan_hdr->flags = 0x08;
	send_vxlan_hdr->vlan_id_half_high = ntohs(single_addr->vlan_id) >> 4;
	send_vxlan_hdr->vlan_id_half_low = ntohs(single_addr->vlan_id) & 0xF;
	send_vxlan_hdr->link_layer_type = single_addr->link_type;
	send_vxlan_hdr->link_id = single_addr->link_id;
	send_vxlan_hdr->dir = single_addr->dir;     //20220415 liuxueli for TSG-10227
#if 0  //20220415 liuxueli for TSG-10227
	if(DIR_C2S == send_stream_dir){
		send_vxlan_hdr->dir = stream_pr->stream_c2s_route_dir;
	}else{
		send_vxlan_hdr->dir = stream_pr->stream_c2s_route_dir ^ 1;
	}
#endif
}

static int build_net_layer_vxlan(struct streaminfo_private *stream_pr, int carry_layer_type,
			int carry_layer_len, unsigned char *buf, UCHAR send_stream_dir, const raw_pkt_t *raw_pkt, const struct layer_addr_vxlan_private *raw_vxlan_hdr)

{
	const struct layer_addr_vxlan *in_stream_addr;
	inline_vxlan_hdr_t *send_vxlan_hdr = (inline_vxlan_hdr_t *)buf;


	in_stream_addr = (struct layer_addr_vxlan *)(stream_pr->stream_public.addr.vxlan);

	if(DIR_C2S == send_stream_dir){
		if(in_stream_addr->C2S_vxlan_addr.flag != 0){
			build_net_single_layer_vxlan(stream_pr, send_vxlan_hdr, raw_vxlan_hdr, send_stream_dir);
		}else{ 
			/* 本侧没有地址, 取决于配置文件asymmetric_addr_layer是否可以用对侧地址 */
			if(0 == g_asymmetric_addr_layer_set.layer_type_index[ADDR_TYPE_VXLAN][stream_pr->layer_index]){
				build_net_single_layer_vxlan(stream_pr, send_vxlan_hdr, raw_vxlan_hdr, send_stream_dir ^ DIR_DOUBLE);
			}else{
				sapp_global_val->mthread_volatile[stream_pr->stream_public.threadnum]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
				sapp_runtime_log(RLOG_LV_INFO, "build_net_layer_vxlan() error, no c2s vxlan addr, but asymmetric_addr_layer is set!\n");
				return -1;
			}
		}
	}else{
		if(in_stream_addr->S2C_vxlan_addr.flag > 0){
			build_net_single_layer_vxlan(stream_pr, send_vxlan_hdr, raw_vxlan_hdr, send_stream_dir);
		}else{
			/* 本侧没有地址, 取决于配置文件asymmetric_addr_layer是否可以用对侧地址 */
			if(0 == g_asymmetric_addr_layer_set.layer_type_index[ADDR_TYPE_VXLAN][stream_pr->layer_index]){
				build_net_single_layer_vxlan(stream_pr, send_vxlan_hdr, raw_vxlan_hdr, send_stream_dir ^ DIR_DOUBLE);
			}else{
				sapp_global_val->mthread_volatile[stream_pr->stream_public.threadnum]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
				sapp_runtime_log(RLOG_LV_INFO, "build_net_layer_vxlan() error, no s2c vxlan addr, but asymmetric_addr_layer is set!\n");
				return -1;
			}
		}
	}

	/*
		TODO: ppp, hdlc层也分c2s, s2c两个方向存储.
	*/
	if(VXLAN_ENCAP_HDLC == raw_vxlan_hdr->addr_public.C2S_vxlan_addr.link_type){
		struct hdlc_net_hdr *snd_hdlc_hdr = (struct hdlc_net_hdr *)(buf + sizeof(inline_vxlan_hdr_t));
		snd_hdlc_hdr->address = raw_vxlan_hdr->inner_hdlc.address;
		snd_hdlc_hdr->control = raw_vxlan_hdr->inner_hdlc.control;
		snd_hdlc_hdr->protocol = raw_vxlan_hdr->inner_hdlc.protocol;
	}else if(VXLAN_ENCAP_PPP == raw_vxlan_hdr->addr_public.C2S_vxlan_addr.link_type){
		struct layer_ppp_hdr *snd_ppp_hdr = (struct layer_ppp_hdr *)(buf + sizeof(inline_vxlan_hdr_t));
		snd_ppp_hdr->address = raw_vxlan_hdr->inner_ppp.address;
		snd_ppp_hdr->control = raw_vxlan_hdr->inner_ppp.control;
		snd_ppp_hdr->protocol = raw_vxlan_hdr->inner_ppp.protocol;
	}else{
		;//ethernet, do nothing!
	}
	

	return raw_vxlan_hdr->actual_total_len;

}
#endif

static int build_net_layer_l2tp(const struct streaminfo *top_stream, struct streaminfo_private *stream_pr, int carry_layer_type,
			int carry_layer_len, unsigned char *buf, unsigned char send_stream_dir, const raw_pkt_t *raw_pkt, int l2tp_raw_hdr_len)
{
	struct l2tp_hdr_v2 *inject_net_hdr;
	unsigned char *inject_ptr;
	unsigned short* inject_short_ptr;
	const struct layer_addr_l2tp *stream_l2tp_layer_addr = stream_pr->stream_public.addr.l2tp;
	
	if(0 == (top_stream->dir & send_stream_dir)){
		/* TODO 2:
			L2TP包c2s和s2c方向TUNNEL-ID不一样, 目前没有形成L2TP流, 无法保存另一个方向的信息 ,
			所以, 不支持单向流反向注入数据包.
		*/
		sapp_runtime_log(RLOG_LV_INFO, "build_net_layer_l2tp() error, not support inject reverse pkt for single dir stream!");
		return -1;
	}

	memset(buf, 0, l2tp_raw_hdr_len);
	
	inject_net_hdr = (struct l2tp_hdr_v2 *)buf;
	inject_ptr = buf + sizeof(struct l2tp_hdr_v2); /* 指向固定头部后面的缓冲区 */
	
	inject_net_hdr->type = 0; /* 目前仅支持注入data message */
	inject_net_hdr->offset_present = 0;
	inject_net_hdr->priority = 0;
	inject_net_hdr->seq_present = 0; 
	inject_net_hdr->version = 2; /* 目前固定支持v2 */

	/* 
		注入l2tp数据包固定带有length字段
	*/
	{
		inject_net_hdr->length_present = 1;
		inject_short_ptr = (unsigned short *)inject_ptr;
		*inject_short_ptr = htons(carry_layer_len + l2tp_raw_hdr_len);

		inject_ptr += sizeof(struct l2tp_hdr_v2);
	}

	if(DIR_C2S == send_stream_dir){
		inject_short_ptr = (unsigned short *)inject_ptr;
		*inject_short_ptr = stream_l2tp_layer_addr->l2tpun.l2tp_addr_v2.tunnelid_C2S; /* 2 byte tunnel id */
		inject_ptr += sizeof(short);

		inject_short_ptr = (unsigned short *)inject_ptr;
		*inject_short_ptr = stream_l2tp_layer_addr->l2tpun.l2tp_addr_v2.sessionid_C2S; /* 2 byte session id */
		inject_ptr += sizeof(short);	
	}else{
		inject_short_ptr = (unsigned short *)inject_ptr;
		*inject_short_ptr = stream_l2tp_layer_addr->l2tpun.l2tp_addr_v2.tunnelid_S2C; /* 2 byte tunnel id */
		inject_ptr += sizeof(short);

		inject_short_ptr = (unsigned short *)inject_ptr;
		*inject_short_ptr = stream_l2tp_layer_addr->l2tpun.l2tp_addr_v2.sessionid_S2C; /* 2 byte session id */
		inject_ptr += sizeof(short);	
	}

	if(stream_l2tp_layer_addr->l2tpun.l2tp_addr_v2.ppp_hdr_compress_enable){
		*inject_ptr = stream_l2tp_layer_addr->l2tpun.l2tp_addr_v2.compress_ppp_hdr.protocol;
	}else{
		*inject_ptr = stream_l2tp_layer_addr->l2tpun.l2tp_addr_v2.ppp_hdr.address;
		inject_ptr++;
		*inject_ptr = stream_l2tp_layer_addr->l2tpun.l2tp_addr_v2.ppp_hdr.control;
		inject_ptr++;
		inject_short_ptr = (unsigned short *)inject_ptr;
		*inject_short_ptr = stream_l2tp_layer_addr->l2tpun.l2tp_addr_v2.ppp_hdr.protocol;
	}

	return l2tp_raw_hdr_len;
}


/* 
    此函数内部不用再判断是否需要加入bloom filter, 在函数外部已经判断.
*/
static void sendpkt_dup_pkt_mark(const struct streaminfo *top_stream, unsigned char addrtype, const char *this_iphdr, const char *this_transport_hdr)
{
	if(STREAM_TYPE_TCP == top_stream->type){
		sapp_dup_pkt_mark_tcp(top_stream->threadnum, addrtype, this_iphdr, (const struct mesa_tcp_hdr *)(this_transport_hdr));
	}else{
		sapp_dup_pkt_mark_udp(top_stream->threadnum, addrtype, this_iphdr, (const struct mesa_udp_hdr *)(this_transport_hdr));
	}

	return;
}

void sendpkt_dup_pkt_mark_stream(const struct streaminfo *top_stream, const char *ip_hdr)
{
	const struct mesa_ip4_hdr *ip4hdr;
	const struct mesa_ip6_hdr *ip6hdr;
	sapp_dup_pkt_key_v4_t dup_bloom_key_v4;
	sapp_dup_pkt_key_v6_t dup_bloom_key_v6;	
	const char *transport_layer_hdr;
	
	if(ADDR_TYPE_IPV4 == top_stream->addr.addrtype){
		ip4hdr = (struct mesa_ip4_hdr *)ip_hdr;
		transport_layer_hdr = ip_hdr + ip4hdr->ip_hl * 4;
		sendpkt_dup_pkt_mark(top_stream, ADDR_TYPE_IPV4, ip_hdr, transport_layer_hdr);
	}else{
		ip6hdr = (struct mesa_ip6_hdr *)ip_hdr;
		transport_layer_hdr = ip_hdr + sizeof(struct mesa_ip6_hdr);	
		sendpkt_dup_pkt_mark(top_stream, ADDR_TYPE_IPV6, ip_hdr, transport_layer_hdr);
	}
}


/* 
	buf: 执向应用层负载地址, skip hdr.
	reverse: 从应用层的角度区别dir, 表示与当前raw_pkt包相比, 方向是否一致, 对于有方向性的地址, 需反向造包.

	2020-09-25 lijia add args send_stream_dir:
	send_stream_dir: 表示当前发包的流方向, DIR_C2S或者DIR_S2C, 
	                 因为MPLS, GTP等层原始包里只有单向地址, reverse的含义不能精确表示mpls, gtp等层到底使用哪个方向的地址.
	top_stream: 最上层的流结构体, 通常即tcp或udp流, 此值所有函数栈中保持不变.                 
*/
static int build_net_layer_pkt(const struct streaminfo *top_stream, const struct streaminfo *up_stream, struct streaminfo_private *stream_pr, int carry_layer_type,
			int carry_layer_len, unsigned char *buf, int reverse, const raw_pkt_t *raw_pkt, UCHAR send_stream_dir)
{
	int this_layer_len = 0, ret;
	int transport_layer_len;
	struct streaminfo *stream;
	char debug_print_buf[256];
	const struct streaminfo *carry_layer_stream;
	
	
	if(NULL == stream_pr){
		return carry_layer_len;
	}

	stream = &stream_pr->stream_public;
	carry_layer_stream = stream;

	if(is_proxy_stream(stream)){ /* 代理流结构为虚拟结构, 实际的包不存在此层, 构造包时跳过不处理 */
		return build_net_layer_pkt(top_stream, carry_layer_stream, (struct streaminfo_private *)stream->pfather, carry_layer_type, 
								this_layer_len+carry_layer_len, buf, reverse, raw_pkt, send_stream_dir);
	}

	switch(stream->addr.addrtype){
		case ADDR_TYPE_IPV4:
		{
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
			const struct mesa_ip4_hdr *ip4hdr = (struct mesa_ip4_hdr *)buf;
			sapp_runtime_log(RLOG_LV_DEBUG, "build_net_layer_pkt()->IPV4, %s, send_stream_dir:%d, ipid:%u, ip_checksum:0x%x", 
							sapp_raw_ipv4_ntop(ip4hdr, debug_print_buf, sizeof(debug_print_buf)), send_stream_dir,
							ntohs(ip4hdr->ip_id), ntohs(ip4hdr->ip_sum));

			/* 重复流量注入包识别, 加到这里是因为如果有隧道, 可能会有多层, 且不用再经过jump_layer跳转到内部udp/tcp层了 
               vxlan模式底层udp没必要频繁加入bloom filter, 先调用sapp_is_overlay_layer()识别一下.
			*/
			if((sapp_global_val->config.packet_io.dup_pkt_para.dup_pkt_distinguish_all_inject != 0)
			 && (sapp_is_overlay_layer(stream_pr, raw_pkt) == 0)){
				sendpkt_dup_pkt_mark(top_stream, ADDR_TYPE_IPV4, (char *)buf, buf+sizeof(struct mesa_ip4_hdr));
			}
		}	
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

			/* 重复流量识别, 加到这里是因为如果有隧道, 可能会有多层, 且不用再经过jump_layer跳转到内部udp/tcp层了 */
			if(sapp_global_val->config.packet_io.dup_pkt_para.dup_pkt_distinguish_all_inject != 0){
				sendpkt_dup_pkt_mark(top_stream, ADDR_TYPE_IPV6, (char *)buf, buf+sizeof(struct mesa_ip6_hdr));
			}			
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
			this_layer_len = calc_vlan_hdr_len(stream_pr, send_stream_dir);
			if(0 == this_layer_len){
				if(0 == stream_pr->need_update_opposite_addr){
					/* 复用反向地址, 从新计算长度, 构造vlan地址 */
					this_layer_len = calc_vlan_hdr_len(stream_pr, send_stream_dir ^ DIR_DOUBLE);
					buf -= this_layer_len;
					ret = build_net_layer_vlan(stream_pr, carry_layer_type, carry_layer_len, buf, send_stream_dir ^ DIR_DOUBLE, raw_pkt);
					if(ret < 0){
						sapp_runtime_log(RLOG_LV_FATAL, "%s, build_net_layer_vlan() error!\n", printaddr(&top_stream->addr, stream->threadnum));
						return -1;
					}	
					carry_layer_type = ADDR_TYPE_VLAN;					
					sapp_runtime_log(RLOG_LV_INFO, "build_net_layer_vlan() build vlan layer, but no addr of dir:%d, use opposite_addr.\n", send_stream_dir);
				}else{
					sapp_runtime_log(RLOG_LV_FATAL, "build_net_layer_vlan() error, send streamdir:%d, layer len is 0, but create_vlan_anyway is disable!\n", send_stream_dir);
					return -1;
				}
			}else{
				buf -= this_layer_len;
				ret = build_net_layer_vlan(stream_pr, carry_layer_type, carry_layer_len, buf, send_stream_dir, raw_pkt);
				if(ret < 0){
					sapp_runtime_log(RLOG_LV_FATAL, "%s,build_net_layer_vlan() error!\n", printaddr(&top_stream->addr, stream->threadnum));
					return -1;
				}					
				carry_layer_type = ADDR_TYPE_VLAN;
			}
		break;

		case ADDR_TYPE_MAC:
		{
			buf -= sizeof(struct mesa_ethernet_hdr); 
			/* 如果是并联模式, 此处可以不构造mac地址, 仅告知packet_io_send_fake_pkt函数底层类型, MAC还是MAC_IN_MAC 
				串联模式需要根据当前原始包, 和send_dir构造mac地址.
			*/
			unsigned short eth_type_host = net_layer_to_ethernet_protocol_by_stream(up_stream);
			if((unsigned short)-1 == eth_type_host){
				sapp_runtime_log(RLOG_LV_FATAL, "%s,build_net_layer_mac() error, unsupport carry_layer_type:0x%x!\n", printaddr(&stream->addr, stream->threadnum), carry_layer_type);
				return -1;
			}

			if(build_net_layer_ethernet(top_stream, stream_pr, eth_type_host, carry_layer_len, buf, send_stream_dir, raw_pkt) < 0){
				sapp_runtime_log(RLOG_LV_FATAL, "%s, build_net_layer_mac() error!", printaddr(&stream->addr, stream->threadnum));
				return -1;
			}

			this_layer_len = sizeof(struct mesa_ethernet_hdr);
			carry_layer_type = ADDR_TYPE_MAC;
			//ethernet不一定是最后一层, 因为有MAC-in-MAC, 本函数递归结束靠判断NULL == fstream_pr条件.
			//return carry_layer_len;
			//sapp_runtime_log(RLOG_LV_DEBUG, "build_net_layer_pkt()-->ADDR_TYPE_MAC, buf start addr:%p, this_layer_len:%d\n", buf, this_layer_len);
		}
		break;

		/* TODO 2: GRE v1有callid, 分别存储于C2S, S2C两个方向的数据包, 发送双向RST需要记录另一方向的值 */
		case ADDR_TYPE_GRE:
			this_layer_len = calc_gre_hdr_len(
						 (const struct mesa_gre_hdr *)((const char *)stream_pr->raw_pkt->raw_pkt_data + stream_pr->offset_to_raw_pkt_hdr));
			buf -= this_layer_len;
		ret = build_net_layer_gre(top_stream, stream_pr, carry_layer_type, carry_layer_len, buf, reverse, raw_pkt);
			if(ret < 0){
				sapp_runtime_log(RLOG_LV_FATAL, "%s, build_net_layer_gre() error!\n", printaddr(&top_stream->addr, stream->threadnum));
				return -1;
			}
			carry_layer_type = ADDR_TYPE_GRE;
		break;

		case ADDR_TYPE_MPLS:
		{
			this_layer_len = calc_mpls_hdr_len(stream_pr, send_stream_dir);
			if(0 == this_layer_len){
				/* 非对称MPLS, 为了流对齐生造出来的一层, 不构造实际包头 */
				sapp_runtime_log(RLOG_LV_DEBUG, "%s, build_net_layer_mpls() send streamdir:%d, skip fake mpls layer.\n", printaddr(&stream->addr, stream->threadnum), send_stream_dir);
				carry_layer_stream = up_stream;
				break;
			}else{
				buf -= this_layer_len;
				ret = build_net_layer_mpls(stream_pr, carry_layer_type, carry_layer_len, buf, send_stream_dir, raw_pkt);
				if(ret < 0){
					sapp_runtime_log(RLOG_LV_FATAL, "%s, build_net_layer_mpls() error!\n", printaddr(&top_stream->addr, stream->threadnum));
					return -1;
				}				
				carry_layer_type = ADDR_TYPE_MPLS;
			}

			///sapp_runtime_log(RLOG_LV_DEBUG, "build_net_layer_pkt()-->ADDR_TYPE_MPLS, buf start addr:%p, this_layer_len:%d", buf, this_layer_len);
		}	
		break;

		case ADDR_TYPE_GPRS_TUNNEL:
			this_layer_len = calc_gtp_hdr_len(stream_pr, send_stream_dir);
			if(this_layer_len < 0){
				sapp_runtime_log(RLOG_LV_FATAL, "%s, calc_gtp_hdr_len() error!\n", printaddr(&top_stream->addr, stream->threadnum));
				return -1;
			}	
			buf -= this_layer_len;
			ret = build_net_layer_gtp(stream_pr, carry_layer_type, carry_layer_len, buf, send_stream_dir, raw_pkt);
			if(ret < 0){
				sapp_runtime_log(RLOG_LV_FATAL, "%s, build_net_layer_gtp() error!\n", printaddr(&top_stream->addr, stream->threadnum));
				return -1;
			}
			carry_layer_type = ADDR_TYPE_GPRS_TUNNEL;

			///sapp_runtime_log(10, "build_net_layer_pkt()-->ADDR_TYPE_GPRS_TUNNEL, buf start addr:%p, this_layer_len:%d", buf, this_layer_len);
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
			this_layer_len = calc_l2tp_hdr_len(stream_pr, send_stream_dir);
			if(this_layer_len < 0){
				sapp_runtime_log(RLOG_LV_FATAL, "%s, calc_l2tp_hdr_len() error!\n", printaddr(&top_stream->addr, top_stream->threadnum));
				return -1;
			}
			buf -= this_layer_len;
			ret = build_net_layer_l2tp(top_stream, stream_pr, carry_layer_type, carry_layer_len, buf, send_stream_dir, raw_pkt, this_layer_len);
			if(ret < 0){
				sapp_runtime_log(RLOG_LV_FATAL, "%s, build_net_layer_l2tp() error!\n", printaddr(&top_stream->addr, top_stream->threadnum));
				return -1;
			}
			carry_layer_type = ADDR_TYPE_L2TP;
		break;

		case ADDR_TYPE_PPP:
			assert(0); /* PPTP隧道将gre和ppp合并为一层, 代码不会再执行到此处 */
		break;
		
		case ADDR_TYPE_PPTP:
		{
			int gre_layer_len;
			int ppp_hdr_len;

			gre_layer_len = calc_gre_hdr_len(
						 (const struct mesa_gre_hdr *)((const char *)stream_pr->raw_pkt->raw_pkt_data + stream_pr->offset_to_raw_pkt_hdr));
			if(gre_layer_len < 0){
				sapp_runtime_log(RLOG_LV_FATAL, "%s, pptp calc_gre_hdr_len() error!\n", printaddr(&top_stream->addr, stream->threadnum));
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
			ret = build_net_layer_gre(top_stream, stream_pr, ADDR_TYPE_PPP, carry_layer_len, buf, reverse, raw_pkt);
			if(ret < 0){ 
				sapp_runtime_log(RLOG_LV_FATAL, "%s, pptp build_net_layer_gre() error!\n", printaddr(&top_stream->addr, stream->threadnum));
				return -1;
			}
			carry_layer_type = ADDR_TYPE_GRE;
			this_layer_len = gre_layer_len + ppp_hdr_len;
		}	
		break;
#if 0		
		case ADDR_TYPE_MAC_IN_MAC:
		{
			buf -= sizeof(struct mesa_ethernet_hdr); 
	
			build_net_layer_ethernet(stream_pr, ETHERTYPE_PANGU_MAC_IN_MAC, carry_layer_len, buf, reverse, raw_pkt);
			
			/* 此处可以不构造mac地址, 仅告知packet_io_send_fake_pkt函数底层类型, MAC还是MAC_IN_MAC */
		
			/* 并联模式下, 与MAC类似, 可以直接靠系统sendto发送, 所以MAC地址不在build系列函数中添加, 在dl_io中填充 */
			this_layer_len = sizeof(struct mesa_ethernet_hdr);
			carry_layer_type = ETHERTYPE_PANGU_MAC_IN_MAC;

			sapp_runtime_log(10, "build_net_layer_pkt()-->ADDR_TYPE_MAC_IN_MAC, buf start addr:%p, this_layer_len:%d", buf, this_layer_len);
		}	
		break;
#endif

		case ADDR_TYPE_VXLAN:
		{
			const struct layer_addr_vxlan_private *vxaddr_pr = (struct layer_addr_vxlan_private *)stream_pr->stream_public.addr.paddr;
			buf -= vxaddr_pr->actual_total_len;
			this_layer_len = vxaddr_pr->actual_total_len;
			ret = build_net_layer_vxlan(stream_pr, carry_layer_type, carry_layer_len, buf, send_stream_dir, raw_pkt, vxaddr_pr);
			if(ret < 0){ 
				sapp_runtime_log(RLOG_LV_FATAL, "%s, build_net_layer_vxlan() error!\n", printaddr(&top_stream->addr, stream->threadnum));
				return -1;
			}
			carry_layer_type = ADDR_TYPE_VXLAN;		
		}
		break;
		
		default:
			sapp_runtime_log(RLOG_LV_FATAL, "%s, build_net_layer_pkt(): unsupport addr type:%d!\n", printaddr(&stream->addr, stream->threadnum), stream->addr.addrtype);
			goto err;
			break;
	}

done:	
	return build_net_layer_pkt(top_stream, carry_layer_stream, (struct streaminfo_private *)stream_pr->pfather_pr,carry_layer_type, 
							this_layer_len+carry_layer_len, buf, reverse, raw_pkt, send_stream_dir);

err:
	return -1;
}


static raw_pkt_t *update_raw_pkt(struct streaminfo_private *stream_pr, uchar snd_dir, int *inject_dir_reverse)
{
	raw_pkt_t *inject_raw_pkt;
	
	if((stream_pr->packet_io_context != 0)
	|| (0 == sapp_global_val->config.packet_io.polling_enabled)){
		/* 在包处理上下文, 或者没有开启polling, do nothing */
		*inject_dir_reverse = ((snd_dir == stream_pr->stream_public.routedir) ? 0: 1);
		return (raw_pkt_t *)stream_pr->raw_pkt;
	}

	if((DIR_ROUTE_DOWN & snd_dir) == DIR_ROUTE_DOWN){
		inject_raw_pkt = (raw_pkt_t *)stream_pr->polling_inject_context->raw_pkt_down;
		if(inject_raw_pkt){
			*inject_dir_reverse = (((snd_dir & DIR_ROUTE_DOWN) == DIR_ROUTE_DOWN) ? 0: 1);
		}else{/* 本端还没收到过包,使用对端数据包构造本端的包,对于某些非对称协议,如GRE, MPLS等,会有问题! reverse需要反向 */
			inject_raw_pkt = (raw_pkt_t *)stream_pr->polling_inject_context->raw_pkt_up;
			*inject_dir_reverse = (((snd_dir & DIR_ROUTE_DOWN) == DIR_ROUTE_DOWN) ? 1: 0);
		}
	}else{
		inject_raw_pkt = (raw_pkt_t *)stream_pr->polling_inject_context->raw_pkt_up;
		if(inject_raw_pkt){
			*inject_dir_reverse = (((snd_dir & DIR_ROUTE_DOWN) == DIR_ROUTE_DOWN) ? 1: 0);
		}else{/* 本端还没收到过包,使用对端数据包构造本端的包,对于某些非对称协议,如GRE, MPLS等,会有问题! reverse需要反向 */
			inject_raw_pkt = (raw_pkt_t *)stream_pr->polling_inject_context->raw_pkt_down;
			*inject_dir_reverse = (((snd_dir & DIR_ROUTE_DOWN) == DIR_ROUTE_DOWN) ? 0: 1);
		}		
	}
	
	if((NULL == inject_raw_pkt) || (RAW_PKT_MAGIC_NUM != inject_raw_pkt->magic_num)){
		return NULL;
	}

	return inject_raw_pkt;
}


static int __do_kill_tcp(struct streaminfo *stream, const void *ext_raw_pkt, int kill_num,
								char *feedback_buf, int *feedback_buf_len)
{
	int i, ret = -1, reserved_hdr_len, send_len = 0;
	MESA_send_handle *send_handle;
	int thread_num;
	int low_net_layer_type = -1;
	tcp_rst_finger_mark_t *tcp_rst_finger;
	const raw_pkt_t *raw_pkt = NULL;
	struct streaminfo_private *stream_pr;
	sapp_gval_mthread_sys_stat_t *local_sys_stat;
	
	(void)ext_raw_pkt;

	if(NULL == stream){
		return -1;
	}
	thread_num = stream->threadnum;
	stream_pr = (struct streaminfo_private *)stream;
	send_handle = &g_send_handle[thread_num];
	/* 因改变了某些回调函数的原始包类型为IP包头(兼容之前papp平台), 所以不需要插件传输原始包, 信息都存储于私有流结构体内 */
	raw_pkt = (const raw_pkt_t *)stream_pr->raw_pkt;
	if((NULL == raw_pkt) || (RAW_PKT_MAGIC_NUM != raw_pkt->magic_num)){
		return -1;
	}
	local_sys_stat = &sapp_global_val->mthread_volatile[thread_num]->sys_stat;
	send_handle->user_arg = (void *)stream;

	tcp_rst_finger = make_tcp_rst_finger_mark(thread_num, (const raw_pkt_t *)raw_pkt);
	set_build_layer_ipv4_args(thread_num, tcp_rst_finger->ip_ttl, tcp_rst_finger->ip_id_host_order);

	if(0 == ABBR_INJECT_RST_SIGN){
		set_build_layer_tcp_args(thread_num, TH_RST, tcp_rst_finger->tcp_win_host_order, 0);
	}else{
		set_build_layer_tcp_args(thread_num, TH_RST|TH_ACK, tcp_rst_finger->tcp_win_host_order, 0);
	}
	
	for(i = 0; i < kill_num; i++){
		/* 因MPLS非对称问题,  calc_reserved_hdr_len()需要分不同方向计算, 与当前包同向发包 */
		reserved_hdr_len = calc_reserved_hdr_len(stream, &low_net_layer_type, stream_pr->stream_public.curdir);
		if((reserved_hdr_len < 0) || (-1 == low_net_layer_type)){
			sapp_global_val->mthread_volatile[thread_num]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
			sapp_runtime_log(RLOG_LV_INFO, "__do_kill_tcp() calc_reserved_hdr_len error !");
			ret = -1;
			goto fun_exit;
		}
		low_net_layer_type = get_eth_carry_layer_type(stream, stream_pr->stream_public.curdir);
		if(low_net_layer_type < 0){
			sapp_global_val->mthread_volatile[thread_num]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
			sapp_runtime_log(RLOG_LV_INFO, "__do_kill_tcp(): can't get ethernet carry layer type");
			ret = -1;
			goto fun_exit;
		}		
		if(sapp_global_val->config.packet_io.inject_pkt_mode == SEND_PKT_MODE_GDEV){ /* gdev注入模式时预留底层封装vxlan包的空间, 避免再二次copy */
			reserved_hdr_len += sizeof(inline_vxlan_hdr_t);
		}
	
		send_handle->send_buf = packet_io_get_sendbuf(SEND_TYPE_LINK_INJECT, thread_num);

		sapp_runtime_log(RLOG_LV_DEBUG, "before build_net_layer_pkt(), buf addr:%p, streamdir:%d, total layer len:%d", send_handle->send_buf, stream->curdir, reserved_hdr_len);
		send_len = build_net_layer_pkt(stream, stream, stream_pr, ADDR_TYPE_TCP, 0, send_handle->send_buf + reserved_hdr_len, 0, raw_pkt, stream->curdir);
		if(send_len > 0){		
			/* 修改错误判断逻辑, 构造失败不退出, 继续尝试反方向造包 */
			ret = packet_io_send(send_handle, reserved_hdr_len, SEND_TYPE_LINK_INJECT, 
								low_net_layer_type, stream_pr->stream_public.routedir, thread_num,
								feedback_buf, feedback_buf_len, stream_pr->raw_pkt);		
			if(ret < 0){
				send_handle->tot_send_err++;
			}else{
				send_handle->tot_send_pkt++;
				send_handle->tot_send_byte += send_len;
			}
			
			packet_io_free_sendbuf(SEND_TYPE_LINK_INJECT, thread_num);	
			local_sys_stat->count[SAPP_STAT_SND_TCP_RST]++;

			sapp_runtime_log(RLOG_LV_DEBUG, "do_kill_tcp() succ, stream:%s, streamdir:%d, routedir:%d, send_len=%d\n", 
							printaddr(&stream->addr, thread_num),
							stream_pr->stream_public.curdir,
							stream_pr->stream_public.routedir, send_len);
		}else{
			sapp_global_val->mthread_volatile[thread_num]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
			sapp_runtime_log(RLOG_LV_INFO, "do_kill_tcp()-->build_net_layer_pkt() error, send streamdir:%d, routedir:%d, send_len=%d\n", 
							stream_pr->stream_public.curdir ^ DIR_DOUBLE,
							stream_pr->stream_public.routedir, send_len);
		}
		
 /****************************************** 
    并联模式下, 两个方向各发一个, 总计三次, 
    而不是先发C2S三次、再发S2C三次,
    防止因RST包延时问题, 另一方迟迟没有包; 
 ******************************************/			
		 /* 因MPLS非对称问题,  calc_reserved_hdr_len()需要分不同方向计算, 与当前包反向发包 */
		 reserved_hdr_len = calc_reserved_hdr_len(stream, &low_net_layer_type, stream_pr->stream_public.curdir ^ DIR_DOUBLE);
		 if((reserved_hdr_len < 0) || (-1 == low_net_layer_type)){
			 sapp_runtime_log(RLOG_LV_INFO, "MESA_kill_tcp() calc_reserved_hdr_len error !");
			 ret = -1;
			 goto fun_exit;
		 }
		 if(sapp_global_val->config.packet_io.inject_pkt_mode == SEND_PKT_MODE_GDEV){ /* gdev注入模式时预留底层封装vxlan包的空间, 避免再二次copy */
			 reserved_hdr_len += sizeof(inline_vxlan_hdr_t);
		 }
		 low_net_layer_type = get_eth_carry_layer_type(stream, stream_pr->stream_public.curdir ^ DIR_DOUBLE);
		 if(low_net_layer_type < 0){
			 sapp_runtime_log(RLOG_LV_FATAL, "__do_kill_tcp(): can't get ethernet carry layer type");
			 ret = -1;
			 goto fun_exit;
		 }	 

		send_handle->send_buf = packet_io_get_sendbuf(SEND_TYPE_LINK_INJECT, thread_num);
		sapp_runtime_log(10, "before build_net_layer_pkt(), buf addr:%p, streamdir:%d, total layer len:%d", send_handle->send_buf, stream->curdir ^ DIR_DOUBLE, reserved_hdr_len);
		send_len = build_net_layer_pkt(stream, stream, stream_pr, ADDR_TYPE_TCP, 0, send_handle->send_buf + reserved_hdr_len, 1, raw_pkt, stream->curdir ^ DIR_DOUBLE);
		if(send_len > 0){
			/* 修改错误判断逻辑, 构造失败不退出, 继续尝试反方向造包 */
			ret = packet_io_send(send_handle, reserved_hdr_len, SEND_TYPE_LINK_INJECT, 
								low_net_layer_type, stream_pr->stream_public.routedir ^ 1, thread_num,
								feedback_buf, feedback_buf_len, stream_pr->raw_pkt);	
			if(ret < 0){
			send_handle->tot_send_err++;
			}else{
				send_handle->tot_send_pkt++;
				send_handle->tot_send_byte += send_len;
			}
			packet_io_free_sendbuf(SEND_TYPE_LINK_INJECT, thread_num);	
			local_sys_stat->count[SAPP_STAT_SND_TCP_RST]++;

			sapp_runtime_log(RLOG_LV_DEBUG, "do_kill_tcp() succ, stream:%s, streamdir:%d, routedir:%d, send_len=%d\n", 
							printaddr(&stream->addr, thread_num),
							stream_pr->stream_public.curdir ^ DIR_DOUBLE,
							stream_pr->stream_public.routedir ^ 1, send_len);
		}else{
			sapp_runtime_log(RLOG_LV_INFO, "do_kill_tcp()-->build_net_layer_pkt() error, send streamdir:%d, routedir:%d, send_len=%d\n",
							stream_pr->stream_public.curdir ^ DIR_DOUBLE,
							stream_pr->stream_public.routedir ^ 1, send_len);
		}
	}

fun_exit:

	detach_build_layer_ipv4_args(thread_num);
	detach_build_layer_tcp_args(thread_num);

	stream_pr->stream_killed_flag = 1;

	/* 兼容新的标志位, kill_tcp自动设置, 保持功能跟之前一致 */
	struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private*)(stream->pdetail);
	pdetail_pr->auto_remedy_flag = sapp_global_val->config.stream.tcp.inject.auto_remedy;
	pdetail_pr->drop_stream_flag = 1;

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
#if 0
int MESA_kill_tcp(struct streaminfo *stream, const void *ext_raw_pkt)
{
	if(STREAM_TYPE_TCP != stream->type){
		sapp_runtime_log(RLOG_LV_INFO, "MESA_kill_tcp error: stream type is not tcp!\n");
		return -1;
	}							

	/* 外部调用, 第一次FD, 发送KILL_TCP_RST_NUM次. */
	return __do_kill_tcp(stream, ext_raw_pkt, ABBR_INJECT_RST_NUM, (char *)KILL_TCP_PHONY_POINTER, (int *)KILL_TCP_PHONY_POINTER);
}
#else //2020-10-05 lijia modify
int MESA_kill_tcp(struct streaminfo *stream, const void *ext_raw_pkt)
{
	int ret1,ret2;
	struct rst_tcp_para rst_paras = {};
	struct streaminfo_private *stream_pr = (struct streaminfo_private *)stream;
	
	if(STREAM_TYPE_TCP != stream->type){
		sapp_runtime_log(RLOG_LV_INFO, "MESA_kill_tcp error: stream type is not tcp!\n");
		return -1;
	}				

	rst_paras.th_flags = TH_RST | TH_ACK; 
	rst_paras.rst_pkt_num = ABBR_INJECT_RST_NUM;
	rst_paras.dir = stream->curdir;
	rst_paras.signature_seed1 = sapp_global_val->config.stream.tcp.inject.rst_signature_seed1;
	rst_paras.signature_seed2 = sapp_global_val->config.stream.tcp.inject.rst_signature_seed2;

	ret1 = MESA_rst_tcp(stream, &rst_paras, sizeof(struct rst_tcp_para));
	/* 此处不管是否发生错误, 反方向的也要发送, 某个单方向成功也是可以产生实际效果的 */
	rst_paras.dir = stream->curdir ^ DIR_DOUBLE;
	ret2 = MESA_rst_tcp(stream, &rst_paras, sizeof(struct rst_tcp_para));

	/* 兼容新的标志位, kill_tcp自动设置, 保持功能跟之前一致 */
	stream_pr->stream_killed_flag = 1;

	struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private*)(stream->pdetail);
	pdetail_pr->auto_remedy_flag = sapp_global_val->config.stream.tcp.inject.auto_remedy;
	pdetail_pr->drop_stream_flag = 1;

	if((ret1 < 0) && (ret2 < 0)){
		return -1;
	}
	
	return 0; 
}

#endif

int MESA_kill_tcp_feedback(struct streaminfo *stream, const void *raw_pkt, char *feedback_buf, int *feedback_buf_len)
{
	if(STREAM_TYPE_TCP != stream->type){
		sapp_runtime_log(RLOG_LV_INFO, "MESA_kill_tcp error: stream type is not tcp!\n");
		return -1;
	}	

	if((NULL == feedback_buf) || (NULL == feedback_buf_len)){
		return -2;
	}
	if(*feedback_buf_len <= 0){
		return -2;
	}
	return __do_kill_tcp(stream, raw_pkt, ABBR_INJECT_RST_NUM, feedback_buf, feedback_buf_len);
}

/* 2016-06-15 lijia add  */
int MESA_kill_tcp_remedy(struct streaminfo *stream, const void *ext_raw_pkt)
{
	struct streaminfo_private *stream_pr = (struct streaminfo_private *)stream;
	int last_send_time = g_CurrentTime % 255;

	if((sapp_global_val->config.stream.tcp.inject.remedy_kill_tcp_by_inline_device != 0 ) 
	 && (stream_pr->gdev_block_timer < last_send_time)){
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
	int thread_num;
	int low_net_layer_type;
	tcp_rst_finger_mark_t *tcp_rst_finger;
	const raw_pkt_t *raw_pkt = NULL;
	struct streaminfo_private *stream_pr;
	sapp_gval_mthread_sys_stat_t *local_sys_stat;

	(void)ext_raw_pkt;
	
	if(NULL == stream){
		return -1;
	}
	thread_num = stream->threadnum;
	stream_pr = (struct streaminfo_private *)stream;
	send_handle = &g_send_handle[thread_num];
	raw_pkt = (const raw_pkt_t *)stream_pr->raw_pkt;
	if((NULL == raw_pkt) || (RAW_PKT_MAGIC_NUM != raw_pkt->magic_num)){
		return -1;
	}
	local_sys_stat = &sapp_global_val->mthread_volatile[thread_num]->sys_stat;
    //send_handle->user_arg = (void *)stream;
    reserved_hdr_len = calc_reserved_hdr_len(stream, &low_net_layer_type, stream_pr->stream_c2s_route_dir ^ 1);
	if((reserved_hdr_len < 0) || (-1 == low_net_layer_type)){
		ret = -1;
		goto fun_exit;
	}
	tcp_rst_finger = make_tcp_rst_finger_mark(thread_num, (const raw_pkt_t *)raw_pkt);
	set_build_layer_ipv4_args(thread_num, tcp_rst_finger->ip_ttl, tcp_rst_finger->ip_id_host_order);
	set_build_layer_tcp_args(thread_num, TH_SYN|TH_ACK, tcp_rst_finger->tcp_win_host_order, MESA_rand());

	for(i = 0; i < KILL_TCP_SYN_ACK_NUM; i++){
		send_handle->send_buf = packet_io_get_sendbuf(SEND_TYPE_LINK_INJECT, thread_num);
		
		send_len = build_net_layer_pkt(stream, stream, stream_pr, ADDR_TYPE_TCP, 0, send_handle->send_buf + reserved_hdr_len, 1, raw_pkt, stream->curdir ^ DIR_DOUBLE);
		if(send_len < 0){
			ret = -1;
			goto fun_exit;		
		}
		send_handle->user_arg = (void *)stream;
		ret = packet_io_send(send_handle, reserved_hdr_len, SEND_TYPE_LINK_INJECT, 
							low_net_layer_type, stream->routedir ^ 1, thread_num,
							feedback_buf, feedback_buf_len, stream_pr->raw_pkt);		
		if(ret < 0){
			send_handle->tot_send_err++;
		}else{
			send_handle->tot_send_pkt++;
			send_handle->tot_send_byte += send_len;
		}
		
		packet_io_free_sendbuf(SEND_TYPE_LINK_INJECT, thread_num);	
		local_sys_stat->count[SAPP_STAT_SND_TCP_SYNACK]++;
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
			sapp_runtime_log(30, "stream type: %d, not support kill_connection!\n", stream->type);
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
			sapp_runtime_log(30, "stream type: %d, not support kill_connection!\n", stream->type);
			return -1;
			//assert(0);
		break;

		default:
			ret = -1;
			break;
	}

	return ret;
}

static int build_tcp_rst_pkt_finger(struct streaminfo *stream,
					unsigned short signature_seed1, unsigned short signature_seed2, tcp_rst_finger_mark_t *rst_finger)
{
	const raw_pkt_t *raw_pkt;
	struct streaminfo_private *stream_pr;
	const struct mesa_ip4_hdr *ip4_hdr;

	stream_pr = (struct streaminfo_private *)stream;
	raw_pkt = (const raw_pkt_t *)stream_pr->raw_pkt;

	ip4_hdr = (const struct mesa_ip4_hdr *)((char *)raw_pkt->raw_pkt_data + stream_pr->offset_to_raw_pkt_hdr);
	
	if(ADDR_TYPE_IPV4 == stream->addr.addrtype){
		if(signature_seed1 && signature_seed2){
			trick_algo_getrandval_with_seed(stream->threadnum, 
								  ip4_hdr->ip_src.s_addr,  
								  ip4_hdr->ip_dst.s_addr,  
								  &rst_finger->ip_id_host_order,
								  &rst_finger->tcp_win_host_order,
								  &rst_finger->ip_ttl,
								  (int)signature_seed2,
								  (int)signature_seed1);

		}else{
			if(sapp_global_val->config.stream.tcp.inject.rst_signature_enable != 0){
				trick_algo_getrandval_with_seed(stream->threadnum, 
									  ip4_hdr->ip_src.s_addr, 
									  ip4_hdr->ip_dst.s_addr,  
									  &rst_finger->ip_id_host_order,
									  &rst_finger->tcp_win_host_order,
									  &rst_finger->ip_ttl,
									  (int)sapp_global_val->config.stream.tcp.inject.rst_signature_seed2,
									  (int)sapp_global_val->config.stream.tcp.inject.rst_signature_seed1);

			}else{
				goto use_rand_value;
			}
		}
	}else{
		goto use_rand_value;
	}

	return 0;

use_rand_value:
	rst_finger->ip_ttl = (unsigned char)MESA_rand_range(48, 120);
	rst_finger->ip_id_host_order = (unsigned short)MESA_rand();
	rst_finger->tcp_win_host_order = (unsigned short)MESA_rand_range(1000, 1460);

	return 0;
}

/* 2019-11-20 lijia add */
int __MESA_rst_tcp(struct streaminfo *stream, unsigned char rst_th_flags, int rst_pkt_num, unsigned char snd_rst_dir, 
							unsigned short signature_seed1, unsigned short signature_seed2)
{
	int i, ret = -1, reserved_hdr_len, send_len = 0;
	const raw_pkt_t *raw_pkt;
	int threadnum = stream->threadnum;
	struct streaminfo_private *stream_pr;
	unsigned char rst_pkt_buf[256]; /* must > ipv6 address x2 + tcp max header  */
	int rst_pkt_len = 0;
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[threadnum]->sys_stat;
	tcp_rst_finger_mark_t rst_finger;

	stream_pr = (struct streaminfo_private *)stream;
	raw_pkt = (const raw_pkt_t *)stream_pr->raw_pkt;
	if(NULL == raw_pkt){
		return -1;
	}

	for(i = 0; i < rst_pkt_num; i++){
		build_tcp_rst_pkt_finger(stream, signature_seed1, signature_seed2, &rst_finger);
		set_build_layer_ipv4_args(threadnum, rst_finger.ip_ttl, rst_finger.ip_id_host_order);
		set_build_layer_tcp_args(threadnum, rst_th_flags, rst_finger.tcp_win_host_order, 0);
		
		if((DIR_DOUBLE == snd_rst_dir) || (stream->curdir & snd_rst_dir)){
			if(ADDR_TYPE_IPV4 == stream->addr.addrtype){
				rst_pkt_len = sizeof(struct mesa_ip4_hdr) + sizeof(struct mesa_tcp_hdr);
				build_net_layer_tcp(stream_pr, stream->addr.addrtype, 0, rst_pkt_buf+sizeof(struct mesa_ip4_hdr), 0, raw_pkt);	
				build_net_layer_ipv4(stream_pr, ADDR_TYPE_TCP, sizeof(struct mesa_tcp_hdr), rst_pkt_buf, 0, raw_pkt);
				/* 使用SIO_EXCLUDE_THIS_LAYER_HDR类型, 需要自行计算校验和 */
				checksum_for_carry_layer(rst_pkt_buf, __ADDR_TYPE_IP_PAIR_V4, ADDR_TYPE_TCP, sizeof(struct mesa_tcp_hdr));				
			}else{
				rst_pkt_len = sizeof(struct mesa_ip6_hdr) + sizeof(struct mesa_tcp_hdr);
				build_net_layer_tcp(stream_pr, stream->addr.addrtype, 0, rst_pkt_buf+sizeof(struct mesa_ip6_hdr), 0, raw_pkt);	
				build_net_layer_ipv6(stream_pr, ADDR_TYPE_TCP, sizeof(struct mesa_tcp_hdr), rst_pkt_buf, 0, raw_pkt);
				checksum_for_carry_layer(rst_pkt_buf, __ADDR_TYPE_IP_PAIR_V6, ADDR_TYPE_TCP, sizeof(struct mesa_tcp_hdr));				
			}
		
			ret = sapp_inject_pkt(stream, SIO_EXCLUDE_THIS_LAYER_HDR, rst_pkt_buf, rst_pkt_len, stream->routedir);
			if(ret < 0){
				return -1;
			}
			local_sys_stat->count[SAPP_STAT_SND_TCP_RST]++;
		}
		/* 可能是双向发包, 所以这里不是else if */
		if((DIR_DOUBLE == snd_rst_dir) || ((stream->curdir ^ snd_rst_dir) & 0x3) == DIR_DOUBLE){ /* 反向发包 */	
			if(ADDR_TYPE_IPV4 == stream->addr.addrtype){
				rst_pkt_len = sizeof(struct mesa_ip4_hdr) + sizeof(struct mesa_tcp_hdr);
				build_net_layer_tcp(stream_pr, stream->addr.addrtype, 0, rst_pkt_buf+sizeof(struct mesa_ip4_hdr), 1, raw_pkt);	
				build_net_layer_ipv4(stream_pr, ADDR_TYPE_TCP, sizeof(struct mesa_tcp_hdr), rst_pkt_buf, 1, raw_pkt);
				checksum_for_carry_layer(rst_pkt_buf, __ADDR_TYPE_IP_PAIR_V4, ADDR_TYPE_TCP, sizeof(struct mesa_tcp_hdr));
			}else{
				rst_pkt_len = sizeof(struct mesa_ip6_hdr) + sizeof(struct mesa_tcp_hdr);
				build_net_layer_tcp(stream_pr, stream->addr.addrtype, 0, rst_pkt_buf+sizeof(struct mesa_ip6_hdr), 1, raw_pkt);	
				build_net_layer_ipv6(stream_pr, ADDR_TYPE_TCP, sizeof(struct mesa_tcp_hdr), rst_pkt_buf, 1, raw_pkt);
				checksum_for_carry_layer(rst_pkt_buf, __ADDR_TYPE_IP_PAIR_V6, ADDR_TYPE_TCP, sizeof(struct mesa_tcp_hdr));
			}		

				
			ret = sapp_inject_pkt(stream, SIO_EXCLUDE_THIS_LAYER_HDR, rst_pkt_buf, rst_pkt_len, stream->routedir ^ 1);
			if(ret < 0){
				return -1;
			}
			local_sys_stat->count[SAPP_STAT_SND_TCP_RST]++;
		}
	}

	stream_pr->stream_killed_flag = 1;

	detach_build_layer_ipv4_args(threadnum);
	detach_build_layer_tcp_args(threadnum);
	
	return ret;
}


int MESA_rst_tcp(struct streaminfo *stream, struct rst_tcp_para *paras, int struct_para_len)
{
	unsigned short tmp_signature_seed1, tmp_signature_seed2;
	
	if((NULL == stream) || (NULL == paras)){
		sapp_runtime_log(RLOG_LV_INFO, "MESA_rst_tcp() error: mandatory args is NULL!\n");
		return -1;
	}

	if(STREAM_TYPE_TCP != stream->type){
		sapp_runtime_log(RLOG_LV_INFO, "MESA_rst_tcp() error: stream type is not tcp!\n");
		return -1;
	}	
	
	if((TH_RST != paras->th_flags) && ((TH_RST|TH_ACK) != paras->th_flags)){
		sapp_runtime_log(RLOG_LV_INFO, "MESA_rst_tcp() error: th_flags is invalid!\n");
		return -1;
	}

	if((DIR_C2S != paras->dir)
	&& (DIR_S2C != paras->dir)
	&& (DIR_DOUBLE != paras->dir)){
		sapp_runtime_log(RLOG_LV_INFO, "MESA_rst_tcp() error: dir is invalid!\n");
		return -1;
	}

	if((paras->rst_pkt_num < 1) || (paras->rst_pkt_num > 3)){
		sapp_runtime_log(RLOG_LV_INFO, "MESA_rst_tcp() error: rst pkt number range [1-3]!\n");
		return -1;
	}

	if(struct_para_len > sizeof(struct rst_tcp_para)){
		sapp_runtime_log(RLOG_LV_INFO, "MESA_rst_tcp() warning: the caller version is newer than sapp, not support new paras!\n");
	}

	if((0 == paras->signature_seed1) && (0 == paras->signature_seed2)){
		if(0 == sapp_global_val->config.stream.tcp.inject.rst_signature_enable){
			tmp_signature_seed1 = 0;
			tmp_signature_seed2 = 0;
		}else{
			tmp_signature_seed1 = sapp_global_val->config.stream.tcp.inject.rst_signature_seed1;
			tmp_signature_seed2 = sapp_global_val->config.stream.tcp.inject.rst_signature_seed2;
		}
	}else{
		tmp_signature_seed1 = paras->signature_seed1;
		tmp_signature_seed2 = paras->signature_seed2;
	}

	return __MESA_rst_tcp((struct streaminfo *)stream, paras->th_flags, paras->rst_pkt_num, paras->dir, 
						  tmp_signature_seed1, tmp_signature_seed2);
}



int __do_inject_pkt(struct streaminfo *stream, const char *payload, int payload_len, 
						const void *ext_raw_pkt, UCHAR snd_routedir,
						char *feedback_buf, int *feedback_buf_len)
{
	int ret = -1, reserved_hdr_len, send_len = 0;
	MESA_send_handle *send_handle;
	int thread_num;
	int low_net_layer_type;
	int snd_routedir_reverse;
	UCHAR stream_send_dir;
	const raw_pkt_t *raw_pkt;
	struct streaminfo_private *stream_pr;
	sapp_gval_mthread_sys_stat_t *local_sys_stat;

	(void)ext_raw_pkt;
	
	if(NULL == stream){
		return -1;
	}
	
	if(dir_check(snd_routedir) < 0){
		return -1;
	}
	thread_num = stream->threadnum;
	
	stream_pr = (struct streaminfo_private *)stream;
	/* 因改变了某些回调函数的原始包类型为IP包头, 所以不需要插件传输原始包, 信息都存储于私有流结构体内 */
	raw_pkt = (const raw_pkt_t *)stream_pr->raw_pkt;
	if((NULL == raw_pkt) || (RAW_PKT_MAGIC_NUM != raw_pkt->magic_num)){
		return -1;
	}
	
	local_sys_stat = &sapp_global_val->mthread_volatile[thread_num]->sys_stat;

	if(snd_routedir == stream->routedir){
		snd_routedir_reverse = 0;
		stream_send_dir = stream->curdir;
	}else{
		snd_routedir_reverse = 1;
		stream_send_dir = stream->curdir ^ DIR_DOUBLE;
	}
	
	send_handle = &g_send_handle[thread_num];

	reserved_hdr_len = calc_reserved_hdr_len(stream, &low_net_layer_type, snd_routedir);
	if((reserved_hdr_len < 0) || (-1 == low_net_layer_type)){
		ret = -1;
		goto fun_exit;
	}
	
	if(payload_len + reserved_hdr_len > MTU_MAX){
		sapp_runtime_log(RLOG_LV_FATAL, "MESA_inject_pkt() error! payload_len too long:%d.\n", payload_len + reserved_hdr_len);	
		return -1;
		//assert(0);
	}

	/* 
	   2021-09-18 fix bug:
	   原来仅Ipv4增加build-args, 原意是在ipv4和tcp包头增加指纹,
	   改为ipv6也加 build_args, 
	   否则在build_net_layer_tcp()时判断build_tcp_args是NULL, 会使用随机序号, 发包就不对了!! 
	 */

	set_build_layer_tcp_args(thread_num, TH_PUSH|TH_ACK, MESA_rand_range(1000, 1460), 0);

	send_handle->send_buf = packet_io_get_sendbuf(SEND_TYPE_LINK_INJECT, thread_num);

	memcpy(send_handle->send_buf + reserved_hdr_len, payload, payload_len);
	
	send_len = build_net_layer_pkt(stream, stream, stream_pr, stream->addr.addrtype, payload_len, 
							   send_handle->send_buf + reserved_hdr_len, snd_routedir_reverse, raw_pkt, stream_send_dir);
	if(send_len < 0){
		ret = -1;
		goto err;
	}
	send_handle->user_arg = (void *)stream;
	ret = packet_io_send(send_handle, reserved_hdr_len+payload_len, SEND_TYPE_LINK_INJECT, 
						low_net_layer_type, snd_routedir, thread_num,
						feedback_buf, feedback_buf_len, stream_pr->raw_pkt);		
	if(ret < 0){
		send_handle->tot_send_err++;
	}else{
		send_handle->tot_send_pkt++;
		send_handle->tot_send_byte += send_len;
	}

	if(STREAM_TYPE_TCP == stream->type){
		local_sys_stat->count[SAPP_STAT_SND_TCP]++;
		local_sys_stat->length[SAPP_STAT_SND_TCP]+= raw_pkt->raw_pkt_len;	
	}else{
		local_sys_stat->count[SAPP_STAT_SND_UDP]++;
		local_sys_stat->length[SAPP_STAT_SND_UDP]+= raw_pkt->raw_pkt_len;		
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

#if 0
int MESA_inject_pkt(struct streaminfo *stream, const char *payload, int payload_len, 
						const void *ext_raw_pkt, UCHAR snd_routedir)
{
	return __do_inject_pkt(stream, payload, payload_len, ext_raw_pkt, snd_routedir, 
				(char *)KILL_TCP_PHONY_POINTER, (int *)KILL_TCP_PHONY_POINTER);
}
#else //2020-10-05 lijia modify
int MESA_inject_pkt(struct streaminfo *stream, const char *payload, int payload_len, 
						const void *ext_raw_pkt, UCHAR snd_routedir)
{
	return sapp_inject_pkt(stream, SIO_DEFAULT, payload, payload_len, snd_routedir);
}

#endif


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


/*
	TODO:
		先判断这一层是不是asymmetric_presence_layer,
		然后再判断本层地址有没有.
*/
static int skip_asymmetric_presence_layer(const struct streaminfo *stream, UCHAR send_stream_dir)
{
	int need_skip = 0;
	const struct streaminfo_private *stream_pr = (struct streaminfo_private *)stream;
	
	switch(stream->addr.addrtype){
		case ADDR_TYPE_VLAN:
		{
			const struct layer_addr_vlan *vaddr = stream->addr.vlan;

			/* 如果不是生造出来的虚拟空层, 还有可能是单向流, 还要看实际有没有地址 */
			if(DIR_C2S == send_stream_dir){
				if(0 == vaddr->c2s_layer_num){
					/* 如果本侧没有地址, 看是否强制要求非对称原则, 如果是, 其实都走不到这里,构造包时就失败了; 如果不是可以复用对侧地址 */
					if(g_asymmetric_addr_layer_set.layer_type_index[ADDR_TYPE_VLAN][stream_pr->layer_index] != 0){
						need_skip = 1;
					}
				}
			}else{
				if(0 == vaddr->s2c_layer_num){
					/* 如果本侧没有地址, 看是否强制要求非对称原则, 如果是, 其实都走不到这里,构造包时就失败了; 如果不是可以复用对侧地址 */
					if(g_asymmetric_addr_layer_set.layer_type_index[ADDR_TYPE_VLAN][stream_pr->layer_index] != 0){
						need_skip = 1;
					}
				}
			}
		}
		break;
		
		case ADDR_TYPE_MPLS:
		{
			const struct layer_addr_mpls *maddr = stream->addr.mpls;

			if(DIR_C2S == send_stream_dir){
				if(0 == maddr->c2s_layer_num){
					/* 如果本侧没有地址, 看是否强制要求非对称原则, 如果是, 其实都走不到这里,构造包时就失败了; 如果不是可以复用对侧地址 */
					if(g_asymmetric_addr_layer_set.layer_type_index[ADDR_TYPE_MPLS][stream_pr->layer_index] != 0){
						need_skip = 1;
					}
				}
			}else{
				if(0 == maddr->s2c_layer_num){
					if(g_asymmetric_addr_layer_set.layer_type_index[ADDR_TYPE_MPLS][stream_pr->layer_index] != 0){
						need_skip = 1;
					}
				}
			}
		}
		break;

		default:
			sapp_runtime_log(RLOG_LV_DEBUG, "skip_asymmetric_presence_layer(): not asymmetric addr index:%d, addrtype:%d", stream_pr->layer_index, stream->addr.addrtype);
	}

	return need_skip;
}

static int get_eth_carry_layer_type(struct streaminfo *stream, UCHAR send_stream_dir)
{
	int ret = -1;
	struct streaminfo_private *stream_pr = (struct streaminfo_private *)stream;

	while(stream_pr && stream_pr->pfather_pr){
#if 0 //使用动态创建非对称协议层, 此处不用再额外判断了	
		if(skip_asymmetric_presence_layer(stream, send_stream_dir)){
			stream_pr = stream_pr->pfather_pr;
			continue;
		}
#endif		
		if(CAP_LEVEL_MAC == g_packet_io_cap_level) {
			if(stream_pr->pfather_pr 
			 && ((ADDR_TYPE_MAC_IN_MAC == stream_pr->pfather_pr->stream_public.addr.addrtype) || (ADDR_TYPE_MAC == stream_pr->pfather_pr->stream_public.addr.addrtype))){
				/* 记录MAC层之上的协议地址类型, 用于填充Ethernet->type字段, 对于MAC-in-MAC的inner_eth, 记录上层协议类型 */
				ret = (int)stream->addr.addrtype;
			}
		}else{
			/* to do:
				如果捕包库自动屏蔽了ethernet层, 甚至剥掉了vlan等层而且还要发包怎么办?
			*/
			if(NULL == stream_pr->pfather_pr){
				if(g_packet_io_cap_level == stream->addr.addrtype){
					ret = (int)stream->addr.addrtype;
				}
				if((CAP_LEVEL_IPV4 == g_packet_io_cap_level)
				 && (ADDR_TYPE_IPV4 == stream->addr.addrtype)){
					ret = CAP_LEVEL_IPV4;
				}			
			}
		}
	
		stream_pr = stream_pr->pfather_pr;
		stream = &stream_pr->stream_public;
	}

	return ret;
}

int __sapp_inject_pkt(struct streaminfo *raw_stream, enum sapp_inject_opt sio, 
  const void *payload, int payload_len, unsigned char snd_routedir, void *user_arg)

{
	int ret = -1, reserved_hdr_len = 0, send_len = 0;
	MESA_send_handle *send_handle;
	int thread_num;
	int low_net_layer_type;
	int snd_routedir_reverse;
	UCHAR send_stream_dir;
	const raw_pkt_t *raw_pkt;
	struct streaminfo_private *raw_stream_pr;
	sapp_gval_mthread_sys_stat_t *local_sys_stat;
	int carry_layer_type;
	struct streaminfo *inject_stream;
	struct streaminfo_private *inject_stream_pr;
	
	if(NULL == raw_stream){
		return -1;
	}
	
	if(dir_check(snd_routedir) < 0){
		return -1;
	}
	thread_num = raw_stream->threadnum;
	carry_layer_type = raw_stream->addr.addrtype;
	inject_stream = raw_stream;
	inject_stream_pr = (struct streaminfo_private *)raw_stream;
	local_sys_stat = &sapp_global_val->mthread_volatile[thread_num]->sys_stat;
	if((SIO_EXCLUDE_THIS_LAYER_HDR & sio) != 0){
		/* 跳过当前层 */
		inject_stream = raw_stream->pfather;
		inject_stream_pr = (struct streaminfo_private *)inject_stream;
		/* 如果插件发包时指定了SIO_EXCLUDE_THIS_LAYER_HDR, 说明内层四元组是由插件构造的, 比如kni, 
		   一般不会再走到build_pkt的函数中, 此处需要解析ip包并加入bloom filter */
		if(sapp_global_val->config.packet_io.dup_pkt_para.dup_pkt_distinguish_all_inject != 0){
			sendpkt_dup_pkt_mark_stream(raw_stream, (char *)payload);
		}
	}else{
		/* 
		   2021-09-18 fix bug:
		   原来仅Ipv4增加build-args, 原意是在ipv4和tcp包头增加指纹,
		   改为ipv6也加 build_args, 
		   否则在build_net_layer_tcp()时判断build_tcp_args是NULL, 会使用随机序号, 发包就不对了!! 
		 */
		set_build_layer_tcp_args(thread_num, TH_PUSH|TH_ACK, MESA_rand_range(1000, 1460), 0);
	}
	
	raw_stream_pr = (struct streaminfo_private *)raw_stream;
	/* 因改变了某些回调函数的原始包类型为IP包头, 所以不需要插件传输原始包, 信息都存储于私有流结构体内 */
	raw_pkt = update_raw_pkt(raw_stream_pr, snd_routedir, &snd_routedir_reverse);
	if(NULL == raw_pkt){
		sapp_global_val->mthread_volatile[thread_num]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
		sapp_runtime_log(RLOG_LV_INFO, "__sapp_inject_pkt() error, not found raw_pkt!");
		return -1;
	}

	/* inject使用的是routedir, 此处转换成stream dir, 
	   注意: 插件发包的动作可能不是由当前包触发的,  比如kni, 是从其他网卡收到数据包, 再注入链路的,
	         不能从raw_pkt或raw_stream->routedir判断方向!!!!
	*/
	if(snd_routedir == raw_stream_pr->stream_c2s_route_dir){
		send_stream_dir = DIR_C2S;
	}else{
		send_stream_dir = DIR_S2C;
	}
	
	send_handle = &g_send_handle[thread_num];

	reserved_hdr_len = calc_reserved_hdr_len(inject_stream, &low_net_layer_type, send_stream_dir);
	if(reserved_hdr_len < 0){
		sapp_runtime_log(RLOG_LV_FATAL, "__sapp_inject_pkt()->calc_reserved_hdr_len() error");
		return -1;
	}

	low_net_layer_type = get_eth_carry_layer_type(raw_stream, send_stream_dir);
	if(low_net_layer_type < 0){
		sapp_global_val->mthread_volatile[thread_num]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
		sapp_runtime_log(RLOG_LV_INFO, "__sapp_inject_pkt(): can't get ethernet carry layer type");
		return -1;
	}
	
	if(payload_len + reserved_hdr_len > MTU_MAX){
		sapp_global_val->mthread_volatile[thread_num]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
		sapp_runtime_log(RLOG_LV_INFO, "__sapp_inject_pkt() error! payload_len too long:%d.\n", 
		                 payload_len + reserved_hdr_len);	
		return -1;
	}

	send_handle->send_buf = packet_io_get_sendbuf(SEND_TYPE_LINK_INJECT, thread_num);

	memcpy(send_handle->send_buf + reserved_hdr_len, payload, payload_len);
	
	send_len = build_net_layer_pkt(raw_stream, raw_stream, inject_stream_pr, carry_layer_type, payload_len, 
							   send_handle->send_buf + reserved_hdr_len, snd_routedir_reverse, raw_pkt, send_stream_dir);
	if(send_len < 0){
		ret = -1;
		goto err;
	}
	send_handle->user_arg = (void *)raw_stream;
	ret = packet_io_send(send_handle, reserved_hdr_len+payload_len, SEND_TYPE_LINK_INJECT, 
						low_net_layer_type, snd_routedir, thread_num,
						(char *)KILL_TCP_PHONY_POINTER, (int *)KILL_TCP_PHONY_POINTER,
						raw_pkt);		
	if(ret < 0){
		send_handle->tot_send_err++;
	}else{
		send_handle->tot_send_pkt++;
		send_handle->tot_send_byte += send_len;

		if(STREAM_TYPE_TCP == raw_stream->type){
			local_sys_stat->count[SAPP_STAT_SND_TCP]++;
			local_sys_stat->length[SAPP_STAT_SND_TCP]+= raw_pkt->raw_pkt_len;	
		}else{
			local_sys_stat->count[SAPP_STAT_SND_UDP]++;
			local_sys_stat->length[SAPP_STAT_SND_UDP]+= raw_pkt->raw_pkt_len;		
		}
	}

err:	
	packet_io_free_sendbuf(SEND_TYPE_LINK_INJECT, thread_num);	

	return ret;
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
	int max_thread_num;
	const sapp_config_packet_io_t *pcfg_io = &sapp_global_val->config.packet_io;
#if 0 /* 2018 lijia modify , 增加插件创建的线程主动发包功能 */
	for(i = 0; i < tot_thread_num; i++){
#else

	//max_thread_num = ((tot_thread_num) >= (INDEPENDENT_SEND_QUEUE_MAX_NUM)) ? (tot_thread_num) : (INDEPENDENT_SEND_QUEUE_MAX_NUM);
	max_thread_num = sapp_global_val->config.cpu.worker_threads + sapp_global_val->config.cpu.send_only_threads_max_num;
	
	for(i = 0; i < max_thread_num; i++){
#endif	
		g_send_handle[i].raw_ipv4_fd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
		if(g_send_handle[i].raw_ipv4_fd < 0){
			sapp_log(30, ~0, ~0, "create raw socket v4 error, %s\n", strerror(errno));
			return -1;
		}else{
			sapp_runtime_log(RLOG_LV_DEBUG, "send_handle_init() create raw_ipv4_fd socket:%d\n", g_send_handle[i].raw_ipv4_fd );
		}
		
		g_send_handle[i].raw_udp_fd = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, 0);
		if(g_send_handle[i].raw_udp_fd < 0){
			sapp_log(30, ~0, ~0, "create udp socket error, %s\n", strerror(errno));
			return -1;
		}else{
			sapp_runtime_log(RLOG_LV_DEBUG, "send_handle_init() create raw_udp_fd socket:%d\n", g_send_handle[i].raw_udp_fd );
		}

		if(SEND_PKT_MODE_GDEV == pcfg_io->inject_pkt_mode)
		{
			int opt_value = 1;
			setsockopt(g_send_handle[i].raw_udp_fd, SOL_SOCKET, SO_REUSEADDR, &opt_value, sizeof(int));
			struct sockaddr_in listen_addr;
			memset(&listen_addr, 0, sizeof(listen_addr));
			listen_addr.sin_family = AF_INET;
			listen_addr.sin_port = htons((unsigned short)sapp_global_val->config.packet_io.inject_mode_inline_device_sport); /* 根据配置文件填写vxlan源端口 */
			if(bind(g_send_handle[i].raw_udp_fd, (struct sockaddr *) &listen_addr, sizeof(listen_addr)) != 0){
				sapp_log(30, ~0, ~0, "socket bind udp port '%u' error", sapp_global_val->config.packet_io.inject_mode_inline_device_sport);
				return -1;
			}
		}
		
		if(g_ipv6_send_packet_enabled){
			g_send_handle[i].raw_ipv6_fd = socket(PF_INET6, SOCK_RAW, IPPROTO_RAW);
			if(g_send_handle[i].raw_ipv6_fd < 0){
				sapp_log(30, ~0, ~0, "create socket v6 error, %s\n", strerror(errno));
				sapp_log(30, ~0, ~0, "Please disable IPv6 module, then try again!\n");
				return -1;
			}else{
				sapp_runtime_log(RLOG_LV_DEBUG, "send_handle_init() create raw_ipv6_fd socket:%d\n", g_send_handle[i].raw_ipv6_fd );
			}
		}
		
		if(pcfg_io->inject_mode_single_gateway_device[0] != '\0'){
			ret = g_send_handle[i].raw_eth_fd =  socket(PF_INET, SOCK_PACKET, htons(ETH_P_ALL));
			if(g_send_handle[i].raw_eth_fd < 0){
				sapp_log(30, ~0, ~0, "create socket raw eth error, %s\n", strerror(errno));
				return -1;
			}else{
				sapp_runtime_log(RLOG_LV_DEBUG, "send_handle_init() create raw_eth_fd socket:%d\n", g_send_handle[i].raw_eth_fd );
			}
			
			ret = snprintf(g_send_handle[i].saddr_raw_eth.sa_data, sizeof(g_send_handle[i].saddr_raw_eth.sa_data), 
						   "%s", pcfg_io->inject_mode_single_gateway_device);
			if(ret >= (int)sizeof(g_send_handle[i].saddr_raw_eth.sa_data)){
				sapp_log(30, ~0, ~0, "send device name is too long!\n");
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

void send_handle_destroy(int thread_index)
{
	if(dl_io_fun_list.dl_io_free_send_handle){
		dl_io_fun_list.dl_io_free_send_handle(thread_index, g_send_handle[thread_index].low_level_send_handle);
	}
}


/* 2015-01-04 lijia add, 从papp平台迁移到sapp平台, 底层发包接口不同 */
int MESA_sendpacket_ethlayer(int thread_num,const char *data, int data_len, unsigned int target_id)
{
	int ret;

	if(data_len > MTU_MAX)
	{
		sapp_runtime_log(RLOG_LV_INFO, "MESA_sendpacket_ethlayer(): data length:%d is more than MTU:%d\n", data_len, MTU_MAX);
		sapp_global_val->mthread_volatile[thread_num]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
		return -1;
	}

	ret = packet_io_send_raw(thread_num, (char *)data, data_len, target_id);

	return (ret);	
}

int sendpacket_init_new(int tot_thread_num)
{
	struct timespec curtime;
	clock_gettime (CLOCK_THREAD_CPUTIME_ID, &curtime);

	///srand(time(NULL));

	g_rand_seed *= curtime.tv_nsec;

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

void sendpacket_destroy(int tot_thread_num)
{
	int i, max_thread_num;

	//max_thread_num = ((tot_thread_num) >= (INDEPENDENT_SEND_QUEUE_MAX_NUM)) ? (tot_thread_num) : (INDEPENDENT_SEND_QUEUE_MAX_NUM);
	max_thread_num = sapp_global_val->config.cpu.worker_threads + sapp_global_val->config.cpu.send_only_threads_max_num;

	for(i = 0; i < max_thread_num; i++){
		if(g_send_handle[i].raw_ipv4_fd > 0){
			sapp_runtime_log(RLOG_LV_DEBUG, "sendpacket_destroy() close raw_ipv4_fd socket:%d\n", g_send_handle[i].raw_ipv4_fd );
			close(g_send_handle[i].raw_ipv4_fd);
		}
		if(g_send_handle[i].raw_ipv6_fd > 0){
			sapp_runtime_log(RLOG_LV_DEBUG, "sendpacket_destroy() close raw_ipv6_fd socket:%d\n", g_send_handle[i].raw_ipv6_fd );
			close(g_send_handle[i].raw_ipv6_fd);
		}	
		if(g_send_handle[i].raw_udp_fd > 0){
			sapp_runtime_log(RLOG_LV_DEBUG, "sendpacket_destroy() close raw_udp_fd socket:%d\n", g_send_handle[i].raw_udp_fd );
			close(g_send_handle[i].raw_udp_fd);
		}			
		if(g_send_handle[i].raw_eth_fd > 0){
			sapp_runtime_log(RLOG_LV_DEBUG, "sendpacket_destroy() close raw_eth_fd socket:%d\n", g_send_handle[i].raw_eth_fd );
			close(g_send_handle[i].raw_eth_fd);
		}	

		send_handle_destroy(i);
	}
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
	unsigned char reverse_dir;
	
	switch(raw_dir){
		case 0:
			reverse_dir = 1;
		break;

		case 0x80:
			reverse_dir = 0;
		break;

		case 0x01:
			reverse_dir = 0;
		break;

		case 0x81:
			reverse_dir = 0;
		break;
	}

	return reverse_dir;
}


/*************************************************************************************** 	
	NOTE:
		在被动模式下, 插件无需关心route_dir的绝对值, 只需要理解同向和反向即可,
		但主动发包必须要精确理解route_dir是0还是1, 因外界网络拓扑模式不同, 可能随时会变化,
		所以设置此接口, 插件只需传入人易理解的方向, 返回当前链路的link route dir,
		注意etc/sapp.toml inbound_route_dir要设置正确.

	args: 表示发包目标相对于当前设备所在的地理位置,
		'E' or 'e': 表示发包方向是从Internal to External.
		'I' or 'i': 表示发包方向是从External to Internal.

	return value:
		0 or 1: success.
		-1 : error.
****************************************************************************************/
int MESA_dir_human_to_link(int human_dir)
{
	int link_route_dir;
	
	switch(human_dir){
		case 'E':
		case 'e':
			link_route_dir = sapp_global_val->config.packet_io.inbound_route_dir ^ 1;
		break;

		case 'I':
		case 'i':
			link_route_dir = sapp_global_val->config.packet_io.inbound_route_dir;
		break;	

		default:
			link_route_dir = -1;
			break;
	}

	return link_route_dir;
}

/*
	args:
		链路传输方向: 0或1, 通常来自stream->routedir;
	
	返回值:
		'E' or 'e': 表示发包方向是从Internal to External.
		'I' or 'i': 表示发包方向是从External to Internal.
		'x': 参数错误;
*/
int MESA_dir_link_to_human(int link_route_dir)
{	
	int human_dir;
	
	if((link_route_dir != 0) && (link_route_dir != 1)){
		return 'x';
	}
	
	if(0 == sapp_global_val->config.packet_io.inbound_route_dir){
		if(0 == link_route_dir){
			human_dir = 'I';
		}else{
			human_dir = 'E';
		}
	}else{
		if(0 == link_route_dir){
			human_dir = 'E';
		}else{
			human_dir = 'I';
		}
	}
	
	return human_dir;
}



static inline int dir_check(unsigned char raw_dir)
{
	if(raw_dir & DIR_BIT_UNUSE_MASK){ /* 方向只使用了最高和最低位bit, 如果出现其他值,说明插件在转换dir时出了错误 */
		sapp_runtime_log(30, "dir = 0x%x, is invalid, only the most or least significant bit can be used!", raw_dir);
		//assert(0);
		return -1;
	}

	return 0;
}

static int __MESA_sendpacket_iplayer(int thread_index,const char *data,  int data_len, u_int8_t dir, int layer_type)
{
	MESA_send_handle *send_handle;
	int ret, offset = 0;
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_index]->sys_stat;
	
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
		    sapp_runtime_log(30, "MESA_sendpacket_iplayer: Invalid cap_mode:%d\n", g_packet_io_cap_level);
		    //exit(1);
		return -1;
	}	

	if(data_len > (int)MTU_MAX-(int)sizeof(struct mesa_ethernet_hdr)){
		sapp_runtime_log(30,"TODO: MESA_sendpacket_iplayer error! datalen is more than MTU, need ip fragment!\n");
		return -1;
	}

	memcpy(send_handle->send_buf + offset, data, data_len);
	
	ret = packet_io_send_fake_pkt(send_handle, data_len+sizeof(struct mesa_ethernet_hdr), SEND_TYPE_LINK_INJECT, 
							   layer_type, dir, thread_index,
							   (char *)KILL_TCP_PHONY_POINTER, (int *)KILL_TCP_PHONY_POINTER, NULL);

	packet_io_free_sendbuf(SEND_TYPE_LINK_INJECT, thread_index);	

	if(ret > 0){
		local_sys_stat->count[SAPP_STAT_SND_IPV4]++;
		local_sys_stat->length[SAPP_STAT_SND_IPV4]+= ret;	
	}
	
	return ret;
}

int MESA_sendpacket_iplayer(int thread_index,const char *data,  int data_len, u_int8_t dir)
{
	return __MESA_sendpacket_iplayer(thread_index, data, data_len, dir, __ADDR_TYPE_IP_PAIR_V4);
}

int MESA_sendpacket_ipv6_layer(int thread_index,const char *data,  int data_len, u_int8_t dir)
{
	return __MESA_sendpacket_iplayer(thread_index, data, data_len, dir, __ADDR_TYPE_IP_PAIR_V6);
}

int MESA_fakepacket_send_ipv4(int thread_index,u_int8_t ttl,
							u_int8_t protocol,u_int32_t sip, u_int32_t dip, const char *payload,
							int payload_len,u_int8_t dir)
{
	MESA_send_handle *send_handle;
	int ret, offset = 0;
	u_int16_t ipid;
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_index]->sys_stat;

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
		    sapp_runtime_log(30,"MESA_fakepacket_send_ipv4: Invalid cap_mode:%d\n", g_packet_io_cap_level);
		    //exit(1);
		return -1;
	}	

	if(payload_len > (int)MTU_MAX-(int)sizeof(struct mesa_ethernet_hdr)-(int)sizeof(struct mesa_ip4_hdr)){
		sapp_runtime_log(30,"MESA_fakepacket_send_ipv4 error! datalen is more than MTU, need ip fragment!\n");
		return -1;
	}
	
	ipid = MESA_rand() % 65535;
	sendpacket_build_ipv4(payload_len, 0, ipid, 0 , ttl, protocol, 
						htonl(sip), htonl(dip), payload, payload_len, send_handle->send_buf+offset);

	sendpacket_do_checksum(send_handle->send_buf+offset, IPPROTO_IP, SENDPACKET_IP_H);

	ret = packet_io_send_fake_pkt(send_handle, payload_len+sizeof(struct mesa_ip4_hdr)+sizeof(struct mesa_ethernet_hdr), 
								SEND_TYPE_LINK_INJECT, __ADDR_TYPE_IP_PAIR_V4, dir, thread_index,
								(char *)KILL_TCP_PHONY_POINTER, (int *)KILL_TCP_PHONY_POINTER, NULL);
							   
	packet_io_free_sendbuf(SEND_TYPE_LINK_INJECT, thread_index);	

	if(ret > 0){
		local_sys_stat->count[SAPP_STAT_SND_IPV4]++;
		local_sys_stat->length[SAPP_STAT_SND_IPV4]+= ret;	
	}

	return ret;	
}

int MESA_fakepacket_send_ipv4_detail(int thread_index,u_int8_t ttl,
							u_int8_t protocol,u_int32_t sip, u_int32_t dip, u_int16_t ipid, 
							const char *payload, int payload_len,u_int8_t dir)
{
	MESA_send_handle *send_handle;
	int ret, offset = 0;
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_index]->sys_stat;

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
		    sapp_runtime_log(30,"MESA_fakepacket_send_ipv4: Invalid cap_mode:%d\n", g_packet_io_cap_level);
		    //exit(1);
		return -1;
	}	

	if(payload_len > (int)MTU_MAX-(int)sizeof(struct mesa_ethernet_hdr)-(int)sizeof(struct mesa_ip4_hdr)){
		sapp_runtime_log(30,"MESA_fakepacket_send_ipv4 error! datalen is more than MTU, need ip fragment!\n");
		return -1;
	}
	sendpacket_build_ipv4(payload_len, 0, ipid, 0 , ttl, protocol, 
						htonl(sip), htonl(dip), payload, payload_len, send_handle->send_buf+offset);

	sendpacket_do_checksum(send_handle->send_buf+offset, IPPROTO_IP, SENDPACKET_IP_H);

	ret = packet_io_send_fake_pkt(send_handle, payload_len+sizeof(struct mesa_ip4_hdr)+sizeof(struct mesa_ethernet_hdr), 
								SEND_TYPE_LINK_INJECT, __ADDR_TYPE_IP_PAIR_V4, dir, thread_index,
								(char *)KILL_TCP_PHONY_POINTER, (int *)KILL_TCP_PHONY_POINTER, NULL);
							   
	packet_io_free_sendbuf(SEND_TYPE_LINK_INJECT, thread_index);	

	if(ret > 0){
		local_sys_stat->count[SAPP_STAT_SND_IPV4]++;
		local_sys_stat->length[SAPP_STAT_SND_IPV4]+= ret;	
	}

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
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_index]->sys_stat;

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
		   sapp_runtime_log(30,"MESA_fakepacket_send_tcp: Invalid cap_mode:%d\n", g_packet_io_cap_level);
		    //exit(1);
		return -1;
	}	

	if(payload_len > (int)MTU_MAX- (int)sizeof(struct mesa_ethernet_hdr)- (int)sizeof(struct mesa_ip4_hdr)- (int)sizeof(struct mesa_tcp_hdr)){
		sapp_runtime_log(30,"MESA_fakepacket_send_tcp error! datalen is more than MTU, need ip fragment!\n");
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
								(char *)KILL_TCP_PHONY_POINTER, (int *)KILL_TCP_PHONY_POINTER, NULL);
							   
	packet_io_free_sendbuf(SEND_TYPE_LINK_INJECT, thread_index);	

	if(ret > 0){
		local_sys_stat->count[SAPP_STAT_SND_TCP]++;
		local_sys_stat->length[SAPP_STAT_SND_TCP]+= ret;	
	}

	return ret;	
}

int MESA_fakepacket_send_tcp_detail(int thread_index,u_int sip_host_order,u_int dip_host_order,
										u_short ipid, u_char ip_ttl,
							u_short sport_host_order,u_short dport_host_order,
							u_int sseq_host_order,u_int sack_host_order, 
							u_char control, u_short tcp_win, const char* payload,int payload_len, u_int8_t dir)
{
	MESA_send_handle *send_handle;
	int ret, offset = 0;
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_index]->sys_stat;

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
		    sapp_runtime_log(30,"MESA_fakepacket_send_tcp: Invalid cap_mode:%d\n", g_packet_io_cap_level);
		    //exit(1);
		return -1;
	}	

	if(payload_len > (int)MTU_MAX- (int)sizeof(struct mesa_ethernet_hdr)- (int)sizeof(struct mesa_ip4_hdr)- (int)sizeof(struct mesa_tcp_hdr)){
		sapp_runtime_log(30,"MESA_fakepacket_send_tcp error! datalen is more than MTU, need ip fragment!\n");
		return -1;
	}

	sendpacket_build_tcp(sport_host_order, dport_host_order, sseq_host_order, sack_host_order,
						control, tcp_win, 0, payload, payload_len, send_handle->send_buf+offset+sizeof(struct mesa_ip4_hdr));
						
	sendpacket_build_ipv4(payload_len+SENDPACKET_TCP_H, 0, ipid, 0, ip_ttl, IPPROTO_TCP, 
						htonl(sip_host_order), htonl(dip_host_order), NULL, 0, send_handle->send_buf+offset);

	sendpacket_do_checksum(send_handle->send_buf+offset, IPPROTO_TCP, SENDPACKET_TCP_H+payload_len);
	
	sendpacket_do_checksum(send_handle->send_buf+offset, IPPROTO_IP, SENDPACKET_IP_H);

	ret = packet_io_send_fake_pkt(send_handle, payload_len+sizeof(struct mesa_tcp_hdr)+sizeof(struct mesa_ip4_hdr)+sizeof(struct mesa_ethernet_hdr), 
								SEND_TYPE_LINK_INJECT, __ADDR_TYPE_IP_PAIR_V4, dir, thread_index,
								(char *)KILL_TCP_PHONY_POINTER, (int *)KILL_TCP_PHONY_POINTER, NULL);
							   
	packet_io_free_sendbuf(SEND_TYPE_LINK_INJECT, thread_index);	

	if(ret > 0){
		local_sys_stat->count[SAPP_STAT_SND_TCP]++;
		local_sys_stat->length[SAPP_STAT_SND_TCP]+= ret;	
	}		
	return ret;	
}
int MESA_fakepacket_send_udp(int thread_index, u_int sip_host_order, u_int dip_host_order, 
							u_short sport_host_order,u_short dport_host_order, 
							const char *payload, int payload_len,u_int8_t dir)
{
	MESA_send_handle *send_handle;
	int ret, offset = 0;
	u_int16_t  ipid;
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_index]->sys_stat;

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
		    sapp_runtime_log(30,"MESA_fakepacket_send_udp: Invalid cap_mode:%d\n", g_packet_io_cap_level);
		    //exit(1);
		return -1;
	}	

	if(payload_len > (int)MTU_MAX- (int)sizeof(struct mesa_ethernet_hdr)- (int)sizeof(struct mesa_ip4_hdr)- (int)sizeof(struct mesa_tcp_hdr)){
		sapp_runtime_log(30,"MESA_fakepacket_send_udp error! datalen is more than MTU, need ip fragment!\n");
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
								(char *)KILL_TCP_PHONY_POINTER, (int *)KILL_TCP_PHONY_POINTER, NULL);
							   
	packet_io_free_sendbuf(SEND_TYPE_LINK_INJECT, thread_index);	

	if(ret > 0){
		local_sys_stat->count[SAPP_STAT_SND_UDP]++;
		local_sys_stat->length[SAPP_STAT_SND_UDP]+= ret;	
	}

	return ret;	
}

int MESA_fakepacket_send_udp_detail(int thread_index, u_int sip_host_order, u_int dip_host_order, 
							u_short ipid, u_int8_t ip_ttl, u_short sport_host_order,u_short dport_host_order, 
							const char *payload, int payload_len,u_int8_t dir)
{
	MESA_send_handle *send_handle;
	int ret, offset = 0;
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_index]->sys_stat;

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
		    sapp_runtime_log(30,"MESA_fakepacket_send_udp: Invalid cap_mode:%d\n", g_packet_io_cap_level);
		    //exit(1);
		return -1;
	}	

	if(payload_len > (int)MTU_MAX- (int)sizeof(struct mesa_ethernet_hdr)- (int)sizeof(struct mesa_ip4_hdr)- (int)sizeof(struct mesa_tcp_hdr)){
		sapp_runtime_log(30,"MESA_fakepacket_send_udp error! datalen is more than MTU, need ip fragment!\n");
		return -1;
	}

	sendpacket_build_udp_dual_stack(sport_host_order, dport_host_order, payload, payload_len, payload_len,
						send_handle->send_buf+offset+sizeof(struct mesa_ip4_hdr));
						
	sendpacket_build_ipv4(payload_len+SENDPACKET_UDP_H, 0, ipid, 0, ip_ttl, IPPROTO_UDP, 
						htonl(sip_host_order), htonl(dip_host_order), NULL, 0, send_handle->send_buf+offset);

	sendpacket_do_checksum(send_handle->send_buf+offset, IPPROTO_UDP, SENDPACKET_UDP_H+payload_len);
	
	sendpacket_do_checksum(send_handle->send_buf+offset, IPPROTO_IP, SENDPACKET_IP_H);

	ret = packet_io_send_fake_pkt(send_handle, payload_len+sizeof(struct mesa_udp_hdr)+sizeof(struct mesa_ip4_hdr)+sizeof(struct mesa_ethernet_hdr), 
								SEND_TYPE_LINK_INJECT, __ADDR_TYPE_IP_PAIR_V4, dir, thread_index,
								(char *)KILL_TCP_PHONY_POINTER, (int *)KILL_TCP_PHONY_POINTER, NULL);
							   
	packet_io_free_sendbuf(SEND_TYPE_LINK_INJECT, thread_index);	

	if(ret > 0){
		local_sys_stat->count[SAPP_STAT_SND_UDP]++;
		local_sys_stat->length[SAPP_STAT_SND_UDP]+= ret;	
	}

	return ret;	
}

#if IOMODE_MARSIO

static struct mr_instance *dl_io_marsio4_instance = NULL;
extern struct mr_instance *sapp_marsio4_instance;
extern int marsio_send_burst_with_options_for_tcpdumpmesa(struct mr_sendpath * sendpath, queue_id_t sid, marsio_buff_t * mbufs[], int nr_mbufs, uint16_t options);
extern int (*ptr_marsio_buff_malloc_global)(struct mr_instance * instance, marsio_buff_t *marsio_buff[], unsigned int nr_mbufs, int socket_id, int thread_id);
extern  char * (*ptr_marsio_buff_append)(marsio_buff_t *m, uint16_t len);
extern void (*ptr_marsio_buff_ctrlzone_set)(marsio_buff_t *m, uint8_t id, void* ptr_data, uint8_t size);
extern int (*ptr_marsio_send_burst)(struct mr_sendpath * sendpath,  queue_id_t qid, marsio_buff_t * mbufs[], int nr_mbufs);
extern marsio_buff_t * (*ptr_marsio_buff_clone_with_options)(struct mr_instance * instance, marsio_buff_t * md, int socket_id, int thread_id, uint16_t options);
extern void (*ptr_marsio_buff_set_rehash_index)(marsio_buff_t *m, uint32_t hash);
extern void (*ptr_marsio_buff_free)(struct mr_instance * instance, marsio_buff_t *marsio_buff[],unsigned int nr_mbufs, int socket_id, int thread_id);
struct mr_instance *sapp_get_marsio_instance(void)
{
	void *address_of_sapp_marsio4_instance;
	
#if LINK_MODE_DYNAMIC
	void *dl_handle;
	char lib_path[256];
	
	snprintf(lib_path, 256, "%s/%s", "platform_lib", g_dl_io_lib_info[g_packet_io_cap_mode].lib_name);

	dl_handle = dlopen(lib_path, RTLD_NOW);
	if(NULL == dl_handle){
		printf("\033[41m[Error]dlopen %s error!\033[0m\n", lib_path);
		return NULL;
	}

	address_of_sapp_marsio4_instance = dlsym(dl_handle, "sapp_marsio4_instance");
	if(NULL == address_of_sapp_marsio4_instance){
		printf("\033[41m[Error]dlsym %s from %s error!\033[0m\n", "sapp_marsio4_instance", lib_path);
		return NULL;
	}

	/* dlsym 获取的是sapp_marsio4_instance符号的起始地址, 对此地址取8bytes值, 才是指针的真实值 */
	memcpy(&dl_io_marsio4_instance, address_of_sapp_marsio4_instance, sizeof(void *));
#else
	dl_io_marsio4_instance = sapp_marsio4_instance;
#endif
	return dl_io_marsio4_instance; 
}


static void sapp_fakepacket_set_vxlan_options(struct mr_tunnat_ctrlzone *mr_ctrlzone, SAPP_TLV_T *option)
{
	switch(option->type){
		case SAPP_SEND_OPT_GDEV_DMAC:
			memcpy(mr_ctrlzone->g_device_mac, option->array_value, 6);
		break;

		case SAPP_SEND_OPT_GDEV_SMAC:
			memcpy(mr_ctrlzone->l_device_mac, option->array_value, 6);
		break;

		case SAPP_SEND_OPT_GDEV_DIP:
			mr_ctrlzone->g_device_in_addr = option->int_value;
		break;
		
		case SAPP_SEND_OPT_GDEV_SIP:
			mr_ctrlzone->l_device_in_addr = option->int_value;
		break;

		case SAPP_SEND_OPT_GDEV_UDP_DPORT:
			/* default 4789, do nothing */
		break;

		case SAPP_SEND_OPT_GDEV_UDP_SPORT:
			mr_ctrlzone->l4_src_port = option->short_value;
		break;

		case SAPP_SEND_OPT_VXLAN_VPN_ID:
			mr_ctrlzone->g_device_vpn_id = option->int_value;
			mr_ctrlzone->action |= TUNNAT_CZ_ACTION_ENCAP_NO_SESSION;  /* 直接构造好整个包再发送, 不需要驱动查表 */
		break;	

		case SAPP_SEND_OPT_VXLAN_LINK_ID:
			mr_ctrlzone->g_device_linkpair = option->int_value;
			mr_ctrlzone->action |= TUNNAT_CZ_ACTION_ENCAP_NO_SESSION;  /* 直接构造好整个包再发送, 不需要驱动查表 */
		break;

		case SAPP_SEND_OPT_VXLAN_LINK_ENCAP_TYPE:
			mr_ctrlzone->g_device_outer_encap_type = option->char_value;
		break;

		case SAPP_SEND_OPT_VXLAN_LINK_DIR:
			mr_ctrlzone->route_dir = option->char_value;
			mr_ctrlzone->action |= TUNNAT_CZ_ACTION_ENCAP_NO_SESSION;  /* 直接构造好整个包再发送, 不需要驱动查表 */
		break;

		case SAPP_SEND_OPT_INNER_LINK_ENCAP_TYPE:
			mr_ctrlzone->g_device_inner_encap_type = option->char_value;
		break;

		case SAPP_SEND_OPT_VIRTUAL_LINK_ID:
			mr_ctrlzone->virtual_link_id = option->long_value;
			mr_ctrlzone->action |= TUNNAT_CZ_ACTION_ENCAP_VIRTUAL_LINK_ID; 
		break;

		case SAPP_SEND_OPT_REHASH_INDEX:
			/* rehash_index不能在ctrlzone里设置, 要通过接口marsio_buff_set_rehash_index() */
			//mr_ctrlzone->rehash_index = option->long_value;
			//mr_ctrlzone->action |= TUNNAT_CZ_ACTION_ENCAP_VIRTUAL_LINK_ID;
			sapp_runtime_log(30, "sendpacket set vxlan options error, cat't set REHASH_INDEX in ctrlzone\n");
		break;

		case SAPP_SEND_OPT_VXLAN_FLAGS:
			//dpdk driver not support, use fix value 0x08
		break;

		default:
			sapp_runtime_log(20, "sendpacket set vxlan options error, invalid opt type:%d\n", option->type);
		break;
	}

	return;
}

/*
	此函数由ipv4, ipv6发包函数共用, 靠ether_type_host参数区别.
	data: 包含ip头部的整个ip包;
	data_len: 包含ip头部长度.
*/
static int __MESA_sendpacket_iplayer_options(int thread_index,const char *data,  int data_len, 
    u_int8_t dir, SAPP_TLV_T *options, int opt_num, unsigned short ether_type_host)
{
	/* marsio系列函数0表示正常, -1表示错误, g_serial系列函数正常返回字节数, 错误返回-1 */
	int inner_ret;
	marsio_buff_t *send_mbuf[1];
	unsigned char *real_buf;
	struct mr_tunnat_ctrlzone mr_ctrlzone;
	int i;
	
	if(NULL == dl_io_marsio4_instance){
		dl_io_marsio4_instance = sapp_get_marsio_instance();
	}
	
	inner_ret = ptr_marsio_buff_malloc_global(dl_io_marsio4_instance, send_mbuf, 1, MARSIO_SOCKET_ID_ANY, thread_index);
	if(inner_ret < 0){
		sapp_runtime_log(RLOG_LV_INFO, "call marsio_buff_malloc_global() failed!\n");
		sapp_global_val->mthread_volatile[thread_index]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
		return -1;
	}	
	
	real_buf = (unsigned char *)ptr_marsio_buff_append(send_mbuf[0], data_len+sizeof(struct mesa_ethernet_hdr));
	if(NULL == real_buf){
		ptr_marsio_buff_free(dl_io_marsio4_instance, send_mbuf, 1, MARSIO_SOCKET_ID_ANY, thread_index);
		sapp_global_val->mthread_volatile[thread_index]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
		return -1;
	}	
	struct mesa_ethernet_hdr *inner_ehdr = (struct mesa_ethernet_hdr *)real_buf;
	inner_ehdr->ether_type = ntohs(ether_type_host);/* 底层设为ethernet */

	/* 此处只处理跟IP层相关的选项, vxlan相关选项在公共函数sapp_fakepacket_set_vxlan_options()设置 */
	memset(&mr_ctrlzone, 0 , sizeof(struct mr_tunnat_ctrlzone));
	for(i = 0; i < opt_num; i++){
		if(SAPP_SEND_OPT_INNER_SMAC == options[i].type){
			memcpy(inner_ehdr->ether_shost, options[i].array_value, ETHER_ADDR_LEN);
		}else if(SAPP_SEND_OPT_INNER_DMAC == options[i].type){
			memcpy(inner_ehdr->ether_dhost, options[i].array_value, ETHER_ADDR_LEN);
		}else if(SAPP_SEND_OPT_REHASH_INDEX == options[i].type){
			ptr_marsio_buff_set_rehash_index(send_mbuf[0], options[i].int_value);
		}else{
			sapp_fakepacket_set_vxlan_options(&mr_ctrlzone, &options[i]);
		}
	}
	memcpy(real_buf + sizeof(struct mesa_ethernet_hdr), data, data_len);

	mr_ctrlzone.action |= TUNNAT_CZ_ACTION_ENCAP_INNER | TUNNAT_CZ_ACTION_ENCAP_OUTER;
	mr_ctrlzone.route_dir = dir; /* 通过选项也可设置, 但还是保留了接口直接设置dir的参数, 接口dir优先 */
	ptr_marsio_buff_ctrlzone_set(send_mbuf[0], 0, &mr_ctrlzone, sizeof(struct mr_tunnat_ctrlzone));
	inner_ret = marsio_send_burst_with_options_for_tcpdumpmesa((struct mr_sendpath *)g_packet_device_alias[0].dl_io_param, thread_index, 
								    send_mbuf, 1, MARSIO_SEND_OPT_FAST);	
	if(inner_ret < 0){
		return -1;
	}
								    	
	return data_len;
}


int MESA_sendpacket_iplayer_options(int thread_index,const char *data,  int data_len, 
    u_int8_t dir, SAPP_TLV_T *options, int opt_num)
{
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_index]->sys_stat;
	int ret;

	ret = __MESA_sendpacket_iplayer_options(thread_index, data, data_len, dir, options, opt_num, ETHERTYPE_IP);
	if(ret > 0){
		local_sys_stat->count[SAPP_STAT_SND_IPV4]++;
		local_sys_stat->length[SAPP_STAT_SND_IPV4]+= data_len;	
	}

	return ret;
}

int MESA_sendpacket_ipv6_layer_options(int thread_index,const char *data,  int data_len, 
    u_int8_t dir, SAPP_TLV_T *options, int opt_num)
{
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_index]->sys_stat;
	int ret;

	ret = __MESA_sendpacket_iplayer_options(thread_index, data, data_len, dir, options, opt_num, ETHERTYPE_IPv6);

	if(ret > 0){
		local_sys_stat->count[SAPP_STAT_SND_IPV6]++;
		local_sys_stat->length[SAPP_STAT_SND_IPV6]+= data_len;	
	}

	return ret;	
}

int MESA_fakepacket_send_ipv4_options(const struct streaminfo *stream, uint8_t protocol,
							uint32_t sip_host_order, uint32_t dip_host_order, 
							const char *payload, int payload_len, uint8_t dir, 
							SAPP_TLV_T *options, int opt_num)
{
	int snd_len, inner_ret;
	marsio_buff_t *send_mbuf[1];
	u_int16_t ipid = MESA_rand() & 0xFFFF;
	u_int8_t ip_ttl = MESA_rand() % 64 + 32;
	int thread_index = stream->threadnum;
	int i;
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_index]->sys_stat;
	
	struct mr_tunnat_ctrlzone mr_ctrlzone;
	unsigned char *real_buf;

	if(NULL == dl_io_marsio4_instance){
		dl_io_marsio4_instance = sapp_get_marsio_instance();
	}
	
	inner_ret = ptr_marsio_buff_malloc_global(dl_io_marsio4_instance, send_mbuf, 1, MARSIO_SOCKET_ID_ANY, thread_index);
	if(inner_ret < 0){
		sapp_runtime_log(RLOG_LV_INFO, "MESA_fakepacket_send_ipv4_options-> marsio_buff_malloc_global() failed!\n");
		sapp_global_val->mthread_volatile[thread_index]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
		return -1;
	}	

	/* 此处使用append而不是mtod, append内部实际包括了set datalen的操作 */
	real_buf = (unsigned char *)ptr_marsio_buff_append(send_mbuf[0], payload_len + sizeof(struct mesa_ip4_hdr)+sizeof(struct mesa_ethernet_hdr));
	if(NULL == real_buf){
		ptr_marsio_buff_free(dl_io_marsio4_instance, send_mbuf, 1, MARSIO_SOCKET_ID_ANY, thread_index);
		sapp_global_val->mthread_volatile[thread_index]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
		return -1;
	}		
	struct mesa_ethernet_hdr *inner_ehdr = (struct mesa_ethernet_hdr *)real_buf;
	inner_ehdr->ether_type = ntohs(ETHERTYPE_IP);/* 底层设为ethernte */
	
	/* 此处只处理跟IP层相关的选项, vxlan相关选项在公共函数sapp_fakepacket_set_vxlan_options()设置 */
	memset(&mr_ctrlzone, 0 , sizeof(struct mr_tunnat_ctrlzone));
	for(i = 0; i < opt_num; i++){
		if(SAPP_SEND_OPT_IP_ID == options[i].type){
			ipid = options[i].short_value;
		}else if(SAPP_SEND_OPT_IP_TTL == options[i].type){
			ip_ttl = options[i].char_value;
		}else if(SAPP_SEND_OPT_INNER_SMAC == options[i].type){
			memcpy(inner_ehdr->ether_shost, options[i].array_value, ETHER_ADDR_LEN);
		}else if(SAPP_SEND_OPT_INNER_DMAC == options[i].type){
			memcpy(inner_ehdr->ether_dhost, options[i].array_value, ETHER_ADDR_LEN);
		}else if(SAPP_SEND_OPT_REHASH_INDEX == options[i].type){
			ptr_marsio_buff_set_rehash_index(send_mbuf[0], options[i].int_value);
		}else{
			sapp_fakepacket_set_vxlan_options(&mr_ctrlzone, &options[i]);
		}
	}
	sendpacket_build_ipv4(payload_len, 0, ipid, 0 , ip_ttl, protocol, 
						htonl(sip_host_order), htonl(dip_host_order), payload, payload_len, 
						(unsigned char *)real_buf + sizeof(struct mesa_ethernet_hdr));

	sendpacket_do_checksum(real_buf + sizeof(struct mesa_ethernet_hdr), IPPROTO_IP, SENDPACKET_IP_H);
	
	if(payload){
		memcpy(real_buf + sizeof(struct mesa_ip4_hdr)+sizeof(struct mesa_ethernet_hdr), payload, payload_len);
	}

	mr_ctrlzone.action |= TUNNAT_CZ_ACTION_ENCAP_INNER | TUNNAT_CZ_ACTION_ENCAP_OUTER;
	mr_ctrlzone.route_dir = dir; /* 通过选项也可设置, 但还是保留了接口直接设置dir的参数, 接口dir优先 */
	ptr_marsio_buff_ctrlzone_set(send_mbuf[0], 0, &mr_ctrlzone, sizeof(struct mr_tunnat_ctrlzone));
	inner_ret = marsio_send_burst_with_options_for_tcpdumpmesa((struct mr_sendpath *)g_packet_device_alias[0].dl_io_param, thread_index, 
								    send_mbuf, 1, MARSIO_SEND_OPT_FAST);	

	if(inner_ret < 0){
		sapp_global_val->mthread_volatile[thread_index]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
		return -1;
	}

	snd_len = sizeof(struct mesa_ip4_hdr)+sizeof(struct mesa_ethernet_hdr) + payload_len;
	local_sys_stat->count[SAPP_STAT_SND_IPV4]++;
	local_sys_stat->length[SAPP_STAT_SND_IPV4]+= snd_len;

	
	return snd_len;	
}

int MESA_fakepacket_send_ipv6_options(const struct streaminfo *stream, uint8_t protocol,
							struct in6_addr *sip, struct in6_addr *dip,
							const char *payload, int payload_len, uint8_t dir, 
							SAPP_TLV_T *options, int opt_num)
{
	int inner_ret, snd_len;
	u_int8_t ip_ttl = MESA_rand() % 64 + 32;
	int thread_index = stream->threadnum;
	int i;
	marsio_buff_t *send_mbuf[1];
	struct mr_tunnat_ctrlzone mr_ctrlzone;
	unsigned char *real_buf;
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_index]->sys_stat;

	if(NULL == dl_io_marsio4_instance){
		dl_io_marsio4_instance = sapp_get_marsio_instance();
	}
	
	inner_ret = ptr_marsio_buff_malloc_global(dl_io_marsio4_instance, send_mbuf, 1, MARSIO_SOCKET_ID_ANY, thread_index);
	if(inner_ret < 0){
		sapp_global_val->mthread_volatile[thread_index]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
		return -1;
	}	

	/* 此处使用append而不是mtod, append内部实际包括了set datalen的操作 */
	real_buf = (unsigned char *)ptr_marsio_buff_append(send_mbuf[0], payload_len + sizeof(struct mesa_ip6_hdr)+sizeof(struct mesa_ethernet_hdr));
	if(NULL == real_buf){
		ptr_marsio_buff_free(dl_io_marsio4_instance, send_mbuf, 1, MARSIO_SOCKET_ID_ANY, thread_index);
		sapp_global_val->mthread_volatile[thread_index]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
		return -1;
	}		
	struct mesa_ethernet_hdr *inner_ehdr = (struct mesa_ethernet_hdr *)real_buf;
	inner_ehdr->ether_type = ntohs(ETHERTYPE_IPv6);/* 底层设为ethernet */
	
	/* 此处只处理跟IP层相关的选项, vxlan相关选项在公共函数sapp_fakepacket_set_vxlan_options()设置 */
	memset(&mr_ctrlzone, 0 , sizeof(struct mr_tunnat_ctrlzone));
	for(i = 0; i < opt_num; i++){
		if(SAPP_SEND_OPT_IP_TTL == options[i].type){
			ip_ttl = options[i].char_value;
		}else if(SAPP_SEND_OPT_INNER_SMAC == options[i].type){
			memcpy(inner_ehdr->ether_shost, options[i].array_value, ETHER_ADDR_LEN);
		}else if(SAPP_SEND_OPT_INNER_DMAC == options[i].type){
			memcpy(inner_ehdr->ether_dhost, options[i].array_value, ETHER_ADDR_LEN);
		}else if(SAPP_SEND_OPT_REHASH_INDEX == options[i].type){
			ptr_marsio_buff_set_rehash_index(send_mbuf[0], options[i].int_value);
		}else{
			sapp_fakepacket_set_vxlan_options(&mr_ctrlzone, &options[i]);
		}
	}
	sendpacket_build_ipv6(0, 0, payload_len, protocol, ip_ttl, sip, dip, 
						payload, payload_len, 
						(unsigned char *)real_buf + sizeof(struct mesa_ethernet_hdr));

	mr_ctrlzone.action |= TUNNAT_CZ_ACTION_ENCAP_INNER | TUNNAT_CZ_ACTION_ENCAP_OUTER;
	mr_ctrlzone.route_dir = dir; /* 通过选项也可设置, 但还是保留了接口直接设置dir的参数, 接口dir优先 */
	ptr_marsio_buff_ctrlzone_set(send_mbuf[0], 0, &mr_ctrlzone, sizeof(struct mr_tunnat_ctrlzone));
	inner_ret = marsio_send_burst_with_options_for_tcpdumpmesa((struct mr_sendpath *)g_packet_device_alias[0].dl_io_param, thread_index, 
								    send_mbuf, 1, MARSIO_SEND_OPT_FAST);	
	if(inner_ret < 0){
		sapp_global_val->mthread_volatile[thread_index]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
		return -1;
	}

	snd_len = sizeof(struct mesa_ip6_hdr)+sizeof(struct mesa_ethernet_hdr) + payload_len;
	local_sys_stat->count[SAPP_STAT_SND_IPV6]++;
	local_sys_stat->length[SAPP_STAT_SND_IPV6]+= snd_len;

	return snd_len;	
}

int MESA_fakepacket_send_tcp_options(const struct streaminfo *stream,
							u_int sip_host_order,u_int dip_host_order,
							u_short sport_host_order,u_short dport_host_order,
							u_int sseq_host_order,u_int sack_host_order,
							u_char control,
							const char* payload,int payload_len, u_int8_t dir,
							SAPP_TLV_T *options, int opt_num)
{
	int i, snd_len, inner_ret, offset = sizeof(struct mesa_ethernet_hdr);
	int thread_index = stream->threadnum;
	marsio_buff_t *send_mbuf[1];
	struct mr_tunnat_ctrlzone mr_ctrlzone;
	unsigned char *real_buf;
	unsigned short ipid = MESA_rand() & 0xFFFF;
	unsigned short tcp_win = MESA_rand_range(8192, 32768);
	unsigned char ip_ttl = MESA_rand_range(32,65);
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_index]->sys_stat;

	if(NULL == dl_io_marsio4_instance){
		dl_io_marsio4_instance = sapp_get_marsio_instance();
	}
	
	inner_ret = ptr_marsio_buff_malloc_global(dl_io_marsio4_instance, send_mbuf, 1, MARSIO_SOCKET_ID_ANY, thread_index);
	if(inner_ret < 0){
		sapp_global_val->mthread_volatile[thread_index]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
		sapp_runtime_log(RLOG_LV_INFO, "MESA_fakepacket_send_tcp_options()-> marsio_buff_malloc_global() failed!\n");
		return -1;
	}	

	/* 此处使用append而不是mtod, append内部实际包括了set datalen的操作 */
	real_buf = (unsigned char *)ptr_marsio_buff_append(send_mbuf[0], payload_len + sizeof(struct mesa_tcp_hdr) + sizeof(struct mesa_ip4_hdr)+sizeof(struct mesa_ethernet_hdr));
	if(NULL == real_buf){
		ptr_marsio_buff_free(dl_io_marsio4_instance, send_mbuf, 1, MARSIO_SOCKET_ID_ANY, thread_index);
		sapp_global_val->mthread_volatile[thread_index]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
		return -1;
	}			
	struct mesa_ethernet_hdr *inner_ehdr = (struct mesa_ethernet_hdr *)real_buf;
	inner_ehdr->ether_type = ntohs(ETHERTYPE_IP);/* 底层设为ethernte */
	
	memset(&mr_ctrlzone, 0 , sizeof(struct mr_tunnat_ctrlzone));
	for(i = 0; i < opt_num; i++){
		if(SAPP_SEND_OPT_IP_ID == options[i].type){
			ipid = options[i].short_value;
		}else if(SAPP_SEND_OPT_IP_TTL == options[i].type){
			ip_ttl = options[i].char_value;
		}if(SAPP_SEND_OPT_TCP_WIN == options[i].type){
			tcp_win = options[i].short_value;
		}else if(SAPP_SEND_OPT_INNER_SMAC == options[i].type){
			memcpy(inner_ehdr->ether_shost, options[i].array_value, ETHER_ADDR_LEN);
		}else if(SAPP_SEND_OPT_INNER_DMAC == options[i].type){
			memcpy(inner_ehdr->ether_dhost, options[i].array_value, ETHER_ADDR_LEN);
		}else if(SAPP_SEND_OPT_REHASH_INDEX == options[i].type){
			ptr_marsio_buff_set_rehash_index(send_mbuf[0], options[i].int_value);
		}else{
			sapp_fakepacket_set_vxlan_options(&mr_ctrlzone, &options[i]);
		}
	}
	
	sendpacket_build_tcp(sport_host_order, dport_host_order, sseq_host_order, sack_host_order,
						control, tcp_win, 0, payload, payload_len, real_buf+offset+sizeof(struct mesa_ip4_hdr));
						
	sendpacket_build_ipv4(payload_len+SENDPACKET_TCP_H, 0, ipid, 0, ip_ttl, IPPROTO_TCP, 
						htonl(sip_host_order), htonl(dip_host_order), NULL, 0, real_buf+offset);

	sendpacket_do_checksum(real_buf+offset, IPPROTO_TCP, SENDPACKET_TCP_H+payload_len);
	
	sendpacket_do_checksum(real_buf+offset, IPPROTO_IP, SENDPACKET_IP_H);

	mr_ctrlzone.action |= TUNNAT_CZ_ACTION_ENCAP_INNER | TUNNAT_CZ_ACTION_ENCAP_OUTER;
	mr_ctrlzone.route_dir = dir; /* 通过选项也可设置, 但还是保留了接口直接设置dir的参数, 接口dir优先 */
	ptr_marsio_buff_ctrlzone_set(send_mbuf[0], 0, &mr_ctrlzone, sizeof(struct mr_tunnat_ctrlzone));
	inner_ret = marsio_send_burst_with_options_for_tcpdumpmesa((struct mr_sendpath *)g_packet_device_alias[0].dl_io_param, thread_index, 
								    send_mbuf, 1, MARSIO_SEND_OPT_FAST);	

	if(inner_ret < 0){
		sapp_global_val->mthread_volatile[thread_index]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
		return -1;
	}

	snd_len = sizeof(struct mesa_ip4_hdr)+sizeof(struct mesa_ethernet_hdr) +sizeof(struct mesa_tcp_hdr) + payload_len;
	
	local_sys_stat->count[SAPP_STAT_SND_TCP]++;
	local_sys_stat->length[SAPP_STAT_SND_TCP]+= snd_len;
	
	return snd_len;	
}


int MESA_fakepacket_send_ipv6_tcp_options(const struct streaminfo *stream,
							struct in6_addr *sip, struct in6_addr *dip,
							u_short sport_host_order,u_short dport_host_order,
							u_int sseq_host_order,u_int sack_host_order,
							u_char control,
							const char* payload,int payload_len, u_int8_t dir,
							SAPP_TLV_T *options, int opt_num)
{
	int i, snd_len, inner_ret, offset = sizeof(struct mesa_ethernet_hdr);
	int thread_index = stream->threadnum;
	marsio_buff_t *send_mbuf[1];
	struct mr_tunnat_ctrlzone mr_ctrlzone;
	unsigned char *real_buf;
	unsigned short tcp_win = MESA_rand_range(8192, 32768);
	unsigned char ip_ttl = MESA_rand_range(32,65);
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_index]->sys_stat;

	if(NULL == dl_io_marsio4_instance){
		dl_io_marsio4_instance = sapp_get_marsio_instance();
	}
	
	inner_ret = ptr_marsio_buff_malloc_global(dl_io_marsio4_instance, send_mbuf, 1, MARSIO_SOCKET_ID_ANY, thread_index);
	if(inner_ret < 0){
		sapp_runtime_log(RLOG_LV_INFO, "MESA_fakepacket_send_ipv6_tcp_options-> marsio_buff_malloc_global() failed!\n");
		sapp_global_val->mthread_volatile[thread_index]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
		return -1;
	}	

	/* 此处使用append而不是mtod, append内部实际包括了set datalen的操作 */
	real_buf = (unsigned char *)ptr_marsio_buff_append(send_mbuf[0], payload_len + sizeof(struct mesa_tcp_hdr) + sizeof(struct mesa_ip6_hdr)+sizeof(struct mesa_ethernet_hdr));
	if(NULL == real_buf){
		ptr_marsio_buff_free(dl_io_marsio4_instance, send_mbuf, 1, MARSIO_SOCKET_ID_ANY, thread_index);
		sapp_global_val->mthread_volatile[thread_index]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
		return -1;
	}		
	struct mesa_ethernet_hdr *inner_ehdr = (struct mesa_ethernet_hdr *)real_buf;
	inner_ehdr->ether_type = ntohs(ETHERTYPE_IPv6);/* 底层设为ethernte */
	
	memset(&mr_ctrlzone, 0 , sizeof(struct mr_tunnat_ctrlzone));
	for(i = 0; i < opt_num; i++){
		if(SAPP_SEND_OPT_IP_TTL == options[i].type){
			ip_ttl = options[i].char_value;
		}if(SAPP_SEND_OPT_TCP_WIN == options[i].type){
			tcp_win = options[i].short_value;
		}else if(SAPP_SEND_OPT_INNER_SMAC == options[i].type){
			memcpy(inner_ehdr->ether_shost, options[i].array_value, ETHER_ADDR_LEN);
		}else if(SAPP_SEND_OPT_INNER_DMAC == options[i].type){
			memcpy(inner_ehdr->ether_dhost, options[i].array_value, ETHER_ADDR_LEN);
		}else if(SAPP_SEND_OPT_REHASH_INDEX == options[i].type){
			ptr_marsio_buff_set_rehash_index(send_mbuf[0], options[i].int_value);
		}else{
			sapp_fakepacket_set_vxlan_options(&mr_ctrlzone, &options[i]);
		}
	}
	
	sendpacket_build_tcp(sport_host_order, dport_host_order, sseq_host_order, sack_host_order,
						control, tcp_win, 0, payload, payload_len, real_buf+offset+sizeof(struct mesa_ip6_hdr));
						
	sendpacket_build_ipv6(0, 0, payload_len + sizeof(struct mesa_tcp_hdr), IPPROTO_TCP, ip_ttl, sip, dip, 
						NULL, 0, 
						(unsigned char *)real_buf + sizeof(struct mesa_ethernet_hdr));

	sendpacket_do_checksum(real_buf+offset, IPPROTO_TCP, SENDPACKET_TCP_H+payload_len);

	mr_ctrlzone.action |= TUNNAT_CZ_ACTION_ENCAP_INNER | TUNNAT_CZ_ACTION_ENCAP_OUTER;
	mr_ctrlzone.route_dir = dir; /* 通过选项也可设置, 但还是保留了接口直接设置dir的参数, 接口dir优先 */
	ptr_marsio_buff_ctrlzone_set(send_mbuf[0], 0, &mr_ctrlzone, sizeof(struct mr_tunnat_ctrlzone));
	inner_ret = marsio_send_burst_with_options_for_tcpdumpmesa((struct mr_sendpath *)g_packet_device_alias[0].dl_io_param, thread_index, 
								    send_mbuf, 1, MARSIO_SEND_OPT_FAST);	
	if(inner_ret < 0){
		sapp_global_val->mthread_volatile[thread_index]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
		return -1;
	}

	snd_len = sizeof(struct mesa_ip6_hdr)+sizeof(struct mesa_ethernet_hdr) +sizeof(struct mesa_tcp_hdr) + payload_len;
	local_sys_stat->count[SAPP_STAT_SND_TCP]++;
	local_sys_stat->length[SAPP_STAT_SND_TCP]+= snd_len;

	return snd_len;	
}

int MESA_fakepacket_send_udp_options(const struct streaminfo *stream,
							u_int sip_host_order, u_int dip_host_order, 
							u_short sport_host_order,u_short dport_host_order, 
							const char *payload, int payload_len,u_int8_t dir,
							SAPP_TLV_T *options, int opt_num)
{
	int i, snd_len, inner_ret, offset = sizeof(struct mesa_ethernet_hdr);
	int thread_index = stream->threadnum;
	marsio_buff_t *send_mbuf[1];
	struct mr_tunnat_ctrlzone mr_ctrlzone;
	unsigned char *real_buf;
	unsigned short ipid = MESA_rand();
	unsigned char ip_ttl = MESA_rand_range(32, 64);
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_index]->sys_stat;

	if(NULL == dl_io_marsio4_instance){
		dl_io_marsio4_instance = sapp_get_marsio_instance();
	}
	
	inner_ret = ptr_marsio_buff_malloc_global(dl_io_marsio4_instance, send_mbuf, 1, MARSIO_SOCKET_ID_ANY, thread_index);
	if(inner_ret < 0){
		sapp_runtime_log(30, "call marsio_buff_malloc_global() failed!\n");
		return -1;
	}	

	/* 此处使用append而不是mtod, append内部实际包括了set datalen的操作 */
	real_buf = (unsigned char *)ptr_marsio_buff_append(send_mbuf[0], payload_len + sizeof(struct mesa_udp_hdr) + sizeof(struct mesa_ip4_hdr)+sizeof(struct mesa_ethernet_hdr));
	if(NULL == real_buf){
		ptr_marsio_buff_free(dl_io_marsio4_instance, send_mbuf, 1, MARSIO_SOCKET_ID_ANY, thread_index);
		sapp_global_val->mthread_volatile[thread_index]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
		return -1;
	}			
	struct mesa_ethernet_hdr *inner_ehdr = (struct mesa_ethernet_hdr *)real_buf;
	inner_ehdr->ether_type = ntohs(ETHERTYPE_IP);/* 底层设为ethernte */
	
	memset(&mr_ctrlzone, 0 , sizeof(struct mr_tunnat_ctrlzone));
	for(i = 0; i < opt_num; i++){
		if(SAPP_SEND_OPT_IP_ID == options[i].type){
			ipid = options[i].short_value;
		}else if(SAPP_SEND_OPT_IP_TTL == options[i].type){
			ip_ttl = options[i].char_value;
		}else if(SAPP_SEND_OPT_INNER_SMAC == options[i].type){
			memcpy(inner_ehdr->ether_shost, options[i].array_value, ETHER_ADDR_LEN);
		}else if(SAPP_SEND_OPT_INNER_DMAC == options[i].type){
			memcpy(inner_ehdr->ether_dhost, options[i].array_value, ETHER_ADDR_LEN);
		}else if(SAPP_SEND_OPT_REHASH_INDEX == options[i].type){
			ptr_marsio_buff_set_rehash_index(send_mbuf[0], options[i].int_value);
		}else{
			sapp_fakepacket_set_vxlan_options(&mr_ctrlzone, &options[i]);
		}
	}
	
	sendpacket_build_udp(sport_host_order, dport_host_order, payload, payload_len,
						real_buf+offset+sizeof(struct mesa_ip4_hdr));
						
	sendpacket_build_ipv4(payload_len+SENDPACKET_UDP_H, 0, ipid, 0, ip_ttl, IPPROTO_UDP, 
						htonl(sip_host_order), htonl(dip_host_order), NULL, 0, real_buf+offset);

	sendpacket_do_checksum(real_buf+offset, IPPROTO_UDP, SENDPACKET_UDP_H+payload_len);
	
	sendpacket_do_checksum(real_buf+offset, IPPROTO_IP, SENDPACKET_IP_H);

	if((mr_ctrlzone.action & TUNNAT_CZ_ACTION_ENCAP_NO_SESSION) == 0){
		mr_ctrlzone.action |= TUNNAT_CZ_ACTION_ENCAP_INNER | TUNNAT_CZ_ACTION_ENCAP_OUTER;
	}
	mr_ctrlzone.route_dir = dir; /* 通过选项也可设置, 但还是保留了接口直接设置dir的参数, 接口dir优先 */
	ptr_marsio_buff_ctrlzone_set(send_mbuf[0], 0, &mr_ctrlzone, sizeof(struct mr_tunnat_ctrlzone));
#if 0
	inner_ret = marsio_send_burst_with_options_for_tcpdumpmesa((struct mr_sendpath *)g_packet_device_alias[0].dl_io_param, thread_index, 
								    send_mbuf, 1, MARSIO_SEND_OPT_FAST);	
#else
	inner_ret = marsio_send_burst_with_options_for_tcpdumpmesa((struct mr_sendpath *)g_packet_device_alias[0].dl_io_param, thread_index, 
									send_mbuf, 1, 0);	
#endif
	if(inner_ret < 0){
		sapp_global_val->mthread_volatile[thread_index]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
		return -1;
	}

	snd_len = sizeof(struct mesa_ip4_hdr)+sizeof(struct mesa_ethernet_hdr) +sizeof(struct mesa_udp_hdr) + payload_len;

	local_sys_stat->count[SAPP_STAT_SND_TCP]++;
	local_sys_stat->length[SAPP_STAT_SND_TCP]+= snd_len;		
	return snd_len;	
}

int MESA_fakepacket_send_ipv6_udp_options(const struct streaminfo *stream,
							struct in6_addr *sip, struct in6_addr *dip,
							u_short sport_host_order,u_short dport_host_order, 
							const char *payload, int payload_len,u_int8_t dir,
							SAPP_TLV_T *options, int opt_num)
{
	int i, snd_len, inner_ret, offset = sizeof(struct mesa_ethernet_hdr);
	int thread_index = stream->threadnum;
	marsio_buff_t *send_mbuf[1];
	struct mr_tunnat_ctrlzone mr_ctrlzone;
	unsigned char *real_buf;
	unsigned char ip_ttl = MESA_rand_range(32, 64);
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_index]->sys_stat;

	if(NULL == dl_io_marsio4_instance){
		dl_io_marsio4_instance = sapp_get_marsio_instance();
	}
	
	inner_ret = ptr_marsio_buff_malloc_global(dl_io_marsio4_instance, send_mbuf, 1, MARSIO_SOCKET_ID_ANY, thread_index);
	if(inner_ret < 0){
		sapp_runtime_log(RLOG_LV_INFO, "MESA_fakepacket_send_ipv6_udp_options-> marsio_buff_malloc_global() failed!\n");
		sapp_global_val->mthread_volatile[thread_index]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
		return -1;
	}	

	/* 此处使用append而不是mtod, append内部实际包括了set datalen的操作 */
	real_buf = (unsigned char *)ptr_marsio_buff_append(send_mbuf[0], payload_len + sizeof(struct mesa_udp_hdr) + sizeof(struct mesa_ip6_hdr)+sizeof(struct mesa_ethernet_hdr));
	if(NULL == real_buf){
		ptr_marsio_buff_free(dl_io_marsio4_instance, send_mbuf, 1, MARSIO_SOCKET_ID_ANY, thread_index);
		sapp_global_val->mthread_volatile[thread_index]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
		return -1;
	}		
	struct mesa_ethernet_hdr *inner_ehdr = (struct mesa_ethernet_hdr *)real_buf;
	inner_ehdr->ether_type = ntohs(ETHERTYPE_IPv6);/* 底层设为ethernte */
	
	memset(&mr_ctrlzone, 0 , sizeof(struct mr_tunnat_ctrlzone));
	for(i = 0; i < opt_num; i++){
		if(SAPP_SEND_OPT_IP_TTL == options[i].type){
			ip_ttl = options[i].char_value;
		}else if(SAPP_SEND_OPT_INNER_SMAC == options[i].type){
			memcpy(inner_ehdr->ether_shost, options[i].array_value, ETHER_ADDR_LEN);
		}else if(SAPP_SEND_OPT_INNER_DMAC == options[i].type){
			memcpy(inner_ehdr->ether_dhost, options[i].array_value, ETHER_ADDR_LEN);
		}else if(SAPP_SEND_OPT_REHASH_INDEX == options[i].type){
			ptr_marsio_buff_set_rehash_index(send_mbuf[0], options[i].int_value);
		}else{
			sapp_fakepacket_set_vxlan_options(&mr_ctrlzone, &options[i]);
		}
	}
	
	sendpacket_build_udp(sport_host_order, dport_host_order, payload, payload_len,
						real_buf+offset+sizeof(struct mesa_ip6_hdr));
						
	sendpacket_build_ipv6(0, 0, payload_len + sizeof(struct mesa_udp_hdr), IPPROTO_UDP, ip_ttl, sip, dip, 
						NULL, 0, 
						(unsigned char *)real_buf + sizeof(struct mesa_ethernet_hdr));

	sendpacket_do_checksum(real_buf+offset, IPPROTO_UDP, SENDPACKET_UDP_H+payload_len);

	mr_ctrlzone.action |= TUNNAT_CZ_ACTION_ENCAP_INNER | TUNNAT_CZ_ACTION_ENCAP_OUTER;
	mr_ctrlzone.route_dir = dir; /* 通过选项也可设置, 但还是保留了接口直接设置dir的参数, 接口dir优先 */
	ptr_marsio_buff_ctrlzone_set(send_mbuf[0], 0, &mr_ctrlzone, sizeof(struct mr_tunnat_ctrlzone));
	inner_ret = marsio_send_burst_with_options_for_tcpdumpmesa((struct mr_sendpath *)g_packet_device_alias[0].dl_io_param, thread_index, 
								    send_mbuf, 1, MARSIO_SEND_OPT_FAST);	
	if(inner_ret < 0){
		sapp_global_val->mthread_volatile[thread_index]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
		return -1;
	}

	snd_len = sizeof(struct mesa_ip6_hdr)+sizeof(struct mesa_ethernet_hdr) +sizeof(struct mesa_udp_hdr) + payload_len;
	local_sys_stat->count[SAPP_STAT_SND_UDP]++;
	local_sys_stat->length[SAPP_STAT_SND_UDP]+= snd_len;
	
	return snd_len;	
}
#endif

int sapp_forward_current_pkt(const struct streaminfo *stream, unsigned int target_id)
{
	int ret;
#if IOMODE_MARSIO
	marsio_buff_t *raw_mbuf, *new_clone_buf;
	const struct streaminfo_private *stream_pr = (const struct streaminfo_private *)stream;

	if(NULL == dl_io_marsio4_instance){
		dl_io_marsio4_instance = sapp_get_marsio_instance();
	}

	if(NULL == stream_pr->raw_pkt){ /* 可能是流超时淘汰结束, 插件仍调用此接口 */
		return 0;
	}

	/* TODO: 
	   判断当前包是否是乱序包, 主从分流挂载到TCPALL层,
	   乱序包的io_lib_pkt_reference指向dpdk的内存, 并没有复制保存,
	   发包时会导致内存混乱.

	   NOTE:
	   其实上述担心无必要, 转发流插件挂载到TCPALL层, 但deal_unorder函数根本不会调用TCPALL接口!
	*/
	if((stream->addr.pkttype & PKT_TYPE_TCPREORDER) != 0){
		return 0;
	}
	raw_mbuf = (marsio_buff_t *)stream_pr->raw_pkt->io_lib_pkt_reference;

	assert(raw_mbuf);
	
	/* NOTE, 
		marsio在同时给收包卡和虚拟从应用网卡发送时会有问题,
		所以此处给从应用网卡发送之前, 先clone一份new_clone_buf, 发送后会自动free.
		回注原始包的还用原来的raw_mbuf. 
	*/	
	new_clone_buf = ptr_marsio_buff_clone_with_options(dl_io_marsio4_instance, raw_mbuf, 
										MARSIO_SOCKET_ID_ANY, stream->threadnum, 
										MR_BUFF_CLONE_BUFF  | MR_BUFF_CLONE_CTRLZONE);

	assert(new_clone_buf);

	ret = ptr_marsio_send_burst((struct mr_sendpath *)g_packet_device_alias[target_id].dl_io_param, 
									stream->threadnum, &new_clone_buf, 1); 
	
#else
	sapp_runtime_log(30, "sapp_forward_current_pkt() not support in non-marsio mode, TODO!\n");
	return -1;/* 其他模式todo */
#endif

	return ret;
}


int MESA_send_smart_offload(const struct streaminfo *pstream, const void *raw_pkt, int thread_num)
{
	if(pstream==NULL || pstream->pdetail==NULL)
	{
		return -1;
	}
	
	switch(pstream->type)
	{
		case	STREAM_TYPE_TCP:
			if(sapp_global_val->config.stream.tcp.meaningful_statistics_minimum_pkt>=(pstream->ptcpdetail->serverpktnum+pstream->ptcpdetail->clientpktnum))
			{
				return 0;
			}
			break;
		case	STREAM_TYPE_UDP:
			if(sapp_global_val->config.stream.udp.meaningful_statistics_minimum_pkt>=(pstream->pudpdetail->serverpktnum+pstream->pudpdetail->clientpktnum))
			{
				return 0;
			}
			break;
		default:
			return -1;
	}

	const raw_pkt_t *_raw_pkt=(raw_pkt_t *)raw_pkt;

	MESA_send_handle *send_handle = packet_io_get_send_handle(thread_num);
	
	return dl_io_fun_list.dl_io_smart_offload(_raw_pkt->device_index, 
										(unsigned char *)_raw_pkt->__lib_raw_pkt_data,
										_raw_pkt->__lib_raw_pkt_len,
										pstream->routedir,
										thread_num);
}

#ifdef __cplusplus
}
#endif

