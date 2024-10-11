#include "stream_inc/stream_base.h"
#include <MESA_handle_logger.h>
#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"
#include "sapp_declaration.h"


//#define KILL_TCP_RST_NUM				(3)
#define KILL_TCP_SYN_ACK_NUM			(1) /* ���SYN/ACKֻ����һ������ */

typedef struct{
	UINT32 gateway_ip;	/* network order */
	UINT8 gateway_mac[ETHER_ADDR_LEN];
	char to_gateway_device_name[DEV_NAME_STR_LEN];
}sys_route_t;

//static sys_route_t g_sys_route_info;
MESA_send_handle g_send_handle[MAX_THREAD_NUM];
static volatile UINT64 g_rand_seed = 0x013579ABCDEF;

/* ������ƽ̨����randֵ���㷨, ����У��RST���Ƿ�Ϊ��ϵͳ���� */
static int randgroup[MAX_THREAD_NUM];
//static int g_iRandKey=13;
//static int g_iMaxRandVal=65535;

typedef struct{
	unsigned char ip_ttl;
	unsigned short ip_id_host_order;
	char __cache_align_pad_[60]; /* ���߳�ȫ�ֱ���, ��֤64�ֽ�cache����߽� */
}bulid_layer_ipv4_args_t;

typedef struct{
	int to_do;
}bulid_layer_ipv6_args_t;

typedef struct{
	unsigned char tcp_flags;
	unsigned short tcp_win_host_order;
	unsigned int tcp_seq;
	char __cache_align_pad_[56]; /* ���߳�ȫ�ֱ���, ��֤64�ֽ�cache����߽� */
}bulid_layer_tcp_args_t;


typedef struct{
	unsigned char ip_ttl;
	unsigned short ip_id_host_order;
	unsigned short tcp_win_host_order;
	char __cache_align_pad_[58]; /* ���߳�ȫ�ֱ���, ��֤64�ֽ�cache����߽� */
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
extern int calc_l2tp_hdr_len_by_net_pkt(const struct l2tp_hdr_v2 *l2tp_hdr, size_t left_len);
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
	�����յ����ֽ��������ϸ����ĳ��Ȳ�����ݰ��ĵ�ַ����, �õ����������������.
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
	Ϊ�˼����ϰ�ϵͳ, ��׷�ٱ�ϵͳ������RST��.
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


/* 2014-08-26 lijia add, ��׷�ٱ�ϵͳ������RST��.*/
static tcp_rst_finger_mark_t *make_tcp_rst_finger_mark(int thread_id,  const raw_pkt_t *raw_pkt)
{
	tcp_rst_finger_mark_t *rst_finger;
	const struct mesa_ip4_hdr *ip4_hdr;

	rst_finger = &g_tcp_rst_finger[thread_id];

	/* NOTE, ֻ��IPv4����ip_id����Щ���, IPv6�ݲ�֧��RSTָ�� */
	/* TODO 2, �˴����������, ��jump_to_layer��֪��������һ��, Ӧ����stream_private->offset_to_ip_hdrƫ�Ƶ������IPͷ�� */
	ip4_hdr = (const struct mesa_ip4_hdr *)MESA_jump_layer(raw_pkt->raw_pkt_data, raw_pkt->low_layer_type, __ADDR_TYPE_IP_PAIR_V4);
	if((NULL == ip4_hdr) || (0 == ABBR_INJECT_RST_SIGN)){ /* ������, ��ָ����Ϣ */
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


/* 2012-04-10 LiJia add, ��ȡ����IPv4��ַ
����:
	device: ��������
	ip_add: �洢IP��ַ��ָ�룬���Ϊ������.
����ֵ:
	0: ����
	-1:����
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
		fprintf(stderr, "MESA_get_dev_ipv4(%s), ioctl SIOCGIFADDR: %s\n", device, strerror(errno));
        goto err_exit;
    }

    *ip_add = ((struct sockaddr_in*)&ifr.ifr_ifru.ifru_addr)->sin_addr.s_addr;

    close(fd);

    return 0;

err_exit:
    close(fd);
    return -1;
}


/* 2012-04-10 LiJia add, ��ȡ����MAC��ַ
����:
	device: ��������
	mac: �洢MAC��ַ������,���Ϊ������,
		 ������MAC��ַΪ11:22:33:44:55:66,��mac[0]Ϊ0x11,mac[5]Ϊ0x66.
����ֵ:
	0: ����
	-1:����
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


/*  2012-04-11 LiJia add,��MAC�ַ�����ʽת��Ϊ16����MAC��ַ.
����:
	str:   MAC��ַ�ַ���
	delim: �ַ����ָ���������Ϊ':', '-'��,��: xx:xx:xx:xx:xx:xx
			����ַ����޷ָ�����delim��Ϊ-1.
	mac:   �洢MAC��ַ������(ָ��),���Ϊ������,
		   ������MAC��ַΪ11:22:33:44:55:66,��mac[0]Ϊ0x11,mac[5]Ϊ0x66.
����ֵ:
	0: ����
	-1:����
*/
int MESA_mac_pton(const char *str, int delim, char *mac)
{
#define MAC_STR_LEN_DELIM		(17) /* length of "11:22:33:44:55:66" */
#define MAC_STR_LEN_NODELIM		(12) /* length of "112233445566" */
	const char *s = str;
	int i; 

	/* �������Ϸ��� */
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

	/* �������Ϸ��ԣ�ͬʱת����16����ֵ */
	for(i = 0; i < 6; i++)
	{
		mac[i] = 0; /* �����㣬��ֵ��䶼�ǻ���� */
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

static inline unsigned short from32to16(unsigned int x)
{
	/* add up 16-bit and 16-bit for 16+c bit */
	x = (x & 0xffff) + (x >> 16);
	/* add up carry.. */
	x = (x & 0xffff) + (x >> 16);
	return x;
}

static unsigned int do_csum(const unsigned char *buff, int len)
{
	int odd;
	unsigned int result = 0;

	if (len <= 0)
		goto out;
	odd = 1 & (unsigned long) buff;
	if (odd) {
#ifdef __LITTLE_ENDIAN
		result += (*buff << 8);
#else
		result = *buff;
#endif
		len--;
		buff++;
	}
	if (len >= 2) {
		if (2 & (unsigned long) buff) {
			result += *(unsigned short *) buff;
			len -= 2;
			buff += 2;
		}
		if (len >= 4) {
			const unsigned char *end = buff + ((unsigned)len & ~3);
			unsigned int carry = 0;
			do {
				unsigned int w = *(unsigned int *) buff;
				buff += 4;
				result += carry;
				result += w;
				carry = (w > result);
			} while (buff < end);
			result += carry;
			result = (result & 0xffff) + (result >> 16);
		}
		if (len & 2) {
			result += *(unsigned short *) buff;
			buff += 2;
		}
	}
	if (len & 1)
#ifdef __LITTLE_ENDIAN
		result += *buff;
#else
		result += (*buff << 8);
#endif
	result = from32to16(result);
	if (odd)
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
	return result;
}

static inline int sendpacket_in_cksum(const unsigned char *addr, size_t len)
{
	return do_csum(addr, len);
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

    if(4 == iph_p->ip_v)  /* IP�汾���ֶΣ�IPv4��IPv6��ʽ����ͬ�� */
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
                sum = sendpacket_in_cksum((const unsigned char *)&ip6h_p->ip6_src, 32);
            }
            else
            {
                sum = sendpacket_in_cksum((const unsigned char *)&iph_p->ip_src, 8);
            }    
            sum += ntohs(IPPROTO_TCP + len);
            sum += sendpacket_in_cksum((const unsigned char *)tcph_p, len);
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
                sum = sendpacket_in_cksum((const unsigned char *)&ip6h_p->ip6_src, 32);
            }
            else
            {
                sum = sendpacket_in_cksum((const unsigned char *)&iph_p->ip_src, 8);
            }   
            sum += ntohs(IPPROTO_UDP + len);
            sum += sendpacket_in_cksum((const unsigned char *)udph_p, len);
            udph_p->uh_sum = SENDPACKET_CKSUM_CARRY(sum);
            break;
        }
        
        case IPPROTO_IP: /* Dummy protocol for TCP.  */
        {
            iph_p->ip_sum = 0;
            sum = sendpacket_in_cksum((const unsigned char *)iph_p, len);
            iph_p->ip_sum = SENDPACKET_CKSUM_CARRY(sum);
            break;
        }

        case IPPROTO_ICMP:
        {
            struct mesa_icmp_hdr *icmph_p =
                (struct mesa_icmp_hdr *)(buf + ip_hl);

            icmph_p->icmp_sum = 0;
            sum = sendpacket_in_cksum((const unsigned char *)icmph_p, len);
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
	ip_hdr->ip_src.s_addr = src; /* Ϊʲô��ַ��������? ��ʷ����ԭ��, �Ķ�̫��,ֻ����ô������ */
	ip_hdr->ip_dst.s_addr = dst; /* Ϊʲô��ַ��������? ��ʷ����ԭ��, �Ķ�̫��,ֻ����ô������ */
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


/* TODO 2: ����չͷ����IPv6�� */
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

/* 2012-04-10 LiJia add, ���ڹ���ICMP-ECHO-REQUEST, ICMP-ECHO-REPLAY�� */
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
	��Ƕ�ס�����ģʽ�¹������ݰ�, û��payload, ��ʵ�ʻ����ϲ�Э��, ��teredo, ��Э��ʱʹ��.
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
		/* �����ǿ��Ҫ��ǶԳƵ�ַ, �������û�е�ַ, ��ʹ�öԲ��ַ��Ϣ */
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
		/* �����ǿ��Ҫ��ǶԳƵ�ַ, �������û��, ��ʹ�öԲ��ַ��Ϣ */
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
	    �ݲ�֧�ִ���ŵ�GTP����, 
		һ��GTP�������ܳ��ض���ڲ���Ԫ��, ���ڲ��Ԫ���������һ���ֵ�ͬһ���߳���, 
		��ô��֤����ڲ�TCP/UDP����֮���GTP���ͬ��??
	    ̫������!  
	    TODO��!!
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
		/* ���GTP�����˷ǶԳƱ��, ���뱣֤��ǰע�뷽��֮ǰ���������ݰ� */
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
		/* ��ǿ��GTP��ַ�ǶԳ�, sapp�����϶��ǿ��Ե�, ���ǿ��ܶԶ˲����� */
	}
	
	return hdr_len;
}

extern int calc_l2tp_hdr_len(struct streaminfo_private * stream_pr, UCHAR send_stream_dir);
/*
	1-�������а�ͷ�ĳ���, ����Ԥ���ռ�. ���㵽��ײ�Э��, �����MACҲ����MACͷ�ռ�;
	2-�ݹ�����л�ȡEthernet����ص�Э������.

	2020-09-25 lijia add args send_stream_dir, 
	send_stream_dir: ��MPLSЭ��ֻ�е����ַ, ���ܲ������ǷǶԳƵ�, ��Ҫ֪����������, ����ȷ��Ԥ��ͷ������. 
*/
static int calc_reserved_hdr_len(struct streaminfo *stream, int *net_layer_type, UCHAR send_stream_dir)
{
	int  reserved_hdr_len = 0;
    struct streaminfo_private *stream_pr = (struct streaminfo_private *)stream;
    int pfather_hdr_len;

	if(NULL == stream){ /* �ݹ�����ս�����! */
		return 0;
	}
    
	if(is_proxy_stream(stream)){ /* �������ṹΪ����ṹ, ʵ�ʹ����ʱ���������� */
		return calc_reserved_hdr_len((struct streaminfo *)stream->pfather, net_layer_type, send_stream_dir);
	}
	
	switch(stream->addr.addrtype){
		case ADDR_TYPE_IPV4:
			/* 2015-12-30 lijia modify, IP�Ͷ˿�ͬʱ�洢�ڴ˽ṹ */
			if(STREAM_TYPE_TCP == stream->type){
				reserved_hdr_len = sizeof(struct mesa_tcp_hdr) + sizeof(struct mesa_ip4_hdr);
			}else if (STREAM_TYPE_UDP == stream->type){
				reserved_hdr_len = sizeof(struct mesa_udp_hdr) + sizeof(struct mesa_ip4_hdr);
			}else{
				//printf("addr type is tuple4v4, but stream type is not TCP or UDP!\n");
				sapp_runtime_log(RLOG_LV_FATAL, "calc_reserved_hdr_len(): addr type is tuple4v4, but stream type is :%d, not TCP or UDP.", stream->type);		
				return -1;
				//assert(0);
			}
		break;
		
		case ADDR_TYPE_IPV6:
			/* 2015-12-30 lijia modify, IP�Ͷ˿�ͬʱ�洢�ڴ˽ṹ */
			if(STREAM_TYPE_TCP == stream->type){
				reserved_hdr_len = sizeof(struct mesa_tcp_hdr) + sizeof(struct mesa_ip6_hdr);;
			}else if (STREAM_TYPE_UDP == stream->type){
				reserved_hdr_len = sizeof(struct mesa_udp_hdr) + sizeof(struct mesa_ip6_hdr);;
			}else{
				//printf("addr type is tuple4v6, but stream type is not TCP or UDP!\n");
				sapp_runtime_log(RLOG_LV_FATAL, "calc_reserved_hdr_len(): addr type is tuple4v6, but stream type is :%d, not TCP or UDP.", stream->type);		
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
			sapp_runtime_log(RLOG_LV_INFO, "calc_reserved_hdr_len(): Sendpacket use ARP.");		
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
			/* to do, ������ʹ�ѡ��İ�, ���Һ�ԭʼ����һ���Ļ�, ��ô����? 
				��Ԥ����󳤶�, Ȼ�����ʵ��ѡ���, ��memmove�ƶ��ѹ���ĸ���.
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
			/* to do, ��������ѡ��İ�, ��ô����? */
			reserved_hdr_len = sizeof(struct mesa_ip4_hdr);
		break;
		
		case __ADDR_TYPE_IP_PAIR_V6:
			/* to do, ��������ѡ��İ�, ��ô����? */
			reserved_hdr_len = sizeof(struct mesa_ip6_hdr);
		break;

		case ADDR_TYPE_PPP:
			assert(0); /* ���ٵ�����PPP��, ��L2TP, PPTP��Ϊһ�� */
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
			sapp_runtime_log(RLOG_LV_FATAL, "calc_reserved_hdr_len(): Not support addrtype:%d\n", stream->addr.addrtype);
			reserved_hdr_len = -1;
			break;
	}

	if(reserved_hdr_len < 0){
		sapp_runtime_log(RLOG_LV_FATAL, "calc_reserved_hdr_len() < 0 stream_type:%d, addrtype:%d\n", stream->type, stream->addr.addrtype);	
		return -1;
	}


	if(CAP_LEVEL_MAC == g_packet_io_cap_level) {
		if(stream_pr->pfather_pr 
		 && ((ADDR_TYPE_MAC_IN_MAC == stream_pr->pfather_pr->stream_public.addr.addrtype) || (ADDR_TYPE_MAC == stream_pr->pfather_pr->stream_public.addr.addrtype))){
			/* ��¼MAC��֮�ϵ�Э���ַ����, �������Ethernet->type�ֶ�, ����MAC-in-MAC��inner_eth, ��¼�ϲ�Э������ */
			*net_layer_type = (int)stream->addr.addrtype;
		}
	}else{
		/* to do:
			����������Զ�������ethernet��, ����������vlan�Ȳ���һ�Ҫ������ô��?
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
	
	pfather_hdr_len = calc_reserved_hdr_len((struct streaminfo *)stream_pr->pfather_pr, net_layer_type, send_stream_dir);
	if(pfather_hdr_len < 0){
		sapp_runtime_log(RLOG_LV_FATAL, "pfather_hdr_len < 0 stream_type:%d, addrtype:%d\n", stream->type, stream->addr.addrtype);	
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
	   ע��˴�����ʹ��ԭʼ���еĵ�ַ, ��Ϊ�漰�������ַ���Գ�, ����ip��ַ�Ͷ˿�, �ߵ�src��dst����,
	   ���C2S��S2C�����ֱ�����������·, C2S��S2C�����macȫ����һ��, һ�������ĸ�MAC��ַ, ����������!
	   ����Ƿ��򷢰�, ��ʹ�ߵ�src, dstҲ�Ǵ����!!
	*/
	const struct layer_addr_mac *in_stream_addr;
	in_stream_addr = (struct layer_addr_mac *)(stream_pr->stream_public.addr.mac);
	struct mesa_ethernet_hdr *send_hdr = (struct mesa_ethernet_hdr *)buf;

	send_hdr->ether_type = htons(eth_type_host);

	/* ����ģʽ��,��ײ����蹹��ethernet��ַ,
	   ����inject_pkt_mode��ʲôģʽ, sys_route����raw_ethernet_single_gateway�ȵ�, �����macʵ�ʶ�����ԭʼ���е�mac��ַ,
	   ��ʱҲ�����������ļ�etc/asymmetric_addr_layer.conf��ethernet[0]�Ƿ���, �Ӷ����µ������ķ��򷢰���Ч.
	*/
	if((NULL == stream_pr->pfather_pr)  
	 && (DEPLOYMENT_MODE_MIRROR == sapp_global_val->config.packet_io.deployment_mode_bin)){
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
			sapp_runtime_log(RLOG_LV_INFO, "build_net_layer_ethernet() error! ethernet[%d] asymmetric_addr_layer is enabled, but has not recv this dir packet!\n", stream_pr->layer_index);
			return -1;
		}
		if(DIR_C2S == send_stream_dir){
			memcpy(send_hdr->ether_shost, in_stream_addr->src_addr.h_source, ETHER_ADDR_LEN); /* ��ַͬ��copy */
			memcpy(send_hdr->ether_dhost, in_stream_addr->src_addr.h_dest, ETHER_ADDR_LEN);
		}else{
			memcpy(send_hdr->ether_shost, in_stream_addr->dst_addr.h_source, ETHER_ADDR_LEN); /* ��ַͬ��copy */
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
	if(raw_pkt->raw_pkt_len < (int)(stream_pr->offset_to_raw_pkt_hdr + stream_pr->offset_to_ip_hdr + sizeof(struct mesa_tcp_hdr)))
	{
		return -1;
	}
	raw_tcp_hdr = (struct mesa_tcp_hdr *)(stream_pr->offset_to_raw_pkt_hdr + stream_pr->offset_to_ip_hdr + (char *)raw_pkt->raw_pkt_data);

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
	&& (g_overlay_layer_set[ADDR_TYPE_UDP][stream_pr->layer_index] == 0)){ /* vxlan��overlay�㲻��ת�˿� */
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
	
	/* PPPOE�޷�����, ��ԭʼ����copy���� */
	(void)reverse;
	memcpy(send_hdr, raw_hdr, sizeof(struct mesa_pppoe_session_hdr));

	/* lijia comment:
		�˴�Ϊ��Ҫ��sizeof(send_hdr->ppp_protocol)?
		��ΪPPPOE_SES��ͷ�����ǲ���PPPЭ�������ֶε�, ��Ϊ�˷��㴦��, ������2��1��.
	*/
	send_hdr->len = htons(carry_layer_len + sizeof(send_hdr->ppp_protocol));

	return sizeof(struct mesa_pppoe_session_hdr);
}

/* �����紫��ĵ�ַת��Ϊ�ڴ�ṹ, ����ҵ�������� */
int vlan_addr_net_to_mem(const struct mesa_vlan_detail_hdr *net_vlan_hdr, struct single_layer_vlan_addr *mem_vlan_hdr)
{
	mem_vlan_hdr->VID = htons(net_vlan_hdr->vlan_id_high << 8 | net_vlan_hdr->vlan_id_low);
	mem_vlan_hdr->TPID = net_vlan_hdr->type;
	mem_vlan_hdr->PCP = net_vlan_hdr->priority;
	mem_vlan_hdr->DEI = net_vlan_hdr->del_flag;

	return 0;
}

/* ���ڴ��ַ�ṹת��ΪRFC��׼ͷ����ʽ, ���͵������� */
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
			/* ����û�е�ַ, ȡ���������ļ�asymmetric_addr_layer�Ƿ�����öԲ��ַ */
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
			/* ����û�е�ַ, ȡ���������ļ�asymmetric_addr_layer�Ƿ�����öԲ��ַ */
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

	memcpy(send_ext_value, &payload_len, sizeof(short)); /* GREv1 �ض���length�ֶ� */
	send_ext_value += sizeof(short);	

	memcpy(send_ext_value, &send_call_id, sizeof(short)); /* GREv1 �ض���callid�ֶ� */
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
	/* NOTE: BUGFIX, ��ǰ����curdir���ܲ�û������, ��Ϊֻ��TCP��������curdir, ���Բ���ȡ��������curdirֵ */
	UCHAR curdir = stream_pr->stream_public.curdir;
#endif
	UINT16 send_call_id;

	raw_hdr = (const struct mesa_gre_hdr *)(stream_pr->offset_to_raw_pkt_hdr + (char *)raw_pkt->raw_pkt_data);
	gre_hdr_len = set_gre_hdr(&stack_hdr, (const void *)raw_hdr);
	if(gre_hdr_len < 0){
		return -1;
	}
	
	if((reverse != 0) && (top_stream->dir != DIR_DOUBLE)){
	    	/* ������û���յ�����, �������޷���� */
	    	sapp_runtime_log(20, "in gre layer, send dir is reverse, but haven't get opposite single stream info!\n");
		return -1;
	}

	if(0 == reverse){
		if(stack_hdr.gre_extend.call_id == raw_pptp_addr->C2S_call_id){
			/* ͬ�򷢰�, �͵�ǰ����һ�� */
			send_call_id = raw_pptp_addr->C2S_call_id;
		}else{
			send_call_id = raw_pptp_addr->S2C_call_id;
		}
	}else{
		/* ���򷢰�, ʹ�öԶ˵�callid */
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

/* �����紫��ĵ�ַת��Ϊ�ڴ�ṹ, ����ҵ�������� */
int mpls_addr_net_to_mem(const struct mesa_mpls_hdr *net_mpls_hdr, struct single_layer_mpls_addr *mem_mpls_hdr)
{
	memset(mem_mpls_hdr, 0, sizeof(struct single_layer_mpls_addr));

	mem_mpls_hdr->label = htonl( (net_mpls_hdr->mpls_label_low<<12) | (net_mpls_hdr->mpls_label_mid<<4) | net_mpls_hdr->mpls_label_high ); /* network order */
	mem_mpls_hdr->experimental = net_mpls_hdr->mpls_exp;
	mem_mpls_hdr->bottom = net_mpls_hdr->mpls_bls;
	mem_mpls_hdr->ttl = net_mpls_hdr->mpls_ttl;

	return 0;
}

/* ���ڴ��ַ�ṹת��ΪRFC��׼ͷ����ʽ, ���͵������� */
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
			/* ����û�е�ַ, ȡ���������ļ�asymmetric_addr_layer�Ƿ�����öԲ��ַ */
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
			/* ����û�е�ַ, ȡ���������ļ�asymmetric_addr_layer�Ƿ�����öԲ��ַ */
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
	struct gtp_hdr *gtp_send_hdr;
	int gtp_net_layer_len = sizeof(struct gtp_hdr);
	const struct layer_addr_gtp *p_gtp_layer_addr = stream_pr->stream_public.addr.gtp;
	unsigned int this_pkt_teid;
	
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

	gtp_send_hdr->flags = 0x30; /* ��ʱֻ֧��v1�汾, ����seq */
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

	/* PPP�޷�����, ��ԭʼ����copy���� */
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
			/* ����û�е�ַ, ȡ���������ļ�asymmetric_addr_layer�Ƿ�����öԲ��ַ */
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
			/* ����û�е�ַ, ȡ���������ļ�asymmetric_addr_layer�Ƿ�����öԲ��ַ */
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
		TODO: ppp, hdlc��Ҳ��c2s, s2c��������洢.
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
			L2TP��c2s��s2c����TUNNEL-ID��һ��, Ŀǰû���γ�L2TP��, �޷�������һ���������Ϣ ,
			����, ��֧�ֵ���������ע�����ݰ�.
		*/
		sapp_runtime_log(RLOG_LV_INFO, "build_net_layer_l2tp() error, not support inject reverse pkt for single dir stream!");
		return -1;
	}

	memset(buf, 0, l2tp_raw_hdr_len);
	
	inject_net_hdr = (struct l2tp_hdr_v2 *)buf;
	inject_ptr = buf + sizeof(struct l2tp_hdr_v2); /* ָ��̶�ͷ������Ļ����� */
	
	inject_net_hdr->type = 0; /* Ŀǰ��֧��ע��data message */
	inject_net_hdr->offset_present = 0;
	inject_net_hdr->priority = 0;
	inject_net_hdr->seq_present = 0; 
	inject_net_hdr->version = 2; /* Ŀǰ�̶�֧��v2 */

	/* 
		ע��l2tp���ݰ��̶�����length�ֶ�
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
    �˺����ڲ��������ж��Ƿ���Ҫ����bloom filter, �ں����ⲿ�Ѿ��ж�.
*/



extern int sapp_is_overlay_layer(const struct streaminfo_private *stream_pr, const raw_pkt_t *rawpkt);
/* 
	buf: ִ��Ӧ�ò㸺�ص�ַ, skip hdr.
	reverse: ��Ӧ�ò�ĽǶ�����dir, ��ʾ�뵱ǰraw_pkt�����, �����Ƿ�һ��, �����з����Եĵ�ַ, �跴�����.

	2020-09-25 lijia add args send_stream_dir:
	send_stream_dir: ��ʾ��ǰ������������, DIR_C2S����DIR_S2C, 
	                 ��ΪMPLS, GTP�Ȳ�ԭʼ����ֻ�е����ַ, reverse�ĺ��岻�ܾ�ȷ��ʾmpls, gtp�Ȳ㵽��ʹ���ĸ�����ĵ�ַ.
	top_stream: ���ϲ�����ṹ��, ͨ����tcp��udp��, ��ֵ���к���ջ�б��ֲ���.                 
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

	if((stream->addr.pktipfragtype&PKT_TYPE_IP_FRAG_LAST)!=0 || (stream->addr.pktipfragtype&PKT_TYPE_IP_FRAG)!=0)
	{
		sapp_runtime_log(RLOG_LV_INFO, "build_net_layer_vlan() error, send streamdir:%d, fragment packet, type:%c!\n", send_stream_dir, stream->addr.pktipfragtype);
		return -1;
	}

	if(is_proxy_stream(stream)){ /* �������ṹΪ����ṹ, ʵ�ʵİ������ڴ˲�, �����ʱ���������� */
		return build_net_layer_pkt(top_stream, carry_layer_stream, (struct streaminfo_private *)stream->pfather, carry_layer_type, 
								this_layer_len+carry_layer_len, buf, reverse, raw_pkt, send_stream_dir);
	}

	switch(stream->addr.addrtype){
		case ADDR_TYPE_IPV4:
		{
			/* 2015-12-30 lijia modify, IP�Ͷ˿ڴ洢��һ���ṹ, �ȹ���TCP/UDP�� */
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

			/* 2015-12-30 lijia modify, IP�Ͷ˿ڴ洢��һ���ṹ, ��������IPv4�� */
			this_layer_len += sizeof(struct mesa_ip4_hdr) + transport_layer_len;
			buf -= sizeof(struct mesa_ip4_hdr);
			build_net_layer_ipv4(stream_pr, carry_layer_type, carry_layer_len + transport_layer_len, buf, reverse, raw_pkt);
			
			/* TCP��У�����ҪIP��ַ��Ϣ, ����Ҫ�ڹ�����IP����Ϣ��, �ټ���checksum */
			checksum_for_carry_layer(buf, __ADDR_TYPE_IP_PAIR_V4, carry_layer_type, carry_layer_len+transport_layer_len);
			carry_layer_type = __ADDR_TYPE_IP_PAIR_V4;
			const struct mesa_ip4_hdr *ip4hdr = (struct mesa_ip4_hdr *)buf;
			sapp_runtime_log(RLOG_LV_DEBUG, "build_net_layer_pkt()->IPV4, %s, send_stream_dir:%d, ipid:%u, ip_checksum:0x%x", 
							sapp_raw_ipv4_ntop(ip4hdr, debug_print_buf, sizeof(debug_print_buf)), send_stream_dir,
							ntohs(ip4hdr->ip_id), ntohs(ip4hdr->ip_sum));

			/* �ظ�����ע���ʶ��, �ӵ���������Ϊ���������, ���ܻ��ж��, �Ҳ����پ���jump_layer��ת���ڲ�udp/tcp���� 
               vxlanģʽ�ײ�udpû��ҪƵ������bloom filter, �ȵ���sapp_is_overlay_layer()ʶ��һ��.
			*/
			if((sapp_global_val->config.packet_io.dup_pkt_para.dup_pkt_distinguish_all_inject != 0)
			 && (sapp_is_overlay_layer(stream_pr, raw_pkt) == 0)){
				sapp_dup_pkt_mark_l4((struct streaminfo *)top_stream, (const void *)buf, (const char *)buf+sizeof(struct mesa_ip4_hdr));
			}
		}	
		break;
		
		case ADDR_TYPE_IPV6:
			/* 2015-12-30 lijia modify, IP�Ͷ˿ڴ洢��һ���ṹ, �ȹ���TCP/UDP�� */
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

			/* 2015-12-30 lijia modify, IP�Ͷ˿ڴ洢��һ���ṹ, ��������IPv6�� */
			this_layer_len += sizeof(struct mesa_ip6_hdr) + transport_layer_len;
			buf -= sizeof(struct mesa_ip6_hdr);
			build_net_layer_ipv6(stream_pr, carry_layer_type, carry_layer_len + transport_layer_len, buf, reverse, raw_pkt);
			
			/* TCP��У�����ҪIP��ַ��Ϣ, ����Ҫ�ڹ�����IP����Ϣ��, �ټ���checksum */
			checksum_for_carry_layer(buf, __ADDR_TYPE_IP_PAIR_V6, carry_layer_type, carry_layer_len+transport_layer_len);
			carry_layer_type = __ADDR_TYPE_IP_PAIR_V6;

			/* �ظ�����ʶ��, �ӵ���������Ϊ���������, ���ܻ��ж��, �Ҳ����پ���jump_layer��ת���ڲ�udp/tcp���� */
			if(sapp_global_val->config.packet_io.dup_pkt_para.dup_pkt_distinguish_all_inject != 0){
				sapp_dup_pkt_mark_l4((struct streaminfo *)top_stream, (const void *)buf, (const char *)buf+sizeof(struct mesa_ip6_hdr));
			}			
		break;
		
		case __ADDR_TYPE_IP_PAIR_V4:
			/* to do, ��������ѡ��İ�, ��ô����? */
			this_layer_len = sizeof(struct mesa_ip4_hdr);
			buf -= sizeof(struct mesa_ip4_hdr);
			build_net_layer_ipv4(stream_pr, carry_layer_type, carry_layer_len, buf, reverse, raw_pkt);
			
			/* TCP��У�����ҪIP��ַ��Ϣ, ����Ҫ�ڹ�����IP����Ϣ��, �ټ���checksum */
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
					/* ���÷����ַ, ���¼��㳤��, ����vlan��ַ */
					this_layer_len = calc_vlan_hdr_len(stream_pr, send_stream_dir ^ DIR_DOUBLE);
					buf -= this_layer_len;
					ret = build_net_layer_vlan(stream_pr, carry_layer_type, carry_layer_len, buf, send_stream_dir ^ DIR_DOUBLE, raw_pkt);
					if(ret < 0){
						sapp_runtime_log(RLOG_LV_INFO, "%s, build_net_layer_vlan() error!\n", printaddr(&top_stream->addr, stream->threadnum));
						return -1;
					}	
					carry_layer_type = ADDR_TYPE_VLAN;					
					sapp_runtime_log(RLOG_LV_INFO, "build_net_layer_vlan() build vlan layer, but no addr of dir:%d, use opposite_addr.\n", send_stream_dir);
				}else{
					sapp_runtime_log(RLOG_LV_INFO, "build_net_layer_vlan() error, send streamdir:%d, layer len is 0, but create_vlan_anyway is disable!\n", send_stream_dir);
					return -1;
				}
			}else{
				buf -= this_layer_len;
				ret = build_net_layer_vlan(stream_pr, carry_layer_type, carry_layer_len, buf, send_stream_dir, raw_pkt);
				if(ret < 0){
					sapp_runtime_log(RLOG_LV_INFO, "%s,build_net_layer_vlan() error!\n", printaddr(&top_stream->addr, stream->threadnum));
					return -1;
				}					
				carry_layer_type = ADDR_TYPE_VLAN;
			}
		break;

		case ADDR_TYPE_MAC:
		{
			buf -= sizeof(struct mesa_ethernet_hdr); 
			/* ����ǲ���ģʽ, �˴����Բ�����mac��ַ, ����֪packet_io_send_fake_pkt�����ײ�����, MAC����MAC_IN_MAC 
				����ģʽ��Ҫ���ݵ�ǰԭʼ��, ��send_dir����mac��ַ.
			*/
			unsigned short eth_type_host = net_layer_to_ethernet_protocol_by_stream(up_stream);
			if((unsigned short)-1 == eth_type_host){
				sapp_runtime_log(RLOG_LV_INFO, "%s,build_net_layer_mac() error, unsupport carry_layer_type:0x%x!\n", printaddr(&stream->addr, stream->threadnum), carry_layer_type);
				return -1;
			}

			if(build_net_layer_ethernet(top_stream, stream_pr, eth_type_host, carry_layer_len, buf, send_stream_dir, raw_pkt) < 0){
				sapp_runtime_log(RLOG_LV_INFO, "%s, build_net_layer_mac() error!", printaddr(&stream->addr, stream->threadnum));
				return -1;
			}

			this_layer_len = sizeof(struct mesa_ethernet_hdr);
			carry_layer_type = ADDR_TYPE_MAC;
			//ethernet��һ�������һ��, ��Ϊ��MAC-in-MAC, �������ݹ�������ж�NULL == fstream_pr����.
			//return carry_layer_len;
			//sapp_runtime_log(RLOG_LV_DEBUG, "build_net_layer_pkt()-->ADDR_TYPE_MAC, buf start addr:%p, this_layer_len:%d\n", buf, this_layer_len);
		}
		break;

		/* TODO 2: GRE v1��callid, �ֱ�洢��C2S, S2C������������ݰ�, ����˫��RST��Ҫ��¼��һ�����ֵ */
		case ADDR_TYPE_GRE:
			this_layer_len = calc_gre_hdr_len(
						 (const struct mesa_gre_hdr *)((const char *)stream_pr->raw_pkt->raw_pkt_data + stream_pr->offset_to_raw_pkt_hdr));
			buf -= this_layer_len;
		ret = build_net_layer_gre(top_stream, stream_pr, carry_layer_type, carry_layer_len, buf, reverse, raw_pkt);
			if(ret < 0){
				sapp_runtime_log(RLOG_LV_INFO, "%s, build_net_layer_gre() error!\n", printaddr(&top_stream->addr, stream->threadnum));
				return -1;
			}
			carry_layer_type = ADDR_TYPE_GRE;
		break;

		case ADDR_TYPE_MPLS:
		{
			this_layer_len = calc_mpls_hdr_len(stream_pr, send_stream_dir);
			if(0 == this_layer_len){
				/* �ǶԳ�MPLS, Ϊ�����������������һ��, ������ʵ�ʰ�ͷ */
				sapp_runtime_log(RLOG_LV_DEBUG, "%s, build_net_layer_mpls() send streamdir:%d, skip fake mpls layer.\n", printaddr(&stream->addr, stream->threadnum), send_stream_dir);
				carry_layer_stream = up_stream;
				break;
			}else{
				buf -= this_layer_len;
				ret = build_net_layer_mpls(stream_pr, carry_layer_type, carry_layer_len, buf, send_stream_dir, raw_pkt);
				if(ret < 0){
					sapp_runtime_log(RLOG_LV_INFO, "%s, build_net_layer_mpls() error!\n", printaddr(&top_stream->addr, stream->threadnum));
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
				sapp_runtime_log(RLOG_LV_INFO, "%s, calc_gtp_hdr_len() error!\n", printaddr(&top_stream->addr, stream->threadnum));
				return -1;
			}	
			buf -= this_layer_len;
			ret = build_net_layer_gtp(stream_pr, carry_layer_type, carry_layer_len, buf, send_stream_dir, raw_pkt);
			if(ret < 0){
				sapp_runtime_log(RLOG_LV_INFO, "%s, build_net_layer_gtp() error!\n", printaddr(&top_stream->addr, stream->threadnum));
				return -1;
			}
			carry_layer_type = ADDR_TYPE_GPRS_TUNNEL;

			break;

		case ADDR_TYPE_PPPOE_SES:
			this_layer_len = sizeof(struct mesa_pppoe_session_hdr);
			buf -= sizeof(struct mesa_pppoe_session_hdr);
			build_net_layer_pppoe_ses(stream_pr, carry_layer_type, carry_layer_len, buf, reverse, raw_pkt);
			carry_layer_type = ADDR_TYPE_PPPOE_SES;
		break;
	
		case ADDR_TYPE_TCP:
			/* to do, ��������ѡ��İ�, ��ô����? */
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
				sapp_runtime_log(RLOG_LV_INFO, "%s, calc_l2tp_hdr_len() error!\n", printaddr(&top_stream->addr, top_stream->threadnum));
				return -1;
			}
			buf -= this_layer_len;
			ret = build_net_layer_l2tp(top_stream, stream_pr, carry_layer_type, carry_layer_len, buf, send_stream_dir, raw_pkt, this_layer_len);
			if(ret < 0){
				sapp_runtime_log(RLOG_LV_INFO, "%s, build_net_layer_l2tp() error!\n", printaddr(&top_stream->addr, top_stream->threadnum));
				return -1;
			}
			carry_layer_type = ADDR_TYPE_L2TP;
		break;

		case ADDR_TYPE_PPP:
			assert(0); /* PPTP������gre��ppp�ϲ�Ϊһ��, ���벻����ִ�е��˴� */
		break;
		
		case ADDR_TYPE_PPTP:
		{
			int gre_layer_len;
			int ppp_hdr_len;

			gre_layer_len = calc_gre_hdr_len(
						 (const struct mesa_gre_hdr *)((const char *)stream_pr->raw_pkt->raw_pkt_data + stream_pr->offset_to_raw_pkt_hdr));
			if(gre_layer_len < 0){
				sapp_runtime_log(RLOG_LV_INFO, "%s, pptp calc_gre_hdr_len() error!\n", printaddr(&top_stream->addr, stream->threadnum));
				return -1;
			}						 
			ppp_hdr_len = stream_pr->cur_layer_raw_hdr_len - gre_layer_len;
			if(ppp_hdr_len < 1){
				return -1;
			}

			buf -= ppp_hdr_len;
			build_net_layer_ppp(stream_pr, carry_layer_type, carry_layer_len, buf, reverse, raw_pkt, ppp_hdr_len);	
			
			/* ֱ��copy pppͷ������ */
			memcpy(buf, (char *)raw_pkt->raw_pkt_data + stream_pr->offset_to_raw_pkt_hdr + gre_layer_len, ppp_hdr_len);
			
			buf -= gre_layer_len;
			ret = build_net_layer_gre(top_stream, stream_pr, ADDR_TYPE_PPP, carry_layer_len, buf, reverse, raw_pkt);
			if(ret < 0){ 
				sapp_runtime_log(RLOG_LV_INFO, "%s, pptp build_net_layer_gre() error!\n", printaddr(&top_stream->addr, stream->threadnum));
				return -1;
			}
			carry_layer_type = ADDR_TYPE_GRE;
			this_layer_len = gre_layer_len + ppp_hdr_len;
		}	
		break;
		case ADDR_TYPE_VXLAN:
		{
			const struct layer_addr_vxlan_private *vxaddr_pr = (struct layer_addr_vxlan_private *)stream_pr->stream_public.addr.paddr;
			buf -= vxaddr_pr->actual_total_len;
			this_layer_len = vxaddr_pr->actual_total_len;
			ret = build_net_layer_vxlan(stream_pr, carry_layer_type, carry_layer_len, buf, send_stream_dir, raw_pkt, vxaddr_pr);
			if(ret < 0){ 
				sapp_runtime_log(RLOG_LV_INFO, "%s, build_net_layer_vxlan() error!\n", printaddr(&top_stream->addr, stream->threadnum));
				return -1;
			}
			carry_layer_type = ADDR_TYPE_VXLAN;		
		}
		break;
		
		default:
			sapp_runtime_log(RLOG_LV_INFO, "%s, build_net_layer_pkt(): unsupport addr type:%d!\n", printaddr(&stream->addr, stream->threadnum), stream->addr.addrtype);
			goto err;
			break;
	}

	return build_net_layer_pkt(top_stream, carry_layer_stream, (struct streaminfo_private *)stream_pr->pfather_pr,carry_layer_type, 
							this_layer_len+carry_layer_len, buf, reverse, raw_pkt, send_stream_dir);

err:
	return -1;
}

static raw_pkt_t *update_raw_pkt(struct streaminfo_private *stream_pr, uchar snd_dir, int *inject_dir_reverse)
{
    raw_pkt_t *inject_raw_pkt = NULL;

    if (stream_pr->plugin_process_context != 0)
    {
            /* �ڰ�����������, ����û�п���polling, do nothing */
            *inject_dir_reverse = ((snd_dir == stream_pr->stream_public.routedir) ? 0 : 1);
            inject_raw_pkt = (raw_pkt_t *)stream_pr->raw_pkt;
    }
    else if (stream_pr->polling_inject_context != NULL)
    {
		if(snd_dir == stream_pr->stream_c2s_route_dir) // if send dir is same as c2s route dir, return c2s raw_pkt
		{
				inject_raw_pkt = (raw_pkt_t *)stream_pr->polling_inject_context->raw_pkt_stream_dir[DIR_C2S-1];
				*inject_dir_reverse=0;
		}
		else
		{
				inject_raw_pkt = (raw_pkt_t *)stream_pr->polling_inject_context->raw_pkt_stream_dir[DIR_S2C-1];
				*inject_dir_reverse=1;
		}

#if 0		
            if ((DIR_ROUTE_DOWN & snd_dir) == DIR_ROUTE_DOWN)
            {
                inject_raw_pkt = (raw_pkt_t *)stream_pr->polling_inject_context->raw_pkt_down;
                if (inject_raw_pkt)
                {
                    *inject_dir_reverse = (((snd_dir & DIR_ROUTE_DOWN) == DIR_ROUTE_DOWN) ? 0 : 1);
                }
                else
                { /* ���˻�û�յ�����,ʹ�öԶ����ݰ����챾�˵İ�,����ĳЩ�ǶԳ�Э��,��GRE, MPLS��,��������!
                     reverse��Ҫ���� */
                    inject_raw_pkt = (raw_pkt_t *)stream_pr->polling_inject_context->raw_pkt_up;
                    *inject_dir_reverse = (((snd_dir & DIR_ROUTE_DOWN) == DIR_ROUTE_DOWN) ? 1 : 0);
                }
            }
            else
            {
                inject_raw_pkt = (raw_pkt_t *)stream_pr->polling_inject_context->raw_pkt_up;
                if (inject_raw_pkt)
                {
                    *inject_dir_reverse = (((snd_dir & DIR_ROUTE_DOWN) == DIR_ROUTE_DOWN) ? 1 : 0);
                }
                else
                { /* ���˻�û�յ�����,ʹ�öԶ����ݰ����챾�˵İ�,����ĳЩ�ǶԳ�Э��,��GRE, MPLS��,��������!
                     reverse��Ҫ���� */
                    inject_raw_pkt = (raw_pkt_t *)stream_pr->polling_inject_context->raw_pkt_down;
                    *inject_dir_reverse = (((snd_dir & DIR_ROUTE_DOWN) == DIR_ROUTE_DOWN) ? 0 : 1);
                }
            }
#endif			
    }
    else
            ;
    if ((NULL == inject_raw_pkt) || (RAW_PKT_MAGIC_NUM != inject_raw_pkt->magic_num))
    {
            return NULL;
    }

    if (stream_pr->polling_inject_context != NULL)
    {
		inject_raw_pkt->meta_route_dir[stream_pr->stream_c2s_route_dir]=stream_pr->polling_inject_context->meta_stream_dir[DIR_C2S-1];
        inject_raw_pkt->meta_route_dir[stream_pr->stream_c2s_route_dir^1]=stream_pr->polling_inject_context->meta_stream_dir[DIR_S2C-1];

#if 0
		if(snd_dir==stream_pr->stream_c2s_route_dir)
		{
			inject_raw_pkt->meta_route_dir[snd_dir]=stream_pr->polling_inject_context->meta_stream_dir[DIR_C2S-1];
			inject_raw_pkt->meta_route_dir[snd_dir^1]=stream_pr->polling_inject_context->meta_stream_dir[DIR_S2C-1];
		}
		else
		{
			inject_raw_pkt->meta_route_dir[snd_dir]=stream_pr->polling_inject_context->meta_stream_dir[DIR_S2C-1];
			inject_raw_pkt->meta_route_dir[snd_dir^1]=stream_pr->polling_inject_context->meta_stream_dir[DIR_C2S-1];

		}
#endif		
    }

    return inject_raw_pkt;
}


/*
	LiJia note, to do:
	�����Ϊ��������, 1,2,3,4,x,6, ��5��������, ��6����������,
	�����6��������������Ϣ, ��Ҫkill_tcp,
	����5��������ʱ, streaminfo��洢�Ķ��ǵ�5��������Ϣ,
	Ȼ���ٴ��������е�6����������, ��ʱ����kill_tcp, ��ز����ǲ��Ե�,
	ʵ�ʵ�seq��ackʹ�õ��ǵ�5������!
	Ӧ��ʹ��buf_unorder�е�seq��ack, �����ǵ�ǰ����ԭʼ��.
*/

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
	/* �˴������Ƿ�������, �������ҲҪ����, ĳ��������ɹ�Ҳ�ǿ��Բ���ʵ��Ч���� */
	rst_paras.dir = stream->curdir ^ DIR_DOUBLE;
	ret2 = MESA_rst_tcp(stream, &rst_paras, sizeof(struct rst_tcp_para));

	/* �����µı�־λ, kill_tcp�Զ�����, ���ֹ��ܸ�֮ǰһ�� */
	stream_pr->stream_killed_flag = 1;

	struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private*)(stream->pdetail);
	pdetail_pr->auto_remedy_flag = sapp_global_val->config.stream.tcp.inject.auto_remedy;
	pdetail_pr->drop_stream_flag = 1;

	if((ret1 < 0) && (ret2 < 0)){
		return -1;
	}
	
	return 0; 
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

	if (ADDR_TYPE_IPV4 == stream->addr.addrtype)
	{
		if (signature_seed1 && signature_seed2)
		{
			trick_algo_getrandval_with_seed(stream->threadnum,
											ip4_hdr->ip_src.s_addr,
											ip4_hdr->ip_dst.s_addr,
											&rst_finger->ip_id_host_order,
											&rst_finger->tcp_win_host_order,
											&rst_finger->ip_ttl,
											(int)signature_seed2,
											(int)signature_seed1);
		}
		else
		{
			if (sapp_global_val->config.stream.tcp.inject.rst_signature_enable != 0)
			{
				trick_algo_getrandval_with_seed(stream->threadnum,
												ip4_hdr->ip_src.s_addr,
												ip4_hdr->ip_dst.s_addr,
												&rst_finger->ip_id_host_order,
												&rst_finger->tcp_win_host_order,
												&rst_finger->ip_ttl,
												(int)sapp_global_val->config.stream.tcp.inject.rst_signature_seed2,
												(int)sapp_global_val->config.stream.tcp.inject.rst_signature_seed1);
			}
			else
			{
				goto use_rand_value;
			}
		}
	}
	else
	{
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
	int i, ret = -1;
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
				/* ʹ��SIO_EXCLUDE_THIS_LAYER_HDR����, ��Ҫ���м���У��� */
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
		/* ������˫�򷢰�, �������ﲻ��else if */
		if((DIR_DOUBLE == snd_rst_dir) || ((stream->curdir ^ snd_rst_dir) & 0x3) == DIR_DOUBLE){ /* ���򷢰� */	
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

	if(struct_para_len > (int)sizeof(struct rst_tcp_para)){
		sapp_runtime_log(RLOG_LV_INFO, "MESA_rst_tcp() warning: the caller version is newer than sapp, not support new paras!\n");
	}
	tmp_signature_seed1 = paras->signature_seed1;
	tmp_signature_seed2 = paras->signature_seed2;
	if((0 == tmp_signature_seed1) && (0 == tmp_signature_seed2)){
		if(0 != sapp_global_val->config.stream.tcp.inject.rst_signature_enable){
			tmp_signature_seed1 = sapp_global_val->config.stream.tcp.inject.rst_signature_seed1;
			tmp_signature_seed2 = sapp_global_val->config.stream.tcp.inject.rst_signature_seed2;
		}
	}
	return __MESA_rst_tcp((struct streaminfo *)stream, paras->th_flags, paras->rst_pkt_num, paras->dir, 
						tmp_signature_seed1, tmp_signature_seed2);
}

/* 2016-06-15 lijia add  */
inline int MESA_kill_tcp_remedy(struct streaminfo *stream, const void *ext_raw_pkt)
{
	return __MESA_rst_tcp(stream, (unsigned char)(TH_RST | TH_ACK), 1, (unsigned char)(stream->curdir ^ DIR_DOUBLE), 
						(unsigned short )sapp_global_val->config.stream.tcp.inject.rst_signature_seed1, 
						(unsigned short )sapp_global_val->config.stream.tcp.inject.rst_signature_seed2);
}


inline int MESA_inject_pkt(struct streaminfo *stream, const char *payload, int payload_len, 
						const void *ext_raw_pkt, UCHAR snd_routedir)
{
	return sapp_inject_pkt(stream, SIO_DEFAULT, payload, payload_len, snd_routedir);
}


/*
	TODO:
		���ж���һ���ǲ���asymmetric_presence_layer,
		Ȼ�����жϱ����ַ��û��.
*/
static int skip_asymmetric_presence_layer(const struct streaminfo *stream, UCHAR send_stream_dir)
{
	int need_skip = 0;
	const struct streaminfo_private *stream_pr = (struct streaminfo_private *)stream;
	
	switch(stream->addr.addrtype){
		case ADDR_TYPE_VLAN:
		{
			const struct layer_addr_vlan *vaddr = stream->addr.vlan;

			/* ��������������������ղ�, ���п����ǵ�����, ��Ҫ��ʵ����û�е�ַ */
			if(DIR_C2S == send_stream_dir){
				if(0 == vaddr->c2s_layer_num){
					/* �������û�е�ַ, ���Ƿ�ǿ��Ҫ��ǶԳ�ԭ��, �����, ��ʵ���߲�������,�����ʱ��ʧ����; ������ǿ��Ը��öԲ��ַ */
					if(g_asymmetric_addr_layer_set.layer_type_index[ADDR_TYPE_VLAN][stream_pr->layer_index] != 0){
						need_skip = 1;
					}
				}
			}else{
				if(0 == vaddr->s2c_layer_num){
					/* �������û�е�ַ, ���Ƿ�ǿ��Ҫ��ǶԳ�ԭ��, �����, ��ʵ���߲�������,�����ʱ��ʧ����; ������ǿ��Ը��öԲ��ַ */
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
					/* �������û�е�ַ, ���Ƿ�ǿ��Ҫ��ǶԳ�ԭ��, �����, ��ʵ���߲�������,�����ʱ��ʧ����; ������ǿ��Ը��öԲ��ַ */
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

    while (stream_pr && stream_pr->pfather_pr)
    {
        if (CAP_LEVEL_MAC == g_packet_io_cap_level)
        {
            if (stream_pr->pfather_pr &&
                ((ADDR_TYPE_MAC_IN_MAC == stream_pr->pfather_pr->stream_public.addr.addrtype) ||
                 (ADDR_TYPE_MAC == stream_pr->pfather_pr->stream_public.addr.addrtype)))
            {
                /* ��¼MAC��֮�ϵ�Э���ַ����, �������Ethernet->type�ֶ�, ����MAC-in-MAC��inner_eth, ��¼�ϲ�Э������
                 */
                ret = (int)stream->addr.addrtype;
            }
        }
        else
        {
            /* to do:
                ����������Զ�������ethernet��, ����������vlan�Ȳ���һ�Ҫ������ô��?
            */
        }

        stream_pr = stream_pr->pfather_pr;
        stream = &stream_pr->stream_public;
    }

    return ret;
}

int __sapp_inject_ctrl_pkt(struct streaminfo *stream, enum sapp_inject_opt sio, const void *payload, int payload_len, unsigned char snd_routedir)
{
	sapp_gval_mthread_sys_stat_t *local_sys_stat=&sapp_global_val->mthread_volatile[stream->threadnum]->sys_stat;
	if(dir_check(snd_routedir) < 0 || stream == NULL || payload == NULL || payload_len <=0){
		local_sys_stat->count[SAPP_STAT_SND_ERROR]++;
        sapp_runtime_log(RLOG_LV_FATAL, "__sapp_inject_ctrl_pkt() error, dir_check < 0 or payload_len illgel!");
		return -1;
	}
    struct streaminfo_private *raw_stream_pr = (struct streaminfo_private *)stream;
	//raw_pkt_t *raw_pkt = update_raw_pkt(raw_stream_pr, snd_routedir, &snd_routedir_reverse);
	raw_pkt_t *raw_pkt=(raw_pkt_t *)raw_stream_pr->raw_pkt;
	if(NULL == raw_pkt)
	{

        if (raw_stream_pr->polling_inject_context == NULL || 
		(raw_stream_pr->polling_inject_context->raw_pkt_stream_dir[DIR_C2S-1] == NULL &&
			raw_stream_pr->polling_inject_context->raw_pkt_stream_dir[DIR_S2C-1] == NULL))
        {
            local_sys_stat->count[SAPP_STAT_SND_ERROR]++;
            sapp_runtime_log(RLOG_LV_FATAL, "__sapp_inject_ctrl_pkt() error, not found raw_pkt!");
            return -1;
        }

		if(snd_routedir==raw_stream_pr->stream_c2s_route_dir)
		{
			if(raw_stream_pr->polling_inject_context->raw_pkt_stream_dir[DIR_C2S-1])
				raw_pkt=(raw_pkt_t *)raw_stream_pr->polling_inject_context->raw_pkt_stream_dir[DIR_C2S-1];
			else
			{
				raw_pkt=(raw_pkt_t *)raw_stream_pr->polling_inject_context->raw_pkt_stream_dir[DIR_S2C-1];
				snd_routedir^=1;
			}
		}
		else
		{
			if(raw_stream_pr->polling_inject_context->raw_pkt_stream_dir[DIR_S2C-1])
				raw_pkt=(raw_pkt_t *)raw_stream_pr->polling_inject_context->raw_pkt_stream_dir[DIR_S2C-1];
			else
			{
				raw_pkt=(raw_pkt_t *)raw_stream_pr->polling_inject_context->raw_pkt_stream_dir[DIR_C2S-1];
				snd_routedir^=1;
			};
		}
    }	
	raw_pkt->meta_route_dir[raw_stream_pr->stream_c2s_route_dir]=raw_stream_pr->polling_inject_context->meta_stream_dir[DIR_C2S-1];
    raw_pkt->meta_route_dir[raw_stream_pr->stream_c2s_route_dir^1]=raw_stream_pr->polling_inject_context->meta_stream_dir[DIR_S2C-1];
	
	if(raw_stream_pr->sid_prepend_list != NULL)
	{
		raw_pkt->prepend_list=raw_stream_pr->sid_prepend_list;
    }
	if(raw_stream_pr->sid_append_list != NULL)
	{
		raw_pkt->append_list=raw_stream_pr->sid_append_list;
    }
	if (raw_stream_pr->stream_trace_id != 0)
	{
		raw_pkt->stream_trace_id = raw_stream_pr->stream_trace_id;
	}

    int low_net_layer_type = get_eth_carry_layer_type(stream, stream->curdir);
	int raw_pkt_l2_l3_hdr_len=raw_pkt->offset_to_raw_pkt_hdr - raw_pkt->overlay_layer_bytes;
	int raw_pkt_l4_hdr_len=0;
	if(stream->type==STREAM_TYPE_TCP)
	{
		if(raw_pkt->raw_pkt_len < raw_pkt_l2_l3_hdr_len + (int)sizeof(struct mesa_tcp_hdr))
		{
			local_sys_stat->count[SAPP_STAT_SND_ERROR]++;
			sapp_runtime_log(RLOG_LV_FATAL, "__sapp_inject_ctrl_pkt() error! raw_pkt_len:%d < raw_pkt_l3_hdr_len:%d+tcphdr_len:d\n",
                        raw_pkt->raw_pkt_len, raw_pkt_l2_l3_hdr_len, (int)sizeof(struct mesa_tcp_hdr));
			return -1;
		}
		struct mesa_tcp_hdr *tcph = (struct mesa_tcp_hdr *)((char *)raw_pkt->raw_pkt_data + raw_pkt->offset_to_raw_pkt_hdr);
		raw_pkt_l4_hdr_len = tcph->th_off<<2;
	}
	else if(stream->type==STREAM_TYPE_UDP)
	{
		raw_pkt_l4_hdr_len = sizeof(struct mesa_udp_hdr);
	}
	else 
	{
		local_sys_stat->count[SAPP_STAT_SND_ERROR]++;
		sapp_runtime_log(RLOG_LV_FATAL, "__sapp_inject_ctrl_pkt() error! not support stream_type:%d.\n",
                        stream->type);
		return -1;
	}

	if(raw_pkt->overlay_layer_bytes + raw_pkt_l2_l3_hdr_len + raw_pkt_l4_hdr_len > raw_pkt->raw_pkt_len)
	{
		local_sys_stat->count[SAPP_STAT_SND_ERROR]++;
        sapp_runtime_log(RLOG_LV_FATAL, "__sapp_inject_ctrl_pkt() error! overlay_len:%d, l3_hdr_len:%d + l4_hdr_len:%d > raw_pkt_len:%d.\n",
                        raw_pkt->overlay_layer_bytes, raw_pkt_l2_l3_hdr_len, raw_pkt_l2_l3_hdr_len, raw_pkt->raw_pkt_len);
        return -1;
	}
    if (payload_len + raw_pkt_l2_l3_hdr_len + raw_pkt_l4_hdr_len > MTU_MAX)
    {
		local_sys_stat->count[SAPP_STAT_SND_ERROR]++;
        sapp_runtime_log(RLOG_LV_FATAL, "__sapp_inject_ctrl_pkt() error! payload_len too long:%d.\n",
                        payload_len + raw_pkt_l2_l3_hdr_len);
        return -1;
    }
	MESA_send_handle *send_handle = &g_send_handle[stream->threadnum];
	send_handle->send_buf = packet_io_get_sendbuf(SEND_TYPE_LINK_INJECT, stream->threadnum);
	send_handle->user_arg = (void *)stream;
    memcpy(send_handle->send_buf, (const char *)(raw_pkt->raw_pkt_data)+raw_pkt->overlay_layer_bytes, raw_pkt_l2_l3_hdr_len+raw_pkt_l4_hdr_len);
	memcpy(send_handle->send_buf+raw_pkt_l2_l3_hdr_len+raw_pkt_l4_hdr_len, payload, payload_len);
	((raw_pkt_t *)raw_pkt)->is_ctrl_pkt=1;
	int raw_payload_len=((raw_pkt_t *)raw_pkt)->payload_len;
	((raw_pkt_t *)raw_pkt)->payload_len=payload_len;
	int ret = packet_io_send(send_handle, raw_pkt_l4_hdr_len+raw_pkt_l2_l3_hdr_len+payload_len, SEND_TYPE_LINK_INJECT, 
						low_net_layer_type, snd_routedir, stream->threadnum,
						(char *)KILL_TCP_PHONY_POINTER, (int *)KILL_TCP_PHONY_POINTER,
						raw_pkt);	
	if(ret < 0)
	{
		send_handle->tot_send_err++;
		sapp_runtime_log(RLOG_LV_FATAL, "packet_io_send() ret < 0, stream_type:%d, addrtype:%d\n", stream->type, stream->addr.addrtype);					 
	}
	else
	{
		send_handle->tot_send_pkt++;
		send_handle->tot_send_byte += payload_len;
		local_sys_stat->count[SAPP_STAT_SND_CTRL]++;
		local_sys_stat->length[SAPP_STAT_SND_CTRL]+= raw_pkt->raw_pkt_len;	
	}
	((raw_pkt_t *)raw_pkt)->is_ctrl_pkt=0;
	((raw_pkt_t *)raw_pkt)->payload_len=raw_payload_len;
	packet_io_free_sendbuf(SEND_TYPE_LINK_INJECT, stream->threadnum);		
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
    if ((SIO_EXCLUDE_THIS_LAYER_HDR & sio) != 0)
    {
        /* ������ǰ�� */
        inject_stream = raw_stream->pfather;
        inject_stream_pr = (struct streaminfo_private *)inject_stream;
        /* ����������ʱָ����SIO_EXCLUDE_THIS_LAYER_HDR, ˵���ڲ���Ԫ�����ɲ�������, ����kni,
           һ�㲻�����ߵ�build_pkt�ĺ�����, �˴���Ҫ����ip��������bloom filter */
        if (sapp_global_val->config.packet_io.dup_pkt_para.dup_pkt_distinguish_all_inject != 0)
        {
            const struct mesa_ip4_hdr *ip4hdr;
            const char *transport_layer_hdr;

            if (ADDR_TYPE_IPV4 == raw_stream->addr.addrtype)
            {
                ip4hdr = (struct mesa_ip4_hdr *)payload;
                transport_layer_hdr = (char*)payload + ip4hdr->ip_hl * 4;
            }
            else
            {
                transport_layer_hdr = (char*)payload + sizeof(struct mesa_ip6_hdr);
            }
            sapp_dup_pkt_mark_l4(raw_stream, payload, (const void *)transport_layer_hdr);
        }
    }
    else
    {
        /*
           2021-09-18 fix bug:
           ԭ����Ipv4����build-args, ԭ������ipv4��tcp��ͷ����ָ��,
           ��Ϊipv6Ҳ�� build_args,
           ������build_net_layer_tcp()ʱ�ж�build_tcp_args��NULL, ��ʹ��������, �����Ͳ�����!!
         */
        set_build_layer_tcp_args(thread_num, TH_PUSH | TH_ACK, MESA_rand_range(1000, 1460), 0);
    }

    raw_stream_pr = (struct streaminfo_private *)raw_stream;
	/* ��ı���ĳЩ�ص�������ԭʼ������ΪIP��ͷ, ���Բ���Ҫ�������ԭʼ��, ��Ϣ���洢��˽�����ṹ���� */
	raw_pkt = update_raw_pkt(raw_stream_pr, snd_routedir, &snd_routedir_reverse);
	if(NULL == raw_pkt){
		sapp_global_val->mthread_volatile[thread_num]->sys_stat.count[SAPP_STAT_SND_ERROR]++;
		sapp_runtime_log(RLOG_LV_INFO, "__sapp_inject_pkt() error, not found raw_pkt!");
		return -1;
	}

	if(raw_stream_pr->sid_append_list != NULL)
	{
		((raw_pkt_t *)raw_pkt)->append_list=raw_stream_pr->sid_append_list;
    }
    struct segment_id_list inject_sid = {
        {(unsigned short)sapp_global_val->config.packet_io.inject_pkt_prepend_segment_id}, 1};
    if (sapp_global_val->config.packet_io.inject_pkt_prepend_segment_id > 0 && raw_stream_pr->is_ctrl_pkt == 0) // update sid_prepend_list, insert inject_pkt_prepend_segment_id to head
    {
        if (raw_stream_pr->sid_prepend_list != NULL)
        {
			unsigned int i = 0;
			for(i = 0; i < MIN(raw_stream_pr->sid_prepend_list->sz_sidlist, MAX_SID_NUM-1); i++)
			{
				inject_sid.sid_list[i+1] = raw_stream_pr->sid_prepend_list->sid_list[i];
			}
			inject_sid.sz_sidlist=i+1;
        }
        ((raw_pkt_t *)raw_pkt)->prepend_list = &inject_sid;
    }
    if (raw_stream_pr->stream_trace_id != 0)
	{
		((raw_pkt_t *)raw_pkt)->stream_trace_id = raw_stream_pr->stream_trace_id;
	}
	/* injectʹ�õ���routedir, �˴�ת����stream dir, 
	   ע��: ��������Ķ������ܲ����ɵ�ǰ��������,  ����kni, �Ǵ����������յ����ݰ�, ��ע����·��,
	         ���ܴ�raw_pkt��raw_stream->routedir�жϷ���!!!!
	*/
	if(snd_routedir == raw_stream_pr->stream_c2s_route_dir){
		send_stream_dir = DIR_C2S;
	}else{
		send_stream_dir = DIR_S2C;
	}
	
	send_handle = &g_send_handle[thread_num];

	reserved_hdr_len = calc_reserved_hdr_len(inject_stream, &low_net_layer_type, send_stream_dir);
	if(reserved_hdr_len < 0){
		sapp_runtime_log(RLOG_LV_INFO, "__sapp_inject_pkt()->calc_reserved_hdr_len() error");
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
    ((raw_pkt_t *)raw_pkt)->prepend_list = raw_stream_pr->sid_prepend_list;// set back stream sid_prepend_list
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
#if 0 /* 2018 lijia modify , ���Ӳ���������߳������������� */
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
			listen_addr.sin_port = htons((unsigned short)sapp_global_val->config.packet_io.inject_mode_inline_device_sport); /* ���������ļ���дvxlanԴ�˿� */
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
			g_send_handle[i].raw_eth_fd =  socket(PF_INET, SOCK_PACKET, htons(ETH_P_ALL));
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


/* 2015-01-04 lijia add, ��pappƽ̨Ǩ�Ƶ�sappƽ̨, �ײ㷢���ӿڲ�ͬ */
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
	
		����һ���߳�, ��̬��ȡĬ�����ص�MAC��ַ, ����Ŀ�������IPv4��ַ����������IP,����arp����,
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
	MESA_sendpacket_xxx��MESA_fakepacket_send_xxxϵ�к�����, dir��sapp�е�routedir���岻ͬ,
	pappƽ̨�е�dirʹ�����λbit��ʾ����, ������Ϊ0x00, ����Ϊ0x80,
	��sapp�е�routedir�����λ��ʾ����, ������Ϊ0x00, ����Ϊ0x01.
	Ϊ��ͬʱ���ݴ�����ƽ̨�Ͳ��, ����MESA_dir_reverse()����, ���ڷ��򷢰�.
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
		�ڱ���ģʽ��, ����������route_dir�ľ���ֵ, ֻ��Ҫ����ͬ��ͷ��򼴿�,
		��������������Ҫ��ȷ����route_dir��0����1, �������������ģʽ��ͬ, ������ʱ��仯,
		�������ô˽ӿ�, ���ֻ�贫����������ķ���, ���ص�ǰ��·��link route dir,
		ע��etc/sapp.toml inbound_route_dirҪ������ȷ.

	args: ��ʾ����Ŀ������ڵ�ǰ�豸���ڵĵ���λ��,
		'E' or 'e': ��ʾ���������Ǵ�Internal to External.
		'I' or 'i': ��ʾ���������Ǵ�External to Internal.

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
		��·���䷽��: 0��1, ͨ������stream->routedir;
	
	����ֵ:
		'E' or 'e': ��ʾ���������Ǵ�Internal to External.
		'I' or 'i': ��ʾ���������Ǵ�External to Internal.
		'x': ��������;
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
	if(raw_dir & DIR_BIT_UNUSE_MASK){ /* ����ֻʹ������ߺ����λbit, �����������ֵ,˵�������ת��dirʱ���˴��� */
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
	
	ret = packet_io_send(send_handle, data_len+sizeof(struct mesa_ethernet_hdr), SEND_TYPE_LINK_INJECT, 
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

	ret = packet_io_send(send_handle, payload_len+sizeof(struct mesa_ip4_hdr)+sizeof(struct mesa_ethernet_hdr), 
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

	ret = packet_io_send(send_handle, payload_len+sizeof(struct mesa_ip4_hdr)+sizeof(struct mesa_ethernet_hdr), 
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

	ret = packet_io_send(send_handle, payload_len+sizeof(struct mesa_tcp_hdr)+sizeof(struct mesa_ip4_hdr)+sizeof(struct mesa_ethernet_hdr), 
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

	ret = packet_io_send(send_handle, payload_len+sizeof(struct mesa_tcp_hdr)+sizeof(struct mesa_ip4_hdr)+sizeof(struct mesa_ethernet_hdr), 
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

	ret = packet_io_send(send_handle, payload_len+sizeof(struct mesa_udp_hdr)+sizeof(struct mesa_ip4_hdr)+sizeof(struct mesa_ethernet_hdr), 
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

	ret = packet_io_send(send_handle, payload_len+sizeof(struct mesa_udp_hdr)+sizeof(struct mesa_ip4_hdr)+sizeof(struct mesa_ethernet_hdr), 
								SEND_TYPE_LINK_INJECT, __ADDR_TYPE_IP_PAIR_V4, dir, thread_index,
								(char *)KILL_TCP_PHONY_POINTER, (int *)KILL_TCP_PHONY_POINTER, NULL);
							   
	packet_io_free_sendbuf(SEND_TYPE_LINK_INJECT, thread_index);	

	if(ret > 0){
		local_sys_stat->count[SAPP_STAT_SND_UDP]++;
		local_sys_stat->length[SAPP_STAT_SND_UDP]+= ret;	
	}

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
			if(sapp_global_val->config.stream.tcp.meaningful_statistics_minimum_pkt>=(int)(pstream->ptcpdetail->serverpktnum+pstream->ptcpdetail->clientpktnum))
			{
				return 0;
			}
			break;
		case	STREAM_TYPE_UDP:
			if(sapp_global_val->config.stream.udp.meaningful_statistics_minimum_pkt>=(int)(pstream->pudpdetail->serverpktnum+pstream->pudpdetail->clientpktnum))
			{
				return 0;
			}
			break;
		default:
			return -1;
	}

	const raw_pkt_t *_raw_pkt=(raw_pkt_t *)raw_pkt;
	
	return dl_io_fun_list.dl_io_smart_offload(_raw_pkt->device_index, 
										(unsigned char *)_raw_pkt->__lib_raw_pkt_data,
										_raw_pkt->__lib_raw_pkt_len,
										pstream->routedir,
										thread_num);
}

#ifdef __cplusplus
}
#endif

