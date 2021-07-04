#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <errno.h>
#include <pcap.h>
#include <linux/if_tun.h>
#include <assert.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <ctype.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>


#if 1
   #define dprint(fmt, args...) printf(fmt, ## args)
#else
   #define dprint(fmt, args...)
#endif

#define SAPP_BRIDGE_SNAT_ENABLE (0)
#define SAPP_BRIDGE_SNAT_SIP (0xFEFEFEA9) //169.254.254.254

/*
	此程序可以跑通单机单网卡模式下的串联功能,
	一个卡是本程序创建的tun0, 另一个是物理网卡ens33.
*/

#define USE_TUN_MODE	(1) /* 虚拟设备用tun还是TAP,  1:tun;         0:tap */

/*
 *  Checksum stuff
 */
#define BRIDGE_CKSUM_CARRY(x) \
    (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))
    

static pcap_t * tun_pcap_handle;
static pcap_t * phy_pcap_handle;

static char *phy_dev_name;
static char *tun_dev_name;

static struct sockaddr tun_sock_addr;
static struct sockaddr phy_sock_addr;

static struct nfq_handle *g_nfq_handle;
static int g_nfq_fd;

static int phy_dev_fd, tun_dev_fd;

static unsigned int local_phy_dev_ip_net;

static unsigned char local_phy_mac_addr[ETH_ALEN];
static unsigned char default_gw_mac_addr[ETH_ALEN];


static char MESA_ascii_to_hex(char ascii)
{
	char c = 0;
	
	switch(ascii)
	{
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			c = ascii - 0x30;
		break;

		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
			c = 10 + ascii - 0x61;
		break;

		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
			c = 10 + ascii - 0x41;
		break;

		default:
			c = 0;
		break;
	}

	return c;
}

static int MESA_mac_pton(const char *str, int delim, unsigned char *mac)
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

static int MESA_get_dev_mac(const char *device, unsigned char mac[6])
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

static int MESA_get_dev_ipv4(const char *device, unsigned int *ip_add_net)
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

    *ip_add_net = ((struct sockaddr_in*)&ifr.ifr_ifru.ifru_addr)->sin_addr.s_addr;

    close(fd);

    return 0;

err_exit:
    close(fd);
    return -1;
}

int getifindex(int fd,char *ifname)
{
    struct ifreq ifr;
    memset(&ifr,0,sizeof(ifr));
    strncpy(ifr.ifr_name,ifname,sizeof(ifr.ifr_name));
    if(-1 == ioctl(fd,SIOCGIFINDEX,&ifr))
    {
        printf("ioctl error\n");
        return -1;
    }
    return ifr.ifr_ifindex;
}

static inline int is_private_addr_v4(unsigned int  ip_add_host)
{
/* 10/8 */
#define IPV4_LOCAL_CLASS_A(_add) (((_add&0xFF000000)==0x0A000000)?1:0) 
/* 172.16/12 */
#define IPV4_LOCAL_CLASS_B(_add) (((_add&0xFFF00000)==0xAC100000)?1:0) 
/* 192.168/16 */
#define IPV4_LOCAL_CLASS_C(_add) (((_add&0xFFFF0000)==0xC0A80000)?1:0) 

    if((int)IPV4_LOCAL_CLASS_A(ip_add_host) 
      || (int)IPV4_LOCAL_CLASS_B(ip_add_host) 
      || (int)IPV4_LOCAL_CLASS_C(ip_add_host))
    {
        return 1;
    }

    return 0;
}

static int bridge_in_cksum(u_int16_t *addr, int len)
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


static int bridge_do_checksum(unsigned char *buf, int protocol, int len)
{
    struct ip *iph_p;
    struct ip6_hdr *ip6h_p;
    int ip_hl;
    int sum;
    int is_ipv6 = 0;

    sum = 0;
    iph_p = (struct ip *)buf;

    if(4 == iph_p->ip_v)  /* IP版本号字段，IPv4和IPv6格式是相同的 */
    {
        ip_hl = iph_p->ip_hl << 2;
        ip6h_p = NULL;
    }
    else if(6 == iph_p->ip_v)
    {
        ip6h_p = (struct ip6_hdr *)buf;
        iph_p = NULL;
        ip_hl = sizeof(struct ip6_hdr);
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
            struct tcphdr *tcph_p =
                (struct tcphdr *)(buf + ip_hl);

#if (STUPID_SOLARIS_CHECKSUM_BUG)
            tcph_p->th_sum = tcph_p->th_off << 2;
            return (1);
#endif /* STUPID_SOLARIS_CHECKSUM_BUG */

            tcph_p->check = 0;
            /* 2012-03-19 LiJia add, for IPv6 */
            if(is_ipv6)
            {
                sum = bridge_in_cksum((u_int16_t *)&ip6h_p->ip6_src, 32);
            }
            else
            {
                sum = bridge_in_cksum((u_int16_t *)&iph_p->ip_src, 8);
            }    
            sum += ntohs(IPPROTO_TCP + len);
            sum += bridge_in_cksum((u_int16_t *)tcph_p, len);
            tcph_p->check = BRIDGE_CKSUM_CARRY(sum);
            break;
        }
        
        case IPPROTO_UDP:
        {
            struct udphdr *udph_p =
                (struct udphdr *)(buf + ip_hl);

            udph_p->check = 0;
            /* 2012-03-19 LiJia add, for IPv6 */
            if(is_ipv6)
            {
                sum = bridge_in_cksum((u_int16_t *)&ip6h_p->ip6_src, 32);
            }
            else
            {
                sum = bridge_in_cksum((u_int16_t *)&iph_p->ip_src, 8);
            }   
            sum += ntohs(IPPROTO_UDP + len);
            sum += bridge_in_cksum((u_int16_t *)udph_p, len);
            udph_p->check = BRIDGE_CKSUM_CARRY(sum);
            break;
        }
   
        case IPPROTO_IP: /* Dummy protocol for TCP.  */
        {
            iph_p->ip_sum = 0;
            sum = bridge_in_cksum((u_int16_t *)iph_p, len);
            iph_p->ip_sum = BRIDGE_CKSUM_CARRY(sum);
            break;
        }
#if 0

        case IPPROTO_ICMP:
        {
            struct mesa_icmp_hdr *icmph_p =
                (struct mesa_icmp_hdr *)(buf + ip_hl);

            icmph_p->icmp_sum = 0;
            sum = bridge_in_cksum((u_short *)icmph_p, len);
            icmph_p->icmp_sum = BRIDGE_CKSUM_CARRY(sum);
            break;
        }
#endif        
        default:
        {
            return (-1);
        }
    }
    return (1);
}


/* pptp的控制包和数据包要返回给内核协议栈处理, 否则client拨号会失败;
*/
static int is_need_to_kernel_pkt(const struct ip *ihdr)
{
	const struct tcphdr *thdr;
	
	if(IPPROTO_GRE == ihdr->ip_p){
		return 1;
	}

	/* icmp优先给tun1,保证pptp vpn client的正确性, 此时物理主机的ping失效  */
	if(IPPROTO_ICMP == ihdr->ip_p){
		return 0;
	}
	
	thdr = (const struct tcphdr *)((char *)ihdr + ihdr->ip_hl * 4);
	if((22 == ntohs(thdr->dest)) 
	 || (1723 == ntohs(thdr->dest))){
		return 1;
	}
	
	return 0;
}

/*
	iptabels nat跟路由有冲突, 各种没调通, 先人工做一次简易应用层SNAT.
*/
static void bridge_preout_snat(struct ip *ihdr)
{
	struct udphdr *udp_header;
	struct tcphdr *tcp_header;
	int payload_len;
	
	ihdr->ip_src.s_addr = local_phy_dev_ip_net;  //sip改成本机物理网卡ip
	payload_len = ntohs(ihdr->ip_len) - ihdr->ip_hl * 4;

	bridge_do_checksum((unsigned char *)ihdr, IPPROTO_IP, sizeof(struct ip));
	if(IPPROTO_TCP == ihdr->ip_p){
		tcp_header = (struct tcphdr *)((char *)ihdr + ihdr->ip_hl * 4);
		tcp_header->check = 0;
		bridge_do_checksum((unsigned char *)ihdr, IPPROTO_TCP, payload_len);	
	}else if(IPPROTO_UDP == ihdr->ip_p){
		udp_header = (struct udphdr *)((char *)ihdr + ihdr->ip_hl * 4);
		udp_header->check = 0;
		bridge_do_checksum((unsigned char *)ihdr, IPPROTO_UDP, payload_len);
	}
}

#if SAPP_BRIDGE_SNAT_ENABLE
/* 从物理网卡收到的包, 恢复SNAT之前的ip, 169.254.254.254 */
static void bridge_prein_snat_recover(struct ip *ihdr)
{
	struct udphdr *udp_header;
	struct tcphdr *tcp_header;
	int payload_len;
	
	ihdr->ip_dst.s_addr = SAPP_BRIDGE_SNAT_SIP; 
	payload_len = ntohs(ihdr->ip_len) - ihdr->ip_hl * 4;

	bridge_do_checksum((unsigned char *)ihdr, IPPROTO_IP, sizeof(struct ip));
	if(IPPROTO_TCP == ihdr->ip_p){
		tcp_header = (struct tcphdr *)((char *)ihdr + ihdr->ip_hl * 4);
		tcp_header->check = 0;
		bridge_do_checksum((unsigned char *)ihdr, IPPROTO_TCP, payload_len);	
	}else if(IPPROTO_UDP == ihdr->ip_p){
		udp_header = (struct udphdr *)((char *)ihdr + ihdr->ip_hl * 4);
		udp_header->check = 0;
		bridge_do_checksum((unsigned char *)ihdr, IPPROTO_UDP, payload_len);
	}
}
#endif

static void phy_pkt_cb(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
	int sn;
	struct ethhdr *ehdr = (struct ethhdr *)packet;
	struct ip *ihdr = (struct ip *)(packet);
	struct tcphdr *thdr;
	//char ip_str[64];

	if(ntohs(ehdr->h_proto) != ETH_P_IP){
		return;
	}
	ihdr = (struct ip *)(packet + 14);
	if(local_phy_dev_ip_net != ihdr->ip_dst.s_addr){
		//inet_ntop(AF_INET, &ihdr->ip_dst.s_addr, ip_str, sizeof(ip_str));
		//dprint("packet from %s dst ip '%s' is not local device, ignore it!\n", phy_dev_name, ip_str);
		return;
	}
	switch(ihdr->ip_p){
	    /* UDP, ICMP等包不太好区分哪个包是本机所发出的, 默认给sapp,  */
		case IPPROTO_UDP:	
		case IPPROTO_ICMP:
		case IPPROTO_ESP:
		break;
	
		case IPPROTO_TCP:
		{
			/* 只保证物理机的ssh, pptp vpn的连通性, 其他都给sapp */
			thdr = (struct tcphdr *)( (char *)ihdr + ihdr->ip_hl * 4);
			  if((ntohs(thdr->dest) == 22)
			   ||(ntohs(thdr->dest) == 1723)){
				return;
			  }
		}
		break;
		
		case IPPROTO_GRE: /* pptp vpn流量给sapp */
			return; /* 协议栈处理 */
		break;
	
		default:
			return;  /* 协议栈处理 */
		break;
	  }	

#if SAPP_BRIDGE_SNAT_ENABLE
	bridge_prein_snat_recover(ihdr);
#endif

	/* 发给tun设备 */
	sn = sendto(tun_dev_fd, ihdr, pkthdr->caplen-14, 0, (struct sockaddr *)&tun_sock_addr, sizeof(struct sockaddr));
	if(sn < 0){
		dprint("sendto tun error, len=%d, %s\n", pkthdr->caplen, strerror(errno));
	}else{
		dprint("from phy '%s' to '%s' succ, len=%d\n", phy_dev_name, tun_dev_name, pkthdr->caplen);
	}

	return;
}




/*
	tun模式下, 收到的包没有MAC, 直接是ip头部.
*/
static void tun_pkt_cb(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
	int sn;
	unsigned char buf[2048];

	if(0x40 != (packet[0] & 0xF0)){
		dprint("recv not ipv4 pkt from tun\n");
		return;
	}
	
#if USE_TUN_MODE	
	memcpy(buf+14, packet, pkthdr->caplen); /* tun模式要预留mac头部空间 */
	memcpy(buf, default_gw_mac_addr, 6);
	memcpy(buf+6, local_phy_mac_addr, 6);
	buf[12] = 0x08;
	buf[13] = 0x0;
#else
	memcpy(buf, packet, pkthdr->caplen);
	memcpy(buf, default_gw_mac_addr, 6);
	memcpy(buf+6, local_phy_mac_addr, 6);
	buf[12] = 0x08;
	buf[13] = 0x0;	
#endif

#if SAPP_BRIDGE_SNAT_ENABLE
	bridge_preout_snat((struct ip *)(buf + 14));
#endif

	/* 通过raw_socket从物理网卡发出时, 必须要带mac头 */

#if USE_TUN_MODE	
	sn = sendto(phy_dev_fd, buf, pkthdr->caplen+14, 0, (struct sockaddr *)&phy_sock_addr, sizeof(struct sockaddr));
#else
	sn = sendto(phy_dev_fd, buf, pkthdr->caplen, 0, (struct sockaddr *)&phy_sock_addr, sizeof(struct sockaddr));
#endif
	if(sn < 0){
		dprint("sendto phy error, len=%d, %s\n", pkthdr->caplen+14, strerror(errno));
	}else{
		dprint("from tun '%s' to phy '%s' succ, len=%d\n", tun_dev_name, phy_dev_name, pkthdr->caplen+14);
	}
}

static int pcap_set_filter(pcap_t *handle, const char *filter_str)
{
	struct bpf_program bpf_filter;

	if((NULL == handle) || (NULL == filter_str) || ('\0' == *filter_str)){
		return 0;
	}
	
	if(pcap_compile(handle, &bpf_filter, (char *)filter_str, 1, 0) < 0)
	{
		printf("Compile pcap filter '%s' error:%s\n", filter_str, pcap_geterr(handle));
		return -1;
	}

	if(pcap_setfilter(handle, &bpf_filter) < 0){
		printf("Set pcap filter '%s' error:%s\n", filter_str, pcap_geterr(handle));
		return -1;
	}

	return 0;
}

static int pcap_init(void)
{
	char errBuf[65535];
	char local_ip_str[64];
	char pcap_filter_str[256];

	/* open a device, wait until a packet arrives */
	phy_pcap_handle = pcap_open_live(phy_dev_name, 65535, 1, 0, errBuf);
	if(!phy_pcap_handle)
	{
	  printf("error: pcap_open_live(): %s\n", errBuf);
	  exit(1);
	}
	
	inet_ntop(AF_INET, &local_phy_dev_ip_net, local_ip_str, sizeof(local_ip_str));
	snprintf(pcap_filter_str, sizeof(pcap_filter_str), "ip and dst host %s", local_ip_str);

	pcap_setdirection(phy_pcap_handle, PCAP_D_IN);
	pcap_set_filter(phy_pcap_handle, pcap_filter_str);
	printf("capture phy dev %s use filter '%s'.\n", phy_dev_name, pcap_filter_str);

	tun_pcap_handle = pcap_open_live(tun_dev_name, 65535, 1, 0, errBuf);
	if(!tun_pcap_handle)
	{
	  printf("error: pcap_open_live(): %s\n", errBuf);
	  exit(1);
	}

	pcap_setdirection(tun_pcap_handle, PCAP_D_IN);
	
	return 0;
}



void *phy_pcap_rcv_thread(void *arg)
{
	while(1){
		pcap_loop(phy_pcap_handle, -1, phy_pkt_cb, NULL);
	}

	return NULL;

}

void *tun_pcap_rcv_thread(void *arg)
{
	while(1){
		pcap_loop(tun_pcap_handle, -1, tun_pkt_cb, NULL);
	}

	return NULL;
}

static int sock_init(void)
{
	phy_dev_fd = socket(PF_INET, SOCK_PACKET, htons(ETH_P_ALL));    
    if(phy_dev_fd < 0)
    {
        printf("Create socket error!\n");
        return -1;
    }
    
	tun_dev_fd = socket(PF_INET, SOCK_PACKET, htons(ETH_P_ALL));    
    if(tun_dev_fd < 0)
    {
        printf("Create socket error!\n");
        return -1;
    }

	strncpy(phy_sock_addr.sa_data, phy_dev_name, sizeof(phy_sock_addr.sa_data));
	phy_sock_addr.sa_family = PF_INET;

	strncpy(tun_sock_addr.sa_data, tun_dev_name, sizeof(tun_sock_addr.sa_data));
	tun_sock_addr.sa_family = PF_INET;

	if(MESA_get_dev_ipv4(phy_dev_name, &local_phy_dev_ip_net) < 0){
        	printf("get device '%s' ip address error!\n", phy_dev_name);
        	return -1;
	}
	
	if(MESA_get_dev_mac(phy_dev_name, local_phy_mac_addr) < 0){
        	printf("get device '%s' MAC address error!\n", phy_dev_name);
        	return -1;
	}

	return 0;
}


static void usage(void)
{
	printf("usage: ./eth_tun_bridge <phy_device> <tun_device> <gw_mac>\n");
	printf("\t for example: ./eth_tun_bridge eth0 tun1 50:d2:f5:f3:8e:93\n");
	exit(1);
}

 
int main(int argc, char *argv[])
{
	//int rphy, rtun;
	pthread_t pid;
	int i;
	
	if(argc != 4){
		printf("args number is not 4!\n");
		for(i = 0; i < argc; i++){
			printf("%s ", argv[i]);
		}
		printf("\n\n");
		usage();
	}
	
	phy_dev_name = strdup(argv[1]);
	tun_dev_name = strdup(argv[2]);
	if(MESA_mac_pton(argv[3], ':', default_gw_mac_addr) < 0){
		printf("args gw_mac is invalid!\n");
		usage();
	}

	if(sock_init() < 0){
		return -1;
	}
	
	if(pcap_init() < 0){
		return -1;
	}
	
	printf("init succ, start capturing...\n");

	pthread_create(&pid, NULL, phy_pcap_rcv_thread, NULL);
	pthread_create(&pid, NULL, tun_pcap_rcv_thread, NULL);

    while(1){
		pause();

    }
     
    return 0;
}

