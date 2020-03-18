#include <linux/inet.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/netfilter.h>  
#include <linux/init.h>  
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/tcp.h>

#include <linux/ip.h>
#include <linux/version.h>

#if 0
   #define dprint(fmt, args...) printk (KERN_INFO  fmt, ## args) 
#else
   #define dprint(fmt, args...)
#endif

static char *devname = "xxx";
static char *devip = "169.254.1.1";
static char *devmac = "FF:FF:FF:FF:FF:FF";

static unsigned int local_dev_ip_bin; /* network order */
static unsigned char local_dev_mac_bin[ETH_ALEN];

module_param(devname, charp,S_IRUGO);
module_param(devip, charp,S_IRUGO);
module_param(devmac,charp,S_IRUGO);


static char nf_ascii_to_hex(char ascii)
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
	}

	return c;
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
static int nf_mac_pton(const char *str, int delim, char *mac)
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
			return -1;
		}
	}
	else
	{
		if(strlen(str) != MAC_STR_LEN_NODELIM) 
		{
			return -1;
		}
	}

	/* 检查输入合法性，同时转换成16进制值 */
	for(i = 0; i < 6; i++)
	{
		mac[i] = 0; /* 先清零，赋值语句都是或操作 */
		if(isxdigit(*s)==0)
		{
			return -1;
		}
		mac[i] |= nf_ascii_to_hex(*s) << 4;
		s++;
		
		if(isxdigit(*s)==0)
		{
			return -1;
		}
		mac[i] |= nf_ascii_to_hex(*s);
		s++;
		
		if((delim != -1) && i<5 && (*s++ != (char)delim))
		{
			return -1;
		}
	}

	return 0;
}

/*
	从网关收到的回复包, dip肯定是本机物理网卡的ip, 
	要把dip改成iptables的SNAT目标ip, 169.254.254.254, 
	第1, 欺骗内核, 让此包的四元组跟本机无关, 协议栈不做特殊处理;
	第2, iptables的SNAT才能进一步恢复NAT之前, ppp0设备的ip.
*/
static void modify_dip_spoofing_kernal(struct sk_buff *skb)
{	
	struct iphdr *ip_header;
	struct udphdr *udp_header;
	struct tcphdr *tcp_header;
	int payload_len;

	ip_header = (struct iphdr *) skb_network_header (skb);

	dprint("rcv pkt from %s, modify dip to '169.254.254.254'\n", skb->dev->name);
	ip_header->daddr = 0xFEFEFEA9;//169.254.254.254
	ip_send_check(ip_header);

	if(IPPROTO_UDP == ip_header->protocol){
		udp_header = (struct udphdr *)((char *)ip_header + ip_header->ihl * 4);
		udp_header->check = 0;
		udp_lib_checksum_complete(skb);
	}else if(IPPROTO_TCP == ip_header->protocol){
		tcp_header = (struct tcphdr *)((char *)ip_header + ip_header->ihl * 4);
		payload_len = ntohs(ip_header->tot_len) - ip_header->ihl * 4;
		tcp_header->check = 0;

		//TODO, 下面方式的tcp校验和计算不对!!
		//tcp_checksum_complete(skb);
		tcp_header->check = tcp_v4_check(payload_len, ip_header->saddr, ip_header->daddr,
					csum_partial((char *)tcp_header, payload_len, 0));
	}
}

/*
	处理从物理网卡收到的流量, 
	只有dmac, dip都是本机的, 才可能是sapp串联流量.
*/
static unsigned int phy_dev_decide(struct sk_buff *skb, const char *devname)
{
	struct ethhdr *ehdr;
	//struct udphdr *udp_header;
	struct tcphdr *tcp_header;
	struct iphdr *ip_header;
	unsigned int action = NF_ACCEPT;

	ehdr = (struct ethhdr *)skb_mac_header(skb);

	/* DMAC不是给本机的包, 可能是广播、组播等包, 给内核处理 */
	if(memcmp(ehdr->h_dest, local_dev_mac_bin, ETH_ALEN) != 0){ 
		dprint("recv pkt from %s, dst mac is not local, action=%d\n", skb->dev->name, action);
		return NF_ACCEPT;
	}

	if(ntohs(ehdr->h_proto) != ETH_P_IP){
		/* 非ip包,  给内核协议栈处理 */
		dprint("recv pkt from %s, is not ipv4, action=%d\n", skb->dev->name, action);
		return NF_ACCEPT;
	}
	
#if 0//debug
	  printk("smac:%02x-%02x-%02x-%02x-%02x-%02x, dmac:%02x-%02x-%02x-%02x-%02x-%02x\n", 
		ehdr->h_source[0],
		ehdr->h_source[1],
		ehdr->h_source[2],
		ehdr->h_source[3],
		ehdr->h_source[4],
		ehdr->h_source[5],
	
		ehdr->h_dest[0],
		ehdr->h_dest[1],
		ehdr->h_dest[2],
		ehdr->h_dest[3],
		ehdr->h_dest[4],
		ehdr->h_dest[5]
	);
#endif
	
	  ip_header = (struct iphdr *) skb_network_header (skb);
	   /* DIP不是给本机的包, 给内核处理 */
	  if(ip_header->daddr != local_dev_ip_bin){
			//printk (KERN_INFO "### recv not local dip packet, 0x%x!.\n", ntohl(ip_header->daddr));
			return NF_ACCEPT;
	  }
	
	  switch(ip_header->protocol){
	    /* UDP, ICMP等包不太好区分哪个包是本机所发出的, 默认给sapp,  */
		case IPPROTO_UDP:
			//dprint("sapp-kmod: rcv udp pkt from %s, to user queue.\n", devname);
			modify_dip_spoofing_kernal(skb);
			action = NF_QUEUE;
		break;
		
		case IPPROTO_ICMP:
			dprint("sapp-kmod: rcv icmp pkt from %s, to user queue.\n", devname);
			modify_dip_spoofing_kernal(skb);
			action = NF_QUEUE;
		break;
		
		case IPPROTO_ESP:
			//dprint("sapp-kmod: rcv ip-esp pkt from %s, to user queue.\n", devname);
			modify_dip_spoofing_kernal(skb);
			action = NF_QUEUE;
		break;
	
		case IPPROTO_TCP:
		{
			/* 只保证物理机的ssh, pptp vpn的连通性, 其他都给sapp */
			tcp_header = (struct tcphdr *)( (char *)ip_header + ip_header->ihl * 4);
			  if((ntohs(tcp_header->dest) == 22)
			   ||(ntohs(tcp_header->dest) == 1723)){
				  //dprint("sapp-kmod: rcv tcp and (port 22 or port 1723) pkt, to kernel ip stack.");
				  action = NF_ACCEPT;
			  }else{
			  	dprint("sapp-kmod: rcv tcp and not port 22 and not port 1723 pkt, to user queue.\n");
				modify_dip_spoofing_kernal(skb);
				action = NF_QUEUE;
				}
		}
		break;
		
		case IPPROTO_GRE: /* pptp vpn流量给sapp */
			//dprint("sapp-kmod: rcv gre pkt from %s, to kernel ip stack\n", devname);
			action = NF_ACCEPT;
		break;
	
		default:
		break;
	  }

	return action;
}

static unsigned int virtual_dev_decide(struct sk_buff *skb, const char *devname)
{
	return NF_ACCEPT; /* from all virtual device action is accept */
	
	if(strncasecmp(devname, "tun_kni", strlen("tun_kni")) == 0){
		//dprint("sapp-kmod: recv from dev:%s, accept it\n", devname);
		return NF_ACCEPT; /* kni with tfe */
	}

	if(strncasecmp(devname, "lo", strlen("lo")) == 0){
		return NF_ACCEPT; /* loopback */
	}

	if(strncasecmp(devname, "ppp", 3) == 0){
		return NF_ACCEPT; /* ppp0, ppp1, ppp2, pptp vpn vdev */
	}

	/* tun0 tun1是sapp串联的两块虚拟卡, 要使用STOP机制, 
       即不让后续的hook再处理, 跳过tfe模块, 只给系统内核.
	*/
	if(strncasecmp(devname, "tun0", strlen("tun0")) == 0){
		//dprint("sapp-kmod: recv from dev:%s, stop it\n", devname);
		return NF_ACCEPT; /* stop follow hooks and to sapp user space */
	}
	
	if(strncasecmp(devname, "tun1", strlen("tun1")) == 0){
		//dprint("sapp-kmod: recv from dev:%s, stop it\n", devname);
		return NF_ACCEPT; /* stop follow hooks and to sapp user space */
	}

	return NF_ACCEPT; /* default is accept */
}

/* This function to be called by hook. */
static unsigned int hook_func (unsigned int hooknum,
         struct sk_buff *skb,
         const struct net_device *in,
         const struct net_device *out, int (*okfn) (struct sk_buff *))
{
  unsigned int action = NF_ACCEPT;

  if(strncasecmp(skb->dev->name, devname, strlen(devname)) == 0){
	action = phy_dev_decide(skb, skb->dev->name);
  }else{
	action = virtual_dev_decide(skb, skb->dev->name);
  }

  dprint("recv pkt from %s, action=%d\n", skb->dev->name, action);
 
	return action;
}


static struct nf_hook_ops stb_hook = {
	.hook = hook_func,
	.hooknum = NF_INET_PRE_ROUTING,			   /* NF_IP_LOCAL_IN */
	.pf = PF_INET,
	.priority = NF_IP_PRI_FIRST,
};

static int __init init_nf (void)
{
	if(strncasecmp(devip, "169.254.1.1", strlen("169.254.1.1")) == 0){
		printk (KERN_ERR "sapp_tun_bridge init error, must set devip!\n");
		printk (KERN_ERR "Usage: insmod sapp_tun_bridge.ko devname=\"eth0\" devip=\"x.x.x.x\" devmac=\"xx:xx:xx:xx:xx:xx\"!\n");
		return -1;
	}
	if(strncasecmp(devmac, "FF:FF:FF:FF:FF:FF", strlen("FF:FF:FF:FF:FF:FF")) == 0){
		printk (KERN_ERR "sapp_tun_bridge init error, must set devmac!\n");
		printk (KERN_ERR "Usage: insmod sapp_tun_bridge.ko devname=\"eth0\" devip=\"x.x.x.x\" devmac=\"xx:xx:xx:xx:xx:xx\"!\n");
		return -1;
	}

	if(strncasecmp(devname, "xxx", strlen("xxx")) == 0){
		printk (KERN_ERR "sapp_tun_bridge init error, must set devname!\n");
		printk (KERN_ERR "Usage: insmod sapp_tun_bridge.ko devname=\"eth0\" devip=\"x.x.x.x\" devmac=\"xx:xx:xx:xx:xx:xx\"!\n");
		return -1;
	}
	
	if(nf_mac_pton(devmac, ':', local_dev_mac_bin) < 0){
		printk (KERN_ERR "sapp_tun_bridge init error, invalid devmac:%s!\n", devmac);
		printk (KERN_ERR "Usage: insmod sapp_tun_bridge.ko devip=\"x.x.x.x\" devmac=\"xx:xx:xx:xx:xx:xx\"!\n");
		return -1;
	}

	if(in4_pton(devip, strlen(devip), (unsigned char *)&local_dev_ip_bin, -1, NULL) < 0){
		printk (KERN_ERR "sapp_tun_bridge init error, invalid devip:%s!\n", devip);
		printk (KERN_ERR "Usage: insmod sapp_tun_bridge.ko devip=\"x.x.x.x\" devmac=\"xx:xx:xx:xx:xx:xx\"!\n");
		return -1;
	}

	printk (KERN_INFO "Register sapp_tun_bridge module succ, local devip:%s, devmac:%02x-%02x-%02x-%02x-%02x-%02x\n",
			devip,
			local_dev_mac_bin[0],
			local_dev_mac_bin[1],
			local_dev_mac_bin[2],
			local_dev_mac_bin[3],
			local_dev_mac_bin[4],
			local_dev_mac_bin[5]
			);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	nf_register_net_hook (&init_net, &stb_hook);
#else
	nf_register_hook (&stb_hook);
#endif

	return 0;
}

static void __exit exit_nf (void)
{
	printk (KERN_INFO "Unregister sapp_tun_bridge module.\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)	
	nf_unregister_net_hook (&init_net, &stb_hook);
#else
	nf_unregister_hook (&stb_hook);
#endif
}

module_init (init_nf);
module_exit (exit_nf);
MODULE_LICENSE ("GPL");

