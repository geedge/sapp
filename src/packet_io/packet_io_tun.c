#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <string.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <assert.h>
#include <errno.h>
#include <pcap.h>


#define TUN_MODE_NAT_XOR_IP  (0xFFFFFFFF)

static char *tun_up_dev_name;
static char *tun_down_dev_name;
static int g_tun_fd[2]; /* DIR_ROUTE_UP */
static PACKET_IO_CB_T g_tun_work_fun;
static int g_tun_topology_mode = NET_CONN_SERIAL_2CARD;
static int g_tun_version = 20200317;

static MESA_lqueue_head g_tun_work_queue;

typedef struct{
	int thread_num; 
	UINT8 send_buf[SENDPACKET_BUF_LEN];
}tun_send_handle;


/* 为了一次性把数据全部copy到queue�? 使用连续内存结构 */
typedef struct{
	raw_pkt_t  raw_pkt;
	char pkt_buf[SENDPACKET_BUF_LEN];
}tun_raw_pkt_t;

static void tun_xor_static_nat(struct mesa_ip4_hdr *ihdr)
{
	struct mesa_udp_hdr *udp_header;
	struct mesa_tcp_hdr *tcp_header;
	int payload_len;
	
	ihdr->ip_src.s_addr ^= TUN_MODE_NAT_XOR_IP;
	ihdr->ip_dst.s_addr ^= TUN_MODE_NAT_XOR_IP;

	payload_len = ntohs(ihdr->ip_len) - ihdr->ip_hl * 4;

	sendpacket_do_checksum((unsigned char *)ihdr, IPPROTO_IP, sizeof(struct ip));
	if(IPPROTO_TCP == ihdr->ip_p){
		tcp_header = (struct mesa_tcp_hdr *)((char *)ihdr + ihdr->ip_hl * 4);
		tcp_header->th_sum = 0;
		sendpacket_do_checksum((unsigned char *)ihdr, IPPROTO_TCP, payload_len);	
	}else if(IPPROTO_UDP == ihdr->ip_p){
		udp_header = (struct mesa_udp_hdr *)((char *)ihdr + ihdr->ip_hl * 4);
		udp_header->uh_sum = 0;
		sendpacket_do_checksum((unsigned char *)ihdr, IPPROTO_UDP, payload_len);
	}
}


int tun_dl_io_set_topology_mode(int topology_mode)
{
	return 0;
}

int tun_dl_io_set_cap_level(int cap_level)
{
	return 0;
}

int tun_dl_io_set_cap_mode(int cap_mode)
{
	return 0;
}

int tun_dl_io_set_capdev_parallel(const char *cap_dev)
{
	tun_up_dev_name = strdup(cap_dev);

	return 0;
}

int tun_dl_io_set_capdev_serial(const char *up_dev, const char *down_dev)
{
	tun_up_dev_name = strdup(up_dev);
	tun_down_dev_name = strdup(down_dev);

	return 0;
}

int tun_dl_io_set_capture_filter(const char *filter_rule)
{
	return 0;
}

int tun_dl_io_set_cap_buf_queue(int queue_num_max)
{
	return 0;
}

int tun_dl_io_set_work_thread_num(int thread_num_max)
{
	return 0;
}

long tun_dl_io_get_app_drop_num(int thread_num)
{
	return 0;
}

long tun_dl_io_get_lib_drop_num(void)
{
	return 0;
}

void * tun_dl_io_device_alias(unsigned int target_id, char *device_args)
{
	/* 对于tun模式来说, 就是设备名称 eth1, eth2, etc. */
	return (void *)strdup(device_args);
}

int tun_dl_io_register_cb(PACKET_IO_CB_T fun)
{
	g_tun_work_fun = fun;

	return 0;
}

unsigned char *tun_dl_io_get_sendbuf(void *phandle, int thread_num)
{
	tun_send_handle *send_handle = (tun_send_handle *)phandle;
	
	return send_handle->send_buf;
}

void tun_dl_io_free_sendbuf(void *phandle, int thread_num)
{
	(void)phandle;
	(void)thread_num;
	
	/* TUN模式无需释放 */
	return;
}

void *tun_dl_io_get_send_handle(int thread_num)
{
	tun_send_handle *send_handle = (tun_send_handle *)calloc(1, sizeof(tun_send_handle));

	send_handle->thread_num = thread_num;

	return send_handle;
}

int tun_dl_io_low_level_send(void *phandle, UINT8 *data,int datalen,
						int eth_carry_layer_addr_type, int dir,int thread_num)
{
	tun_send_handle *send_handle = (tun_send_handle *)phandle;
	int dir_reverse, ret;

send_again:
	/* 发包时, dir要取反一次, 因为从tun0收的包,rcv_dir=0, 如果send_dir=0, 即业务插件要同向发送,实际是从tun1发走 */

	/* 发包之前恢复原始ip地址, kni, tfe看到的都是假象 */
	tun_xor_static_nat((struct mesa_ip4_hdr *)data);
	
	ret = write(g_tun_fd[(dir & 0x1) ^ 1], data, datalen);
	if(ret < 0){
		if((EAGAIN == errno) || (EINTR == errno) ){
			goto send_again;
		}else{
			return -1;
		}
	}	

	return ret;
}


int tun_dl_io_get_version(void)
{
	return g_tun_version;
}


static int ifconfig_device_up(const char *interface_name)
{
	int err;
	int 			ret;	
	int 			socket_fd;	  
	struct ifreq	ifr;		
	//struct sockaddr_in sin;
	
	if(interface_name == NULL)  
	{  
		return -1;	
	}  
	
	socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_fd < 0)	  
	{
		printf("Create Socket Failed.\n");		  
		return -2;	  
	}
	//指定网卡名称且up
	sprintf(ifr.ifr_name, "%s", interface_name);
	/* 获得接口的标�?*/
	if ((err = ioctl(socket_fd, SIOCGIFFLAGS, (void *)&ifr)) < 0) {
		perror("ioctl SIOCGIFADDR");
		close(socket_fd);
		return -3;
	}
	ifr.ifr_flags |= IFF_UP;
	ret = ioctl(socket_fd, SIOCSIFFLAGS, &ifr);
	if (ret != 0)	 
	{
		printf("Up Device %s Failed.\n", interface_name);
		close(socket_fd);
		return -3;
	}
	
	close(socket_fd);

	return 0;
}

int getifindex(int fd,char *ifname)
{
    struct ifreq ifr;
    memset(&ifr,0,sizeof(ifr));
    strcpy(ifr.ifr_name,ifname);
    if(-1 == ioctl(fd,SIOCGIFINDEX,&ifr))
    {
        printf("ioctl error\n");
        return -1;
    }
    return ifr.ifr_ifindex;
}


int tun_alloc(char *dev, int flags)
{
    assert(dev != NULL);

    struct ifreq ifr;
    int fd, err;

    char *clonedev = "/dev/net/tun";

    if ((fd = open(clonedev, O_RDWR)) < 0) {
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = flags;
    
    if (*dev != '\0') {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }
    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
        close(fd);
        return err;
    }

    // 一旦设备开启成功，系统会给设备分配一个名称，对于tun设备，一般为tunX，X为从0开始的编号�?    // 对于tap设备，一般为tapX
    strcpy(dev, ifr.ifr_name);

    return fd;
}


int create_dev_fd(const char *dev_name)
{
	int tun_fd;
    char tun_name[IFNAMSIZ];

    strcpy(tun_name, dev_name);

    /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
     *        IFF_TAP   - TAP device
     *        IFF_NO_PI - Do not provide packet information
     */
    tun_fd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI);

    if (tun_fd < 0) {
        sapp_runtime_log(30, "create tun device '%s' error!\n", dev_name);
        exit(1);
    }
    
	return tun_fd;
}

static int tun_forward_pkt(int thread_num, const unsigned char *data,int data_len, unsigned char this_pkt_rcv_dir)
{
	int sn;
	unsigned char snd_dir = this_pkt_rcv_dir ^ 1;
	
	sn = write(g_tun_fd[snd_dir], data, data_len);
	if(sn < 0){
		sapp_runtime_log(30, "tun write error, %s\n", strerror(errno));
	}

	return sn;
}


void *tun_work_thread(void *arg)
{
	int sapp_ret, queue_ret;
	tun_raw_pkt_t tun_raw_pkt;
	long buf_len;
	struct mesa_ip4_hdr *ihdr;
	struct mesa_ethernet_hdr *ehdr;
	int total_call_times = 0;
	int polling_work_times = 0;
	
	while(1){
		buf_len = sizeof(tun_raw_pkt);
		queue_ret = MESA_lqueue_try_get_head(g_tun_work_queue, &tun_raw_pkt, &buf_len);
		if(queue_ret >= 0){
			tun_raw_pkt.raw_pkt.__lib_raw_pkt_data = tun_raw_pkt.pkt_buf;
			tun_raw_pkt.raw_pkt.raw_pkt_data = tun_raw_pkt.pkt_buf + 14;

			ehdr = (struct mesa_ethernet_hdr *)tun_raw_pkt.pkt_buf;
			ehdr->ether_type = htons(ETH_P_IP);

			ihdr = (struct mesa_ip4_hdr *)tun_raw_pkt.raw_pkt.raw_pkt_data;
			/* 调用插件之前先伪造ip地址, 欺骗kni, tfe和tfe-kmod模块 */
			tun_xor_static_nat(ihdr);
			
			sapp_ret = g_tun_work_fun(&tun_raw_pkt.raw_pkt, tun_raw_pkt.raw_pkt.route_dir, 0); 
			if((g_tun_topology_mode & __NET_CONN_SERIAL) && (PASS == sapp_ret)){
				/* 转发之前恢复原始ip地址 */
				tun_xor_static_nat(ihdr);
				tun_forward_pkt(0, tun_raw_pkt.raw_pkt.raw_pkt_data, tun_raw_pkt.raw_pkt.raw_pkt_len, tun_raw_pkt.raw_pkt.route_dir);
			}
		}else{
			if(stream_process_polling(0) != 0){
				polling_work_times++;
			}
			total_call_times++;
			
			if(total_call_times >= 100){
				total_call_times = 0;
				usleep(1);
			}
		}
	}

	return NULL;
}


void *tun_rcv_thread(void *arg)
{
	int rcv_byte, queue_ret;
	tun_raw_pkt_t tun_raw_pkt;
	long route_dir_arg = (long)arg; 
	unsigned char route_dir = (unsigned char)route_dir_arg;
	unsigned char reverse_route_dir = route_dir ^ 1;

	memset(&tun_raw_pkt, 0, sizeof(tun_raw_pkt));

	tun_raw_pkt.raw_pkt.magic_num = RAW_PKT_MAGIC_NUM;
	tun_raw_pkt.raw_pkt.raw_pkt_ts.tv_sec = 0;
	tun_raw_pkt.raw_pkt.raw_pkt_ts.tv_usec = 0;
	tun_raw_pkt.raw_pkt.low_layer_type = __ADDR_TYPE_IP_PAIR_V4;
	tun_raw_pkt.raw_pkt.hd_hash = 0; 
	tun_raw_pkt.raw_pkt.io_lib_pkt_reference = NULL;
	tun_raw_pkt.raw_pkt.route_dir = route_dir;
	
	while(1){
		/* 预留mac头部, 方便tcpdump_mesa捕包分析 */
		rcv_byte = read(g_tun_fd[route_dir], tun_raw_pkt.pkt_buf+14, sizeof(tun_raw_pkt.pkt_buf)-14);
		if(rcv_byte > 0){
			if(0x60 == (tun_raw_pkt.pkt_buf[14] & 0xF0)){
				/* TODO: tun模式先不支持ipv6 */
				continue;
			}
			
			//tun_raw_pkt.raw_pkt.__lib_raw_pkt_data = pkt;
			//tun_raw_pkt.raw_pkt.raw_pkt_data = pkt;
			tun_raw_pkt.raw_pkt.__lib_raw_pkt_len = rcv_byte;
			tun_raw_pkt.raw_pkt.raw_pkt_len = rcv_byte;
			tun_raw_pkt.raw_pkt.route_dir = route_dir;
			queue_ret = MESA_lqueue_join_tail(g_tun_work_queue, &tun_raw_pkt, sizeof(tun_raw_pkt));
			if(queue_ret < 0){
				sapp_runtime_log(30, "tun join queue error, ret = %d!", queue_ret);
			}
		}
	}

	return NULL;
}



int tun_dl_io_init(int argc, char *argv[])
{		
	g_tun_fd[0] = create_dev_fd(tun_up_dev_name);
	if(g_tun_fd[0] < 0){
		return -1;
	}
	g_tun_fd[1] = create_dev_fd(tun_down_dev_name);
	if(g_tun_fd[1] < 0){
		return -1;
	}

	g_tun_work_queue = MESA_lqueue_create(1, 10000);

	ifconfig_device_up(tun_up_dev_name);
	ifconfig_device_up(tun_down_dev_name);

    return 0;
}


void tun_dl_io_run(void)
{
	pthread_t pid;

	pthread_create(&pid, NULL, tun_work_thread, NULL);

	/* tun模式暂时只支�?个线�? 非阻塞模式分别处理两个tun虚拟网卡 */
	pthread_create(&pid, NULL, tun_rcv_thread, (void *)DIR_ROUTE_UP);
	pthread_create(&pid, NULL, tun_rcv_thread, (void *)DIR_ROUTE_DOWN);

	
}


#ifdef __cplusplus
}
#endif

