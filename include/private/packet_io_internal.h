#ifndef _PACKET_IO_INTERNAL_H_
#define _PACKET_IO_INTERNAL_H_
#include <linux/limits.h>
#include <netinet/in.h>
#include "private/mesa_net.h"
#include "stream_inc/stream_base.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef RTE_CACHE_LINE_SIZE
	#define RTE_CACHE_LINE_SIZE 64
	#define __sapp_aligned(a) __attribute__((__aligned__(a)))
	#define __sapp_cache_aligned __sapp_aligned(RTE_CACHE_LINE_SIZE)
#endif

/* 虚假指针, 用于MESA_kill_tcp和MESA_kill_tcp_feedback区分, 是否需要反馈数据包 */
#define KILL_TCP_PHONY_POINTER			((void *)0x1A2B3C4D5E6F)
#define INDEPENDENT_SEND_QUEUE_MAX_NUM	(64) /* 插件自己创建的线程, 支持的最大发送队列数量, 此值主要受限于marsio模式, 其他比如libpcap其实无影响, 为了统一, 不能高于64!! */

typedef struct{
	int threadnum; 
	int raw_ipv4_fd; /* 仅用于发送IPv4的rst包 */
	int raw_ipv6_fd; /* 仅用于发送IPv6的rst包 */
	int raw_udp_fd;
	int raw_eth_fd; /* 仅用于发送Ethernet原始报文 */
	unsigned char *send_buf;
	void *low_level_send_handle; /* 底层发包句柄, 根据底层库决定, 通过dl_io_get_send_handle()获取 */
	int sendtype; /* 仅用于Zhuanyong网卡 */
	struct sockaddr saddr_raw_eth;
	unsigned long tot_send_pkt;
	unsigned long tot_send_byte;
	unsigned long tot_send_err;
	void *user_arg; /* 2018-08-31 lijia add, for PanGu, 使用串联vxlan发送rst包 */
}MESA_send_handle;

/* 2012-07-10 LiJia add, 网络连接模式，可根据配置文件内容，更改工作模式: 
   目前支持四种模式:
	0: 并联模式， 不需要发包，只捕包;
	1: 并联模式， 单网卡捕包+发包, 发包使用IP层socket, 通过系统路由确定由哪块网卡发出;
	2: 串联模式， 双网卡捕包+发包;
	3: 逻辑串联模式， 基于特殊设备的重定向与回注.
*/
#define __NET_CONN_PARALLEL		(0x1)	/* 并联模式 */
#define __NET_CONN_SERIAL			(0x2)	/* 串联模式 */

#define __NET_CONN_SENPACKET		(0x10)	/* 会主动发包 */
#define __NET_CONN_NO_SENPACKET	(0x20)	/* 不需要发包 */

#define __NET_CONN_GDEV			(0x100)	/* 基于特殊设备 */

#define __NET_CONN_LINK_LAYER		(0x1000) /* 需要处理链路层MAC地址 */

#define __NET_CONN_PARA_ETH		(0x2000) /* 2013-11-08 add, 需要处理并联模式下的MAC地址 */

#define NET_CONN_PARA_NOSEND	(__NET_CONN_PARALLEL | __NET_CONN_NO_SENPACKET)
#define NET_CONN_PARALLEL		(__NET_CONN_PARALLEL | __NET_CONN_SENPACKET | __NET_CONN_PARA_ETH)
#define NET_CONN_SERIAL_2CARD	(__NET_CONN_SERIAL   | __NET_CONN_SENPACKET | __NET_CONN_LINK_LAYER)
#define NET_CONN_SERIAL_GDEV	(__NET_CONN_SERIAL   | __NET_CONN_SENPACKET | __NET_CONN_GDEV | __NET_CONN_LINK_LAYER)

#define CAP_FILTER_STR_LEN			(1024)
#define DEV_NAME_STR_LEN			(32)

#define VXLAN_HDR_RESERVED_LEN	(14+8+8+20) /* 发送vxlan数据包预留的头部空间, 使用ip_socket发送, 不含最外层的mac, 即inner_eth+vxlan+outer_udp+outer_ip */

typedef struct 
{
	unsigned char flags;

	/*------------byte delim -------*/
	unsigned char reserved[3];

	/*--------int delim -------*/
	unsigned char vlan_id_half_high;
	unsigned char link_layer_type : 4; /* 二层报文封装格式 */
	unsigned char vlan_id_half_low : 4;
	unsigned int online_test : 1;
	unsigned int link_id : 6;
	unsigned int dir : 1;

	unsigned int r7 : 1;
	unsigned int r6 : 1;
	unsigned int r5 : 1;
	unsigned int r4 : 1;
	unsigned int vni_flag : 1;
	unsigned int r2 : 1;
	unsigned int r1 : 1;
	unsigned int r0 : 1;
}vxlan_header_t;  /* 在线GDEV标准 */

struct sendpacket_mac_table{
	unsigned char src_mac[6];
	unsigned char rcv_dir;
	char __pad1__;	 /* 使mac起始地址8字节对齐 */
	unsigned char dst_mac[6];
	char __pad2__[2];/* 使mac起始地址8字节对齐 */
};

typedef struct{
	union{
		char dev_name[128];	/* for pcap, pag, marsio, etc. */
		unsigned int port_id;	/* for DPDK */
		void *sendpath; /* for marsio4.1 */
	};
}send_raw_args_t;


enum io_status_t{
	IO_STATUS_ETH = 0,				/* 0 */
	IO_STATUS_IPV4 = 1,				/* 1, 基于IPv4地址的四元组信息 */
	IO_STATUS_IPV6,				/* 2, 基于IPv6地址的四元组信息 */
	IO_STATUS_VLAN,				/* 3 */
	IO_STATUS_ARP,					/* 4 */
	IO_STATUS_GRE,					/* 5 */
	IO_STATUS_MPLS,				/* 6 */
	IO_STATUS_PPPOE_SES,			/* 7 */
	IO_STATUS_TCP_PKT,				/* 8, TCP单包相关, 包数、字节数, SYN、SYN/ACK、RST包数等等 */
	IO_STATUS_UDP_PKT,				/* 9, UDP单包相关, 包数、字节数 */
	IO_STATUS_L2TP,				/* 10 */
	IO_STATUS_PPP,					/* 11 */
	IO_STATUS_TCP_STREAM,			/* 12 TCP流表相关, 当前并发流数, 每秒新建流数, 每秒删除流数等 */
	IO_STATUS_UDP_STREAM,			/* 13 UDP流表相关, 当前并发流数, 每秒新建流数, 每秒删除流数等 */
	IO_STATUS_STREAM_HASH,		/* 14 HASH 流表相关, 如最大冲突链表长度, 平均查找长度等 */
	IO_STATUS_MAX,					/* 15 */
};

typedef struct{
	unsigned long long pkt_num;
	unsigned long long pkt_byte;
}packet_io_status_base_t; /* 基本参数, 每个协议类型都有的参数 */

typedef struct{
	packet_io_status_base_t *packet_io_status[IO_STATUS_MAX]; /* 实际存储结构由具体协议类型决定 */
}packet_io_status_t;






struct dl_io_lib_name{
	int cap_mode;
	const char *prefix;
	const char *lib_name;
};

typedef struct{
	unsigned int target_id; /* 配置文件中的ID */
	char *device_args;    /* 配置文件中的原始配置字符串, 需要驱动层的回调函数转换成io_io_param; */
	union{ /* 经过转换后的底层发送参数, 比如对于marsio驱动来说, 就是struct mr_sendpath; 对于pcap模式来说, 就是设备名称"eth1"等. */
		void *dl_io_param;
		char *string_param;
		int int_param;
		long long llong_param;
	};
}packet_io_device_alias_t;
extern packet_io_device_alias_t *g_packet_device_alias;

enum timestamp_level{
	TS_LEVEL_LIB			=	0,	/* pcap_hand, libpcap库拿到,入队列之前 */
	TS_LEVEL_WORK			=	1,	/* pcap_worker, 从队里里取出 */
	TS_LEVEL_IP_ENTRY		=	2,	
	TS_LEVEL_BEFORE_PLUG	= 	3,
	TS_LEVEL_AFTER_PLUG	=	4,
	__TS_LEVEL_MAX		=	5,
};

/* 临时存储用于构造每层包头的参数, 如ip->id, ip->ttl, tcp->flags, tcp->win参数等 */
typedef struct{
	void *layer_args[__ADDR_TYPE_MAX] __sapp_cache_aligned;
	//long __pad[6];
}layer_args_t ;


int MESA_get_dev_mac(const char *device, unsigned char mac[6]);
int MESA_mac_pton(const char *str, int delim, char *mac);
int sendpacket_init_new(int tot_thread_num);
int packet_io_set_max_rand_value(int rand_max);
int packet_io_set_rand_key(int rand_key);
MESA_send_handle *packet_io_get_send_handle(int thread_id);
int packet_io_send(MESA_send_handle *send_handle,int datalen,int send_type, 
					int low_layer_type, int dir,int thread_num, char *feedback_buf, int *feedback_buf_len);

void sysinfo_output(void);
int is_proxy_stream(const struct streaminfo *pstream);
int packet_io_send_raw(int thread_num, char *data, int datalen,unsigned int target_id);
extern void ipv4_frag_exit(void);
extern void ipv6_frag_exit(void);
extern int set_gre_hdr(struct mesa_gre_hdr *stack_gre_addr, const void *this_layer_data);
extern int calc_gre_hdr_len(const struct mesa_gre_hdr *gre_hdr);
extern int packet_io_status_vlan_init(void);
extern int get_pkt_len_from_eth_hdr(const struct mesa_ethernet_hdr *ehdr);
extern int packet_io_send_fake_pkt_by_gdev(MESA_send_handle *send_handle, enum addr_type_t addrtype, 
	char *data, int datalen, int dir_reverse,char *feedback_buf, int *feedback_buf_len);
unsigned long long MESA_rand_range(unsigned long long start, unsigned long long end);
int __MESA_rst_tcp_c(struct streaminfo *stream, unsigned char rst_th_flags, int rst_pkt_num, unsigned char snd_rst_dir, 
							unsigned short signature_seed1, unsigned short signature_seed2);

/********************** funcitons for dynamic link ***********************/
extern int dl_io_set_cap_level(int cap_level);
extern int dl_io_set_cap_mode(int cap_mode);
extern int dl_io_set_topology_mode(int topology_mode);
extern int dl_io_set_capdev_parallel(const char *cap_dev);
extern int dl_io_set_capdev_serial(const char *up_dev, const char *down_dev);
extern int dl_io_set_capture_filter(const char *filter_rule);
extern int dl_io_set_cap_buf_queue(int queue_num_max);
extern int dl_io_set_work_thread_num(int thread_num_max);
extern long dl_io_get_app_drop_num(int thread_num);
extern long dl_io_get_lib_drop_num(void);
extern unsigned char * dl_io_get_sendbuf(void *, int );
extern void dl_io_free_sendbuf(void *, int thread_num);
extern void * dl_io_get_send_handle(int  thread_num);
extern int dl_io_low_level_send(void *phandle, unsigned char *data,int datalen,
						int eth_carry_layer_addr_type, int dir,int thread_num); /* 不含ethernet层 */
extern int dl_io_raw_pkt_send(void *phandle, unsigned char *data,int datalen, void *arg, int thread_num); /* 全部原始包 */
extern int dl_io_init(int argc, char *argv[]);
extern void dl_io_run(void);
extern int dl_io_register_cb(PACKET_IO_CB_T fun);
extern int dl_io_register_exit_cb(PACKET_IO_EXIT_CB_T exit_fun); 
extern int dl_io_get_version(void);
extern void * dl_io_device_alias(unsigned int target_id, char *device_args);

/********************** funcitons for dynamic link ***********************/


/********************** pcap funcitons for dynamic link ***********************/
extern int pcap_dl_io_set_cap_level(int cap_level);
extern int pcap_dl_io_set_cap_mode(int cap_mode);
extern int pcap_dl_io_set_topology_mode(int topology_mode);
extern int pcap_dl_io_set_capdev_parallel(const char *cap_dev);
extern int pcap_dl_io_set_capdev_serial(const char *up_dev, const char *down_dev);
extern int pcap_dl_io_set_capture_filter(const char *filter_rule);
extern int pcap_dl_io_set_cap_buf_queue(int queue_num_max);
extern int pcap_dl_io_set_work_thread_num(int thread_num_max);
extern long pcap_dl_io_get_app_drop_num(int thread_num);
extern long pcap_dl_io_get_lib_drop_num(void);
extern unsigned char * pcap_dl_io_get_sendbuf(void *, int );
extern void pcap_dl_io_free_sendbuf(void *, int thread_num);
extern void * pcap_dl_io_get_send_handle(int  thread_num);
extern int pcap_dl_io_low_level_send(void *phandle, unsigned char *data,int datalen,
						int eth_carry_layer_addr_type, int dir,int thread_num); /* 不含ethernet层 */
extern int pcap_dl_io_raw_pkt_send(void *phandle, unsigned char *data,int datalen, void *arg, int thread_num); /* 全部原始包 */
extern int pcap_dl_io_init(int argc, char *argv[]);
extern void pcap_dl_io_run(void);
extern int pcap_dl_io_register_cb(PACKET_IO_CB_T fun);
extern int pcap_dl_io_register_exit_cb(PACKET_IO_EXIT_CB_T exit_fun); 
extern int pcap_dl_io_get_version(void);
extern void * pcap_dl_io_device_alias(unsigned int target_id, char *device_args);

/********************** pcap funcitons for dynamic link ***********************/


/********************** pag funcitons for dynamic link ***********************/
extern int pag_dl_io_set_cap_level(int cap_level);
extern int pag_dl_io_set_cap_mode(int cap_mode);
extern int pag_dl_io_set_topology_mode(int topology_mode);
extern int pag_dl_io_set_capdev_parallel(const char *cap_dev);
extern int pag_dl_io_set_capdev_serial(const char *up_dev, const char *down_dev);
extern int pag_dl_io_set_capture_filter(const char *filter_rule);
extern int pag_dl_io_set_cap_buf_queue(int queue_num_max);
extern int pag_dl_io_set_work_thread_num(int thread_num_max);
extern long pag_dl_io_get_app_drop_num(int thread_num);
extern long pag_dl_io_get_lib_drop_num(void);
extern unsigned char * pag_dl_io_get_sendbuf(void *, int );
extern void pag_dl_io_free_sendbuf(void *, int thread_num);
extern void * pag_dl_io_get_send_handle(int  thread_num);
extern int pag_dl_io_low_level_send(void *phandle, unsigned char *data,int datalen,
						int eth_carry_layer_addr_type, int dir,int thread_num); /* 不含ethernet层 */
extern int pag_dl_io_raw_pkt_send(void *phandle, unsigned char *data,int datalen, void *arg, int thread_num); /* 全部原始包 */
extern int pag_dl_io_init(int argc, char *argv[]);
extern void pag_dl_io_run(void);
extern int pag_dl_io_register_cb(PACKET_IO_CB_T fun);
extern int pag_dl_io_register_exit_cb(PACKET_IO_EXIT_CB_T exit_fun); 
extern int pag_dl_io_get_version(void);
extern void * pag_dl_io_device_alias(unsigned int target_id, char *device_args);

/********************** pag funcitons for dynamic link ***********************/


/********************** marsio funcitons for dynamic link *********************/
extern int marsio_dl_io_set_cap_level(int cap_level);
extern int marsio_dl_io_set_cap_mode(int cap_mode);
extern int marsio_dl_io_set_topology_mode(int topology_mode);
extern int marsio_dl_io_set_capdev_parallel(const char *cap_dev);
extern int marsio_dl_io_set_capdev_serial(const char *up_dev, const char *down_dev);
extern int marsio_dl_io_set_capture_filter(const char *filter_rule);
extern int marsio_dl_io_set_cap_buf_queue(int queue_num_max);
extern int marsio_dl_io_set_work_thread_num(int thread_num_max);
extern long marsio_dl_io_get_app_drop_num(int thread_num);
extern long marsio_dl_io_get_lib_drop_num(void);
extern unsigned char * marsio_dl_io_get_sendbuf(void *, int );
extern void marsio_dl_io_free_sendbuf(void *, int thread_num);
extern void * marsio_dl_io_get_send_handle(int  thread_num);
extern int marsio_dl_io_low_level_send(void *phandle, unsigned char *data,int datalen,
						int eth_carry_layer_addr_type, int dir,int thread_num); /* 不含ethernet层 */
extern int marsio_dl_io_raw_pkt_send(void *phandle, unsigned char *data,int datalen, void *arg, int thread_num); /* 全部原始包 */
extern int marsio_dl_io_init(int argc, char *argv[]);
extern void marsio_dl_io_run(void);
extern int marsio_dl_io_register_cb(PACKET_IO_CB_T fun);
extern int marsio_dl_io_register_exit_cb(PACKET_IO_EXIT_CB_T exit_fun); 
extern int marsio_dl_io_get_version(void);
extern void * marsio_dl_io_device_alias(unsigned int target_id, char *device_args);
extern int marsio_dl_io_send_only_thread_init(void);
/********************** marsio funcitons for dynamic link *********************/

/********************** tun funcitons for dynamic link ***********************/
extern int tun_dl_io_set_cap_level(int cap_level);
extern int tun_dl_io_set_cap_mode(int cap_mode);
extern int tun_dl_io_set_topology_mode(int topology_mode);
extern int tun_dl_io_set_capdev_parallel(const char *cap_dev);
extern int tun_dl_io_set_capdev_serial(const char *up_dev, const char *down_dev);
extern int tun_dl_io_set_capture_filter(const char *filter_rule);
extern int tun_dl_io_set_cap_buf_queue(int queue_num_max);
extern int tun_dl_io_set_work_thread_num(int thread_num_max);
extern long tun_dl_io_get_app_drop_num(int thread_num);
extern long tun_dl_io_get_lib_drop_num(void);
extern unsigned char * tun_dl_io_get_sendbuf(void *, int );
extern void tun_dl_io_free_sendbuf(void *, int thread_num);
extern void * tun_dl_io_get_send_handle(int  thread_num);
extern int tun_dl_io_low_level_send(void *phandle, unsigned char *data,int datalen,
						int eth_carry_layer_addr_type, int dir,int thread_num); /* 不含ethernet层 */
extern int tun_dl_io_raw_pkt_send(void *phandle, unsigned char *data,int datalen, void *arg, int thread_num); /* 全部原始包 */
extern int tun_dl_io_init(int argc, char *argv[]);
extern void tun_dl_io_run(void);
extern int tun_dl_io_register_cb(PACKET_IO_CB_T fun);
extern int tun_dl_io_register_exit_cb(PACKET_IO_EXIT_CB_T exit_fun); 
extern int tun_dl_io_get_version(void);
extern void * tun_dl_io_device_alias(unsigned int target_id, char *device_args);

/********************** tun funcitons for dynamic link ***********************/


#ifdef __cplusplus
}
#endif

#endif

