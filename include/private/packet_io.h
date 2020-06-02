#ifndef _PACKET_IO_H_
#define _PACKET_IO_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <time.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <linux/limits.h>
#include "stream_manage.h"
#include "stream_internal.h"
#include "sysinfo.h"

#ifndef MULTITHREAD
#define MULTITHREAD 	(1)
#endif

#ifndef MTU_MAX
#define MTU_MAX 					1514
#endif


#define RAW_PKT_BROKEN_TEST	(0) /* 防止上层插件无意修改原始包, 增加检测机制 */

#define	SENDPACKET_BUF_LEN		(2048)

extern int g_UseFilterCard; //add by lqy 20081110
extern int g_UseSendpktCard; //add by lqy 20090313
extern int g_UseFilterTag; //add by lqy 20090414

extern volatile unsigned long long g_SysInputInfo[MAX_THREAD_NUM][COUNTER_NUM];

enum io_dir_t{
	IO_DIR_UP 		= 0,
	IO_DIR_DOWN	= 1,
};

enum cap_level_t{
	__CAP_LEVEL_UNKNOW = 0, 
	CAP_LEVEL_MAC		= ADDR_TYPE_MAC,
	CAP_LEVEL_IPV4		= __ADDR_TYPE_IP_PAIR_V4, /* 如果是IP层, 默认为IPv4 */
	CAP_LEVEL_IPV6		= __ADDR_TYPE_IP_PAIR_V6,	
	CAP_LEVEL_MAC_IN_MAC = ADDR_TYPE_MAC_IN_MAC,
};

enum cap_mode_t{
	CAP_MODEL_PAG				= 0, 
	CAP_MODEL_PCAP_ONLINE 	= 1,
	CAP_MODEL_PCAP_DUMPFILE 	= 2,
	CAP_MODEL_PFRING			= 3,
	CAP_MODEL_DPDK			= 4,
	CAP_MODEL_PPF				= 5,
	CAP_MODEL_NPACKET		= 6, 
	CAP_MODEL_QNF				= 7, /* for 奇策科技Zhuanyong网卡 */
	CAP_MODEL_N95				= 8, /* to do: for xx9 UDP新接口 */
	CAP_MODEL_PCAP_DUMPLIST	= 9, /* 2014-11-19 lijia add */
	CAP_MODEL_TOPSEC			= 10, /* 2015-09-29 lijia add, for trojan detect */
	CAP_MODEL_IPFILE			= 11,
	CAP_MODEL_MARSIOV4		= 12, /* 2016-10-26 lijia add, for DPDK-marsio-V4.0 */
	CAP_MODEL_AGENT_SMITH	= 13, /* 2016-10-27 lijia add, for 资源隔离共享内存 */
	CAP_MODEL_DPDK_VXLAN	= 14, /* 2016-11-01 lijia add, for DPDK-3.0, vxlan三层回流 */
	CAP_MODEL_MARSIOV4_VXLAN= 15,  /* 2016-11-01 lijia add, for MARSIO-4.0, vxlan三层回流 */
	CAP_MODEL_PAG_MARSIO	= 16, /* 2017-04-07 lijia add, for marsio compat pag */
	CAP_MODEL_TUN			= 17, /* 2020-02-20 lijia add, for tun mode */
	__CAP_MODEL_MAX			= 18,
};

enum send_packet_way{
	SEND_WAY_PLATFORM			= 1, /* 上层应用发包方式,使用平台内置, 暂时仅发送RST和原始报文使用 */
	SEND_WAY_DLL					= 2, /* 上层应用发包方式,使用第三方动态库 */
};

enum send_packet_type{
	SEND_TYPE_LINK_INJECT			= 1, /* 发送数据类型, 捕包链路注入, 如RST, 伪造包等 */
	SEND_TYPE_LOG					= 2, /* 发送数据类型, 回传日志 */
	SEND_TYPE_REDIRECT			= 3, /* 发送数据类型, 数据包重定向, 如水浒中的原始报文转发 */
	SEND_TYPE_FEEDBACK			= 4, /* 发送数据类型, 数据回传分析, 如YSP的节目 */
};

enum send_fake_packet_mode{
	SEND_PKT_MODE_STACK_3_LAYER			= 0, /* 发送数据模式，协议栈三层发包 */
    SEND_PKT_MODE_STACK_2_LAYER_1_ROUTE					= 1, /* 发送数据模式，协议栈二层发包，单一目的路由*/
	SEND_PKT_MODE_STACK_2_LAYER_MUTI_ROUTE					= 2, /* 发送数据模式，协议栈二层发包，多个目的路由*/
	SEND_PKT_MODE_GDEV			= 3, /* 发送数据模式， gdev注入 */
};

typedef int (*PACKET_IO_CB_T)(const raw_pkt_t *p_raw_pkt,unsigned char dir,int thread_num);
typedef void (*PACKET_IO_EXIT_CB_T)(void);
typedef void (*PACKET_IO_EXIT_PER_THREAD_CB_T)(int thread_seq);

extern PACKET_IO_CB_T G_DEFAULT_PKT_CB;

/* 所有捕包库的操作函数全集, 对这些函数不必全支持, 但为了兼容性, 一定要保证有此符号, 写个空函数即可 */
typedef struct{
	int (*dl_io_set_cap_level)(int cap_level);
	int (*dl_io_set_cap_mode)(int cap_mode);
	int (*dl_io_set_topology_mode)(int topology_mode);
	int (*dl_io_set_capdev_parallel)(const char *cap_dev);
	int (*dl_io_set_capdev_serial)(const char *up_dev, const char *down_dev);
	int (*dl_io_set_capture_filter)(const char *filter_rule);
	int (*dl_io_set_cap_buf_queue)(int queue_num_max);
	int (*dl_io_set_work_thread_num)(int thread_num_max);
	long (*dl_io_get_app_drop_num)(int thread_num);
	long (*dl_io_get_lib_drop_num)(void);
	unsigned char * (*dl_io_get_sendbuf)(void *, int );
	void (*dl_io_free_sendbuf)(void *, int thread_num);
	void * (*dl_io_get_send_handle)(int  thread_num);
	int (*dl_io_low_level_send)(void *phandle, unsigned char *data,int datalen,
							int eth_carry_layer_addr_type, int dir,int thread_num); /* 不含ethernet层 */
	int (*dl_io_raw_pkt_send)(void *phandle, unsigned char *data,int datalen, void *arg, int thread_num); /* 全部原始包 */
	int (*dl_io_init)(int argc, char *argv[]);
	void (*dl_io_run)(void);
	int (*dl_io_register_cb)(PACKET_IO_CB_T fun);
	int (*dl_io_register_exit_cb)(PACKET_IO_EXIT_CB_T exit_fun); 
	int (*dl_io_get_version)(void);
	void * (*dl_io_device_alias)(unsigned int target_id, char *device_args);
	int (*dl_io_send_only_thread_init)(void); /* 2020-06-01 lijia add, 插件自行创建的独立发包线程, 需要调用此接口绑定到特定CPU核心上 */
}dl_io_fun_list_t;

/* 以下函数必须调用, 传入正确参数才能正常运行 */
int packet_io_set_cap_mode(int cap_model);
int packet_io_set_topology_mode(int user_topology_mode);
int packet_io_init(int argc, char *argv[]);
void packet_io_run(void); /* not return until error, or use 'CAP_MODEL_PCAP_DUMPFILE' mode */
int packet_io_lib_load(int cap_mode);
int packet_io_set_topology_model(int topology_model);
int packet_io_set_capdev_parallel(const char *cap_dev);
int packet_io_set_capdev_serial(const char *up_dev, const char *down_dev);

/* 以下函数可以不显式调用, 平台内置默认值, 只保证可以正常运行, 但参数设置较为保守, 
   可能与预期不符, 如线程数、缓冲队列大小等. 
 */
int packet_io_set_ipv6_module_enable(int op_switch);
int packet_io_set_capture_filter(const char *filter_rule);
int packet_io_set_cap_buf_queue(int queue_num_max);
int packet_io_set_work_thread_num(int thread_num_max);
long packet_io_get_app_drop_num(int thread_num);
unsigned long packet_io_get_send_pkt_num(int thread_num);
unsigned long packet_io_get_send_pkt_err(int thread_num);
unsigned long packet_io_get_send_pkt_byte(int thread_num);
long packet_io_get_lib_drop_num(void);
long packet_io_get_app_drop_num_tot(void);
int packet_io_register_cb(PACKET_IO_CB_T fun);
unsigned char *packet_io_get_sendbuf(int type, int thread_num);
void packet_io_free_sendbuf(int type, int thread_num);
int packet_io_set_send_dev(const char *send_dev);
int packet_io_set_gateway_mac(const char *gateway_mac);
int packet_io_send_only_thread_init(void);


extern void MESA_runtime_log(int level, char * module, char * fmt, ...);

extern int ipv4_entry(struct streaminfo_private*pfstream, const void *this_layer_data, int thread_num, 
			unsigned char routedir, const raw_pkt_t *raw_pkt, int);
extern int ipv6_entry(struct streaminfo_private *pfstream, const void *this_layer_data, int thread_num, 
			unsigned char routedir, const raw_pkt_t *raw_pkt, int);
int eth_entry(struct streaminfo_private *fstream, const void *this_layer_hdr, 
		int thread_num,  unsigned char dir, const raw_pkt_t *raw_pkt, int offset_to_raw_hdr);
int vlan_8021q_entry(struct streaminfo_private *pfstream,const void *this_layer_hdr,int thread_num,
					unsigned char routedir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr);
int arp_entry(struct streaminfo_private *fstream, const void *this_layer_hdr, 
			 int thread_num, unsigned char dir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr);
extern int ppp_entry(struct streaminfo_private*pfstream, const void *this_layer_data, int thread_num, 
			unsigned char routedir, const raw_pkt_t *raw_pkt, int);		
int pppoe_session_entry(struct streaminfo_private *pfstream, const void *this_layer_hdr,
			int thread_num,unsigned char routedir, const raw_pkt_t *raw_pkt, int);

int gre_entry(struct streaminfo_private *fstream, const void *this_layer_hdr, 
		int thread_num,  unsigned char dir, const raw_pkt_t *raw_pkt, int);

int mpls_uc_entry(struct streaminfo_private *pfstream,const void *this_layer_data,int thread_num, 
						unsigned char routedir, const raw_pkt_t *raw_pkt, int);
int mpls_empty_entry(struct streaminfo_private *pfstream,const void *this_layer_data,int thread_num,
				  unsigned char routedir, const raw_pkt_t *raw_pkt, int);
int teredo_entry(struct streaminfo_private *pfstream,void *this_layer_data,int thread_num, 
		unsigned char routedir, const raw_pkt_t *raw_packet, int offset_to_raw_pkt_hdr);
int gtp_entry(struct streaminfo_private *pfstream,void *this_layer_data,int thread_num,
				 unsigned char routedir, const raw_pkt_t *raw_packet, int offset_to_raw_pkt_hdr);
int icmp_entry(struct streaminfo_private *fstream, const void *this_layer_hdr, 
	int thread_num, unsigned char dir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr)	;
//int MESA_sendpacket_ethlayer(int thread_num,const char *data, int data_len, unsigned char compat_no_use);		
int l2tpv2_entry(struct streaminfo_private *pfstream_pr,const void *this_layer_data,int thread_num, 
						unsigned char routedir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr);			
int mac_in_mac_entry(struct streaminfo_private *fstream_pr, const void *this_layer_hdr,int thread_num, 
			unsigned char dir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr);
#ifdef __cplusplus
}
#endif

#endif
