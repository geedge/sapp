#ifndef _APP_STREAM_INTERNAL_H_
#define _APP_STREAM_INTERNAL_H_ 

#include "stream_inc/stream_base.h"
#include "stream_inc/stream_project.h"
#include "stream_inc/stream_proxy.h"
#include "stream_inc/stream_tunnel.h"
#include "stream_register.h"
#include "stream_custom.h"
#include "stream_inc/stream_inject.h"
#include "stream_inc/stream_rawpkt.h"
#include "stream_inc/stream_control.h"
#include "mesa_net.h"
#include "sysinfo.h"
#include <MESA/MESA_handle_logger.h>

//#define STREAM_BASE_MD5_CHECK		"f9efd82ec3123dcb9075ea916e3936aa"
//#define STREAM_CONTROL_MD5_CHECK 	"f96fffb08330abde4e058db57ef63a43"
//#define STREAM_ENTRY_MD5_CHECK		"7dab86d65114ebe5438e85e0d008645d"
//#define STREAM_INJECT_MD5_CHECK		"3853e02b53c916979d1d4cba4df00d0b"
//#define STREAM_PROJECT_MD5_CHECK		"fc2b981f7e2c99e73d8857e206cb4977"
//#define STREAM_PROXY_MD5_CHECK		"25cec664c9b44a8cac29f6e3e117eaa6"
//#define STREAM_RAWPKT_MD5_CHECK		"7a2023151fe16d54dfefd2724413bcc6"
//#define STREAM_TUNNEL_MD5_CHECK		"d20aa6b4f5683b7b0040676547997be0"

#define IP_PORT_UNION_VERSION			(1) /* 是否将IP-PORT合并 */
#define COMPAT_PAPP_FOR_BENCHMARK	(0) /* 2015-01-07 lijia add, 同papp对比结果时, 临时关闭嵌套、各种隧道协议, 否则不一致 */
#define USE_RBTREE_INSTEAD_LIST		(0) /* 当HASH冲突时, 使用红黑树代替链表, 避免特殊情况下遍历 */
#define USE_LINUX_KERNEL_HASH_ALGO	(1) /* 使用LINUX内核HASH算法 */
//#define SAPP_AS_TARGET_SO				(1) /* 2017-05-17 lijia add, sapp以so形式, 以IP_ENTRY层挂载到另一个平台上运行 */

#define SAPP_INSECTICIDE				(0) /* 杀虫(DEBUG)临时开关, 在遇到莫名其妙的BUG时临时启用, 尽早发现问题, 早死早超生 */

#define CYCLE_PKT_DUMP				(1 && DEBUG) /* 2015-04-16 lijia add, 解决在线流量无故coredump, 但找不到原因 */

#define PCAP_CAP_FROM_IP				(0) /* 为了模拟pag等在线环境, 让pcap也模拟从IPv4头部开始获取 */

#define NON_PKT_THREAD_SEND_QUEUE		(64) /* 非包处理线程最大发送队列数量 */

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif
#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({			 \
	const typeof( ((type *)0)->member ) *__mptr = (ptr); \
	(type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#define sapp_get_struct_header(ptr, type, member)  container_of(ptr, type, member)

#define RAW_PKT_MAGIC_NUM		(0xF1E2D3C4) /* 1:用于兼容旧项目, 在call_old构造旧数据结构时,识别原始包的来源; 2:安全性检测 */

#ifdef __cplusplus
extern "C" {
#endif

/* 原始包结构 */
typedef struct {
	unsigned int magic_num; 
	int offset_to_raw_pkt_hdr;			/* 本层回调对应的数据在raw_pkt_data的偏移量 */
	enum addr_type_t low_layer_type;	/* 原始包最底层协议的类型, 可能是MAC(pcap捕包), 也可能是IPv4(pag捕包) */
	int __lib_raw_pkt_len;		/* 底层捕包库提供的包真实原始长度 */
	int raw_pkt_len;			/* 给上层应用看的原始包总长度, 有可能不是真实的, 比如跳过了Ethernet层 */
	unsigned int hd_hash; /* 网卡硬件计算的四元组HASH, 减少平台CPU计算消耗 */
	const void *__lib_raw_pkt_data; /* 底层捕包库提供的真实原始包指针 */
	const void *raw_pkt_data;	/* 给上层应用看的原始包头指针, 有可能跳过了Ethernet层, 根据low_layer_type判断协议类型 */
	struct timeval raw_pkt_ts;	/* 原始包捕获时间戳, 如果全为0则不支持此功能(如pag模式) */
	const void *io_lib_pkt_reference; /* 引用底层I/O库的原始包管理结构, 例如:对于marsio来说, 即底层的mbuf结构 */
}raw_pkt_t;


struct buf_unorder
{
	struct buf_unorder *next;
	struct buf_unorder *prev;
	//void *data; 
	//UINT32 len;	
	void *this_ip_hdr; /* 可能来源于真实原始包, 也可能来源于重组的IP分片包,靠'ip_reassemble_pkt'区别 */
	struct mesa_tcp_hdr *this_tcp_hdr;
	void *tcpdata; /* TCP的数据部分指针, 不含TCP头 */
	UINT16 tcpdatalen; /* TCP的数据部分长度 */
	UINT16 urg_ptr;
	char fin;
	char urg;
	char rst;   
	unsigned char ip_reassemble_pkt;
	UINT32 seq;
	UINT32 ack;
	raw_ipfrag_list_t *ipfrag_list; /* 如果当前包是IP分片重组的包, 需要存储所有IP分片包链表 */
	raw_pkt_t raw_pkt; /* 乱序包存储原始包 */
};

/*半流结构体定义：*/
struct half_tcpstream
{
  UCHAR *data;
  UINT32 offset;           /*data中第一个字节在TCP数据流中的偏移量*/
  UINT32 count;           /*从连接建立起到现在为止，到达的数据总长度字节数*/
  UINT32 count_new;        /*本次新到的数据字节数*/
  UINT32 count_ideal;      /*从连接建立起到现在为止，理论上应该到达的数据总长度*/
  UINT32 pktcout;          /*本侧累计到达的包个数, 包括重传包, ACK, 但不含SYN */
  UINT32 totallost;        /*本侧累计丢包长度*/
  UINT32 seq;              /*本侧数据期待的seq序号*/
  UINT32 first_data_seq;   /*本侧数据起始的的seq序号*/
  
  //UINT32 ack_seq;          /*本侧数据最后使用的应答号, 2017-08-02 lijia modify , 移动至struct tcpdetail_private */
  
  UINT16 window;           /*本侧数据滑动窗口大小*/
  UCHAR __pad__;
  UCHAR finstate;		    /*fin状态*/
  UINT16 unorder_cnt;/* 2014-11-27 lijia modify, 某些流乱序数巨大, UCHAR型不够, 扩展为UINT16 */
  UINT16 maxunorder; /* 2014-11-27 lijia modify, 某些流乱序数巨大, UCHAR型不够, 扩展为UINT16 */
  struct buf_unorder *unorderlist;	/*乱序包的链表*/
  struct buf_unorder *unorderlisttail;	/*乱序包的链表尾部指针*/
};

struct streaminfo_private
{
	/* 对外结构放置在结构体最前, 指针地址可以互相强转 */
	struct streaminfo stream_public;
	/* 以下变量为平台内部私有, 对外不可见 */
	void   *pproject;		//每个工程可以自定义使用；
	UCHAR  layer_dir:2;   /* 单包有效, 当前层的地址是否和默认规则"大端口是客户端"相同 */	
	UCHAR  stream_dir:2; /* 流的生存期内有效, 流的存储的地址是否和默认规则"大端口是客户端"相同  */		
	UCHAR  addr_use_as_hash:1; /* 本层的addr是否做为HASH计算和比较的参数, 如:MAC地址不参与计算 */
	UCHAR  addr_skip_for_layer_cmp:1;/*本层的addr是否作为地址比较的层级，如：MPLS地址不作为层数计算，直接跳过，该值默认为0，即需要比较*/
	UCHAR  need_update_opposite_addr:1;/*本层的addr是否在对侧来包时更新，如：MPLS标签非对称时需要在S2C侧第一个包记录本侧标签,该值默认为0，即不需要更新*/
	UCHAR  stream_killed_flag:1; /* 2014-08-22 lijia add, 串联模式下, 已经被插件Kill, 之后此流可直接Drop或Kill, 无需再给上层插件 */
	UCHAR  dirreverse;	     /* 建立连接时是否进行了ip地址反转, 即与"大端口是客户端"规则相反 */
	UINT16 timeout;/* 每个链接的独有超时时间, 此值有两个用途, 1:用于尽早淘汰长时间无包到达的流, 以节约内存; 2:用于保护长时间无包的流, 对于IM类长时间无包但连接并未结束, 可设置较大的timeout */
	unsigned short offset_to_raw_pkt_hdr; /* 本层头相对于原始包的起始地址的偏移量 */
	unsigned short offset_to_ip_hdr; /* 2015-12-07 lijia add, UDP/TCP 包头相对于承载的IP包头偏移量 */
	const raw_pkt_t *raw_pkt; /* 2014-12-30 lijia add, 有些回调函数不支持原始包, 但发包又需要, 存储于private结构中 */
	unsigned int hash_slave; /* 2015-12-14 lijia add, 使用linux_jhash计算时, 可以同时得到两个以上的HASH值, 主HASH用于确定在HASH表的SLOT位置, slave_HASH用于快速比较地址是否相等 */
	unsigned char hash_not_head_times;/* 2015-12-15 lijia add, 当前index不在HASH SLOT的第一位的次数 */
	unsigned char cur_layer_raw_hdr_len; /* 2017-10-31 lijia add, 当前层的原始包地址长度, 因ppp头部压缩, 原来版本无法保存这个状态, 发包时也无法得知地址如何填充 */
	char __pad;
	unsigned char gdev_block_timer;
	unsigned short stream_low_layer_tunnel_type; /* 2016-07-25 lijia add, 记录本流底层隧道类型, 0为非隧道, 其他详见:enum stream_carry_tunnel_t */
	unsigned short stream_carry_up_layer_tunnel_type; /* 当前流上层的隧道类型, 比如当前流为UDP, 承载的可能是teredo隧道或L2TP隧道 */
  
	/* 2016-07-08 lijia add, for janus hijack, 本应该存储于half_stream, 但刚收到SYN时, 还没有创建half_stream实体, 所以暂存于streaminfo_private */
	unsigned short syn_opt_num;
	unsigned short synack_opt_num;
	struct tcp_option *syn_opt_array;
	struct tcp_option *synack_opt_array;
};

struct tcpdetail_private
{
	/* 对外结构放置在结构体最前, 指针地址可以互相强转 */
	struct tcpdetail tcpdetail_public;
	UCHAR  multisynflag:2;	  // multi syn
	UCHAR  ignore_rst_fin:2;//不会因rst, fin结束, 只能因超时或lru结束
	UCHAR  needackflag:2;	  //需要上传ack报文
	UCHAR  takeoverflag:2;
	UCHAR  tcpstateflag;	   // 用于记录tcp的会话SYN相关状态
	UCHAR  link_state;		   // 链接的状态
	UCHAR  creat_mod;
	UINT16 tcpoverlen;		// modify by lqy 20150225, 记录当前包与上一个包的重叠tcp长度；
	UINT16 pad;				
	struct half_tcpstream *pclient;  //到client的TCP连接信息
	struct half_tcpstream *pserver;  //到 server的TCP连接信息
	UINT32 iserverseq;	  //链接建立时临时存储seq, C2S, ISN+1
	UINT32 iclientseq;	  //链接建立时临时存储seq, S2C, ISN+1
	/* NOTE:
		为何first_ack_seq不放在half_tcpstream里?
		因half_tcpstream是在收到第一个带有负载的包才分配的, 
		如果在tcp_deal_ack()函数中设置, 如果是S2C方向, 那么第一个S2C数据包到达时, 已经不是first_ack_seq了.
		还可以防止DDOS攻击.
	*/
	UINT32 C2S_first_ack_seq; /* 2017-08-02 lijia modify, C2S侧第一个ACK号, 和half_tcpstream->ack_seq一起可以计算出单向流对侧的数据总量 */
	UINT32 C2S_ack_seq;  /* 2017-08-02 lijia add, C2S侧当前的ACK号 */ 
	UINT32 S2C_first_ack_seq; /* 2017-08-02 lijia modify, C2S侧第一个ACK号, 和half_tcpstream->ack_seq一起可以计算出单向流对侧的数据总量 */
	UINT32 S2C_ack_seq;  /* 2017-08-02 lijia add, S2C侧当前的ACK号 */ 
	void   *apme;		  //应用层上下文
	void   *pAllpktpme;   //无状态的tcp管理上下文
	struct tcp_flow_stat *flow_stat; /* 2016-07-14 lijia add, 用于记录TCP纯data包的计数, 实际内存分配和释放由project模块完成, 可能为NULL,  */
	struct tcp_flow_stat *deduce_flow_stat; /* 2018-10-30 lijia add, 用于记录靠序号推断出理论上传输的数据, 包含丢包的长度; 以及单向流情况下, 对端应该收到的数据  */
};

struct udpdetail_private
{
	/* 对外结构放置在结构体最前, 指针地址可以互相强转 */
	struct udpdetail udpdetail_public;
	void   *apme;		  //应用层上下文
	struct udp_flow_stat *flow_stat; /* 2015-12-28 lijia add, udpdetail中的详细计数(64bit), 实际内存分配和释放由project模块完成, 可能为NULL */
};	

/* 2015-02-26 lijia add, for stream-addr-list ntop, pton */
typedef struct{
	struct streaminfo stream;
	char addr_value[MAX_ADDR_BIN_VALUE_LEN]; /* 为了paddr不用再malloc, 提高性能, 在stream后面追加一块缓存 */
}addr_continuous_bin_t;

typedef struct{
	enum addr_type_t addr_type_bin;
	UCHAR stream_type;/* 用于识别ADDR_TYPE_IPV4是TCP还是UDP */
	const char *addr_type_str;
	const char *addr_type_prefix;
	const char *addr_type_prefix_with_delim; /* 带分隔符的前缀, 用于比较字符串, 防止IPv4和IPv4_TCP字符串比较时混淆, 如果用IPv4:, IPv4_TCP:就不存在混淆风险 */
	int (*addr_n2p_fun)(const struct layer_addr *paddr, char *buf, int buf_len);
	int (*addr_p2n_fun)(char *addr_str, addr_continuous_bin_t *addr_bin_val);
}addr_convert_t;

struct pptp_stream_key{
	UINT32 sip;	/* TCP-SYN包的源IP, 如果是按data建连接, 根据pptp->message_type判断, REQ类请求包的源IP认为是sip */
	UINT32 dip;   /* sip,dip are network order */
	UINT16 sip_side_call_id; /* 网络数据包中由sip发出的GRE包的callid, 实际意义表示peer call id, network order */
	UINT16 dip_side_call_id; /* 网络数据包中由dip发出的GRE包的callid, 实际意义表示peer call id, network order */
	//struct streaminfo_private *stream_pr;  /* TODO, 用于保存地址链表, 目前仅用了最底层的IP和call_id */
};

/* PPTP协议解析层管理结构, sapp内部使用 */
struct pptp_info_pri{
	struct MESA_tunnel_info tunnel_context;
	struct pptp_stream_key pptp_key;
	stSessionInfo ssinfo; /* 调用业务层上下文信息 */
	void *biz_pme; /* 业务层自定义数据 */
	struct streaminfo *my_stream; /* pptp底层UDP流 */
	unsigned char threadnum; 
	char insert_hash_flag; /* 控制连接已将key插入HASH表 */
	char content_notify_biz_flag; /* 是否已经调用过业务插件, 告之content_type */	
};

/* 私有pptp地址, pptp_addr提供给业务插件, 其中gre_layer_len用于FD时快速识别本层头部长度 */
struct layer_addr_pptp_pri{
	struct layer_addr_pptp pptp_addr;
	int gre_layer_len;
};

struct l2tp_stream_key{
	UINT32 sip;	/* L2TP隧道主动发起方的IP, 即控制类型SCCRQ, ICRQ, SCCCN等包的源IP, network order */
	UINT32 dip;   /* L2TP隧道服务器端的IP, network order */
	UINT16 sport; /* network order */
	UINT16 dport; /* network order */
	UINT16 sip_side_tunnel_id; /* sip测发来包的tunnelid, network order */
	UINT16 sip_side_session_id; /* sip测发来包的tunnelid, network order */
	UINT16 dip_side_tunnel_id; /* dip测发来包的tunnelid, network order */
	UINT16 dip_side_session_id; /* dip测发来包的tunnelid, network order */
	//struct streaminfo_private *stream_pr;  /* TODO, 用于保存地址链表, 目前仅用了最底层的IP和call_id */
};

struct l2tp_info_pri{
	struct MESA_tunnel_info tunnel_context;
	struct l2tp_stream_key l2tp_key;
	stSessionInfo ssinfo; /* 调用业务层上下文 */
	void *biz_pme;
	const struct streaminfo *my_stream; /* l2tp底层UDP流 */
	unsigned char thread_seq;
	char content_notify_biz_flag; /* 是否已经调用过业务插件, 告之content_type */	
};

/* 全局唯一的全局变量, 通常是开关类配置项, 或不常变化的全局变量, 如流表数等, 多用于只读 */
struct sapp_global_single_t{
	int signal_take_over_sw; /* 是否接管常见系统信号, 如SIGSEGV, SIGABRT等等 */
	int ipentry_priority_over_ipfrag; /* IP_entry优先级高于IP_frag_entry, 默认为0, 适应WY串联特定需求 */
	int tuple4_reuse_time_interval; /* 四元组重用的最小间隔时间 */
	void *fs2_handle;
	const char *fs2_server_ip;
	unsigned short fs2_server_port_host;
	short __pad1;
	int fs2_filed_id_array[COUNTER_NUM];
	int fs2_latency_id_array[COUNTER_NUM];
	int treat_vlan_as_mac_in_mac_sw;
};

#define TIMESTAMP_SINGLE_PKT_REGION 		(4) /* 单包延时统计区间 */
#define TIMESTAMP_SINGLE_PKT_REGION_MAX     (5) /* 包括超过统计区间的值 */
typedef struct{
	unsigned int runtime_pkt_max_delay; /* 单包最大处理延时 */
	unsigned long long pkt_total_num[TIMESTAMP_SINGLE_PKT_REGION_MAX]; /* 记录包处理延时的总包数, 按区域统计 */
	unsigned long long pkt_total_time; /* 最近一段时间的总延时, 用于计算平均单包处理延时 */
}timestamp_record_region_t;
/* 多线程全局变量, 例如数据包统计信息, 通常值会实时变化 */
struct sapp_global_mthread_t{
	int ipv6_pkt_type_flag; /* ipv6 packet type, normal, or rebuild */
	int pptp_hash_max_search_times;
	int l2tp_hash_max_search_times;
	char __pad1[4];
	double pptp_hash_avg_search_times;
	double l2tp_hash_avg_search_times;
	int tcp_stream_special_timeout_num; /* 设置单独超时时间的流, 默认不允许超过总流表的10% */
	int udp_stream_special_timeout_num;/* 设置单独超时时间的流, 默认不允许超过总流表的10% */
	timestamp_record_region_t runtime_record; /* 平台单包处理延时 */
	timestamp_record_region_t runtime_record_driver; /* 驱动从网卡拿到包, 到平台拿到包的延时 */
	char __pad2__[40];
};

extern struct sapp_global_single_t sapp_global_single;
extern struct sapp_global_mthread_t sapp_global_mthread[MAX_THREAD_NUM];

extern int G_SKIP_NOT_IP_LAYER;
extern int g_sapp_log_level;
extern void *g_sapp_log_handle;

#define sapp_runtime_log(log_level, format, args...)  do{if(log_level>=g_sapp_log_level){MESA_handle_runtime_log(g_sapp_log_handle, log_level, "sapp", format, ##args);}}while(0)


int MESA_kill_tcp_remedy(struct streaminfo *stream, const void *ext_raw_pkt);

int get_stream_carry_tunnel_type(const struct streaminfo *this_stream, const struct streaminfo *upper_stream, unsigned short *tunnel_type);

void cycle_pkt_dump(int thread_seq, const raw_pkt_t *p_raw_pkt);
char biz_retval_to_platform(char biz_ret);
char plat_state_to_biz(char plat_state);
void idle_polling_call(int thread_seq);
int sapp_identify_broad_multicast_pkt(const void *this_layer_data, const raw_pkt_t *raw_pkt);
int sapp_assistant_init(void);

static inline long long sapp_get_cpu_cycle(void)
{
#ifdef __x86_64
#define X86_64_ENV 1
#endif
#ifdef  __x86_64__
#define X86_64_ENV 1
#endif

#ifdef X86_64_ENV
	 long long l;
	 long long h;

	__asm__ volatile("rdtsc" : "=a"(l), "=d"(h));
	return (long long )l | ((long long )h<<32);
#else
	return 0;
#endif
}
#ifdef __cplusplus
}
#endif

#endif

