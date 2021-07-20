#ifndef _APP_STREAM_INTERNAL_H_
#define _APP_STREAM_INTERNAL_H_ 

#include "public/stream.h"
#include "private/mesa_net.h"
#include "private/sysinfo.h"
#include "MESA_handle_logger.h"
#include "mesa_pkt_dump.h"

//#define STREAM_BASE_MD5_CHECK		"dd09b3b11993cc835200db477dad7d4b"
//#define STREAM_CONTROL_MD5_CHECK 	"75aab0821e489b84355fa22ad02a2e78"
//#define STREAM_ENTRY_MD5_CHECK		"7dab86d65114ebe5438e85e0d008645d"
//#define STREAM_INJECT_MD5_CHECK		"1e25b7a8cd812db2ad261264b6783d64"
//#define STREAM_PROJECT_MD5_CHECK		"fc2b981f7e2c99e73d8857e206cb4977"
//#define STREAM_PROXY_MD5_CHECK		"25cec664c9b44a8cac29f6e3e117eaa6"
//#define STREAM_RAWPKT_MD5_CHECK		"48fdc3294bced1c74a853e197db8fd67"
//#define STREAM_TUNNEL_MD5_CHECK		"d20aa6b4f5683b7b0040676547997be0"

#define IP_PORT_UNION_VERSION			(1) /* 是否将IP-PORT合并 */
#define COMPAT_PAPP_FOR_BENCHMARK	(0) /* 2015-01-07 lijia add, 同papp对比结果时, 临时关闭嵌套、各种隧道协议, 否则不一致 */
#define USE_RBTREE_INSTEAD_LIST		(0) /* 当HASH冲突时, 使用红黑树代替链表, 避免特殊情况下遍历 */
#define USE_LINUX_KERNEL_HASH_ALGO	(1) /* 使用LINUX内核HASH算法 */

#define SAPP_INSECTICIDE				(0) /* 杀虫(DEBUG)临时开关, 在遇到莫名其妙的BUG时临时启用, 尽早发现问题, 早死早超生 */

//#define CYCLE_PKT_DUMP				(1 && DEBUG) /* 2015-04-16 lijia add, 解决在线流量无故coredump, 但找不到原因 */
#define CYCLE_PKT_DUMP				(1) /* 2015-04-16 lijia add, 解决在线流量无故coredump, 但找不到原因 */

#define PCAP_CAP_FROM_IP				(0) /* 为了模拟pag等在线环境, 让pcap也模拟从IPv4头部开始获取 */

//#define NON_PKT_THREAD_SEND_QUEUE		(64) /* 纯发包处理线程最大发送队列数量 */

#define IKNOW_ENABLE					(0)

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
	int route_dir;
	int device_index;/* 有多块网卡时, 要保证从哪个卡进就从哪个卡出 */
	int is_overlay_pkt; /* 表示是真实链路中的数据包, 要无条件回注, 即本机看起来像一根网线; 否则要丢弃 */
	unsigned short vlan_flipping_couple[2]; /*2020-09-28 lijia add, in host order, vlan flipping for adev, index0表示收到当前包的vlan_id, index1表示原包转发的vlan_id */
	unsigned char mac_flipping_enable;
	char diagnose_error_to_dump; /* 是某种错误数据包, 期望pkt_dump存储或udp socket发送给tcpdump_mesa */
	unsigned char overlay_layer_bytes; /* 串联封装层长度, 比如vxlan模式下是50字节 */
	char drop_current_pkt_flag; /* 插件调用MSO_DROP_CURRENT_PKT设置丢弃当前包, 每次处理完要清空 */
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

/* 保存每个流两个方向第一个包, 用于polling entry发包使用 */
typedef struct {
	const raw_pkt_t *raw_pkt_up;
	const raw_pkt_t *raw_pkt_down;
}polling_inject_context_t;

struct streaminfo_private
{
	/* 对外结构放置在结构体最前, 指针地址可以互相强转 */
	struct streaminfo stream_public;
	struct streaminfo_private *pfather_pr; /* 真实流量的上层流指针, 包括了vxlan等封装层, stream_public.pfather是给业务插件看的,不包括vxlan层的 */
	/* 以下变量为平台内部私有, 对外不可见 */
	void   *pproject;		//每个工程可以自定义使用；

	/* ---8 bytes-- */
	UCHAR  layer_dir:2;   /* 单包有效, 当前层的地址是否和默认规则"大端口是客户端"相同 */	
	UCHAR  stream_dir:1; /* 流的生存期内有效, 流的存储的地址是否和默认规则"大端口是客户端"相同  */		
	UCHAR  stream_c2s_route_dir:1; /* c2s方向的包, 对应的链路route dir方向, 用于获取inbound, outbound流量 */
	UCHAR  addr_use_as_hash:1; /* 本层的addr是否做为HASH计算和比较的参数, 如:MAC地址不参与计算 */
	UCHAR  __pad1:1;/*因MPLS两侧不对称, 尤其是还有一边有MPLS, 另一端没有MPLS的流, 此变量=1表示虚拟构建的层, 解析时不作为地址比较, 发包时也要跳过 */
	UCHAR  need_update_opposite_addr:1;/*本层的addr是否在对侧来包时更新，如：MPLS标签非对称时需要在S2C侧第一个包记录本侧标签,该值默认为0，即不需要更新*/
	UCHAR  stream_killed_flag:1; /* 2014-08-22 lijia add, 串联模式下, 已经被插件Kill, 之后此流可直接Drop或Kill, 无需再给上层插件 */
	UCHAR  dirreverse;	     /* 建立连接时是否进行了ip地址反转, 即与"大端口是客户端"规则相反 */
	UINT16 timeout;/* 每个链接的独有超时时间, 此值有两个用途, 1:用于尽早淘汰长时间无包到达的流, 以节约内存; 2:用于保护长时间无包的流, 对于IM类长时间无包但连接并未结束, 可设置较大的timeout */
	unsigned short offset_to_raw_pkt_hdr; /* 本层头相对于原始包的起始地址的偏移量 */
	unsigned short offset_to_ip_hdr; /* 2015-12-07 lijia add, UDP/TCP 包头相对于承载的IP包头偏移量 */
	/* ===8 bytes=== */
	const raw_pkt_t *raw_pkt; /* 2014-12-30 lijia add, 有些回调函数不支持原始包, 但发包又需要, 存储于private结构中 */

	/* ---8 bytes-- */
	unsigned int hash_slave; /* 2015-12-14 lijia add, 使用linux_jhash计算时, 可以同时得到两个以上的HASH值, 主HASH用于确定在HASH表的SLOT位置, slave_HASH用于快速比较地址是否相等 */
	unsigned char hash_not_head_times;/* 2015-12-15 lijia add, 当前index不在HASH SLOT的第一位的次数 */
	unsigned char cur_layer_raw_hdr_len; /* 2017-10-31 lijia add, 当前层的原始包地址长度, 因ppp头部压缩, 原来版本无法保存这个状态, 发包时也无法得知地址如何填充 */
	char __pad:3;
	char packet_io_context:1; /* 2019-09-07 lijia add, for polling entry send packet */
	unsigned char stream_close_reason:4; /* 2019-02-14 lijia add, 对于TCP使用tcpdetail_private的link_state变量, 对于UDP之前没有, 拆分pad新增此变量 */
	unsigned char gdev_block_timer;
	/* ===8 bytes=== */

	/* ---8 bytes-- */
	unsigned short stream_low_layer_tunnel_type; /* 2016-07-25 lijia add, 记录本流底层隧道类型, 0为非隧道, 其他详见:enum stream_carry_tunnel_t */
	unsigned short stream_carry_up_layer_tunnel_type; /* 当前流上层的隧道类型, 比如当前流为UDP, 承载的可能是teredo隧道或L2TP隧道 */
	/* 2016-07-08 lijia add, for janus hijack, 本应该存储于half_stream, 但刚收到SYN时, 还没有创建half_stream实体, 所以暂存于streaminfo_private */
	unsigned short syn_opt_num;
	unsigned short synack_opt_num;
	/* ===8 bytes=== */
	
	struct tcp_option *syn_opt_array;
	struct tcp_option *synack_opt_array;

	polling_inject_context_t *polling_inject_context;

	/* 全局流id, stream_index历史上已经表示单机内唯一id, 此处要保证集群所有机器不重复, 所以新建变量;  
		高位 --- 低位
		1 |  12bit device_id | 8bit thread_id | 28bit timestamp in sec | 15bit sequence per thread
	*/
	unsigned long long global_stream_id; 
	unsigned long long stream_create_timestamp_ms; 
	/* ===8 bytes=== */
	unsigned char layer_index:4; /* 表示当前层的计数, 从最底层开始,一般是ethernet开始, 从0开始计数, 4bit最多支持15层嵌套, 也能防止隧道嵌套攻击(目前还没捕到过包) */
	unsigned char create_dir_by_well_known_port:1;  /* UDP或TCP按data建连接, 命中well_known_port规则, 而不是按大端口是客户端原则创建流 */
	char __pad2:3;
	char has_duplicate_pkt; /* 当前流曾经有过重复数据包, 后续的流量应该每个都检测 */
	char __pad3[6];
	/* ===8 bytes=== */
	
	void   *stream_bridge;	/* 20210425 lijia add, 类似project功能, 支持同步和异步两种模式, 原有project类似异步模式 */
};

struct tcpdetail_private
{
	/* 对外结构放置在结构体最前, 指针地址可以互相强转 */
	struct tcpdetail tcpdetail_public;
	
	/* ---8 bytes-- */
	UCHAR  multisynflag:2;	  // multi syn
	UCHAR  ignore_rst_fin:1;  //不会因rst, fin结束, 只能因超时或lru结束
#if 0	
	UCHAR  tcpall_valid_after_kill:1;  //kill_tcp后, TCPALL插件依然有效, 继续处理后续数据包
#else
	UCHAR  drop_stream_flag:1; //2019-11-20 lijia add, 语义同DROPPKT, 只不过作用域是整个stream
#endif
	UCHAR  auto_remedy_flag:1;	  //是否启用FD补救
	UCHAR  needackflag:1;	  //需要上传ack报文
	UCHAR  takeoverflag:1;
	UCHAR  has_lost_pkt_flag:1;		//2020-08-23 lijia add, 本流曾经丢过包标志位
	UCHAR  tcpstateflag;	   // 用于记录tcp的会话SYN相关状态
	UCHAR  link_state;		   // 链接的状态
	UCHAR  creat_mod;
	UINT16 tcpoverlen;		// modify by lqy 20150225, 记录当前包与上一个包的重叠tcp长度；
	UINT16 pad;			
	/* ===8 bytes=== */
	
	struct half_tcpstream *pclient;  //到client的TCP连接信息
	struct half_tcpstream *pserver;  //到 server的TCP连接信息
	UINT32 iserverseq;	  //链接建立时临时存储seq, 此值是C2S->SYN+1
	UINT32 iclientseq;	  //链接建立时临时存储seq, 此值是S2C->SYN+1
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
	UCHAR  drop_stream_flag; //2020-06-02 lijia add, 语义同DROPPKT, 只不过作用域是整个stream
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
	const char *addr_type_string_abbreviation;
}addr_convert_t;

struct pptp_stream_key{
	UINT32 sip;	/* TCP-SYN包的源IP, 如果是按data建连接, 根据pptp->message_type判断, REQ类请求包的源IP认为是sip */
	UINT32 dip;   /* sip,dip are network order */
	UINT16 sip_side_call_id; /* 网络数据包中由sip发出的GRE包的callid, 实际意义表示peer call id, network order */
	UINT16 dip_side_call_id; /* 网络数据包中由dip发出的GRE包的callid, 实际意义表示peer call id, network order */
	//struct streaminfo_private *stream_pr;  /* TODO 1, 用于保存地址链表, 目前仅用了最底层的IP和call_id */
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
	//struct streaminfo_private *stream_pr;  /* TODO 1, 用于保存地址链表, 目前仅用了最底层的IP和call_id */
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

#define STATSD_SEND_MSS	(1472)
/* 全局唯一的全局变量, 通常是开关类配置项, 或不常变化的全局变量, 如流表数等, 多用于只读 */
struct sapp_global_single_t{
	int signal_take_over_sw; /* 是否接管常见系统信号, 如SIGSEGV, SIGABRT等等 */
	int ipentry_priority_over_ipfrag; /* IP_entry优先级高于IP_frag_entry, 默认为0, 适应WY串联特定需求 */
	//int kill_tcp_with_gdev; /* FD未生效时, 借助gdev串联规则 */
	int cfg_send_tcp_offload_sw; /* 超过网卡MTU时, 主动切片成多个小于MTU的包发送 */
	//int cfg_kill_tcp_rst_num; /* kill_tcp发送rst包数量 */
	//int cfg_kill_tcp_rst_signature; /* kill_tcp发送的rst是否需要指纹信息, 用于识别 */
    //int tuple4_reuse_time_interval; /* 四元组重用的最小间隔时间 */
	//void *fs2_handle;
	const char *fs2_server_ip;
	unsigned short fs2_server_port_host;
	short __pad1;

	//int send_fake_pkt_mode; /* 2018-10-26 lijia add, for PanGu, 由于缺少FD路由, 需借用串联GDEV发送rst包, DNS-fake包等,mode 0： 协议栈三层发包， 1：协议栈二层发包，3：gdev注入发包，此模式下send_fake_pkt_gdev_sport有效 */
	//int send_fake_pkt_gdev_sport;  /* 2018-10-26 lijia add, for PanGu, 用于选择vxlan源端口 */
	int send_fake_pkt_sip;	
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
	timestamp_record_region_t runtime_record;
	timestamp_record_region_t runtime_record_driver; /* 驱动从网卡拿到包, 到平台拿到包的延时 */
}__attribute__ ((aligned (64)));

typedef struct{
	unsigned int magic; /* malloc后填充0x4D4D4D4D,  即MMMM 的16进制; free后填充0xFEFEFEFE */
	unsigned int user_buf_size;
}sapp_private_mem_t;


extern struct sapp_global_single_t sapp_global_single;
extern struct sapp_global_mthread_t sapp_global_mthread[MAX_THREAD_NUM];
extern int g_overlay_layer_set[__ADDR_TYPE_MAX][SAPP_SUPPORT_LAYER_NUM_MAX]; 
int MESA_kill_tcp_remedy(struct streaminfo *stream, const void *ext_raw_pkt);

long long sapp_get_cpu_cycle(void);

int get_stream_carry_tunnel_type(const struct streaminfo *this_stream, const struct streaminfo *upper_stream, unsigned short *tunnel_type);

void cycle_pkt_dump(int thread_seq, const raw_pkt_t *p_raw_pkt);
void cycle_diagnose_pkt_dump(int thread_seq, const raw_pkt_t *p_raw_pkt);
void cycle_pkt_dump_by_classify(int thread_seq, const raw_pkt_t *p_raw_pkt, enum _pkt_classify class_val);

char biz_retval_to_platform(char biz_ret);
char plat_state_to_biz(char plat_state);

void idle_polling_call(int thread_seq);
int gdev_block_send_rule(const struct streaminfo *pstream);
int gdev_block_init(void);
int sapp_identify_broad_multicast_pkt(const void *this_layer_data, const raw_pkt_t *raw_pkt);
int sapp_identify_tunnel_inner_pkt(const raw_pkt_t *raw_pkt);
int sapp_assistant_init(void);
int save_polling_inject_context(struct streaminfo_private *pstream_pr, const raw_pkt_t *raw_pkt);
void free_polling_inject_context(struct streaminfo_private *pstream_pr);
int update_polling_inject_context(struct streaminfo_private *pstream_pr, const raw_pkt_t *raw_pkt);
unsigned long long get_global_stream_id(unsigned long long thread_seq);
enum sapp_state_t sapp_get_current_state(void);
extern struct streaminfo_private *copy_stream_info_to_heap(const struct streaminfo_private *stack_stream, int reverse);
enum addr_type_t addr_type_abbreviation_pton(const char *addr_type_abbreviation);
const char *addr_type_abbreviation_ntop(enum addr_type_t addrtype);
int sapp_identify_broad_multicast_init(void);

int plugin_manage_init(void);
void  *plugin_get_plug_entry(const char *plug_name, const char *plug_entry_type);
int libsapp_setup_env(int argc, char *argv[]);
void *stream_bridge_create_per_stream(int thread_num);
void stream_bridge_destroy_per_stream(const struct streaminfo *stream, void *pbridge);
char *sapp_strdup(const char *raw_s);
int MESA_mkdir_p(const char *pathname, mode_t mode);
int sapp_get_secondary_file_path(void);
void sapp_update_config_root_dir(const char *cfg_root_dir);
void sapp_update_data_root_dir(const char *data_root_dir);
int sapp_is_absolute_path(const char *filename);
char *sapp_memmove_for_blank_table(char *data, int max_len);
void del_last_rn(char *data, int max_len);
void sapp_printf_colorful(int level, const char *format, ...);
int set_transport_addr(struct streaminfo *this_stream, int enable_well_known_port, UINT16 sport, UINT16 dport);
long long sapp_random(void);
int sapp_usleep(int usec);

void *sapp_mem_alloc(int size);
void sapp_mem_free(void *data);
void *sapp_mem_realloc(void *old_ptr, int size);



#ifdef __cplusplus
}
#endif

#endif

