////////////////////////////////////////
///@file libpag.h
///
///@brief netfirm2.0的pag接口头文件，包括流还原和正则式匹配
///
///修改记录:
///
///@author mingyr@sugon.com
///@date 2012-11-22
///将乃军在2.0项目中所作的配置分流比例功能移植到3.0
///
///@author jinj@sugon.com
///@date 2011-05-16
///
///修改发包实现原理，为发包函数增加时间戳参数以填充附加包头信息
///
///@author liuzhh@dawning.com.cn
///@date 2010-05-23
///增加了避免重复包含的_PAG_STREAM_宏，去掉了pag_delstream的流编号参数
///
///@author liuzhh@dawning.com.cn
///@date 2010-05-15
///联调应用中发现应用在新建连接时要给tcp_stream中的应用数据指针malloc分配空间，
///为提高性能，增加app_info_struct结构，避免应用malloc
///
///@author liuzhh@dawning.com.cn
///@date 2009-11-10
///
///建立文档
////////////////////////////////////////

#ifndef _LIBPAG_H_
#define _LIBPAG_H_

#ifdef __cplusplus
extern "C"
{
#endif

//////////// 头文件 ///////////
#include <linux/types.h>
#include <netinet/in.h>
#include <stdint.h>

////////// 宏定义 ///////////////

///@name 五元组分类的规则类型
//@{
#define FILTER_TYPE_1  1
#define FILTER_TYPE_2  2
#define FILTER_TYPE_3  3
#define FILTER_TYPE_4  4
#define FILTER_TYPE_5  5
#define FILTER_TYPE_6  6
#define FILTER_TYPE_7  7
#define FILTER_TYPE_8  8
#define FILTER_TYPE_9  9
#define FILTER_TYPE_10    10
#define FILTER_TYPE_11    11
#define FILTER_TYPE_12    12
#define FILTER_TYPE_13    13
#define FILTER_TYPE_14    14
#define FILTER_TYPE_15    15
#define FILTER_TYPE_16    16
//@}

///@name 五元组规则的过滤动作
//@{ 
#define FILTER_ACTION_PASS   0   ///<放行报文
#define FILTER_ACTION_DROP   1   ///<丢弃报文
#define FILTER_ACTION_SYNPASS  2   ///<丢弃当前连接报文,看到SYN(新连接)删除规则，放行报文
//@}

///@name 对五元组规则的操作
//@{
#define FILTER_RULE_ADD      0       ///<增加规则
#define FILTER_RULE_DEL   1       ///<删除规则
//@}


///@name 发FD包类型
//@{
enum rule_action_id
{
    OP_NONE = 0,
    OP_SYN_RST,
    OP_SYN_FIN,
    OP_RST,
    OP_FIN,
    OP_SYN_RST_ACK,
    OP_SYN_FIN_ACK,
    OP_RST_ACK,
    OP_FIN_ACK,
};

//@}

///@name 发日志包类型
//@{
enum rule_log_id
{
    LOG_NONE = 0,  ///< 不记日志
    LOG_S,           ///<记录日志信息
    LOG_M,           ///<转发报文信息
};
//@}                    


///@name tcp连接状态
//@{
#define NIDS_HALF_EST 0
#define NIDS_JUST_EST 1
#define NIDS_DATA  2
#define NIDS_CLOSE 3
#define NIDS_RESET 4
#define NIDS_TIME_OUT 5
//@}

///@name tcp连接方向
//@{
#define DIR_C2S 0x1
#define DIR_S2C 0x2
#define DIR_DOUBLE 0x3
//@}

///@name 应用层协议
//@{
#define PME_PROTO_UNKNOWN    0
#define PME_PROTO_HTTP        1
#define PME_PROTO_FTP        2
#define PME_PROTO_TELNET    3
#define PME_PROTO_SMTP        4
#define PME_PROTO_POP3        5
#define PME_PROTO_SOCKS        6
#define PME_PROTO_PD        7
#define PME_PROTO_WEBMAIL    8
#define PME_PROTO_IMAP        12
#define PME_PROTO_ICQ        13
#define PME_PROTO_MSN        14
#define PME_PROTO_YMSG        15
#define PME_PROTO_DNS        16        
#define PME_PROTO_NETSEND    17        
#define PME_PROTO_MMS        18        
#define PME_PROTO_RTSP        19        
#define PME_PROTO_EMULE        20    
//@}

///@name 增加处理IPV4、IPV6双栈的隐藏结构定义
//@{
typedef struct pkt_header packet_t;

//@} 

///@name Zhuanyong网卡五元组分类相关结构
//@{

///五元组规则结构体
struct filter_full_rule
{
    __u32 sip;                      ///<源ip 
    __u32 dip;                      ///<目的ip 
    __u16 sport;                  ///<源端口
    __u16 dport;                  ///<目的端口

    __u32 ruleid;                ///<规则id
    __u8 optype;                 ///<操作类型：增加或者删除规则 
    __u8 ruletype;               ///<规则类型
    __u8 iaction;                ///<对捕获报文的处理动作(pass,drop,synpass)
    __u8 send_action;            ///<发包动作(发送不同的报文 )
    __u8 log_action;             ///<发日志（发送不同的日志）
    __u8 protocol;               ///<协议类型
    __u16 pad;                   ///<保留
};

///IPV6五元组规则结构体
struct filter_full_rule_v6
{
    struct in6_addr sip;        ///<源ip
    struct in6_addr dip;        ///<目的ip
    __u16 sport;                 ///<源端口
    __u16 dport;                 ///<目的端口

    __u32 ruleid;                ///<规则id
    __u8 optype;                 ///<操作类型：增加或者删除规则 
    __u8 ruletype;               ///<规则类型
    __u8 iaction;                ///<对捕获报文的处理动作(pass,drop,synpass)
    __u8 send_action;            ///<发包动作(发送不同的报文 )
    __u8 log_action;             ///<发日志（发送不同的日志）
    __u8 protocol;               ///<协议类型
    __u16 pad;                   ///<保留
    
};

///日志包附加头结构体
struct _logrz 
{    
    __u32 src_ip;        //访问者IP
    __u32 dst_ip;        //被访问者IP
    __u16 src_port;      //访问者端口号
    __u16 dst_port;    //被访问者端口号
    __u32 local_ip;    //处理机IP，即本机IP
    __u32 time;    //发现时间
    __u32 rule_id;    //配置ID
    __u8 rule_type;    //配置类型
    __u8 proto;    //协议( 17:TCP 6:UDP)    
    __u16 pktlen;    //负载报文长度
};

//@}

#ifndef _PAG_STREAM_  //避免应用多次包含
#define _PAG_STREAM_

///@name tcp还原相关结构
//@{


///四元组 
struct tuple4 
{
  u_short source;             ///<源端口
  u_short dest;               ///<目的端口
  u_int saddr;                ///<源ip
  u_int daddr;                ///<目的ip
};

struct tuple4_v6
{
    struct in6_addr sip;        ///<源ip
    struct in6_addr dip;        ///<目的ip
    u_short sport;              ///<源端口
    u_short dport;              ///<目的端口
};

///半流结构体
struct half_stream
{
    char *data;                ///<收到的TCP负载数据
    u_int offset;            ///<data中第一个字节在TCP数据流中的偏移量
    u_int count;             ///<从连接建立起到现在为止，到达的数据总长度字节数
    u_int count_new;         ///<本次新到的数据字节数
    u_int count_ideal;       ///<从连接建立起到现在为止，理论上应该到达的数据总长度
    u_int pktcount;          ///<本侧累计到达的包个数
    u_int pktcount_new;      ///<本次新到达的包个数
    u_int seq;               ///<本侧数据期待的seq序号
    u_int first_data_seq;    ///<本侧数据起始的的seq序号
    u_int ack_seq;           ///<本侧数据最后使用的应答号    
    u_short window;          ///<本侧数据滑动窗口大小
    u_short pad;             ///<预留补齐
    u_int *sigpktlen;     ///<单包长度数组,数组长度为    pktcout_new
    u_char *tcpflag;         ///<单包的flag组,数组长度为    pktcout_new
    void *pktinfo;       ///<单包其它信息数组，预留，数组长度为    pktcout_new
};  

/// 应用需要的结构
struct app_info_struct
{
    char op_state;
    char op_flag;
    short pad;
    void *listeners;
};

///流结构体
struct tcp_stream 
{
    struct tuple4 addr;      ///<通讯双方的四元组
    u_char nids_state;       ///<当前链接的状态
    u_char dir;              ///<当前四元组捕获的数据链路的方向
    u_char appproto;         ///<当前链接的应用层协议类别
    u_char thread_num;       ///<当前链接所在队列号
    struct half_stream client;    ///<到client的TCP连接信息
    struct half_stream server;    ///<到 server的TCP连接信息
    struct app_info_struct appinfo;  ///<应用层信息指针,链接刚建立为NULL,由应用层赋值,并且在后继过程中使用
};

///上传给应用的结构体
struct pktinfo
{
    u_char ipproto; ///<ip层协议类别，0x06 TCP 0x11 UDP 进行重组的数据的ip协议，未重组的一律为0    
    void *pdata; ///<流结构体，或者ip重组后的ip报文
};

//@}

///@name 327项目定义诊断接口结构
//@{
typedef struct _pag_stat_tag_
{
    uint32_t thr_num; ///<收包缓冲区数目
    
    uint64_t rx_pkts[64]; ///<每个收包线程上收到的报文总数
    uint64_t rx_bytes[64]; ///<每个收包线程上收到的报文总字节数
    uint64_t rx_drop_pkts[64]; ///<每个收包线程上丢的报文总数
    uint64_t rx_drop_bytes[64]; ///<每个收包线程上丢的报文总字节数
    uint64_t rx_buf_used[64]; ///<每个收包缓冲区上使用的字节数
    uint64_t rx_buf_free[64]; ///<每个收包缓冲区上空闲的字节数
    
    uint64_t tx_pkts[64]; ///<每个发包线程上收到的报文总数
    uint64_t tx_bytes[64]; ///<每个发包线程上收到的报文总字节数
    uint64_t tx_drop_pkts[64]; ///<每个发包线程上丢的报文总数
    uint64_t tx_drop_bytes[64]; ///<每个发包线程上丢的报文总字节数
    uint64_t tx_buf_used[64]; ///<每个发包缓冲区上使用的字节数
    uint64_t tx_buf_free[64]; ///<每个发包缓冲区上空闲的字节数
}pag_stat_t;
//@}

///@name 用户定义收包附加头结构
//@{

struct pkt_header_ex
{
    uint64_t timestamp;           ///<时间戳
    uint16_t packet_len;          ///<L2报文长度
    uint16_t total_len;           ///<packet_len + sizeof(struct pkt_header_ex) + 4字节对齐值
    uint16_t port;                 ///<报文进来的端口号
    uint16_t app_data_offset;    ///<payload在缓存区内的偏移
}__attribute__((packed));

//@}
#endif  //_PAG_STREAM_

///五元组分流比例规则结构体
struct ratio_rule
{
    __u32 sip;                   ///<源ip
    __u32 dip;                   ///<目的ip
    __u16 sport;                 ///<源端口
    __u16 dport;                 ///<目的端口

    __u32 ruleid;                ///<规则id
    __u8 optype;                 ///<操作类型：增加或者删除规则
    __u8 ruletype;               ///<规则类型
    __u8 iaction;                ///<对捕获报文的处理动作(pass,drop,synpass)
    __u8 send_action;            ///<发包动作(发送不同的报文 )
    __u8 log_action;             ///<发日志（发送不同的日志）
    __u8 protocol;               ///<协议类型

    char rule[256];              ///分流比例字符串，如"0:0:1:1"
};


////////////////  API函数  //////////

///@name 设备接口
//@{

///@brief 根据配置文件打开设备
///@return  成功返回1，失败返回－1
int pag_open();


///@brief 关闭设备
void pag_close();

//@}


///@name 收包接口
//@{


///@brief 从网卡的一个数据队列中读取一个IP包;
///@param sid 收包数据流的序号（0开始的连续数字）。
///@return 报文的IP头指针；如果没有报文，则返回NULL。
void *pag_get(int sid);

///@brief 获取packet_t结构指针
///@param sid 收包数据流的序号（0开始的连续数字）。
///@return packet_t指针；如果没有报文，则返回NULL。
packet_t *pag_get_packet(int sid);

///@brief 获取帧头
///@param packet_t指针
inline void *pag_get_frame(packet_t *);

///@brief 获取帧长度
inline __u16 pag_get_frame_length(packet_t *);

#ifdef _CONFIG_SUPPORT_MAC_IN_MAC
inline __u16 pag_get_frame_type(packet_t *);
#else
///@brief 获取帧类型
///@brief 返回值为0表示为以太帧，为1表示为HDLC帧，为2表示为MAC IN MAC帧
inline __u8 pag_get_frame_type(packet_t *);
#endif

///@brief 获取最内层网络层数据
///@param packet_t 结构指针
inline void *pag_get_ip(packet_t *);

///@brief 获取最内层网络层数据长度
inline __u16 pag_get_ip_length(packet_t *);

///@brief 获取最内层传输层数据
///@param packet_t 结构指针
inline void *pag_get_tdp(packet_t *);

///@brief 获取最内层传输层数据长度
inline __u16 pag_get_tdp_length(packet_t *);

///@brief 获取应用层数据偏移，即payload的偏移
///@param packet_t 结构指针
///@return 附加包头内的应用数据偏移
inline void *pag_get_payload(packet_t *);

///@brief 获取最内层payload数据的长度
inline __u16 pag_get_payload_length(packet_t *);

///@brief 获取网络层协议
///@param packet_t 结构指针
///@return 附加包头内的网络层协议
inline __u8 pag_get_nl_proto(packet_t *);

///@brief 获取报文时间戳，只要顺序标识，不需要准确时间
///@param packet_t 结构指针
///@return 附加包头内的时间戳
inline __u64 pag_time(packet_t *);

///@brief 释放缓冲区，这里不支持乱序操作，为空函数
inline void pag_free(int sid, void *pkt);

#ifdef _CONFIG_SUPPORT_MAC_IN_MAC
packet_t *pag_get_pkt(int sid);
#else
///@brief 包获取函数，从网卡的一个数据队列中读取一个IP包。
///同时根据不同的mode值，获取包不同的起始位置到pdata中。
///@param sid 收包数据流的序号（0开始的连续数字）。
///@param mode 等于0表示，pdata指向NULL；等于15表示，pdata指向二层头；
///@param mod 等于31表示，pdata指向VLAN头；等于47表示，pdata指向三层头；
///@param mod 等于63表示，pdata指向四层头；等于79表示，pdata指向负载位置。
void *pag_get_pkt(int sid, int mode, void **pdata);
#endif

//@}


///@name 发包接口
//@{

///@brief 获取一个发包缓冲区
///@warning 注意：这里的首地址是从IP头开始的
///@param sid 发包流id
///@return 成功返回发包缓冲区ip头首地址，失败返回NULL
void *pag_getsendbuf(int sid);

///@brief 发送一个ip包
///@warning 注意：发包前要设置报文的mac地址，计算报文的ip头checksum等
///@param pkttype 报文类型
///@param sid 发包流id
///@param ipdatalen ip报文长度
///@return 成功返回0，失败返回-1
int pag_send(int pkttype, int sid, int ipdatalen);

///@brief 获取一个发包缓冲区
///@warning 注意：这里的首地址是从L2层开始的
///@param sid 发包流id
///@return 成功返回发包缓冲区L2层头首地址，失败返回NULL
void *pag_getsendbuf_eth(int sid);

#ifdef _CONFIG_SUPPORT_MAC_IN_MAC
int pag_send_eth(int sid, void *pbuf, int eth_datalen);
#else
///@brief 发送一个ethernet包
///@warning 注意：发包前要在缓冲区（pag_getsendbuf - 14）内构造好完整的ethernet报文
///@param port 发包网口
///@param sid 发包流id
///@param eth_datalen ethernet帧长度
///@return 成功返回0，失败返回-1
int pag_send_eth(int port, int sid, int eth_datalen);
#endif

///@brief 控制某个线程的发包使能
///@param thread_id 线程号
///@param flag 是否使能,1,为使能，0为禁用，输入
///@return 成功返回0，参数不合法失败返回-1
int pag_txbuf_config_enable(int thread_id, int flag);

///@brief 释放缓冲区，这里不支持乱序操作，为空函数
void pag_freesendbuf(int sid);

//@}

///@name 五元组规则过滤接口
//@{


///@brief 向网卡添加或删除一系列规则
///@param sid 线程号（未使用）
///@param rule_num 规则数
///@param pRules 规则数组
///@return 成功返回添加或删除的规则数，失败返回－1
int pag_L4rule(int sid, unsigned int rule_num, struct filter_full_rule *pRules);

///@brief 向网卡添加或删除一系列规则
///@param sid 线程号（未使用）
///@param rule_num 规则数
///@param pRules 指向规则数组的指针
///@param flag 0代表IPV4，1代表IPV6
///@return 成功返回添加或删除的规则数，失败返回－1
int pag_rule(int sid, unsigned int rule_num, void *pRules, int flag);

///@brief 清空一类规则，并向网卡导入一个规则配置文件
///@param ruletype 规则类型(从1开始)
///@param filename 规则文件名
///@return 成功返回0，失败返回－1
int pag_refreshstaticrule(int ruletype, char *filename);

///@brief 获取报文命中规则id
///@param pkt 报文ip头
///@return 附加包头内的规则id
inline int pag_getfilterid(packet_t *pkt);

///@brief 获取报文命中规则类型
///@param pkt 报文ip头
///@return 附加包头内的规则类型，0表示未命中任何规则
inline int pag_getfiltertype(packet_t *pkt);

//@}


///@name 收tcp/udp连接还原接口
//@{

///@brief 从网卡的一个数据流中读取流结构信息，可能是tcp流也可能是udp流;
///@param sid 收包数据流的序号,同时也是tcp流还原句柄的序号
///@return pktinfo结构指针；如果没有报文，则其中的数据字段为NULL。
struct pktinfo *pag_getstream(int sid);

///@brief 从并发连接表中删除一个流
///@param ts 用户流结构的指针
void pag_delstream(struct tcp_stream *ts);

///@brief 暂存一部分数据到下一和新数据一起给应用
///@param ts 用户流结构的指针
///@param dir 需要缓存数据的方向（实际上是新到数据中的后面一部分，所以该参数这里未使用）
///@param len 需要缓存的数据长度（当前包的后一部分数据）
///@warning 暂存数据长度不能超过预定义长度
void pag_savedata(struct tcp_stream *ts, int dir, int len);

///@brief 设置流还原的使能，网卡打开后调用一次,对指定协议进行重组，其他协议不需要进行重组;
///@param proto 需要进行重组的协议：
///0x17|0x06 要求重组tcp，udp协议，其他协议不重组
///0x06 要求重组tcp协议，其他协议不重组
///0x00 所有协议不重组
void pag_setrebuild(char proto);

//@}

///@name 用户定义收发包扩展接口
//@{

///@brief 从网卡的一个数据队列中读取一个数据包
///@param sid 收包数据流的序号（0开始的连续数字）
///@return 报文头指针（包括附加头）；如果没有报文，则返回NULL
void *pag_get_ex(int sid);

///@brief 发送一个数据包
///@param type mac或是pos类型（0为ether，1为pos）
///@param port 发包网口号
///@param sid 发包流id
///@param pkt_addr 存放报文的起始地址
///@param len 报文长度
///@return 成功返回0，失败返回-1
int pag_send_ex(int type, int port, int sid, void *pkt_addr, int len);

//@}

///@name 327项目定义诊断接口
//@{
///@brief 获取pag设备当前的工作状态
///@param stat 状态结构体指针
///@return 返回pag状态结构
pag_stat_t *pag_get_stat(pag_stat_t *stat);

///@brief 清除pag_get_stat返回的数值，将收发包统计计数清零
///@param void
///@return 成功返回0，失败返回－1
int pag_clear_stat();

//@}

///@name 配置分流相关接口
//@{

///@brief 向网卡添加或删除一系列分流比例规则
///@param sid 线程号（未使用）
///@param rule_num 规则数
///@param pRules 规则数组
///@return 成功返回添加或删除的规则数，失败返回－1
int pag_L4ratio_rule(int sid, unsigned int rule_num, struct ratio_rule *pRules);

///@brief 清空一类规则，并向网卡导入一个分流比例规则配置文件
///@warning 这里的规则类型从1开始，所以调用底层函数时要－1
///@param ruletype 规则类型(从1开始)
///@param filename 规则文件名
///@param ratio_file 分流比例配置文件
///@return 成功返回0，失败返回－1
int pag_refreshratiorule(int ruletype, char *filename, char *ratio_file);

//@}

#ifdef __cplusplus
}
#endif

#endif
