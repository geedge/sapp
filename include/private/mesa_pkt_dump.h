#ifndef _MESA_PKT_DUMP_H_
#define _MESA_PKT_DUMP_H_ 1

#define MESA_PKT_DUM_H_VER (20201102)

/* 
	用于DPDK-3.0, PFRING模式下, 驱动独占网卡时, 通过平台实时捕包.
*/

#define PKT_DUMP_HDR_MAGIC	(0x44554D50)

/* 支持按Bit位或 */
enum _pkt_classify{
	PKT_CLASSIFY_IN			= 0x01,  /* DMAC ascii码值: I */
	PKT_CLASSIFY_FORWARD	= 0x02,  /* DMAC ascii码值: F */
	PKT_CLASSIFY_INJECT		= 0x04,  /* DMAC ascii码值: J */
	PKT_CLASSIFY_DROP		= 0x08,  /* DMAC ascii码值: D */
	PKT_CLASSIFY_ERROR		= 0x10,  /* DMAC ascii码值: E */
};

enum pkt_dump_opt_t{
	PKT_DUMP_OPT_RCV_PORT,
	PKT_DUMP_OPT_BPF_FILTER,
	PKT_DUMP_OPT_DATA_OFFSET,
	PKT_DUMP_OPT_THREAD_INDEX,	
	PKT_DUMP_OPT_ACK, /* sapp返回给tcpdump_mesa的ack包 */
	PKT_DUMP_OPT_PERCEPTIVE, /* 明察秋毫模式, 可以发现丢包数量 */	
	PKT_DUMP_OPT_GREEDY_SEEK,  /* 偏移到最内层IP, 便于隧道模式下查找BUG */ 
	PKT_DUMP_OPT_CLASSIFY, /* short类型, 捕包来源分类,  定义详见 enum _pkt_classify, 如果没有指定此参数, 默认值为PKT_CLASSIFY_IN */
	PKT_DUMP_OPT_CLASSIFY_WATERMARK, /* 无需传选项值, 因为仅有两个值0或1, 捕包来源水印,将类型值存入dmac,此参数会修改输出的原始包, 慎用, 默认关闭  */
};

/* 网络序, 便于以后在其他系统如ARM, PowerPC, MIPS上移植 */
struct pkt_dump_opt{
	unsigned short opt_type;
	unsigned short opt_len;
	/* actual opt value */
}__attribute__((packed, aligned(1)));

/* 启动捕包前的握手信息, 网络序, 便于以后在其他系统如ARM, PowerPC, MIPS上移植 */
struct pkt_dump_handshake{
	unsigned int magic;   /* 固定为0x44554D50, 'DUMP' */
	unsigned int version; /* 用于判定双方的版本号, 一般为数字20170106等 */
	unsigned int opt_num; /* 后续选项的数量, 如本端接收端口号, BPF过滤条件, 捕包offset值等等 */
}__attribute__((packed, aligned(1)));

struct perceptive_info{
	unsigned char thread_id;
	unsigned char pad;
	unsigned int pkt_seq; /* 从0开始累计, 如果seq有空洞, 说明传输过程中丢了多少包 */
}__attribute__((packed, aligned(1)));

#endif

