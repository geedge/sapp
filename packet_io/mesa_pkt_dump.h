#ifndef _MESA_PKT_DUMP_H_
#define _MESA_PKT_DUMP_H_ 1

/* 
	用于DPDK-3.0, PFRING模式下, 驱动独占网卡时, 通过平台实时捕包.
*/

#define PKT_DUMP_HDR_MAGIC	(0x44554D50)

enum pkt_dump_opt_t{
	PKT_DUMP_OPT_RCV_PORT,
	PKT_DUMP_OPT_BPF_FILTER,
	PKT_DUMP_OPT_DATA_OFFSET,
	PKT_DUMP_OPT_THREAD_INDEX,	
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


#endif
