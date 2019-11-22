#ifndef _APP_STREAM_CONTROL_H_
#define _APP_STREAM_CONTROL_H_ 

#ifdef __cplusplus
extern "C" {
#endif

#define STREAM_CONTROL_H_VERSION		(20191120)

#define TCP_CTEAT_LINK_BYSYN   			0x01  /* for MESA_stream_opt->MSO_TCP_CREATE_LINK_MODE */
#define TCP_CTEAT_LINK_BYDATA 			0x02  /* for MESA_stream_opt->MSO_TCP_CREATE_LINK_MODE */

/*
	option of stream, 

	MSO_IGNORE_RST_FIN: will not be terminated by RST, FIN packet, only if timeout or in LRU tail, it will be eliminated. 
*/
enum MESA_stream_opt{
	__MSO_PAD			=	0,    /* placeholder */
	MSO_MAX_UNORDER	=	1,  	/* opt_val type must be struct max_unorder_opt */
	MSO_NEED_ACK,				/* opt_val type must be unsigned char, value only be [0,1] */
	MSO_TAKEOVER,				/* opt_val type must be int, value only be [0,1] */
	MSO_TIMEOUT,				/* opt_val type must be unsigned short */
	MSO_IGNORE_RST_FIN, 		/* opt_val type must be unsigned char, value only be [0,1] */
	MSO_TCP_CREATE_LINK_MODE,  /* opt_val must be unsigned char, refer to TCP_CTEAT_LINK_xxx */
	MSO_TCP_ISN_C2S, /* Host-order, opt_val type must be unsigned int */
	MSO_TCP_ISN_S2C, /* Host-order, opt_val type must be unsigned int */
	MSO_TCP_SYN_OPT, /* opt_val must be struct tcp_option **, opt_val_len [OUT} is struct tcp_option number, valid only if SYN packet is captured */
	MSO_TCP_SYNACK_OPT, /* opt_val must be struct tcp_option **, opt_val_len [OUT} is struct tcp_option number, valid only if SYN/ACK packet is captured */
	MSO_STREAM_TUNNEL_TYPE,  /* opt_val must be unsigned short, refer to enum stream_carry_tunnel_t */
	MSO_STREAM_CLOSE_REASON, /* opt_val type must be unsigned char, refer to stream_close_reason_t */
	MSO_STREAM_VXLAN_INFO, /* opt_val type must be struct vxlan_info */
	MSO_TCPALL_VALID_AFTER_KILL, /* opt_val type must be unsigned char, value only be [0,1] */
	MSO_GLOBAL_STREAM_ID, /* opt_val type must be unsigned long long, is value-result argument, IN: device_id, value range[0, 4095]; OUT:global stream id */
	MSO_DROP_STREAM, /* opt_val type must be int, value only be [0,1]; similar to DROPPKT, but effective scope is stream. */
	MSO_TCP_RST_REMEDY, /* opt_val type must be int, value only be [0,1]; if not set this, default is disable. */
	__MSO_MAX,
};

/* for MSO_STREAM_CLOSE_REASON,
   These value is not consecutive, because some value is obsoleted!
*/
enum stream_close_reason_t{
	STREAM_CLOSE_REASON_SYN_REUSE	= 0, /* for TCP tuple4 reuse */
	STREAM_CLOSE_REASON_NORMAL 		= 3, /* for TCP FIN, FIN/ACK */
	STREAM_CLOSE_REASON_RESET 		= 4, /* for TCP RESET */
	STREAM_CLOSE_REASON_TIMEOUT		= 5, /* timeout */
	STREAM_CLOSE_REASON_LRUOUT		= 6, /* stream table full, kick out */
};


enum sapp_platform_opt{
	SPO_TOTAL_RCV_PKT,		/* total recv packet number, opt_val type must be unsigned long long */
	SPO_TOTAL_RCV_BYTE,		/* total recv packet byte, opt_val type must be unsigned long long */
	SPO_REALTIME_RCV_PKT,		/* realtime recv packet number, opt_val type must be unsigned long long */
	SPO_REALTIME_RCV_BYTE,	/* realtime recv packet byte, opt_val type must be unsigned long long */
	SPO_THREAD_COUNT,			/* total thread count, opt_val type must be int */
	SPO_CURTIME_TIMET,			/* current time, opt_val type must be time_t */
	SPO_CURTIME_STRING,		/* current time, opt_val type must be char[], opt_val_len must more than strlen("1970-01-01 01:01:01") */
	SPO_START_TIME,			/* platform start time, opt_val type must be time_t */
	SPO_RUN_TIME,				/* platform running time, opt_val type must be time_t */
	SPO_RAND_NUMBER,			/* get a rand number, opt_val type must be long long */
	SPO_FIELD_STAT_HANDLE,	/* field stat output handle, opt_val type must be void * */
	SPO_INDEPENDENT_THREAD_ID, /* plug independent thread which is created by pthread_create(), opt_val type must be int */
};


/*
	option of device, 
*/
enum sapp_device_opt{
	__SDO_PAD			=	0,    /* placeholder */
	SDO_MAC_ADDR,				/* device mac addr, opt_val type must be at least char[6] */
	SDO_IPV4_ADDR,				/* device ipv4 addr in network order,  opt_val type must be int */
	SDO_MTU,					/* device MTU, opt_val type must be int */
	__SDO_MAX,
};

/* for MSO_MAX_UNORDER  */
struct max_unorder_opt{
	unsigned short stream_dir; /* refer to stream_base.h, DIR_C2S, DIR_S2C, DIR_DOUBLE */
	unsigned short max_unorder_val;
};

#define MAX_TCP_OPT_LEN	(38) /* TCP头部长度最长为60字节, 去除标准头部剩余选项部分最长40字节, 选项数据部分最长38字节 */
#define MAX_TCP_OPT_NUM	(20) /* 单个TCP包最大选项数量 */

enum tcp_option_value{
	TCP_OPT_EOL = 0,
	TCP_OPT_NOP = 1,
	TCP_OPT_MSS = 2,
	TCP_OPT_WIN_SCALE = 3,
	TCP_OPT_SACK = 4,
	TCP_OPT_SACK_EDGE = 5,
	TCP_OPT_TIME_STAMP = 8,	/* refer to struct tcp_option_ts */
	TCP_OPT_MD5 = 19,
	TCP_OPT_MULTI_PATH_TCP = 0x1E,
	TCP_OPT_RIVER_PROBE = 0x4c, 
};

struct tcp_option_ts{
	unsigned int ts_self;
	unsigned int ts_echo_reply;	
};

struct tcp_option{
	unsigned char type;
	unsigned char len; /* pure payload len, not contain type and this len field */
	union{
		unsigned char char_value;
		unsigned short short_value;
		unsigned int int_value;
		unsigned long long long_value;
		char *variable_value;
		struct tcp_option_ts opt_ts_val;
	};	
} __attribute__((packed, aligned(1)));

struct tcp_option_ext{
	unsigned char type;
	unsigned char len;
	union{
		unsigned char char_value;
		unsigned short short_value;
		unsigned int int_value;
		unsigned long long long_value;
		char variable_value[MAX_TCP_OPT_LEN];
		struct tcp_option_ts opt_ts_val;
	};	
} __attribute__((packed, aligned(1)));


/* 2018-10-24 lijia add, for pangu 项目mac_in_mac回流.
   理论上, sapp平台不应该关心和业务密切相关的东西, 比如mac里哪个字段是link_id, 哪个是dev_id,
   但这个玩意太底层了, 平台借用GDEV发送RST包也要填充这些值, 必须平台处理!!
*/
/* 为了方便业务插件获取mac_in_mac地址里的具体信息, 不再使用原始的bit位域, 转换成变量形式 */
struct vxlan_info{
	unsigned char encap_type; /* 原始二层封装格式 */
	unsigned char entrance_id; /* 设备所在出入口ID */
	unsigned char dev_id; /* 设备ID */
	unsigned char link_id; /* 链路ID */
	unsigned char link_dir; /* 链路方向, 指当前四元组的IP被捕获时的传输方向, 对于TCP, SYN包的传输方向; 对于UDP, 端口大IP的传输方向 */
	unsigned char inner_smac[18]; /* 内层真实SMAC, string类型, 例: "11:22:33:44:55:66"  */
	unsigned char inner_dmac[18]; /* 内层真实DMAC, string类型, 例: "11:22:33:44:55:66"  */
	unsigned char inner_smac_hex[6]; /* 内层真实SMAC, 原始二进制类型  */
	unsigned char inner_dmac_hex[6]; /* 内层真实DMAC, 原始二进制类型  */	
};


/*
	plug call MESA_set_stream_opt() to set feature of specified stream.
		opt: option type, refer to enum MESA_stream_opt;
		opt_val: option value, depend on opt type;
		opt_val_len: opt_val size;
	
	return value:
		0 :OK;
		<0:error;
*/
int MESA_set_stream_opt(const struct streaminfo *pstream, enum MESA_stream_opt opt, void *opt_val, int opt_val_len);


/*
	plug call MESA_get_stream_opt() to get feature of specified stream.
		opt: option type, refer to enum MESA_stream_opt;
		opt_val: option value, depend on opt type;
		opt_val_len: value-result argment, IN:opt_val buf size, OUT:opt_val actual size;
	
	return value:
		0 :OK;
		<0:error;
*/
int MESA_get_stream_opt(const struct streaminfo *pstream, enum MESA_stream_opt opt, void *opt_val, int *opt_val_len);


/*
	Get options from tcphdr, and store them in raw_result.
	return value:
		= 0: no option;
		> 0: opt number;
		< 0: error.	
*/
int MESA_get_tcp_pkt_opts(const struct tcphdr *tcphdr, struct tcp_option *raw_result, int res_num);


/*
	Get options from tcphdr, and store them in raw_result.
	return value:
		= 0: no option;
		> 0: opt number;
		< 0: error.	
*/
int MESA_get_tcp_pkt_opts_ext(const struct tcphdr *tcphdr, struct tcp_option_ext *raw_result, int res_num);

/*
	plug call sapp_get_platform_opt() to get feature of platform.
		opt: option type, refer to enum sapp_platform_opt;
		opt_val: option value, depend on opt type;
		opt_val_len: value-result argment, IN:opt_val buf size, OUT:opt_val actual size;
	
	return value:
		0 :OK;
		<0:error;
*/
int sapp_get_platform_opt(enum sapp_platform_opt opt, void *opt_val, int *opt_val_len);


/*
	Get some options of hardware .
		opt: option type, refer to enum sapp_device_opt;
		opt_val: option value, depend on opt type;
		opt_val_len: value-result argment, IN:opt_val buf size, OUT:opt_val actual size;
	
	return value:
		0 :OK;
		<0:error;	
*/
int sapp_get_device_opt(const char *device, enum sapp_device_opt opt_type, void *opt_val, int *opt_val_len);

/****************************************************************************************
	CHN : 因为历史遗留问题,此类函数保留仅为向后兼容,请使用新接口:MESA_set_stream_opt().
	ENG : for compat old version, keep these functions, but we suggest you use new API MESA_set_stream_opt().
*****************************************************************************************/
int tcp_set_single_stream_max_unorder(const struct streaminfo *stream, UCHAR dir, unsigned short unorder_num);
int tcp_set_single_stream_needack(const struct streaminfo *pstream);
int tcp_set_single_stream_takeoverflag(const struct streaminfo *pstream,int flag);
int stream_set_single_stream_timeout(const struct streaminfo *pstream,unsigned short timeout);
int get_thread_count(void);
/****************************************************************************************
****************************************************************************************
****************************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

