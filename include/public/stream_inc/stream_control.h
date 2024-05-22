#ifndef _APP_STREAM_CONTROL_H_
#define _APP_STREAM_CONTROL_H_ 

#ifdef __cplusplus
extern "C" {
#endif

#define STREAM_CONTROL_H_VERSION		(20210818)

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
	MSO_STREAM_VXLAN_INFO, /* opt_val type must be struct vxlan_info, only support for MAC-in-MAC encapsulation in mirror mode  */
	MSO_TCPALL_VALID_AFTER_KILL, /* opt_val type must be unsigned char, value only be [0,1]; Warning, this option is obsolete, use MESA_rst_tcp() instead */
	MSO_GLOBAL_STREAM_ID, /* opt_val type must be unsigned long long, is value-result argument, IN: device_id, value range[0, 4095]; OUT:global stream id */
	MSO_DROP_STREAM, /* opt_val type must be int, value only be [0,1]; similar to DROPPKT, but effective scope is all subsequent packets of this stream. */
	MSO_TCP_RST_REMEDY, /* opt_val type must be int, value only be [0,1]; if not set this, default is disable. */
	MSO_TOTAL_INBOUND_PKT,  /* inbound packet number of this stream, opt_val type must be unsigned long long  */
	MSO_TOTAL_INBOUND_BYTE, /* inbound packet byte of this stream, opt_val type must be unsigned long long  */
	MSO_TOTAL_OUTBOUND_PKT, /* outbound packet pkt of this stream, opt_val type must be unsigned long long  */
	MSO_TOTAL_OUTBOUND_BYTE,/* outbound packet byte of this stream, opt_val type must be unsigned long long  */
	MSO_STREAM_CREATE_TIMESTAMP_MS,/* first pkt arrive timestamp of this stream, opt_val type must be unsigned long long  */
	MSO_TOTAL_INBOUND_BYTE_RAW, /* inbound packet byte of this stream, raw packet len, include ip hdr, ethernet hdr... opt_val type must be unsigned long long  */
	MSO_TOTAL_OUTBOUND_BYTE_RAW,/* outbound packet byte of this stream, raw packet len, include ip hdr, ethernet hdr... opt_val type must be unsigned long long  */
	MSO_STREAM_UP_LAYER_TUNNEL_TYPE,  /* opt_val must be unsigned short, refer to enum stream_carry_tunnel_t */
	MSO_STREAM_PLUG_PME, /* opt_val type must be struct mso_plug_pme, this is a value-result argument, the caller should set plug_name and plug_entry_type, only support: TCP, TCP_ALL, UDP */
	MSO_DROP_CURRENT_PKT,  /* opt_val type must be int, value only be [0,1], notice the difference between MSO_DROP_CURRENT_PKT and MSO_DROP_STREAM, MSO_DROP_CURRENT_PKT only discard current packet, but MSO_DROP_STREAM discard all subsequent packets of stream  */
	MSO_HAVE_DUP_PKT,  /* opt_val type must be int, value only be [0, 1, -2], if the current stream found duplicate packets ? 0:no; 1:yes; -2: not sure */
	MSO_STREAM_LASTUPDATE_TIMESTAMP_MS,/* latest pkt arrive timestamp of this stream, opt_val type must be unsigned long long  */
	MSO_STREAM_TIMED,
	MSO_STREAM_APPLEND_SEGMENT_ID_LIST,
	MSO_STREAM_PREPLEND_SEGMENT_ID_LIST,
	MSO_STREAM_SET_DATAMETA_TRACE_ID,
	MSO_STREAM_C2S_RAWPKT_HDR,
	MSO_STREAM_S2C_RAWPKT_HDR,
	MSO_STREAM_C2S_SYN_NUM,
	MSO_STREAM_S2C_SYN_NUM,
	MSO_STREAM_INBOND_LINK_ID,
	MSO_STREAM_OUTBOND_LINK_ID,
	MSO_STREAM_C2S_ROUTE_DIRECTION,
	MSO_STREAM_INBOND_ROUTE_CTX,
	MSO_STREAM_OUTBOND_ROUTE_CTX,
	MSO_STREAM_C2S_LINK_ID,
	MSO_STREAM_S2C_LINK_ID,
	MSO_STREAM_C2S_ROUTE_CTX,
	MSO_STREAM_S2C_ROUTE_CTX,	
	MSO_IP_TTL_C2S, /* opt_val type must be unsigned char, IPv4 is TTL, IPv6 is Hop Limit */
	MSO_IP_TTL_S2C, /* opt_val type must be unsigned char, IPv4 is TTL, IPv6 is Hop Limit */
	MSO_TCP_RTT_CSC, /* opt_val type must be unsigned short, the full RTT is client->tsg->server->tsg->client, this is |tsg->server->tsg| */
	MSO_TCP_RTT_SCS, /* opt_val type must be unsigned short, the full RTT is server->tsg->client->tsg->server, this is |tsg->client->tsg| */
	MSO_STREAM_C2S_SEGMENT_ID_LIST,
	MSO_STREAM_S2C_SEGMENT_ID_LIST,
	MSO_STREAM_INBOND_SEGMENT_ID_LIST,
	MSO_STREAM_OUTBOND_SEGMENT_ID_LIST,
	__MSO_MAX,
};

/* for MSO_STREAM_CLOSE_REASON,
   don't confuse, these values is not consecutive indeed, because some value(1,2) is obsoleted!
*/
enum stream_close_reason_t{
	STREAM_CLOSE_REASON_SYN_REUSE	= 0, /* for TCP tuple4 reuse */
	STREAM_CLOSE_REASON_NORMAL 		= 3, /* for TCP FIN, FIN/ACK */
	STREAM_CLOSE_REASON_RESET 		= 4, /* for TCP RESET */
	STREAM_CLOSE_REASON_TIMEOUT		= 5, /* timeout */
	STREAM_CLOSE_REASON_LRUOUT		= 6, /* stream table full, kick out */
	STREAM_CLOSE_REASON_DEPRIVE		= 7, /* deprive by some plug who return KILL_FOLLOW or KILL_OTHER */
	STREAM_CLOSE_REASON_DUMPFILE	= 8, /* only for pcap dumpfile mode */
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
	SPO_DEPLOYMENT_MODE_STR, /* opt_val type is char[], optional value is:["mirror", "inline", "transparent"] */
	SPO_TCP_STREAM_NEW,			/* total created tcp streams from start, opt_val type must be unsigned long long */
	SPO_TCP_STREAM_CLOSE,		/* total closed tcp streams from start, opt_val type must be unsigned long long */
	SPO_TCP_STREAM_ESTAB,		/* realtime established tcp streams, opt_val type must be unsigned long long */
	SPO_TOTAL_INBOUND_PKT,		/* total inbound packet number, opt_val type must be unsigned long long */
	SPO_TOTAL_INBOUND_BYTE,		/* total inbound packet bytes, opt_val type must be unsigned long long */
	SPO_TOTAL_OUTBOUND_PKT,		/* total outbound packet number, opt_val type must be unsigned long long */
	SPO_TOTAL_OUTBOUND_BYTE,	/* total outbound packet bytes, opt_val type must be unsigned long long */
	SPO_UDP_STREAM_NEW,			/* total created udp streams from start, opt_val type must be unsigned long long */
	SPO_UDP_STREAM_CLOSE,		/* total closed udp streams from start, opt_val type must be unsigned long long */
	SPO_UDP_STREAM_CONCURRENT,	/* realtime Concurrent udp streams, opt_val type must be unsigned long long */	
	SPO_TOTAL_RCV_INBOUND_IPV4_PKT,		/* total recv ipv4 packet number, opt_val type must be unsigned long long */
	SPO_TOTAL_RCV_INBOUND_IPV4_BYTE,		/* total recv ipv4 packet number, opt_val type must be unsigned long long */
	SPO_TOTAL_RCV_OUTBOUND_IPV4_PKT,	/* total recv ipv4 packet bytes, opt_val type must be unsigned long long */
	SPO_TOTAL_RCV_OUTBOUND_IPV4_BYTE,	/* total recv ipv4 packet bytes, opt_val type must be unsigned long long */
	SPO_TOTAL_RCV_INBOUND_IPV6_PKT,		/* total recv ipv6 packet number, opt_val type must be unsigned long long */
	SPO_TOTAL_RCV_INBOUND_IPV6_BYTE,		/* total recv ipv6 packet number, opt_val type must be unsigned long long */
	SPO_TOTAL_RCV_OUTBOUND_IPV6_PKT,	/* total recv ipv6 packet bytes, opt_val type must be unsigned long long */
	SPO_TOTAL_RCV_OUTBOUND_IPV6_BYTE,	/* total recv ipv6 packet bytes, opt_val type must be unsigned long long */
	SPO_TOTAL_RCV_INBOUND_TCP_PKT,		/* total recv tcp packet number, opt_val type must be unsigned long long */
	SPO_TOTAL_RCV_INBOUND_TCP_BYTE,		/* total recv tcp packet number, opt_val type must be unsigned long long */
	SPO_TOTAL_RCV_OUTBOUND_TCP_PKT,		/* total recv tcp packet bytes, opt_val type must be unsigned long long */
	SPO_TOTAL_RCV_OUTBOUND_TCP_BYTE,		/* total recv tcp packet bytes, opt_val type must be unsigned long long */
	SPO_TOTAL_RCV_INBOUND_UDP_PKT,		/* total recv udp packet number, opt_val type must be unsigned long long */
	SPO_TOTAL_RCV_INBOUND_UDP_BYTE,		/* total recv udp packet number, opt_val type must be unsigned long long */
	SPO_TOTAL_RCV_OUTBOUND_UDP_PKT,		/* total recv udp packet bytes, opt_val type must be unsigned long long */
	SPO_TOTAL_RCV_OUTBOUND_UDP_BYTE,		/* total recv udp packet bytes, opt_val type must be unsigned long long */
	SPO_CURTIME_TIMET_MS,		/* current time in millisecond, opt_val type must be long long */
	SPO_CURRENT_STATE,			/* running stage of sapp, opt_val type is enum sapp_state_t */
	SPO_CONFIG_ROOT_DIR,		/* config file root directory, opt_val type must be char[], opt_val_len is value-result argument */
	SPO_DATA_ROOT_DIR,			/* data or state file root directory, opt_val type must be char[], opt_val_len is value-result argument */
	SPO_DEPLOYMENT_MODE, /* Similar to SPO_DEPLOYMENT_MODE_STR, opt_val type is sapp_deploment_mode_t */
	SPO_TCP_STREAM_C2S,			/* total number of TCP c2s flows processed since start of run, opt_val type must be unsigned long long */
	SPO_TCP_STREAM_S2C,		/* total number of TCP s2c flows processed since start of run, opt_val type must be unsigned long long */
	SPO_TCP_STREAM_DOUBLE,		/* total number of TCP bidirectional flows processed since start of run, opt_val type must be unsigned long long */
	SPO_UDP_STREAM_C2S,			/* total number of TCP c2s flows processed since start of run, opt_val type must be unsigned long long */
	SPO_UDP_STREAM_S2C,		/* total number of TCP s2c flows processed since start of run, opt_val type must be unsigned long long */
	SPO_UDP_STREAM_DOUBLE,		/* total number of TCP bidirectional flows processed since start of run, opt_val type must be unsigned long long */
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


enum stream_timer_return_value{
	 KEEP = 0,
	 DROP = 1,
};


#define MAX_TCP_OPT_LEN	(38) /* TCP max hdr length 60Bytes,  set max opt length 38 Bytes */
#define MAX_TCP_OPT_NUM	(20) 

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


struct vxlan_info{
	unsigned char encap_type; 
	unsigned char entrance_id;
	unsigned char dev_id;
	unsigned char link_id; 
	unsigned char link_dir; 
	unsigned char inner_smac[18]; /*string,  "11:22:33:44:55:66"  */
	unsigned char inner_dmac[18]; /*  string,  "11:22:33:44:55:66"  */
	unsigned char inner_smac_hex[6]; /* hex */
	unsigned char inner_dmac_hex[6]; /* hex */	
};


enum sapp_state_t{
	SAPP_STATE_JUST_START, /* main() called by shell command */
	SAPP_STATE_CONFIG_PARSE,
	SAPP_STATE_PLATFORM_INITING,
	SAPP_STATE_PLATFORM_INITED, /* 3 */
	SAPP_STATE_PLUG_INITING,
	SAPP_STATE_PLUG_INITED,     /* 5 */
	SAPP_STATE_PKT_IO_INITING,
	SAPP_STATE_PKT_IO_INITED,		
	SAPP_STATE_PROCESSING,      /* 8 */
	SAPP_STATE_READY_TO_EXIT,   /* 9,  pcap dumpfile mode, or recv custom signal */
	SAPP_STATE_EXIT,
};


struct mso_plug_pme{
	const char *plug_name;			/* argument: IN, comes from plug.inf-->[PLUGINFO]-->PLUGNAME */
	const char *plug_entry_type; 	/* argument: IN, only support: TCP, TCP_ALL, UDP.  */
	void *plug_pme;					/* argument: OUT, plug private memory address of current stream */
};

enum sapp_deploment_mode_t{
	DEPLOYMENT_MODE_MIRROR		= 1,
	DEPLOYMENT_MODE_TRANSPARENT	= 2,
	DEPLOYMENT_MODE_INLINE		= 3,
};


#ifndef MAX_SID_NUM
#define MAX_SID_NUM 8
#endif
struct segment_id_list
{
	unsigned short sid_list[MAX_SID_NUM];
	unsigned int sz_sidlist;
};

int append_sid_to_rawpkt(const void *rawpkt, struct segment_id_list *sid_list);
int prepend_sid_to_rawpkt(const void *rawpkt, struct segment_id_list *sid_list);

struct streaminfo;
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


struct tcphdr;
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

/*************************************************************************************** 	
	NOTE:
		convernt by etc/sapp.toml->inbound_route_dir.

	args: 
		'E' or 'e': Internal to External.
		'I' or 'i': External to Internal.

	return value:
		0 or 1: success.
		-1 : error.
****************************************************************************************/
int MESA_dir_human_to_link(int human_dir);

/*
	args:
		 0 or 1, stream->routedir;
	
	return value:
		'E' or 'e': Internal to External.
		'I' or 'i': External to Internal.
		'x': error;
*/
int MESA_dir_link_to_human(int link_route_dir);



/****************************************************************************************
	for compat old version, keep these functions, but we suggest you use new API MESA_set_stream_opt().
*****************************************************************************************/
int tcp_set_single_stream_max_unorder(const struct streaminfo *stream, unsigned char dir, unsigned short unorder_num);
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

