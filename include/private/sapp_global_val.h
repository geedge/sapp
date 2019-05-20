#ifndef _SAPP_GLOBAL_VAL_H_
#define _SAPP_GLOBAL_VAL_H_ 1

#include "sapp_api.h"

typedef struct{
	int worker_threads;
	long bind_mask_array[SAPP_MAX_THREADS];
	long bind_mask; /* bind_mask_array中的每个变量做为bit_index转成的整数值 */
}sapp_config_cpu_t;

typedef struct{
	char instance_name[NAME_MAX];
}sapp_config_system_t;


typedef struct{
	unsigned char enabled;
	unsigned char mode;
	unsigned short command_port; /* host order */
	unsigned int storge_size_max;
	char *bpf_filter;
	char *storge_path;
	unsigned char dump_thread_id[SAPP_MAX_THREADS];
}sapp_config_tools_pktdump_t;

typedef struct{
	sapp_config_tools_pktdump_t pkt_dump;
}sapp_config_tools_t;


typedef struct{
	unsigned char rst_signature_enable;
	unsigned char rst_pkt_num;
	unsigned short rst_signature_seed1;
	unsigned short rst_signature_seed2;
	unsigned short mss_size;
}sapp_config_stream_tcp_inject_t;


typedef struct{
	unsigned int max;  /* max stream number per thread */
	unsigned short timeout;
	unsigned short reorder_pkt_max;
	unsigned char syn_mandatory;
	sapp_config_stream_tcp_inject_t inject;
}sapp_config_stream_tcp_t;


typedef struct{
	unsigned int max;  /* max stream number per thread */
	unsigned short timeout;
}sapp_config_stream_udp_t;


typedef struct{
	sapp_config_stream_tcp_t tcp;
	sapp_config_stream_udp_t udp;
}sapp_config_stream_t;


typedef struct{
	unsigned char level;
	unsigned char interval;
	unsigned char server_ip[INET_ADDRSTRLEN]; /* string */
	unsigned short server_port; /* host order */
}sapp_config_profiling_log_t;


typedef struct{
	sapp_config_profiling_log_t log;
}sapp_config_profiling_t;

typedef struct{
	unsigned char type; /* marsio, pcap-online, pcap-dumpfile */
	char *name;
}sapp_config_packet_io_interface_t;


typedef struct{
	sapp_config_packet_io_interface_t interface;
	unsigned char format_type; /* vxlan, ddp, k18mac, 327, etc.. */
}sapp_config_packet_io_dev_t;


enum __sapp_config_packet_io_depolyment_mode{
	SAPP_CFG_PKT_IO_DEPOLY_MODE_MIRROR,
	SAPP_CFG_PKT_IO_DEPOLY_MODE_INLINE,
	SAPP_CFG_PKT_IO_DEPOLY_MODE_TRANSPARENT,
};

typedef struct{
	unsigned char depolyment_mode; /* refer to enum __sapp_config_packet_io_depolyment_mode */
	sapp_config_packet_io_dev_t internal;
	sapp_config_packet_io_dev_t external;
}sapp_config_packet_io_t;

typedef struct{
	sapp_config_cpu_t cpu;
	sapp_config_tools_t tools;
	sapp_config_system_t system;
	sapp_config_stream_t stream;
	sapp_config_profiling_t profiling;
	sapp_config_packet_io_t packet_io;
}sapp_config_t;


typedef struct{
	
}sapp_gval_individual_t;

typedef struct{

}sapp_gval_mthread_t; /*  for multi-thread, must 64byte alignment */


typedef struct{
	sapp_cmd_args_val_t **cmd_args_array;
	int cmd_args_num;
}sapp_cla_t;


typedef struct{
	sapp_cla_t cla;
	sapp_config_t config;
	sapp_gval_individual_t individual;
	sapp_gval_mthread_t mthread[SAPP_MAX_THREADS];
}sapp_global_t;


#endif

