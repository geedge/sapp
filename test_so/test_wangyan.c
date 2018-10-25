#include <stdlib.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <assert.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>
#include "stream.h"
#include "stream_control.h"
#include "mesa_net.h"
#include "gserial_sendpacket.h"
#include "gdev_keepalive.h"
#include "mrtunnat.h"
#include "sysinfo.h"

#ifdef __cplusplus
extern "C" {
#endif 

#define TEST_PLUG_ID 1

extern time_t g_CurrentTime;
extern void del_last_rn(char *data, int max_len);
extern int MESA_mac_pton(const char *str, int delim, char *mac);

char send_iplayer_demo(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	/* ICMP request, from 10.10.6.108 to 10.0.6.59 */
	char snd_pkt_payload[] = 
	{
		0x45,0x00,0x00,0x54,0x00,0x00,0x40,0x00,
		0x40,0x01,0x19,0xF9,
		0x0A,0x0A,0x06,0x6C,
		0x0A,0x00,0x06,0x3B,
		0x08,0x00,0xC2,0x6A,0x18,0x8B,0x00,0x07,
		0xE5,0xB8,0xA8,0x54,0x00,0x00,0x00,0x00,
		0x22,0x5C,0x06,
		0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
	};

	Gserial_sendpacket_iplayer(TEST_PLUG_ID,stream, snd_pkt_payload, sizeof(snd_pkt_payload), 0);

	return APP_STATE_GIVEME;
}


char send_ipv4_pkt_options_demo(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	const struct mesa_ip4_hdr *iphdr = (const struct mesa_ip4_hdr *)raw_pkt;
	/* ICMP request, from 10.10.6.108 to 10.0.6.59 */
	char snd_pkt_payload[] = 
	{
		0x08,0x00,0xD9,0x71,0x18,0x8B,0x00,0x07,
		0xE5,0xB8,0xA8,0x54,0x00,0x00,0x00,0x00,
		0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
	};

#if 0 /* 同向发送 */
	if(0xeca597d == iphdr->ip_src.s_addr) /* 根据特定包造包 */
	{
		SAPP_TLV_T send_opt_array[1];
		send_opt_array[0].type = SAPP_SEND_OPT_IP_ID;
		send_opt_array[0].length = sizeof(short);
		send_opt_array[0].short_value = 0x5A5A;
	MESA_fakepacket_send_ipv4_options(stream, 1, ntohl(stream->addr.ipv4->saddr), 
									ntohl(stream->addr.ipv4->daddr), 
									snd_pkt_payload, sizeof(snd_pkt_payload), stream->routedir, send_opt_array, 1);
	}
#else /* 反向发送 */
	if(0xeca597d == iphdr->ip_src.s_addr) /* 根据特定包造包 */
	{
		SAPP_TLV_T send_opt_array[1];
		send_opt_array[0].type = SAPP_SEND_OPT_IP_ID;
		send_opt_array[0].length = sizeof(short);
		send_opt_array[0].short_value = 0x5A5A;
		
	MESA_fakepacket_send_ipv4_options(stream, 1, ntohl(stream->addr.ipv4->daddr), 
									ntohl(stream->addr.ipv4->saddr), 
									snd_pkt_payload, sizeof(snd_pkt_payload), 
									stream->routedir ^ 1, send_opt_array, 1);
	}
#endif

	return APP_STATE_GIVEME;
}



char test_wangyan_send_tcp_pkt_detail(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	Gserial_sendpacket_tcp_detail(TEST_PLUG_ID, stream, 0x0A0A066C, 0x0A00063B, 0x1234, 55, 0x1111,0x2222,
							0x12345678, 0x87654321, 0x10, 9999, "TCP payload test", strlen("TCP payload test"), 0);	
	return APP_STATE_GIVEME;
}

char test_wangyan_send_tcp_pkt_options(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	if(NULL == raw_pkt){
		return APP_STATE_GIVEME;
	}
	
	const struct mesa_ip4_hdr *iphdr = (const struct mesa_ip4_hdr *)raw_pkt;
	const struct mesa_tcp_hdr *tcphdr = (const struct mesa_tcp_hdr *)((char *)iphdr + iphdr->ip_hl * 4);
	/* ICMP request, from 10.10.6.108 to 10.0.6.59 */
	char http_request[] = "GET alsdkfj/asd/fasd/index.htm HTTP/1.1\r\n";


#if 0 /* 主动造包, 非当前包地址 */
	MESA_fakepacket_send_ipv4_options(stream, 17, 0x01010101, 0x02020202, snd_pkt_payload, sizeof(snd_pkt_payload), 0, NULL, 0);
#elif 0 /* 同向发送 */
	if((0x1A59 == iphdr->ip_id) && (0xd7b2267d == iphdr->ip_src.s_addr)) /* 根据特定包造包 */
	{
		SAPP_TLV_T send_opt_array[1];
		send_opt_array[0].type = SAPP_SEND_OPT_IP_ID;
		send_opt_array[0].length = sizeof(short);
		send_opt_array[0].short_value = 0x5A5A;
	MESA_fakepacket_send_tcp_options(stream, ntohl(iphdr->ip_src.s_addr), 
									ntohl(iphdr->ip_dst.s_addr), 
									ntohs(tcphdr->th_sport),
									ntohs(tcphdr->th_dport),
									0x11111111,
									0x22222222,
									TH_ACK | TH_PUSH,
									http_request, sizeof(http_request), 
									stream->routedir, send_opt_array, 1);
	}
#else /* 反向发送 */
	if((0x1A59 == iphdr->ip_id) && (0xd7b2267d == iphdr->ip_src.s_addr)) /* 根据特定包造包 */
	{
		SAPP_TLV_T send_opt_array[1];
		send_opt_array[0].type = SAPP_SEND_OPT_IP_ID;
		send_opt_array[0].length = sizeof(short);
		send_opt_array[0].short_value = 0x5A5A;
	MESA_fakepacket_send_tcp_options(stream, ntohl(iphdr->ip_dst.s_addr), 
									ntohl(iphdr->ip_src.s_addr), 
									ntohs(tcphdr->th_dport),
									ntohs(tcphdr->th_sport),
									0x22222222,
									0x11111111,
									TH_ACK | TH_PUSH,
									http_request, sizeof(http_request), 
									stream->routedir ^ 1, send_opt_array, 1);
	}
#endif
	return APP_STATE_GIVEME;
}
char test_wangyan_send_udp_pkt(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	Gserial_sendpacket_udp(TEST_PLUG_ID, stream, 0x0A0A066C, 0x0A00063B, 0x1111,0x2222,
							"UDP payload test", strlen("UDP payload test"), 0);	
	return APP_STATE_GIVEME;
}

char test_wangyan_send_udp_pkt_detail(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	Gserial_sendpacket_udp_detail(TEST_PLUG_ID, stream, 0x0A0A066C, 0x0A00063B, 0x1234, 55, 0x1111,0x2222,
							"UDP payload test", strlen("UDP payload test"), 0);	
	return APP_STATE_GIVEME;
}

char test_wangyan_send_udp_pkt_options(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	if(NULL == raw_pkt){
		return APP_STATE_DROPME;
	}
	
	const struct mesa_ip4_hdr *iphdr = (const struct mesa_ip4_hdr *)raw_pkt;
	const struct mesa_udp_hdr *udphdr = (const struct mesa_udp_hdr *)((char *)iphdr + iphdr->ip_hl * 4);
	char udp_paylaod[] = "UDP test payload\r\n";


#if 0 /* 主动造包, 非当前包地址 */
	MESA_fakepacket_send_ipv4_options(stream, 17, 0x01010101, 0x02020202, snd_pkt_payload, sizeof(snd_pkt_payload), 0, NULL, 0);
#elif 0 /* 同向发送 */
	if((0x024e == iphdr->ip_id) && (0xdebb487d == iphdr->ip_src.s_addr)) /* 根据特定包造包 */
	{
		SAPP_TLV_T send_opt_array[1];
		send_opt_array[0].type = SAPP_SEND_OPT_IP_ID;
		send_opt_array[0].length = sizeof(short);
		send_opt_array[0].short_value = 0x5A5A;
	MESA_fakepacket_send_udp_options(stream, ntohl(stream->addr.ipv4->saddr), 
									ntohl(stream->addr.ipv4->daddr), 
									0x1111,
									0x2222,
									udp_paylaod, sizeof(udp_paylaod), 
									stream->routedir, 
									send_opt_array, 1);
	}
#else /* 反向发送 */
	if((0x024e == iphdr->ip_id) && (0xdebb487d == iphdr->ip_src.s_addr)) /* 根据特定包造包 */
	{
		SAPP_TLV_T send_opt_array[1];
		send_opt_array[0].type = SAPP_SEND_OPT_IP_ID;
		send_opt_array[0].length = sizeof(short);
		send_opt_array[0].short_value = 0x5A5A;
	MESA_fakepacket_send_udp_options(stream, ntohl(stream->addr.ipv4->daddr), 
									ntohl(stream->addr.ipv4->saddr), 
									0x2222,
									0x1111,
									udp_paylaod, sizeof(udp_paylaod), 
									stream->routedir ^ 1, 
									send_opt_array, 1);
	}
#endif
	return APP_STATE_GIVEME;
}

char test_wangyan_forward_pkt(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	sapp_forward_current_pkt(stream, 1);	
	sapp_forward_current_pkt(stream, 2);	
	return APP_STATE_GIVEME;
}

extern int gdev_keepalive_set_opt(const SAPP_TLV_T *tlv_value);

char test_gdev_keepalive_ctrl(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	SAPP_TLV_T global_cmd;
	struct gdev_keepalive_service_ctrl service_cmd;
	global_cmd.type = GDEV_KEEPALIVE_OPT_SERVICE_CTRL;
	global_cmd.length = sizeof(struct gdev_keepalive_service_ctrl);
	service_cmd.service_num = 1;
	service_cmd.keepalive_switch = 0;
	global_cmd.ptr_value = &service_cmd;
	
	gdev_keepalive_set_opt(&global_cmd);

	global_cmd.type = GDEV_KEEPALIVE_OPT_GLOBAL_SWITCH;
	global_cmd.length = sizeof(int);
	global_cmd.int_value = 1;

	gdev_keepalive_set_opt(&global_cmd);

	return APP_STATE_GIVEME;	
}

char test_wangyan_send_ipv4_pkt(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	int test_ip;

	if(NULL == raw_pkt){
		return APP_STATE_DROPME;
	}
	
	inet_pton(AF_INET, "202.197.121.1", &test_ip);

	if((test_ip == stream->addr.tuple4_v4->saddr) || (test_ip == stream->addr.tuple4_v4->daddr)){
		Gserial_sendpacket_ipv4(1, stream, 32, 17, 
							  ntohl(stream->addr.tuple4_v4->saddr),
							  ntohl(stream->addr.tuple4_v4->daddr),
							  "11111111111111111111111111111111111111",
							  20,
							  0);
	}
	return APP_STATE_GIVEME;		
}

char test_wangyan_send_ipv6_pkt(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	struct in6_addr sip, dip;
	char payload[] = {
		0x80,0x00, 0x63,0x9d, 0x00,0x30,0xe1,0x38,
		0xc2,0xf6, 0x23,0x5a, 0x00,0x00, 0x00,0x00,
		0xc1,0xe6, 0x00,0x00, 0x00, 0x00, 0x00,0x00,
		0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,
		0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,
		0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,
	};

	inet_pton(AF_INET6, "2001::10:0:6:203", &sip);
	inet_pton(AF_INET6, "2001::10:0:6:201", &dip);


	Gserial_sendpacket_ipv6(10, stream, 33, 17, &sip, &dip, payload, sizeof(payload), 0);

	return APP_STATE_GIVEME;	
}


char test_wangyan_send_ipv6_tcp_pkt(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	struct in6_addr sip, dip;
	char payload[] = {
		0x80,0x00, 0x63,0x9d, 0x00,0x30,0xe1,0x38,
		0xc2,0xf6, 0x23,0x5a, 0x00,0x00, 0x00,0x00,
		0xc1,0xe6, 0x00,0x00, 0x00, 0x00, 0x00,0x00,
		0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,
		0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,
		0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,
	};

	inet_pton(AF_INET6, "2001::10:0:6:203", &sip);
	inet_pton(AF_INET6, "2001::10:0:6:201", &dip);

	Gserial_sendpacket_ipv6_tcp_detail(10, stream, &sip, &dip, 33, 12345, 54321, 11111111, 22222222, 0x14, 10000, payload, sizeof(payload), 0);

	return APP_STATE_GIVEME;	
}

char test_wangyan_send_ipv6_udp_pkt(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	struct in6_addr sip, dip;
	char payload[] = {
		0x80,0x00, 0x63,0x9d, 0x00,0x30,0xe1,0x38,
		0xc2,0xf6, 0x23,0x5a, 0x00,0x00, 0x00,0x00,
		0xc1,0xe6, 0x00,0x00, 0x00, 0x00, 0x00,0x00,
		0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,
		0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,
		0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,
	};

	inet_pton(AF_INET6, "2001::10:0:6:203", &sip);
	inet_pton(AF_INET6, "2001::10:0:6:201", &dip);

	Gserial_sendpacket_ipv6_udp_detail(10, stream, &sip, &dip, 33, 12345, 54321, payload, sizeof(payload), 0);

	return APP_STATE_GIVEME;	
}


typedef struct {
	unsigned char vxlan_smac[6]; /* 最外层mac */
	unsigned char vxlan_dmac[6];  /* 最外层mac */
	unsigned int vxlan_sip_net_order;
	unsigned int vxlan_dip_net_order;
	unsigned short vxlan_sport_net_order;
	unsigned short vxlan_dport_net_order;
	int vxlan_link_id;
	int vxlan_vlan_num;
	int sample_pkt_dir; /* 基准数据包捕获时的传输方向, C:in-to-out, vxlan dir is 0; I:out-to-int, vxlan dir is 1;  */
	int send_pkt_CorI; /* 插件的发包方向, 如果与sample_pkt_dir一致, 内层mac同向, 如果相反, 需要把内层MAC交换 */
	int inner_layer2_type; /* 内层封装类型, Ethernet, PPP, HDLC */

	unsigned short inner_sport_net_order;
	unsigned short inner_dport_net_order;
	unsigned int inner_sip_net_order;
	unsigned int inner_dip_net_order;	
	unsigned char  inner_smac[6];
	unsigned char inner_dmac[6];
	unsigned char payload[1400];
	int payload_len;
	int send_pps; /* 防止发包过快, 允许插件自行指定每秒发包个数 */
}send_pkt_para_t;

static send_pkt_para_t g_wangyan_send_fake_pkt_para;

typedef struct{
	int last_record_time;
	unsigned int realtime_pkt_num;
	char __pad[58];
}send_pkt_realtime_t;

static send_pkt_realtime_t g_wangyan_send_fake_pkt_rt_stat[MAX_THREAD_NUM];

typedef struct {
	int use_which_config;  /*  'M',  'N' */
	char para_name[32];
	char para_delime; /* 配置文件分隔符 */
	char MESA_para_name[32];
	char ONLINE_para_name[32];
	char user_arg[32];
	int (*config_convert)(const char *conf_str, send_pkt_para_t *send_para_bin);
}send_pkt_conf_parse_t;

#if 0
static send_pkt_conf_parse_t g_send_pkt_conf_engine[] =
{
	{'M',"conf_file_name",		'=',		"./conf/wangyan_send_fake_pkt.conf",	"/home/ningsi/new_machine.conf",  	""},	
	{'N',	"vxlan_smac	",		':',		"vxlan_smac",					"SRC_OUT_MAC",					"-"},
	{'N',	"vxlan_dmac	",		':',		"vxlan_dmac",					"DST_OUT_MAC",					":"},
	{'N',	"vxlan_sip		",		':',		"vxlan_sip",					"115_IP",							""},
	{'N',	"vxlan_dip		",		':',		"vxlan_dip",					"GIP",							""},
	{'M',"vxlan_sport	",		'=',		"vxlan_sport",					"",								""},
	{'M',"vxlan_dport	",		'=',		"vxlan_dport",					"",								""},
	{'N',	"vxlan_link_id	",		':',		"vxlan_link_id",					"LINK_ID_VALUE",				""},
	{'N',	"vxlan_vlxn_num",		':',		"vxlan_vlxn_num",				"no",								""},
	{'N',	"vxlan_inner_layer2_type" ,':',		"vxlan_inner_layer2_type",		"LINK_TYPE",					""},
	{'M',"vxlan_trans_dir",		'=',		"vxlan_trans_dir",				"C_DIR",							"CorI"},
	{'N',	"vxlan_inner_smac",		':',		"vxlan_inner_smac",				"SRC_IN_MAC",					":"},
	{'N',	"vxlan_inner_dmac",		':',		"vxlan_inner_dmac",				"DST_IN_MAC",					":"}
}

/*
	#use_which 		PARA_NAME				DELIM	MESA_NAME						ONLINE_NAME					USER_ARG
	#使用来源			
	M				conf_file_name		=		./conf/wangyan_send_pkt.conf	/home/ningsi/new_machine.conf	
	N				vxlan_smac			:		vxlan_smac					SRC_OUT_MAC					-
	N				vxlan_dmac			:		vxlan_dmac					DST_OUT_MAC					:
	N				vxlan_sip				:		vxlan_sip						115_IP
	N				vxlan_dip				:		vxlan_dip						GIP
	M				vxlan_sport			=		vxlan_sport					--no
	M				vxlan_dport			=		vxlan_dport					--no
	N				vxlan_link_id			:		vxlan_link_id					LINK_ID_VALUE
	N				vxlan_vlxn_num		:		vxlan_vlxn_num				no
	N				vxlan_inner_layer2_type :		vxlan_inner_layer2_type		LINK_TYPE
	M				vxlan_trans_dir		=		vxlan_trans_dir				C_DIR						CorI
	N				vxlan_inner_smac		:		vxlan_inner_smac				SRC_IN_MAC					:
	N				vxlan_inner_dmac		:		vxlan_inner_dmac				DST_IN_MAC					:
	
*/
#endif

/* 读取ningsi的配置文件, 没有[main], [module]等section, 自己模拟mesa_prof_load实现一个 */
static int __load_profile_string_no_section(const char *filename, const char *key, int delim, char out_value[256])
{
	FILE *fp;
	char tmp_line[1024];
	char *start_ptr;
	int index;
	
	fp = fopen(filename, "r");
	if(NULL == fp){
		printf("open file %s error, %s\n", filename, strerror(errno));
		return -1;
	}

	memset(tmp_line, 0, 1024);

	while(fgets(tmp_line, 1024, fp) != NULL){
		index = 0;
		del_last_rn(tmp_line, 1024);

		if('#' == tmp_line[0]){
			continue;
		}
		
		if(strncasecmp(key, tmp_line, strlen(key)) == 0){
			start_ptr = memchr(tmp_line, delim, 1024);
			if(start_ptr == NULL){ /* 无分隔符 */
				continue;
			}
			start_ptr++;
			while((start_ptr[index] == ' ' ) || (start_ptr[index] == '\t')){
				index++;
			}

			strncpy(out_value, start_ptr+index, strlen(start_ptr+index)+1);

			fclose(fp);
			return 0;
		}

		memset(tmp_line, 0, 1024);
	}

	fclose(fp);

	printf("config key %s not found!\n", key);

	return -1;
}

static int wangyan_send_fake_pkt_init(void)
{
	char config_file[1024];
	char tmp_str[256];
	int tmp_int;
	unsigned short tmp_short;
	int ret;

	MESA_load_profile_string_def("./conf/wangyan_send_fake_pkt.conf", "main", "config_file_name", config_file, 1024, "/home/ningsi/new_machine.conf");

	MESA_load_profile_int_def("./conf/wangyan_send_fake_pkt.conf", "main", "send_pps", &g_wangyan_send_fake_pkt_para.send_pps, 1);
	
	MESA_load_profile_string_def("./conf/wangyan_send_fake_pkt.conf", "main", "send_CorI", tmp_str, 256, "I");
	if(tmp_str[0] == 'C'){
		g_wangyan_send_fake_pkt_para.send_pkt_CorI = 0;
	}else if(tmp_str[0] == 'I'){
		g_wangyan_send_fake_pkt_para.send_pkt_CorI = 1;
	}else{
		printf("get config %s error, onlye support C or I!\n", "send_CorI");
		return -1;
	}

	/**********   SRC_OUT_MAC  **********/
	ret = __load_profile_string_no_section(config_file, "SRC_OUT_MAC", ':',  tmp_str);
	if(ret < 0){
		printf("get config %s error!\n", "SRC_OUT_MAC");
		return -1;
	}
	ret = MESA_mac_pton(tmp_str, '-', (char *)g_wangyan_send_fake_pkt_para.vxlan_smac);
	if(ret < 0){
		ret = MESA_mac_pton(tmp_str, ':', (char *)g_wangyan_send_fake_pkt_para.vxlan_smac);
		if(ret < 0){
			printf("parse config %s error!\n", "SRC_OUT_MAC");
			return -1;
		}
	}

	/**********   DST_OUT_MAC  **********/
	ret = __load_profile_string_no_section(config_file, "DST_OUT_MAC", ':',  tmp_str);
	if(ret < 0){
		printf("get config %s error!\n", "DST_OUT_MAC");
		return -1;
	}
	ret = MESA_mac_pton(tmp_str, '-', (char *)g_wangyan_send_fake_pkt_para.vxlan_dmac);
	if(ret < 0){
		ret = MESA_mac_pton(tmp_str, ':', (char *)g_wangyan_send_fake_pkt_para.vxlan_dmac);
		if(ret < 0){
			printf("parse config %s error!\n", "DST_OUT_MAC");
			return -1;
		}
	}	

	/**********   115_IP  **********/
	ret = __load_profile_string_no_section(config_file, "115_IP", ':',  tmp_str);
	if(ret < 0){
		printf("get config %s error!\n", "115_IP");
		return -1;
	}
	ret = inet_pton(AF_INET, tmp_str, &g_wangyan_send_fake_pkt_para.vxlan_sip_net_order);
	if(ret <= 0){
		printf("parse config %s error!\n", "115_IP");
		return -1;
	}	

	/**********   GIP  **********/
	ret = __load_profile_string_no_section(config_file, "GIP", ':',  tmp_str);
	if(ret < 0){
		ret = __load_profile_string_no_section(config_file, "G_IP", ':',  tmp_str); /* 有些配置文件不一致, GIP, G_IP都有 */
		if(ret < 0){
			printf("get config %s error!\n", "G_IP");
			return -1;
		}
	}
	ret = inet_pton(AF_INET, tmp_str, &g_wangyan_send_fake_pkt_para.vxlan_dip_net_order);
	if(ret <= 0){
		printf("parse config %s error!\n", "G_IP");
		return -1;
	}

	/**********   vxlan_sport  **********/
	MESA_load_profile_int_def("./conf/wangyan_send_fake_pkt.conf", "ningsi_no_config", "vxlan_sport", &tmp_int, 50704);
	if(tmp_int <= 0 || tmp_int > 65535){
		printf("parse config %s error!\n", "vxlan_sport");
		return -1;
	}
	tmp_short = tmp_int;
	g_wangyan_send_fake_pkt_para.vxlan_sport_net_order = ntohs(tmp_short);


	/**********   vxlan_dport  **********/
	MESA_load_profile_int_def("./conf/wangyan_send_fake_pkt.conf", "ningsi_no_config", "vxlan_dport", &tmp_int, 4789);
	if(tmp_int <= 0 || tmp_int > 65535){
		printf("parse config %s error!\n", "vxlan_dport");
		return -1;
	}
	tmp_short = tmp_int;
	g_wangyan_send_fake_pkt_para.vxlan_dport_net_order = ntohs(tmp_short);


	/**********   LINK_ID_VALUE  **********/
	ret = __load_profile_string_no_section(config_file, "LINK_ID_VALUE", ':',  tmp_str);
	if(ret < 0){
		printf("get config %s error!\n", "LINK_ID_VALUE");
		return -1;
	}
 	tmp_int = atoi(tmp_str);
 	if(tmp_int< 0 || tmp_int > 64){  /* link id 总长6bit, 数值范围[0,63] */
		printf("parse config %s error!\n", "LINK_ID_VALUE");
		return -1;
 	}
 	g_wangyan_send_fake_pkt_para.vxlan_link_id = tmp_int;



	/**********   vxlan_vlxn_num  **********/
	MESA_load_profile_int_def("./conf/wangyan_send_fake_pkt.conf", "ningsi_no_config", "vxlan_vlan_num", &tmp_int, 115);
	if(tmp_int <= 0 || tmp_int > 4096){
		printf("parse config %s error!\n", "vxlan_vlxn_num");
		return -1;
	}
	if(tmp_int < 0 || tmp_int > 4096){
		printf("parse config %s error!\n", "vxlan_vlxn_num");
		return -1;
	}
	g_wangyan_send_fake_pkt_para.vxlan_vlan_num = tmp_int;


	/**********   LINK_TYPE  **********/
	ret = __load_profile_string_no_section(config_file, "LINK_TYPE", ':',  tmp_str);
	if(ret < 0){
		printf("get config %s error!\n", "LINK_TYPE");
		return -1;
	}
 	tmp_int = atoi(tmp_str);

 	if(tmp_int == 0){
		g_wangyan_send_fake_pkt_para.inner_layer2_type = TUNNAT_TUNNEL_TYPE_ETHER;
 	}else if(tmp_int = 0x80){
		g_wangyan_send_fake_pkt_para.inner_layer2_type = TUNNAT_TUNNEL_TYPE_PPP;
 	}else if(tmp_int = 0xC0){
		g_wangyan_send_fake_pkt_para.inner_layer2_type = TUNNAT_TUNNEL_TYPE_HDLC;
 	}else{
		printf("parse config %s error!\n", "LINK_TYPE");
		return -1;
 	}
 	g_wangyan_send_fake_pkt_para.inner_layer2_type = tmp_int;


	/**********   CorI  **********/
	ret = __load_profile_string_no_section(config_file, "CorI", ':',  tmp_str);
	if(ret < 0){
		printf("get config %s error!\n", "CorI");
		return -1;
	}
	if(tmp_str[0] == 'C'){
		g_wangyan_send_fake_pkt_para.sample_pkt_dir = 0;
	}else if(tmp_str[0] == 'I'){
		g_wangyan_send_fake_pkt_para.sample_pkt_dir = 1;
	}else{
		printf("parse config %s error!\n", "CorI");
		return -1;
	}

	/**********   inner sport  **********/
	MESA_load_profile_int_def("./conf/wangyan_send_fake_pkt.conf", "ningsi_no_config", "inner_sport", &tmp_int, 8888);
	if(tmp_int <= 0 || tmp_int > 65535){
		printf("parse config %s error!\n", "inner_sport");
		return -1;
	}
	tmp_short = tmp_int;
	g_wangyan_send_fake_pkt_para.inner_sport_net_order = ntohs(tmp_short);

	/**********   inner dport  **********/
	MESA_load_profile_int_def("./conf/wangyan_send_fake_pkt.conf", "ningsi_no_config", "inner_dport", &tmp_int, 8888);
	if(tmp_int <= 0 || tmp_int > 65535){
		printf("parse config %s error!\n", "inner_dport");
		return -1;
	}
	tmp_short = tmp_int;
	g_wangyan_send_fake_pkt_para.inner_dport_net_order = ntohs(tmp_short);


	/**********   inner_sip  **********/
	memset(tmp_str, 0, sizeof(tmp_str));
	MESA_load_profile_string_nodef("./conf/wangyan_send_fake_pkt.conf", "ningsi_no_config", "inner_sip", tmp_str, sizeof(tmp_str));

	ret = inet_pton(AF_INET, tmp_str, &g_wangyan_send_fake_pkt_para.inner_sip_net_order);
	if(ret <= 0){
		printf("parse config %s error, %s!\n", "inner_sip", strerror(errno));
		return -1;
	}

	/**********   inner_dip  **********/
	memset(tmp_str, 0, sizeof(tmp_str));
	MESA_load_profile_string_nodef("./conf/wangyan_send_fake_pkt.conf", "ningsi_no_config", "inner_dip", tmp_str, sizeof(tmp_str));

	ret = inet_pton(AF_INET, tmp_str, &g_wangyan_send_fake_pkt_para.inner_dip_net_order);
	if(ret <= 0){
		printf("parse config %s error, %s!\n", "inner_dip", strerror(errno));
		return -1;
	}	

	/**********   SRC_IN_MAC  **********/
	ret = __load_profile_string_no_section(config_file, "SRC_IN_MAC", ':',  tmp_str);
	if(ret < 0){
		printf("get config %s error!\n", "SRC_IN_MAC");
		return -1;
	}
	ret = MESA_mac_pton(tmp_str, ':', (char *)g_wangyan_send_fake_pkt_para.inner_smac);
	if(ret < 0){
		ret = MESA_mac_pton(tmp_str, '-', (char *)g_wangyan_send_fake_pkt_para.inner_smac);
		if(ret < 0){
			printf("parse config %s error!\n", "SRC_IN_MAC");
			return -1;
		}
	}	

	/**********   DST_IN_MAC  **********/
	ret = __load_profile_string_no_section(config_file, "DST_IN_MAC", ':',  tmp_str);
	if(ret < 0){
		printf("get config %s error!\n", "DST_IN_MAC");
		return -1;
	}
	ret = MESA_mac_pton(tmp_str, ':', (char *)g_wangyan_send_fake_pkt_para.inner_dmac);
	if(ret < 0){
		ret = MESA_mac_pton(tmp_str, '-', (char *)g_wangyan_send_fake_pkt_para.inner_dmac);
		if(ret < 0){
			printf("parse config %s error!\n", "DST_IN_MAC");
			return -1;
		}
	}

	/**********   payload  **********/

	MESA_load_profile_string_def("./conf/wangyan_send_fake_pkt.conf", "ningsi_no_config", "payload", g_wangyan_send_fake_pkt_para.payload, sizeof(g_wangyan_send_fake_pkt_para.payload),  "test send fake packet");
	g_wangyan_send_fake_pkt_para.payload_len = strlen(g_wangyan_send_fake_pkt_para.payload);
 	

	return 0;
}


static int wangyan_polling_cb_send_control(int tid)
{
	if(g_wangyan_send_fake_pkt_rt_stat[tid].realtime_pkt_num  > g_wangyan_send_fake_pkt_para.send_pps){
		/* 如果包数超限制, 且时间在一个统计周期内(1秒内) */
		if(g_wangyan_send_fake_pkt_rt_stat[tid].last_record_time >= g_CurrentTime){
			return 0;
		}else{
			g_wangyan_send_fake_pkt_rt_stat[tid].last_record_time = g_CurrentTime;
			g_wangyan_send_fake_pkt_rt_stat[tid].realtime_pkt_num = 0;
			return 1;
		}
	}

	return 1;
}

/*
    inside                                      outside

    >------------->C(vxlan dir = 0)------------------->
 
    <--------------I(vxlan dir = 1)-------------------<


    if ningsi.conf->CorI is C, means sample packet from inside to outside, vxlan dir flag is 0;
    if ningsi.conf->CorI is I, means sample packet from outside to inside, vxlan dir flag is 1;
*/

char wangyan_polling_cb_send_fake_pkt_udp(struct streaminfo *__stream,void **__pme, int thread_seq,const void *__raw_pkt)
{

	struct streaminfo phony_stream;
	SAPP_TLV_T option[32];
	int option_num = 0;
	int vxlan_link_id = 1;

	if(0 == wangyan_polling_cb_send_control(thread_seq)){
		return APP_STATE_GIVEME;
	}
	
	phony_stream.threadnum = thread_seq; /* 虚假流结构体, MESA_fakepacket_send_udp_options()函数需要线程id, 此处赋值即可 */

	option[option_num].type = SAPP_SEND_OPT_GDEV_SMAC;
	option[option_num].length = 6;
	memcpy(option[option_num].array_value, g_wangyan_send_fake_pkt_para.vxlan_smac, 6);
	option_num++;////////
	option[option_num].type = SAPP_SEND_OPT_GDEV_DMAC;
	option[option_num].length = 6;
	memcpy(option[option_num].array_value, g_wangyan_send_fake_pkt_para.vxlan_dmac, 6);
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_GDEV_SIP;
	option[option_num].length = 4;
	option[option_num].int_value = g_wangyan_send_fake_pkt_para.vxlan_sip_net_order;
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_GDEV_DIP;
	option[option_num].length = 4;
	option[option_num].int_value = g_wangyan_send_fake_pkt_para.vxlan_dip_net_order;;
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_GDEV_UDP_SPORT;
	option[option_num].length = 2;
//	option[option_num].short_value = ntohs(g_wangyan_send_fake_pkt_para.vxlan_sport_net_order);
	option[option_num].short_value = g_wangyan_send_fake_pkt_para.vxlan_sport_net_order;
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_GDEV_UDP_DPORT;
	option[option_num].length = 2;
	option[option_num].short_value = ntohs(g_wangyan_send_fake_pkt_para.vxlan_dport_net_order);
	option_num++;///////

	option[option_num].type = SAPP_SEND_OPT_VXLAN_VPN_ID;
	option[option_num].length = 4;
//	option[option_num].int_value = htonl(g_wangyan_send_fake_pkt_para.vxlan_vlan_num);
	option[option_num].int_value = g_wangyan_send_fake_pkt_para.vxlan_vlan_num;
	option_num++;///////
	
	option[option_num].type = SAPP_SEND_OPT_VXLAN_LINK_ID;
	option[option_num].length = 4;
	option[option_num].int_value = g_wangyan_send_fake_pkt_para.vxlan_link_id;
	option_num++;///////

	option[option_num].type = SAPP_SEND_OPT_VXLAN_LINK_ENCAP_TYPE;
	option[option_num].length = 1;
	option[option_num].char_value = TUNNAT_TUNNEL_TYPE_ETHER;
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_VXLAN_LINK_DIR;
	option[option_num].length = 1;
	option[option_num].char_value = g_wangyan_send_fake_pkt_para.send_pkt_CorI;
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_INNER_LINK_ENCAP_TYPE;
	option[option_num].length = 1;
	option[option_num].char_value = TUNNAT_TUNNEL_TYPE_ETHER;
	option_num++;///////

	/* 发包方向不同, 仅需交换内层MAC即可, IP和端口由配置文件填写, 严格按照用户需求, 无需修改 */
	option[option_num].type = SAPP_SEND_OPT_INNER_SMAC;
	option[option_num].length = 6;
	if(g_wangyan_send_fake_pkt_para.sample_pkt_dir == g_wangyan_send_fake_pkt_para.send_pkt_CorI){
		memcpy(option[option_num].array_value, g_wangyan_send_fake_pkt_para.inner_smac, 6);
	}else{
		memcpy(option[option_num].array_value, g_wangyan_send_fake_pkt_para.inner_dmac, 6);
	}
	option_num++;///////
	
	option[option_num].type = SAPP_SEND_OPT_INNER_DMAC;
	option[option_num].length = 6;
	if(g_wangyan_send_fake_pkt_para.sample_pkt_dir == g_wangyan_send_fake_pkt_para.send_pkt_CorI){
		memcpy(option[option_num].array_value, g_wangyan_send_fake_pkt_para.inner_dmac, 6);
	}else{
		memcpy(option[option_num].array_value, g_wangyan_send_fake_pkt_para.inner_smac, 6);
	}
	option_num++;///////

	MESA_fakepacket_send_udp_options(&phony_stream,  
					ntohl(g_wangyan_send_fake_pkt_para.inner_sip_net_order),
					  ntohl(g_wangyan_send_fake_pkt_para.inner_dip_net_order),
					  ntohs(g_wangyan_send_fake_pkt_para.inner_sport_net_order),
					  ntohs(g_wangyan_send_fake_pkt_para.inner_dport_net_order),
					  g_wangyan_send_fake_pkt_para.payload,
					  g_wangyan_send_fake_pkt_para.payload_len,
					  g_wangyan_send_fake_pkt_para.send_pkt_CorI,
					  option,
					  option_num);

	g_wangyan_send_fake_pkt_rt_stat[thread_seq].realtime_pkt_num++;
	
	return APP_STATE_GIVEME;	
}

char wangyan_polling_cb_send_fake_pkt_tcp(struct streaminfo *__stream,void **__pme, int thread_seq,const void *__raw_pkt)
{	
	struct streaminfo phony_stream;
	SAPP_TLV_T option[32];
	int option_num = 0;
	int vxlan_link_id = 1;

	if(0 == wangyan_polling_cb_send_control(thread_seq)){
		return APP_STATE_GIVEME;
	}
	
	phony_stream.threadnum = thread_seq; /* 虚假流结构体, MESA_fakepacket_send_udp_options()函数需要线程id, 此处赋值即可 */

	option[option_num].type = SAPP_SEND_OPT_GDEV_SMAC;
	option[option_num].length = 6;
	memcpy(option[option_num].array_value, g_wangyan_send_fake_pkt_para.vxlan_smac, 6);
	option_num++;////////
	option[option_num].type = SAPP_SEND_OPT_GDEV_DMAC;
	option[option_num].length = 6;
	memcpy(option[option_num].array_value, g_wangyan_send_fake_pkt_para.vxlan_dmac, 6);
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_GDEV_SIP;
	option[option_num].length = 4;
	option[option_num].int_value = g_wangyan_send_fake_pkt_para.vxlan_sip_net_order;
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_GDEV_DIP;
	option[option_num].length = 4;
	option[option_num].int_value = g_wangyan_send_fake_pkt_para.vxlan_dip_net_order;;
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_GDEV_UDP_SPORT;
	option[option_num].length = 2;
//	option[option_num].short_value = ntohs(g_wangyan_send_fake_pkt_para.vxlan_sport_net_order);
	option[option_num].short_value = g_wangyan_send_fake_pkt_para.vxlan_sport_net_order;
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_GDEV_UDP_DPORT;
	option[option_num].length = 2;
	option[option_num].short_value = ntohs(g_wangyan_send_fake_pkt_para.vxlan_dport_net_order);
	option_num++;///////


	option[option_num].type = SAPP_SEND_OPT_VXLAN_VPN_ID;
	option[option_num].length = 4;
//	option[option_num].int_value = htonl(g_wangyan_send_fake_pkt_para.vxlan_vlan_num);
	option[option_num].int_value = g_wangyan_send_fake_pkt_para.vxlan_vlan_num;
	option_num++;///////
	
	option[option_num].type = SAPP_SEND_OPT_VXLAN_LINK_ID;
	option[option_num].length = 4;
	option[option_num].int_value = g_wangyan_send_fake_pkt_para.vxlan_link_id;
	option_num++;///////

	option[option_num].type = SAPP_SEND_OPT_VXLAN_LINK_ENCAP_TYPE;
	option[option_num].length = 1;
	option[option_num].char_value = TUNNAT_TUNNEL_TYPE_ETHER;
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_VXLAN_LINK_DIR;
	option[option_num].length = 1;
	option[option_num].char_value = g_wangyan_send_fake_pkt_para.send_pkt_CorI;
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_INNER_LINK_ENCAP_TYPE;
	option[option_num].length = 1;
	option[option_num].char_value = TUNNAT_TUNNEL_TYPE_ETHER;
	option_num++;///////

	/* 发包方向不同, 仅需交换内层MAC即可, IP和端口由配置文件填写, 严格按照用户需求, 无需修改 */
	option[option_num].type = SAPP_SEND_OPT_INNER_SMAC;
	option[option_num].length = 6;
	if(g_wangyan_send_fake_pkt_para.sample_pkt_dir == g_wangyan_send_fake_pkt_para.send_pkt_CorI){
		memcpy(option[option_num].array_value, g_wangyan_send_fake_pkt_para.inner_smac, 6);
	}else{
		memcpy(option[option_num].array_value, g_wangyan_send_fake_pkt_para.inner_dmac, 6);
	}
	option_num++;///////
	
	option[option_num].type = SAPP_SEND_OPT_INNER_DMAC;
	option[option_num].length = 6;
	if(g_wangyan_send_fake_pkt_para.sample_pkt_dir == g_wangyan_send_fake_pkt_para.send_pkt_CorI){
		memcpy(option[option_num].array_value, g_wangyan_send_fake_pkt_para.inner_dmac, 6);
	}else{
		memcpy(option[option_num].array_value, g_wangyan_send_fake_pkt_para.inner_smac, 6);
	}
	option_num++;///////

	MESA_fakepacket_send_tcp_options(&phony_stream,  
					ntohl(g_wangyan_send_fake_pkt_para.inner_sip_net_order),
					  ntohl(g_wangyan_send_fake_pkt_para.inner_dip_net_order),
					  ntohs(g_wangyan_send_fake_pkt_para.inner_sport_net_order),
					  ntohs(g_wangyan_send_fake_pkt_para.inner_dport_net_order),
					  0x12345678,
					  0x87654321,
					  0x2,
					  g_wangyan_send_fake_pkt_para.payload,
					  g_wangyan_send_fake_pkt_para.payload_len,
					  g_wangyan_send_fake_pkt_para.send_pkt_CorI,
					  option,
					  option_num);

	g_wangyan_send_fake_pkt_rt_stat[thread_seq].realtime_pkt_num++;
	
	return APP_STATE_GIVEME;	
}


char wangyan_polling_cb_send_fake_pkt_iplayer(struct streaminfo *__stream, void **__pme, int thread_seq,const void *__raw_pkt)
{
	char snd_pkt_payload[] = 
	{
		/* ICMP request, from 8.8.8.8 to 192.168.11.129 */
		0x45,0x00,0x00,0x54,0x00,0x00,0x40,0x00,
		0x40,0x01,0x19,0xF9,
		0x8,0x8,0x8,0x8, 
		0xC0,0xA8,0x0B,0x81,
		0x08,0x00,0xC2,0x6A,0x18,0x8B,0x00,0x07,
		0xE5,0xB8,0xA8,0x54,0x00,0x00,0x00,0x00,
		0x22,0x5C,0x06,
		0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
	};
	
	if(0 == wangyan_polling_cb_send_control(thread_seq)){
		return APP_STATE_GIVEME;
	}
	
	SAPP_TLV_T option[32];
	int option_num = 0;
	int vxlan_link_id = 1;

	option[option_num].type = SAPP_SEND_OPT_GDEV_SMAC;
	option[option_num].length = 6;
	memcpy(option[option_num].array_value, g_wangyan_send_fake_pkt_para.vxlan_smac, 6);
	option_num++;////////
	option[option_num].type = SAPP_SEND_OPT_GDEV_DMAC;
	option[option_num].length = 6;
	memcpy(option[option_num].array_value, g_wangyan_send_fake_pkt_para.vxlan_dmac, 6);
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_GDEV_SIP;
	option[option_num].length = 4;
	option[option_num].int_value = g_wangyan_send_fake_pkt_para.vxlan_sip_net_order;
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_GDEV_DIP;
	option[option_num].length = 4;
	option[option_num].int_value = g_wangyan_send_fake_pkt_para.vxlan_dip_net_order;;
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_GDEV_UDP_SPORT;
	option[option_num].length = 2;
//	option[option_num].short_value = ntohs(g_wangyan_send_fake_pkt_para.vxlan_sport_net_order);
	option[option_num].short_value = g_wangyan_send_fake_pkt_para.vxlan_sport_net_order;
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_GDEV_UDP_DPORT;
	option[option_num].length = 2;
	option[option_num].short_value = ntohs(g_wangyan_send_fake_pkt_para.vxlan_dport_net_order);
	option_num++;///////


	option[option_num].type = SAPP_SEND_OPT_VXLAN_VPN_ID;
	option[option_num].length = 4;
//	option[option_num].int_value = htonl(g_wangyan_send_fake_pkt_para.vxlan_vlan_num);
	option[option_num].int_value = g_wangyan_send_fake_pkt_para.vxlan_vlan_num;
	option_num++;///////
	
	option[option_num].type = SAPP_SEND_OPT_VXLAN_LINK_ID;
	option[option_num].length = 4;
	option[option_num].int_value = g_wangyan_send_fake_pkt_para.vxlan_link_id;
	option_num++;///////

	option[option_num].type = SAPP_SEND_OPT_VXLAN_LINK_ENCAP_TYPE;
	option[option_num].length = 1;
	option[option_num].char_value = TUNNAT_TUNNEL_TYPE_ETHER;
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_VXLAN_LINK_DIR;
	option[option_num].length = 1;
	option[option_num].char_value = g_wangyan_send_fake_pkt_para.send_pkt_CorI;
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_INNER_LINK_ENCAP_TYPE;
	option[option_num].length = 1;
	option[option_num].char_value = TUNNAT_TUNNEL_TYPE_ETHER;
	option_num++;///////

	/* 发包方向不同, 仅需交换内层MAC即可, IP和端口由配置文件填写, 严格按照用户需求, 无需修改 */
	option[option_num].type = SAPP_SEND_OPT_INNER_SMAC;
	option[option_num].length = 6;
	if(g_wangyan_send_fake_pkt_para.sample_pkt_dir == g_wangyan_send_fake_pkt_para.send_pkt_CorI){
		memcpy(option[option_num].array_value, g_wangyan_send_fake_pkt_para.inner_smac, 6);
	}else{
		memcpy(option[option_num].array_value, g_wangyan_send_fake_pkt_para.inner_dmac, 6);
	}
	option_num++;///////
	
	option[option_num].type = SAPP_SEND_OPT_INNER_DMAC;
	option[option_num].length = 6;
	if(g_wangyan_send_fake_pkt_para.sample_pkt_dir == g_wangyan_send_fake_pkt_para.send_pkt_CorI){
		memcpy(option[option_num].array_value, g_wangyan_send_fake_pkt_para.inner_dmac, 6);
	}else{
		memcpy(option[option_num].array_value, g_wangyan_send_fake_pkt_para.inner_smac, 6);
	}
	option_num++;///////

	MESA_sendpacket_iplayer_options(thread_seq,  
					 snd_pkt_payload,
					 sizeof(snd_pkt_payload),
					  g_wangyan_send_fake_pkt_para.send_pkt_CorI,
					  option,
					  option_num);

	g_wangyan_send_fake_pkt_rt_stat[thread_seq].realtime_pkt_num++;
	
	return APP_STATE_GIVEME;	
}
#if 0
static void *test_gdev_get_opt(void *arg)
{
	SAPP_TLV_T sapp_tlv;

	sapp_tlv.type = GDEV_KEEPALIVE_OPT_RCV_PKT_PPS;
	sapp_tlv.length = sizeof(long);
	
	while(1){
		sapp_tlv.type = GDEV_KEEPALIVE_OPT_RCV_PKT_PPS;
		gdev_keepalive_get_opt(&sapp_tlv);
		printf("GDEV_KEEPALIVE rcv pps:%ld\n", sapp_tlv.long_value);

		sapp_tlv.type = GDEV_KEEPALIVE_OPT_SND_PKT_PPS;
		gdev_keepalive_get_opt(&sapp_tlv);
		printf("GDEV_KEEPALIVE snd pps:%ld\n", sapp_tlv.long_value);	

		sleep(1);
	}

	return NULL;
}
#endif


char test_pkt_action(int net_conn_mode, char plug_action)
{
	char ret = 1;
	
	if(plug_action == 1){
		ret = 0;	
	}

	printf("test_pkt_action_cb return DROP!\n");

	return ret;
}


static void *plug_thread_send(void *arg)
{
	int send_tid;
	int opt_len = sizeof(int);

	char snd_eth_pkt_data[] = 
	{
		0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
		0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
		0x08, 0x00,
		0x45,0x00,0x00,0x54,0x00,0x00,0x40,0x00,
		0x40,0x01,0x19,0xF9,0x0A,0x0A,0x06,0x6C,
		0x0A,0x00,0x06,0x3B,
		0x08,0x00,0xC2,0x6A,0x18,0x8B,0x00,0x07,
		0xE5,0xB8,0xA8,0x54,0x00,0x00,0x00,0x00,
		0x22,0x5C,0x06,
		0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
	};
	
	char snd_ip_pkt_payload[] = 
	{
		0x08,0x00,0xC2,0x6A,0x18,0x8B,0x00,0x07,
		0xE5,0xB8,0xA8,0x54,0x00,0x00,0x00,0x00,
		0x22,0x5C,0x06,
		0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
	};
	
	sapp_get_platform_opt(SPO_INDEPENDENT_THREAD_ID,  &send_tid,  &opt_len);
	sleep(5); /* 等待packet_io初始化成功 */
	
	while(1){
#if 0	
		wangyan_polling_cb_send_fake_pkt_tcp(NULL, NULL, send_tid, NULL);
#else
		struct streaminfo phony_stream;
		phony_stream.threadnum = send_tid;
//		Gserial_sendpacket_ipv4(1, &phony_stream, 32, 17, 0x01010101, 0x02020202, snd_ip_pkt_payload, sizeof(snd_ip_pkt_payload), 0);
		MESA_sendpacket_ethlayer(send_tid, snd_eth_pkt_data, sizeof(snd_eth_pkt_data), 0);
#endif		
		sleep(1);
	}

	return NULL;
}

int test_wangyan_init(void)
{
	int ret;
	pthread_t tid;

	pthread_create(&tid, NULL, plug_thread_send, NULL);

	//platform_register_action_judge(test_pkt_action);
	
	//pthread_create(&tid, NULL, test_shengkou_thread, NULL);	

	//pthread_create(&tid, NULL, wangyan_send_fake_pkt_thread, NULL);	

	ret = wangyan_send_fake_pkt_init();
	
	return ret;
}

#ifdef __cplusplus
}
#endif

