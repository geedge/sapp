#include "sapp_api.h"
#include "sapp_private_api.h"

#ifdef __cplusplus
extern "C" {
#endif 

int wangyan_gdev_measure_version_20190527;

#define GDEV_MEASURE_CONF_DIR "conf/wangyan_gdev_measure/"
#define GDEV_MEASURE_MAX_NUM	 (32) /* 最多同时支持多少个发送实例 */
#define GDEV_MEASURE_SEND_MSS	(1400)


typedef struct {
	/******  NingSi config  ******/
	unsigned char vxlan_smac[6]; /* 最外层mac */
	unsigned char vxlan_dmac[6];  /* 最外层mac */
	unsigned int vxlan_sip_net_order;
	unsigned int vxlan_dip_net_order;
	unsigned short vxlan_sport_net_order;
	unsigned short vxlan_dport_net_order;
	char vxlan_link_dir; /* 原始基准包的vxlan->link_dir值 */
	int vxlan_link_id;
	int vxlan_vlan_num;
	int sample_pkt_dir; /* 基准数据包捕获时的传输方向, C:in-to-out, vxlan dir is 0; I:out-to-in, vxlan dir is 1;  */
	int send_pkt_CorI; /* 插件的发包方向, 如果与sample_pkt_dir一致, 内层mac同向, 如果相反, 需要把内层MAC交换 */
	int inner_layer2_type; /* 内层封装类型, Ethernet, PPP, HDLC */

	/******  Gdev Measure plug config  ******/
	unsigned short inner_sport_net_order;
	unsigned short inner_dport_net_order;
	unsigned int inner_sip_net_order;
	unsigned int inner_dip_net_order;	
	unsigned char  inner_smac[6];
	unsigned char inner_dmac[6];
	unsigned char payload[GDEV_MEASURE_SEND_MSS];
	unsigned char transport_layer_type; /* tcp or udp */
	unsigned char transport_tcp_flags; /* SYN, FIN, RST, etc. */
	int payload_len;
	int send_pps; /* 防止发包过快, 允许插件自行指定每秒发包个数 */
}send_pkt_para_t;

typedef struct{
	send_pkt_para_t send_pkt_para;
	int send_pkt_num;
	time_t last_send_time;
}wangyan_gdev_measure_instance_t;


static wangyan_gdev_measure_instance_t wangyan_gdev_measure_instance_set[GDEV_MEASURE_MAX_NUM];
static int wangyan_gdev_measure_instance_num = 0;

typedef struct{
	int last_record_time;
	unsigned int realtime_pkt_num;
	char __pad[58];
}send_pkt_realtime_t;

static send_pkt_realtime_t g_wangyan_send_fake_pkt_rt_stat[MAX_THREAD_NUM];

static void *gdev_measure_logh;

extern int get_thread_count(void);
#if 0

typedef struct {
	int use_which_config;  /*  'M',  'N' */
	char para_name[32];
	char para_delime; /* 配置文件分隔符 */
	char MESA_para_name[32];
	char ONLINE_para_name[32];
	char user_arg[32];
	int (*config_convert)(const char *conf_str, send_pkt_para_t *send_para_bin);
}send_pkt_conf_parse_t;


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

static inline time_t get_tmie_from_sapp(void)
{
	time_t cur_time;
	int optlen = sizeof(time_t);
	
	sapp_get_platform_opt(SPO_CURTIME_TIMET, &cur_time, &optlen);

	return cur_time;
}


/* 读取NingSi的配置文件, 没有[main], [module]等section, 无法直接使用prof_load接口, 自己模拟mesa_prof_load实现一个 */
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

static int wangyan_gdev_measure_parse_config(const char *config_file, wangyan_gdev_measure_instance_t *tmp_ins)
{
	char tmp_str[256];
	int tmp_int;
	unsigned short tmp_short;
	int ret;


	/**********   SRC_OUT_MAC  **********/
	ret = __load_profile_string_no_section(config_file, "SRC_OUT_MAC", ':',  tmp_str);
	if(ret < 0){
		printf("get config %s error!\n", "SRC_OUT_MAC");
		return -1;
	}
	ret = MESA_mac_pton(tmp_str, '-', (char *)tmp_ins->send_pkt_para.vxlan_smac);
	if(ret < 0){
		ret = MESA_mac_pton(tmp_str, ':', (char *)tmp_ins->send_pkt_para.vxlan_smac);
		if(ret < 0){
			printf("parse config %s error, '%s'!\n", "SRC_OUT_MAC", tmp_str);
			return -1;
		}
	}

	/**********   DST_OUT_MAC  **********/
	ret = __load_profile_string_no_section(config_file, "DST_OUT_MAC", ':',  tmp_str);
	if(ret < 0){
		printf("get config %s error!\n", "DST_OUT_MAC");
		return -1;
	}
	ret = MESA_mac_pton(tmp_str, '-', (char *)tmp_ins->send_pkt_para.vxlan_dmac);
	if(ret < 0){
		ret = MESA_mac_pton(tmp_str, ':', (char *)tmp_ins->send_pkt_para.vxlan_dmac);
		if(ret < 0){
			printf("parse config %s error, %s!\n", "DST_OUT_MAC", tmp_str);
			return -1;
		}
	}	

	/**********   115_IP, NingSi叫115_IP, 也就是前端机的IP **********/
	ret = __load_profile_string_no_section(config_file, "115_IP", ':',  tmp_str);
	if(ret < 0){
		printf("get config %s error!\n", "115_IP");
		return -1;
	}
	ret = inet_pton(AF_INET, tmp_str, &tmp_ins->send_pkt_para.vxlan_sip_net_order);
	if(ret <= 0){
		printf("parse config %s error, %s!\n", "115_IP", tmp_str);
		return -1;
	}	

	/**********   GIP  **********/
	ret = __load_profile_string_no_section(config_file, "GIP", ':',  tmp_str);
	if(ret < 0){
		/* NingSi有些配置文件不一致, GIP, G_IP都有, 两个都尝试读一下试试 */
		ret = __load_profile_string_no_section(config_file, "G_IP", ':',  tmp_str); 
		if(ret < 0){
			printf("get config %s error!\n", "G_IP");
			return -1;
		}
	}
	ret = inet_pton(AF_INET, tmp_str, &tmp_ins->send_pkt_para.vxlan_dip_net_order);
	if(ret <= 0){
		printf("parse config %s error, %s!\n", "G_IP", tmp_str);
		return -1;
	}

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
 	tmp_ins->send_pkt_para.vxlan_link_id = tmp_int;
 	
	/**********   LINK_TYPE  **********/
	ret = __load_profile_string_no_section(config_file, "LINK_TYPE", ':',  tmp_str);
	if(ret < 0){
		printf("get config %s error!\n", "LINK_TYPE");
		return -1;
	}
 	tmp_int = atoi(tmp_str);

 	if(tmp_int == 0){
		tmp_ins->send_pkt_para.inner_layer2_type = TUNNAT_TUNNEL_TYPE_ETHER;
 	}else if(tmp_int = 0x80){
		tmp_ins->send_pkt_para.inner_layer2_type = TUNNAT_TUNNEL_TYPE_PPP;
 	}else if(tmp_int = 0xC0){
		tmp_ins->send_pkt_para.inner_layer2_type = TUNNAT_TUNNEL_TYPE_HDLC;
 	}else{
		printf("parse config %s error!\n", "LINK_TYPE");
		return -1;
 	}

 	/************** C_DIR ***************/
	ret = __load_profile_string_no_section(config_file, "C_DIR", ':', tmp_str);
	if(ret < 0){
		printf("get config %s error!\n", "C_DIR");
		return -1;
	}
 	tmp_int = atoi(tmp_str);
 	if(tmp_int != 0 && tmp_int != 1){ 
		printf("Invalid config %s:%s!\n", "C_DIR", tmp_str);
		return -1;
 	}
 	tmp_ins->send_pkt_para.vxlan_link_dir = (char)tmp_int;

	/**********   CorI  **********/
	ret = __load_profile_string_no_section(config_file, "CorI", ':',  tmp_str);
	if(ret < 0){
		printf("get config %s error!\n", "CorI");
		return -1;
	}
	if(tmp_str[0] == 'C'){
		tmp_ins->send_pkt_para.sample_pkt_dir = 0;
	}else if(tmp_str[0] == 'I'){
		tmp_ins->send_pkt_para.sample_pkt_dir = 1;
	}else{
		printf("parse config %s error!\n", "CorI");
		return -1;
	}
	
	/**********   SRC_IN_MAC  **********/
	ret = __load_profile_string_no_section(config_file, "SRC_IN_MAC", ':',  tmp_str);
	if(ret < 0){
		printf("get config %s error!\n", "SRC_IN_MAC");
		return -1;
	}
	ret = MESA_mac_pton(tmp_str, ':', (char *)tmp_ins->send_pkt_para.inner_smac);
	if(ret < 0){
		ret = MESA_mac_pton(tmp_str, '-', (char *)tmp_ins->send_pkt_para.inner_smac);
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
	ret = MESA_mac_pton(tmp_str, ':', (char *)tmp_ins->send_pkt_para.inner_dmac);
	if(ret < 0){
		ret = MESA_mac_pton(tmp_str, '-', (char *)tmp_ins->send_pkt_para.inner_dmac);
		if(ret < 0){
			printf("parse config %s error!\n", "DST_IN_MAC");
			return -1;
		}
	}
	
	/*****************  wangyan dev measure plug config  **********************/

	/**********   transport type ************************/
	MESA_load_profile_string_def(config_file, "plug", "transport_type", tmp_str, 256,  "tcp");
	if(strncasecmp(tmp_str, "tcp", 3) == 0){
		tmp_ins->send_pkt_para.transport_layer_type = IPPROTO_TCP;
	}else if(strncasecmp(tmp_str, "udp", 3) == 0){
		tmp_ins->send_pkt_para.transport_layer_type = IPPROTO_UDP;
	}else{
		printf("parse config %s error, only uspport tcp or udp!\n", "transport_type");
		return -1;
	}

	/**********   transport type ************************/
	MESA_load_profile_string_def(config_file, "plug", "transport_tcp_flags", tmp_str, 256,  "0x2");
	if(strncasecmp(tmp_str, "0x", 2) == 0){
		tmp_ins->send_pkt_para.transport_tcp_flags = (unsigned char)strtoul(tmp_str, NULL, 16);
	}else{
		tmp_ins->send_pkt_para.transport_tcp_flags = (unsigned char)strtoul(tmp_str, NULL, 10);
	}
	
	/**********   send pps  **********/
	MESA_load_profile_int_def(config_file, "plug", "send_pps", &tmp_int, 1);
	if(tmp_int < 1 || tmp_int > 1000){
		printf("parse config %s error, pps valid range=[1,1000]!\n", "send_pps");
		return -1;
	}
	tmp_ins->send_pkt_para.send_pps = tmp_int;

	/***************** send_CorI ************************/
	MESA_load_profile_string_def(config_file, "plug", "send_CorI", tmp_str, 256, "#");
	if(tmp_str[0] == 'C'){
		tmp_ins->send_pkt_para.send_pkt_CorI = 0;
	}else if(tmp_str[0] == 'I'){
		tmp_ins->send_pkt_para.send_pkt_CorI = 1;
	}else{
		printf("parse config %s error!\n", "send_CorI");
		return -1;
	}
	
	/**********   vxlan_sport  **********/
	MESA_load_profile_int_def(config_file, "plug", "vxlan_sport", &tmp_int, 50704);
	if(tmp_int <= 0 || tmp_int > 65535){
		printf("parse config %s error!\n", "vxlan_sport");
		return -1;
	}
	tmp_short = tmp_int;
	tmp_ins->send_pkt_para.vxlan_sport_net_order = ntohs(tmp_short);


	/**********   vxlan_dport  **********/
	MESA_load_profile_int_def(config_file, "plug", "vxlan_dport", &tmp_int, 4789);
	if(tmp_int <= 0 || tmp_int > 65535){
		printf("parse config %s error!\n", "vxlan_dport");
		return -1;
	}
	tmp_short = tmp_int;
	tmp_ins->send_pkt_para.vxlan_dport_net_order = ntohs(tmp_short);


	/**********   vxlan_vlxn_num  **********/
	MESA_load_profile_int_def(config_file, "plug", "vxlan_vlan_num", &tmp_int, 115);
	if(tmp_int <= 0 || tmp_int > 4096){
		printf("parse config %s error!\n", "vxlan_vlxn_num");
		return -1;
	}
	if(tmp_int < 0 || tmp_int > 4096){
		printf("parse config %s error!\n", "vxlan_vlxn_num");
		return -1;
	}
	tmp_ins->send_pkt_para.vxlan_vlan_num = tmp_int;


	/**********   inner sport  **********/
	MESA_load_profile_int_def(config_file, "plug", "inner_sport", &tmp_int, 8888);
	if(tmp_int <= 0 || tmp_int > 65535){
		printf("parse config %s error!\n", "inner_sport");
		return -1;
	}
	tmp_short = tmp_int;
	tmp_ins->send_pkt_para.inner_sport_net_order = ntohs(tmp_short);

	/**********   inner dport  **********/
	MESA_load_profile_int_def(config_file, "plug", "inner_dport", &tmp_int, 8888);
	if(tmp_int <= 0 || tmp_int > 65535){
		printf("parse config %s error!\n", "inner_dport");
		return -1;
	}
	tmp_short = tmp_int;
	tmp_ins->send_pkt_para.inner_dport_net_order = ntohs(tmp_short);


	/**********   inner_sip  **********/
	memset(tmp_str, 0, sizeof(tmp_str));
	MESA_load_profile_string_nodef(config_file, "plug", "inner_sip", tmp_str, sizeof(tmp_str));

	ret = inet_pton(AF_INET, tmp_str, &tmp_ins->send_pkt_para.inner_sip_net_order);
	if(ret <= 0){
		printf("parse config %s error, %s!\n", "inner_sip", strerror(errno));
		return -1;
	}

	/**********   inner_dip  **********/
	memset(tmp_str, 0, sizeof(tmp_str));
	MESA_load_profile_string_nodef(config_file, "plug", "inner_dip", tmp_str, sizeof(tmp_str));

	ret = inet_pton(AF_INET, tmp_str, &tmp_ins->send_pkt_para.inner_dip_net_order);
	if(ret <= 0){
		printf("parse config %s error, %s!\n", "inner_dip", strerror(errno));
		return -1;
	}	

	/**********   payload  **********/

	MESA_load_profile_string_def(config_file, "plug", "payload", tmp_ins->send_pkt_para.payload, sizeof(tmp_ins->send_pkt_para.payload),  "test send fake packet");
	tmp_ins->send_pkt_para.payload_len = strlen(tmp_ins->send_pkt_para.payload);
 	
	return 0;
}


/*
    inside                                      outside

    >------------->C(vxlan dir = 0)------------------->
 
    <--------------I(vxlan dir = 1)-------------------<


    if ningsi.conf->CorI is C, means sample packet from inside to outside, vxlan dir flag is 0;
    if ningsi.conf->CorI is I, means sample packet from outside to inside, vxlan dir flag is 1;
*/

char wangyan_polling_cb_send_fake_pkt_udp(int thread_seq, wangyan_gdev_measure_instance_t *instance)
{

	struct streaminfo phony_stream;
	SAPP_TLV_T option[32];
	int option_num = 0;
	
	phony_stream.threadnum = thread_seq; /* 虚假流结构体, MESA_fakepacket_send_udp_options()函数需要线程id, 此处赋值即可 */

	option[option_num].type = SAPP_SEND_OPT_GDEV_SMAC;
	option[option_num].length = 6;
	memcpy(option[option_num].array_value, instance->send_pkt_para.vxlan_smac, 6);
	option_num++;////////
	option[option_num].type = SAPP_SEND_OPT_GDEV_DMAC;
	option[option_num].length = 6;
	memcpy(option[option_num].array_value, instance->send_pkt_para.vxlan_dmac, 6);
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_GDEV_SIP;
	option[option_num].length = 4;
	option[option_num].int_value = instance->send_pkt_para.vxlan_sip_net_order;
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_GDEV_DIP;
	option[option_num].length = 4;
	option[option_num].int_value = instance->send_pkt_para.vxlan_dip_net_order;;
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_GDEV_UDP_SPORT;
	option[option_num].length = 2;
//	option[option_num].short_value = ntohs(instance->send_pkt_para.vxlan_sport_net_order);
	option[option_num].short_value = instance->send_pkt_para.vxlan_sport_net_order;
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_GDEV_UDP_DPORT;
	option[option_num].length = 2;
	option[option_num].short_value = ntohs(instance->send_pkt_para.vxlan_dport_net_order);
	option_num++;///////

	option[option_num].type = SAPP_SEND_OPT_VXLAN_VPN_ID;
	option[option_num].length = 4;
//	option[option_num].int_value = htonl(instance->send_pkt_para.vxlan_vlan_num);
	option[option_num].int_value = instance->send_pkt_para.vxlan_vlan_num;
	option_num++;///////
	
	option[option_num].type = SAPP_SEND_OPT_VXLAN_LINK_ID;
	option[option_num].length = 4;
	option[option_num].int_value = instance->send_pkt_para.vxlan_link_id;
	option_num++;///////

	option[option_num].type = SAPP_SEND_OPT_VXLAN_LINK_ENCAP_TYPE;
	option[option_num].length = 1;
	option[option_num].char_value = TUNNAT_TUNNEL_TYPE_ETHER;
	option_num++;///////
	
	option[option_num].type = SAPP_SEND_OPT_VXLAN_LINK_DIR;
	option[option_num].length = 1;
	if(instance->send_pkt_para.sample_pkt_dir == instance->send_pkt_para.send_pkt_CorI){
		option[option_num].char_value = instance->send_pkt_para.vxlan_link_dir;
	}else{
		option[option_num].char_value = instance->send_pkt_para.vxlan_link_dir ^ 1;
	}
	option_num++;///////
	
	option[option_num].type = SAPP_SEND_OPT_INNER_LINK_ENCAP_TYPE;
	option[option_num].length = 1;
	option[option_num].char_value = TUNNAT_TUNNEL_TYPE_ETHER;
	option_num++;///////

	/* 发包方向不同, 仅需交换内层MAC即可, IP和端口由配置文件填写, 严格按照用户需求, 无需修改 */
	option[option_num].type = SAPP_SEND_OPT_INNER_SMAC;
	option[option_num].length = 6;
	if(instance->send_pkt_para.sample_pkt_dir == instance->send_pkt_para.send_pkt_CorI){
		memcpy(option[option_num].array_value, instance->send_pkt_para.inner_smac, 6);
	}else{
		memcpy(option[option_num].array_value, instance->send_pkt_para.inner_dmac, 6);
	}
	option_num++;///////
	
	option[option_num].type = SAPP_SEND_OPT_INNER_DMAC;
	option[option_num].length = 6;
	if(instance->send_pkt_para.sample_pkt_dir == instance->send_pkt_para.send_pkt_CorI){
		memcpy(option[option_num].array_value, instance->send_pkt_para.inner_dmac, 6);
	}else{
		memcpy(option[option_num].array_value, instance->send_pkt_para.inner_smac, 6);
	}
	option_num++;///////

	MESA_fakepacket_send_udp_options(&phony_stream,  
					ntohl(instance->send_pkt_para.inner_sip_net_order),
					  ntohl(instance->send_pkt_para.inner_dip_net_order),
					  ntohs(instance->send_pkt_para.inner_sport_net_order),
					  ntohs(instance->send_pkt_para.inner_dport_net_order),
					  instance->send_pkt_para.payload,
					  instance->send_pkt_para.payload_len,
					  instance->send_pkt_para.send_pkt_CorI,
					  option,
					  option_num);

	g_wangyan_send_fake_pkt_rt_stat[thread_seq].realtime_pkt_num++;
	
	return APP_STATE_GIVEME;	
}

char wangyan_polling_cb_send_fake_pkt_tcp(int thread_seq, wangyan_gdev_measure_instance_t *instance)
{	
	struct streaminfo phony_stream;
	SAPP_TLV_T option[32];
	int option_num = 0;
	
	phony_stream.threadnum = thread_seq; /* 虚假流结构体, MESA_fakepacket_send_udp_options()函数需要线程id, 此处赋值即可 */

	option[option_num].type = SAPP_SEND_OPT_GDEV_SMAC;
	option[option_num].length = 6;
	memcpy(option[option_num].array_value, instance->send_pkt_para.vxlan_smac, 6);
	option_num++;////////
	option[option_num].type = SAPP_SEND_OPT_GDEV_DMAC;
	option[option_num].length = 6;
	memcpy(option[option_num].array_value, instance->send_pkt_para.vxlan_dmac, 6);
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_GDEV_SIP;
	option[option_num].length = 4;
	option[option_num].int_value = instance->send_pkt_para.vxlan_sip_net_order;
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_GDEV_DIP;
	option[option_num].length = 4;
	option[option_num].int_value = instance->send_pkt_para.vxlan_dip_net_order;;
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_GDEV_UDP_SPORT;
	option[option_num].length = 2;
//	option[option_num].short_value = ntohs(instance->send_pkt_para.vxlan_sport_net_order);
	option[option_num].short_value = instance->send_pkt_para.vxlan_sport_net_order;
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_GDEV_UDP_DPORT;
	option[option_num].length = 2;
	option[option_num].short_value = ntohs(instance->send_pkt_para.vxlan_dport_net_order);
	option_num++;///////


	option[option_num].type = SAPP_SEND_OPT_VXLAN_VPN_ID;
	option[option_num].length = 4;
//	option[option_num].int_value = htonl(instance->send_pkt_para.vxlan_vlan_num);
	option[option_num].int_value = instance->send_pkt_para.vxlan_vlan_num;
	option_num++;///////
	
	option[option_num].type = SAPP_SEND_OPT_VXLAN_LINK_ID;
	option[option_num].length = 4;
	option[option_num].int_value = instance->send_pkt_para.vxlan_link_id;
	option_num++;///////

	option[option_num].type = SAPP_SEND_OPT_VXLAN_LINK_ENCAP_TYPE;
	option[option_num].length = 1;
	option[option_num].char_value = TUNNAT_TUNNEL_TYPE_ETHER;
	option_num++;///////

	
	option[option_num].type = SAPP_SEND_OPT_VXLAN_LINK_DIR;
	option[option_num].length = 1;
	if(instance->send_pkt_para.sample_pkt_dir == instance->send_pkt_para.send_pkt_CorI){
		option[option_num].char_value = instance->send_pkt_para.vxlan_link_dir;
	}else{
		option[option_num].char_value = instance->send_pkt_para.vxlan_link_dir ^ 1;
	}
	option_num++;///////

	
	option[option_num].type = SAPP_SEND_OPT_INNER_LINK_ENCAP_TYPE;
	option[option_num].length = 1;
	option[option_num].char_value = TUNNAT_TUNNEL_TYPE_ETHER;
	option_num++;///////

	/* 发包方向不同, 仅需交换内层MAC即可, IP和端口由配置文件填写, 严格按照用户需求, 无需修改 */
	option[option_num].type = SAPP_SEND_OPT_INNER_SMAC;
	option[option_num].length = 6;
	if(instance->send_pkt_para.sample_pkt_dir == instance->send_pkt_para.send_pkt_CorI){
		memcpy(option[option_num].array_value, instance->send_pkt_para.inner_smac, 6);
	}else{
		memcpy(option[option_num].array_value, instance->send_pkt_para.inner_dmac, 6);
	}
	option_num++;///////
	
	option[option_num].type = SAPP_SEND_OPT_INNER_DMAC;
	option[option_num].length = 6;
	if(instance->send_pkt_para.sample_pkt_dir == instance->send_pkt_para.send_pkt_CorI){
		memcpy(option[option_num].array_value, instance->send_pkt_para.inner_dmac, 6);
	}else{
		memcpy(option[option_num].array_value, instance->send_pkt_para.inner_smac, 6);
	}
	option_num++;///////

	MESA_fakepacket_send_tcp_options(&phony_stream,  
					ntohl(instance->send_pkt_para.inner_sip_net_order),
					  ntohl(instance->send_pkt_para.inner_dip_net_order),
					  ntohs(instance->send_pkt_para.inner_sport_net_order),
					  ntohs(instance->send_pkt_para.inner_dport_net_order),
					  0x12345678,
					  0x87654321,
					  instance->send_pkt_para.transport_tcp_flags,
					  instance->send_pkt_para.payload,
					  instance->send_pkt_para.payload_len,
					  instance->send_pkt_para.send_pkt_CorI,
					  option,
					  option_num);

	g_wangyan_send_fake_pkt_rt_stat[thread_seq].realtime_pkt_num++;
	
	return APP_STATE_GIVEME;	
}

#if 0
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
	memcpy(option[option_num].array_value, instance->send_pkt_para.vxlan_smac, 6);
	option_num++;////////
	option[option_num].type = SAPP_SEND_OPT_GDEV_DMAC;
	option[option_num].length = 6;
	memcpy(option[option_num].array_value, instance->send_pkt_para.vxlan_dmac, 6);
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_GDEV_SIP;
	option[option_num].length = 4;
	option[option_num].int_value = instance->send_pkt_para.vxlan_sip_net_order;
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_GDEV_DIP;
	option[option_num].length = 4;
	option[option_num].int_value = instance->send_pkt_para.vxlan_dip_net_order;;
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_GDEV_UDP_SPORT;
	option[option_num].length = 2;
//	option[option_num].short_value = ntohs(instance->send_pkt_para.vxlan_sport_net_order);
	option[option_num].short_value = instance->send_pkt_para.vxlan_sport_net_order;
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_GDEV_UDP_DPORT;
	option[option_num].length = 2;
	option[option_num].short_value = ntohs(instance->send_pkt_para.vxlan_dport_net_order);
	option_num++;///////


	option[option_num].type = SAPP_SEND_OPT_VXLAN_VPN_ID;
	option[option_num].length = 4;
//	option[option_num].int_value = htonl(instance->send_pkt_para.vxlan_vlan_num);
	option[option_num].int_value = instance->send_pkt_para.vxlan_vlan_num;
	option_num++;///////
	
	option[option_num].type = SAPP_SEND_OPT_VXLAN_LINK_ID;
	option[option_num].length = 4;
	option[option_num].int_value = instance->send_pkt_para.vxlan_link_id;
	option_num++;///////

	option[option_num].type = SAPP_SEND_OPT_VXLAN_LINK_ENCAP_TYPE;
	option[option_num].length = 1;
	option[option_num].char_value = TUNNAT_TUNNEL_TYPE_ETHER;
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_VXLAN_LINK_DIR;
	option[option_num].length = 1;
	option[option_num].char_value = instance->send_pkt_para.send_pkt_CorI;
	option_num++;///////
	option[option_num].type = SAPP_SEND_OPT_INNER_LINK_ENCAP_TYPE;
	option[option_num].length = 1;
	option[option_num].char_value = TUNNAT_TUNNEL_TYPE_ETHER;
	option_num++;///////

	/* 发包方向不同, 仅需交换内层MAC即可, IP和端口由配置文件填写, 严格按照用户需求, 无需修改 */
	option[option_num].type = SAPP_SEND_OPT_INNER_SMAC;
	option[option_num].length = 6;
	if(instance->send_pkt_para.sample_pkt_dir == instance->send_pkt_para.send_pkt_CorI){
		memcpy(option[option_num].array_value, instance->send_pkt_para.inner_smac, 6);
	}else{
		memcpy(option[option_num].array_value, instance->send_pkt_para.inner_dmac, 6);
	}
	option_num++;///////
	
	option[option_num].type = SAPP_SEND_OPT_INNER_DMAC;
	option[option_num].length = 6;
	if(instance->send_pkt_para.sample_pkt_dir == instance->send_pkt_para.send_pkt_CorI){
		memcpy(option[option_num].array_value, instance->send_pkt_para.inner_dmac, 6);
	}else{
		memcpy(option[option_num].array_value, instance->send_pkt_para.inner_smac, 6);
	}
	option_num++;///////

	MESA_sendpacket_iplayer_options(thread_seq,  
					 snd_pkt_payload,
					 sizeof(snd_pkt_payload),
					  instance->send_pkt_para.send_pkt_CorI,
					  option,
					  option_num);

	g_wangyan_send_fake_pkt_rt_stat[thread_seq].realtime_pkt_num++;
	
	return APP_STATE_GIVEME;	
}
#endif
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


static void wangyan_gdev_measure_send_pkt(int thread_seq, wangyan_gdev_measure_instance_t *instance)
{
	if(instance->last_send_time == get_tmie_from_sapp()){
		if(instance->send_pkt_num >= instance->send_pkt_para.send_pps){
			return;
		}
	}else{
		instance->last_send_time = get_tmie_from_sapp();
		instance->send_pkt_num = 0; 
	}

	if(IPPROTO_TCP == instance->send_pkt_para.transport_layer_type){
		wangyan_polling_cb_send_fake_pkt_tcp(thread_seq, instance);
	}else{
		wangyan_polling_cb_send_fake_pkt_udp(thread_seq, instance);
	}

	instance->send_pkt_num++;
}


char wangyan_gdev_measure_polling_cb(struct streaminfo *__stream, void **__pme, int thread_seq, const void *__raw_pkt)
{
	int i;

	if(0 != thread_seq){
		/* 暂时仅支持一个线程发包, 使用0号线程 */
		return APP_STATE_GIVEME;
	}

	for(i = 0; i < wangyan_gdev_measure_instance_num; i++){
		wangyan_gdev_measure_send_pkt(thread_seq, &wangyan_gdev_measure_instance_set[i]);
	}
	
	return APP_STATE_GIVEME;
}


static int wangyan_gdev_measure_add_new_instance(wangyan_gdev_measure_instance_t *tmp_ins)
{
	if(wangyan_gdev_measure_instance_num >= GDEV_MEASURE_MAX_NUM){
		printf("\033[1;31;40m[Error]instance number is over limit %d![0m\n", GDEV_MEASURE_MAX_NUM);
		MESA_handle_runtime_log(gdev_measure_logh, 30, "gdev", "instance number is over limit %d!", GDEV_MEASURE_MAX_NUM); 
		return -1;
	}

	memcpy(&wangyan_gdev_measure_instance_set[wangyan_gdev_measure_instance_num], tmp_ins, sizeof(wangyan_gdev_measure_instance_t));
	wangyan_gdev_measure_instance_num++;

	return 0;
}


static int iterate_readdir(const char *conf_dir)
{
    struct stat fstat;
    char tmp_file_name[PATH_MAX];
    DIR *dir_h;
    struct dirent *file_h;
    int ret;
    wangyan_gdev_measure_instance_t tmp_ins;

	stat(conf_dir, &fstat);
	
    if(!S_ISDIR( fstat.st_mode)){
    	printf("\033[1;31;40m[Error]%s is not dir!\033[0m\n", conf_dir);
    	MESA_handle_runtime_log(gdev_measure_logh, 30, "gdev", "%s is not dir!", conf_dir); 
		return -1;
    }

    dir_h = opendir(conf_dir);
    if(NULL == dir_h){
    	printf("\033[1;31;40m[Error]opendir %s error!\033[0m\n", conf_dir);
    	MESA_handle_runtime_log(gdev_measure_logh, 30, "gdev", "opendir %s error!", conf_dir); 
		return -1;
    }

    while((file_h = readdir(dir_h)) != NULL){
        if(strncmp(file_h->d_name, ".", 1) == 0){ /* 当前目录跳过 */
            continue;
        }
        if(strncmp(file_h->d_name, "..", 2) == 0){ /* 上一级目录跳过 */
            continue;
        }

        snprintf(tmp_file_name, PATH_MAX, "%s/%s", conf_dir, file_h->d_name);

        stat(tmp_file_name, &fstat); /* XFS文件系统, d_type获取不准 */

        if(!S_ISREG(fstat.st_mode)){
            continue; /* 非普通文件 */
        }else{
        	memset(&tmp_ins, 0, sizeof(tmp_ins));
        	ret = wangyan_gdev_measure_parse_config(tmp_file_name, &tmp_ins);
        	if(ret >= 0){
				wangyan_gdev_measure_add_new_instance(&tmp_ins);
        	}
        }
    }

	closedir(dir_h);

	MESA_handle_runtime_log(gdev_measure_logh, 10, "gdev", "parse conf succ, total valid config num:%d\n", wangyan_gdev_measure_instance_num);
	
	return 0;
}



int wangyan_gdev_measure_init(void)
{
	int ret;

	gdev_measure_logh = MESA_create_runtime_log_handle("./log/gdev_measure.log", 10);

	if(get_thread_count() != 1){
		printf("\033[1;31;40m[Error]wangyan_gdev_measure plug not support multithread!\033[0m\n");
	}

	iterate_readdir(GDEV_MEASURE_CONF_DIR);

	if(wangyan_gdev_measure_instance_num <= 0){
		printf("\033[1;31;40m[Error]No valid config in %s!\033[0m\n", GDEV_MEASURE_CONF_DIR);
		MESA_handle_runtime_log(gdev_measure_logh, 30, "gdev", "No valid config in %s!", GDEV_MEASURE_CONF_DIR);
		return -1;
	}
	
	return 0;
}


#ifdef __cplusplus
}
#endif 


