#include "sapp_api.h"
#include "sapp_private_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
	设备, 路径;
	id->物理设备->逻辑设备.

	#target_id	pag_arg	pcap_arg	pfring_arg	dpdk_arg
*/


packet_io_device_alias_t *g_packet_device_alias; /* 直接用数组下标代表target_id, 提高查找效率 */
int packet_device_alias_num = 0;

extern void del_last_rn(char *data, int max_len);
extern void * dl_io_device_alias(unsigned int target_id, char *device_args);
extern void * get_dl_io_device_alias_fun_symbol(void);


static int insert_to_device_alias(unsigned int target_id, char *device_args)
{
	void * (*dl_io_device_alias_fun)(unsigned int target_id, char *device_args) = NULL;
	
	if(0 == packet_device_alias_num) {
		g_packet_device_alias = (packet_io_device_alias_t *)calloc(1, sizeof(packet_io_device_alias_t) * (target_id + 1));
		packet_device_alias_num = target_id + 1;
	}else{
		if(packet_device_alias_num <= (int)target_id){
			g_packet_device_alias = (packet_io_device_alias_t *)realloc(g_packet_device_alias, sizeof(packet_io_device_alias_t) * (target_id + 1));
			packet_device_alias_num = target_id + 1;
		}
	}


	//dl_io_device_alias_fun = (void * (*)(unsigned int, char *))get_dl_io_device_alias_fun_symbol();
	dl_io_device_alias_fun = dl_io_fun_list.dl_io_device_alias;
	if(NULL == dl_io_device_alias_fun){
		return -1;
	}

	g_packet_device_alias[target_id].target_id = target_id;
	g_packet_device_alias[target_id].device_args = strdup(device_args);
	g_packet_device_alias[target_id].dl_io_param = dl_io_device_alias_fun(target_id, device_args);
	
	return 0;
}


static int parse_send_raw_pkt_conf(void)
{
	FILE *fp;
	char conf_buf[1024];
	const char *delim = "\t ";
	char *saveptr;
	char *section;
	int column_index = 0; /* 第几列 */
	unsigned int tid;

	fp = fopen(ABBR_SEND_RAW_PKT_CONF_FILE, "r");
	if(NULL == fp){
		printf("\033[41m[Error]open send raw pkt config file '%s' error!\033[0m\n", ABBR_SEND_RAW_PKT_CONF_FILE);
		return -1;
	}

	while(fgets(conf_buf, 1024, fp)){
		if('#' == conf_buf[0] || ' ' == conf_buf[0] || '\r' == conf_buf[0] || '\n' == conf_buf[0]){
			continue;
		}

		del_last_rn(conf_buf, 1024);

		/* 第一列为 target_id */
		section = strtok_r(conf_buf, delim, &saveptr);
		if(NULL == section){
			return -1;
		}
		tid = strtoul(section, NULL, 0);

		if(tid > 1000){
			printf("\033[33mWarning! in '%s', target_id is too large!\033[0m\n", ABBR_SEND_RAW_PKT_CONF_FILE);
			usleep(100000);
		}

		column_index = 0;
		section = strtok_r(NULL, delim, &saveptr);
		while(g_packet_io_cap_mode != column_index){ /* 找到当前捕包模式对应的列 */
			section = strtok_r(NULL, delim, &saveptr);
			if(NULL == section){
				printf("\033[41m[Error]packet_io_mode is %d, but in %s not found related args!\033[0m\n", g_packet_io_cap_mode, ABBR_SEND_RAW_PKT_CONF_FILE);
				return -1;
			}
			column_index++;
		}
		
		insert_to_device_alias(tid, section);

		while(strtok_r(NULL, delim, &saveptr)); /* clear strtok buf */
	}

	fclose(fp);

	return 0;
}


int packet_io_device_alias_init(void)
{
	if(parse_send_raw_pkt_conf() < 0){
		return -1;
	}

	return 0;
}

#ifdef __cplusplus
}
#endif
