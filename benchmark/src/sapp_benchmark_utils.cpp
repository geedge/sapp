#include "sapp_benchmark.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/types.h>			/* See NOTES */
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include "stream.h"
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "wrap_cJSON.h"
#include "sapp_bchmk_inner.h"
#ifdef __cplusplus
extern "C" {
#endif





const char *sapp_bchmk_get_value_from_json(const cJSON *root, const char *expect_section_item, const char *expect_sub_item, char *result, int *result_max_len)
{
	int result_len;
	cJSON *item;
	char tmp_integer_str[64];
	char *jres = NULL;
	
	if((NULL == root) || (NULL == expect_sub_item) ||(NULL == result) || (NULL == result_max_len)){
		return NULL;
	}

	item = cJSON_GetObjectItem(root, expect_sub_item);
	if(NULL == item){
		//printf("json parse error, not found '%s'\n", expect_sub_item);
		goto err_ret;
	}

	if(cJSON_IsString(item)){
		result_len = strlen(item->valuestring);
		jres = item->valuestring;
	}else if(cJSON_IsNumber(item)){
		snprintf(tmp_integer_str, sizeof(tmp_integer_str), "%d", item->valueint);
		result_len = strlen(tmp_integer_str);
		jres = tmp_integer_str;
	}else{
		//printf("houyi_json_object_decode not support complex type, please use houyi_json_array_decode()!\n");
		goto err_ret;
	}
	
	if(result_len >= *result_max_len){
		//printf("json parse error, length is not enough!\n");
		goto err_ret;
	}

	strcpy(result, jres);
	*result_max_len = result_len;

	return result;
err_ret:

	return NULL;
}


const char *sapp_bchmk_md5sum(const void *data, int data_len)
{
	return "";
}

static int ifconfig_device_up(const char *interface_name)
{
	int err;
	int 			ret;	
	int 			socket_fd;	  
	struct ifreq	ifr;		
	//struct sockaddr_in sin;
	
	if(interface_name == NULL)  
	{  
		return -1;	
	}  
	
	socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_fd < 0)	  
	{
		printf("Create Socket Failed.\n");		  
		return -2;	  
	}
	//指定网卡名称且up
	sprintf(ifr.ifr_name, "%s", interface_name);
	/* 获得接口的标志 */
	if ((err = ioctl(socket_fd, SIOCGIFFLAGS, (void *)&ifr)) < 0) {
		perror("ioctl SIOCGIFADDR");
		close(socket_fd);
		return -3;
	}
	ifr.ifr_flags |= IFF_UP;
	ret = ioctl(socket_fd, SIOCSIFFLAGS, &ifr);
	if (ret != 0)	 
	{
		printf("Up Device %s Failed.\n", interface_name);
		close(socket_fd);
		return -3;
	}
	
	close(socket_fd);

	return 0;
}

int ifconfig_device_mtu(const char *interface_name, int mtu_val)
{
	int err;
	int 			ret;	
	int 			socket_fd;	  
	struct ifreq	ifr;		
	
	if(interface_name == NULL)  
	{  
		return -1;	
	}  
	
	socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_fd < 0)	  
	{
		printf("Create Socket Failed.\n");		  
		return -2;	  
	}
	sprintf(ifr.ifr_name, "%s", interface_name);
	/* 获得接口的标志 */
	if ((err = ioctl(socket_fd, SIOCGIFMTU, (void *)&ifr)) < 0) {
		perror("ioctl SIOCGIFMTU");
		close(socket_fd);
		return -3;
	}
	ifr.ifr_ifru.ifru_mtu = mtu_val;  
	ret = ioctl(socket_fd, SIOCSIFMTU, &ifr);
	if (ret != 0)	 
	{
		perror("ioctl SIOCSIFMTU");
		close(socket_fd);
		return -3;
	}
	
	close(socket_fd);

	return 0;
}


static int tuntap_dev_create(char *dev, int flags)
{
    assert(dev != NULL);

    struct ifreq ifr;
    int fd, err;

    char *clonedev = (char *)"/dev/net/tun";

    if ((fd = open(clonedev, O_RDWR)) < 0) {
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = flags;

    if (*dev != '\0') {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }
    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
		perror ("Error: ");
        close(fd);
        return err;
    }

    ifconfig_device_up(dev);

    ifconfig_device_mtu(dev, 2000); /* 某些pcap包可能开启了offload,  或者vlan, vxlan等, 增加MTU */

    return fd;
}

/* 
    根据情况, 如果mirror, inline模式是创建一个TAP, transparent是创建两个TAP,
    直接读取解析sapp.toml文件.
*/
int sapp_bchmk_create_process_engine(benchmark_engine_t *bch_engine)
{
	int ret, opt_len;
	char tmp_str[CONFIG_MAX_LEN];
	char tap_dev_name_up[TAP_DEV_NAME_MAX_LEN];
	char tap_dev_name_down[TAP_DEV_NAME_MAX_LEN];
	pkt_process_engine_t *process_engine;

	process_engine = (pkt_process_engine_t *)calloc(1, sizeof(pkt_process_engine_t));

	ret = MESA_load_profile_string_nodef(SAPP_DEFAULT_MAIN_CONFIG_FILE, (char *)"packet_io.depolyment", (char *)"mode", tmp_str, CONFIG_MAX_LEN);
	if(ret < 0){
		sapp_bchmk_log(bch_engine, RLOG_LV_FATAL, "not found sapp.toml config [packet_io.depolyment]->mode");
		return -1;
	}
	if(strncasecmp(tmp_str, "mirror", strlen("mirror")) == 0){
		process_engine->sapp_deploy_mode = DEPOLYMENT_MODE_MIRROR;
	}else if(strncasecmp(tmp_str, "transparent", strlen("transparent")) == 0){
		process_engine->sapp_deploy_mode = DEPOLYMENT_MODE_TRANSPARENT;
	}else if(strncasecmp(tmp_str, "inline", strlen("inline")) == 0){
		process_engine->sapp_deploy_mode = DEPOLYMENT_MODE_INLINE;
	}else{
		sapp_bchmk_log(bch_engine,RLOG_LV_FATAL, "not support sapp.toml config [packet_io.depolyment]->mode: %s", tmp_str);
		return -1;
	}

	ret = MESA_load_profile_string_nodef(SAPP_DEFAULT_MAIN_CONFIG_FILE, "packet_io.internal.interface", "name", tap_dev_name_up, TAP_DEV_NAME_MAX_LEN);
	if(ret < 0){
		sapp_bchmk_log(bch_engine,RLOG_LV_FATAL, "not found config [packet_io.internal.interface]->name");
		return -1;
	}
	process_engine->tap_internal_fd = tuntap_dev_create(tap_dev_name_up, IFF_TAP | IFF_MULTI_QUEUE | IFF_NO_PI);
	if(process_engine->tap_internal_fd < 0){
		sapp_bchmk_log(bch_engine,RLOG_LV_FATAL, "tuntap_dev_create '%s' error!", tap_dev_name_up);
		return -1;		
	}else{
		sapp_bchmk_log(bch_engine,RLOG_LV_DEBUG, "create packet_io.internal.interface device '%s' success", tap_dev_name_up);
	}
	
	if(DEPOLYMENT_MODE_TRANSPARENT == process_engine->sapp_deploy_mode){
		ret = MESA_load_profile_string_nodef(SAPP_DEFAULT_MAIN_CONFIG_FILE, "packet_io.external.interface", "name", tap_dev_name_up, TAP_DEV_NAME_MAX_LEN);
		if(ret < 0){
			sapp_bchmk_log(bch_engine,RLOG_LV_FATAL, "not found config [packet_io.external.interface]->name");
			return -1;
		}

		process_engine->tap_external_fd = tuntap_dev_create(tap_dev_name_down, IFF_TAP | IFF_MULTI_QUEUE | IFF_NO_PI);
		if(process_engine->tap_external_fd < 0){
			sapp_bchmk_log(bch_engine,RLOG_LV_FATAL, "tuntap_dev_create '%s' error!", tap_dev_name_down);
			return -1;		
		}else{
			sapp_bchmk_log(bch_engine,RLOG_LV_DEBUG, "create packet_io.external.interface device '%s' success", tap_dev_name_down);
		}	
	}

	bch_engine->process_engine = process_engine;

	return 0;
}

int sapp_bchmk_md5_checksum(const char *filename, const char *expect_md5sum)
{
	FILE *cmd_res_fp;
	char file_real_md5sum[33];
	char cmd_buf[1024];
	int ret = 0;

	snprintf(cmd_buf, 1024, "%s %s", "md5sum", filename);

	cmd_res_fp = popen(cmd_buf, "r");
	if(NULL == cmd_res_fp){
		return -1;
	}

	fgets(file_real_md5sum, 33, cmd_res_fp);

	if(strncasecmp(file_real_md5sum, expect_md5sum, 32) != 0){
		ret = -1;
	}

	fclose(cmd_res_fp);

	return ret;
}

/*
	注意:
		此函数实际返回的是TRUE和FALSE,
		0表示不一样, 1表示一样!!
*/
cJSON_bool sapp_bchmk_json_file_compare(benchmark_engine_t *bchmk_engine, const char *json_file1, const char *json_file2, cJSON_Compare_Opt_t opt)
{
	const char *json_mem1 = NULL, *json_mem2 = NULL;
	cJSON *json_struct1 = NULL, *json_struct2 = NULL;
	cJSON_bool ret;

	if((NULL == json_file1) || (NULL == json_file2)){
		return false;
	}

	json_mem1 = sapp_benchmark_load_json_from_file(json_file1);
	if(json_mem1 == NULL){
		sapp_bchmk_log(bchmk_engine, RLOG_LV_FATAL, "open JSON file '%s' error!", json_file1);
		return false;
	}	
	json_mem2 = sapp_benchmark_load_json_from_file(json_file2);
	if(json_mem2 == NULL){
		ret = false;
		sapp_bchmk_log(bchmk_engine, RLOG_LV_FATAL, "open JSON file '%s' error!", json_file2);
		goto err;
	}	

	json_struct1 = cJSON_Parse(json_mem1);
	if(NULL == json_struct1){
		sapp_bchmk_log(bchmk_engine, RLOG_LV_FATAL, "cJSON_Parse file '%s' error, %s", json_file1, cJSON_GetErrorPtr());
		ret = false;
		goto err;
	}
	json_struct2 = cJSON_Parse(json_mem2);
	if(NULL == json_struct2){
		sapp_bchmk_log(bchmk_engine,RLOG_LV_FATAL, "cJSON_Parse file '%s' error, %s", json_file2, cJSON_GetErrorPtr());
		ret = false;
		goto err;
	}

	sapp_bchmk_log(bchmk_engine,RLOG_LV_DEBUG, "start cJSON Compare file_a '%s' and file_b '%s' ...", json_file1, json_file2);
	sapp_bchmk_log(bchmk_engine,RLOG_LV_DEBUG, "start cJSON Compare file_a '%s'" , json_mem1);
	sapp_bchmk_log(bchmk_engine,RLOG_LV_DEBUG, "start cJSON Compare file_b '%s'" , json_mem2);

	ret = cJSON_Compare_options(json_struct1, json_struct2, opt, bchmk_engine->plug_opt.MESA_log_handle);

	sapp_bchmk_log(bchmk_engine,RLOG_LV_DEBUG, "cJSON Compare file_a '%s' and file_b '%s', result=%s", json_file1, json_file2, (ret==true)?"true":"false");
err:
	if(json_mem1){
		free((void *)json_mem1);
	}
	if(json_mem2){
		free((void *)json_mem2);
	}	
	if(json_struct1){
		cJSON_Delete(json_struct1);
	}
	if(json_struct2){
		cJSON_Delete(json_struct2);
	}		
	return ret;
}



static const pcap_file_hdr_t g_pcap_file_hdr = 
{
	0xA1B2C3D4,
	0x0002, 
	0x0004,
	0,
	0,
	0xFFFF,
	1
};

int sapp_bchmk_gen_pcap_header(benchmark_engine_t *bchmk_engine, const char *pcap_filename)
{
	FILE *fp;
	int i;
	pcap_pkt_hdr_t pcap_pkt_hdr = {};
	struct timeval cur_time;
	
	fp = fopen(pcap_filename, "w+");
	if(NULL == fp){
		sapp_bchmk_log(bchmk_engine, RLOG_LV_FATAL, "create pcap header '%s' error, %s", pcap_filename, strerror(errno));
		return -1;
	}
	fwrite(&g_pcap_file_hdr, sizeof(pcap_file_hdr_t), 1, fp);
	fclose(fp);
	sapp_bchmk_log(bchmk_engine, RLOG_LV_DEBUG, "create pcap header '%s' success", pcap_filename);

	return 0;
}

int sapp_bchmk_append_pcap_pkt(benchmark_engine_t *bchmk_engine, const pcap_pkt_detail_t *pkt_detail, int pkt_num, const char *pcap_filename)
{
	FILE *fp;
	int i;
	pcap_pkt_hdr_t pcap_pkt_hdr = {};
	struct timeval cur_time;
	
	fp = fopen(pcap_filename, "a+");
	if(NULL == fp){
		sapp_bchmk_log(bchmk_engine, RLOG_LV_FATAL, "append pcap file '%s' error, %s", pcap_filename, strerror(errno));
		return -1;
	}

	for(i = 0; i < pkt_num; i++){
		pcap_pkt_hdr.caplen = pkt_detail[i].pkt_len;
		pcap_pkt_hdr.len = pkt_detail[i].pkt_len;
		gettimeofday(&cur_time, NULL);
		pcap_pkt_hdr.tv_sec = cur_time.tv_sec;
		pcap_pkt_hdr.tv_usec = cur_time.tv_usec;
		fwrite(&pcap_pkt_hdr, sizeof(pcap_pkt_hdr_t), 1, fp);
		fwrite(pkt_detail[i].pkt_data, 1, pkt_detail[i].pkt_len, fp);
		fflush(fp);
	}

	fclose(fp);
	sapp_bchmk_log(bchmk_engine, RLOG_LV_DEBUG, "append pcap file '%s' success", pcap_filename);

	return 0;
}


int sapp_bchmk_gen_pcap_file(benchmark_engine_t *bchmk_engine, const pcap_pkt_detail_t *pkt_detail, int pkt_num, const char *pcap_filename)
{
	int ret;

	ret = sapp_bchmk_gen_pcap_header(bchmk_engine, pcap_filename);
	if(ret < 0){
		return -1;
	}

	ret = sapp_bchmk_append_pcap_pkt(bchmk_engine, pkt_detail, pkt_num, pcap_filename);

	return ret;
}


/*
	将内存中的一个原始报文, 先生成pcap文件, 再调用tshark -T 生成一个json文件.
*/
int sapp_bchmk_gen_tshark_json(benchmark_engine_t *bchmk_engine, const pcap_pkt_detail_t *pkt_detail, int pkt_num, const char *tshark_json_filename)
{
	int ret;
	char cmd_buf[256];
	
	ret = sapp_bchmk_gen_pcap_file(bchmk_engine, pkt_detail, pkt_num, SAPP_BCHMK_TEMP_PCAP_FILE);
	if(ret < 0){
		return -1;
	}

	snprintf(cmd_buf, sizeof(cmd_buf), "%s -r %s -n -nn -T json > %s", TSHARK_TOOLS_PATH, SAPP_BCHMK_TEMP_PCAP_FILE, tshark_json_filename);
	ret = system(cmd_buf);
	if(ret < 0){
		sapp_bchmk_log(bchmk_engine, RLOG_LV_FATAL, "system exec cmd '%s' error, %s", cmd_buf, strerror(errno));
		return -1;
	}
	
	sapp_bchmk_log(bchmk_engine, RLOG_LV_DEBUG, "system exec cmd '%s' success", cmd_buf);

	return 0;
}

int sapp_bchmk_need_drop_cur_pkt(benchmark_engine_t *bchmk_engine, int pkt_index)
{
	const cJSON *forward_item;
	const cJSON *sub_drop_item;
	const cJSON *sub_pkt_index_item;
	const cJSON *sub_array_item;
	int i, array_size;

	forward_item = cJSON_GetObjectItem(bchmk_engine->benchmark_json_struct, "forward");
	if(NULL == forward_item){
		return 0;
	}

	sub_drop_item = cJSON_GetObjectItem(forward_item, "drop");
	if(NULL == sub_drop_item){
		return 0;
	}	

	sub_pkt_index_item = cJSON_GetObjectItem(sub_drop_item, "pkt_index");
	if(NULL == sub_pkt_index_item){
		return 0;
	}	

	array_size = cJSON_GetArraySize(sub_pkt_index_item);

	/* 将C数组下标转换为wireshark的数据包序号, 其实就是加1 */
	ADJUST_ARRAY_INDEX_to_WIRESHARK(pkt_index);
	
	for(i = 0; i < array_size; i++){
		sub_array_item = cJSON_GetArrayItem(sub_pkt_index_item, i);
		if(pkt_index == sub_array_item->valueint){
			return 1;
		}
	}

	return 0;
}

/*
	返回值: 要检查此包具体参数的json file name.

	如果是NULL, 需要额外判断一下errno, 是否是因为json格式错误, 没有写packet_detail_json_file.
*/
const char *sapp_bchmk_need_check_forward_pkt(benchmark_engine_t *bchmk_engine, int pkt_index)
{
	const cJSON *forward_item;
	const cJSON *sub_pkt_detail_item;
	const cJSON *sub_array_item;
	const cJSON *sub_array_pkt_index_item;
	const cJSON *sub_array_pkt_json_file_item;
	int i, array_size;

	errno = 0;

	forward_item = cJSON_GetObjectItem(bchmk_engine->benchmark_json_struct, "forward");
	if(NULL == forward_item){
		sapp_bchmk_log(bchmk_engine,RLOG_LV_DEBUG, "don't need check forward json, pkt index:%d, ignore it", pkt_index+1);
		return NULL;
	}

	sub_pkt_detail_item = cJSON_GetObjectItem(forward_item, "packet_detail");
	if(NULL == sub_pkt_detail_item){
		return NULL;
	}	

	array_size = cJSON_GetArraySize(sub_pkt_detail_item);

	/* 注意: 为了方便和wireshark对比, pkt index从1开始计算, 数组下标从0开始 */
	ADJUST_ARRAY_INDEX_to_WIRESHARK(pkt_index);

	for(i = 0; i < array_size; i++){
		sub_array_item = cJSON_GetArrayItem(sub_pkt_detail_item, i);
		sub_array_pkt_index_item = cJSON_GetObjectItem(sub_array_item, "pkt_index");
		if(pkt_index == sub_array_pkt_index_item->valueint){
			sub_array_pkt_json_file_item = cJSON_GetObjectItem(sub_array_item, "packet_detail_json_file");
			if(NULL == sub_array_pkt_json_file_item){
				sapp_bchmk_log(bchmk_engine, RLOG_LV_FATAL, "not found 'packet_detail_json_file' item for index:%d", pkt_index);
				errno = ENODATA;
				return NULL;
			}
			if(NULL == sub_array_pkt_json_file_item->valuestring){
				sapp_bchmk_log(bchmk_engine,RLOG_LV_FATAL, "not found 'packet_detail_json_file' value for index:%d", pkt_index);
				errno = ENODATA;
				return NULL;
			}			
			return sub_array_pkt_json_file_item->valuestring;
		}
	}

	return NULL;
}

/*
	返回值: 指向inject块的cjson结构体指针.
*/
const cJSON *sapp_bchmk_need_check_inject_pkt(benchmark_engine_t *bchmk_engine, int carray_pkt_index)
{
	const cJSON *cJSON_inject_root;
	const cJSON *sub_pkt_detail_item;
	const cJSON *sub_array_item;
	const cJSON *sub_array_pkt_index_item;
	const cJSON *sub_array_pkt_json_file_item;
	int i, array_size;

	cJSON_inject_root = cJSON_GetObjectItem(bchmk_engine->benchmark_json_struct, "inject");
	if(NULL == cJSON_inject_root){
		errno = 0;
		return NULL;
	}

	sub_array_pkt_index_item = cJSON_GetObjectItem(cJSON_inject_root, "inject_trigger_pkt_index");
	if(NULL == sub_array_pkt_index_item){
		errno = ENODATA;
		sapp_bchmk_log(bchmk_engine, RLOG_LV_FATAL, "not found object 'inject_trigger_pkt_index' in inject object");
		return NULL;
	}	

	/* 注意: 为了方便和wireshark对比, pkt index从1开始计算, 此处数组从0开始 */
	if(sub_array_pkt_index_item->valueint != (carray_pkt_index+1)){
		/* 当前包不会触发inject动作, do nothing */
		sapp_bchmk_log(bchmk_engine,RLOG_LV_DEBUG, "pkt index:%d, don't need check inject json, ignore it", carray_pkt_index+1);
		errno = 0;
		return NULL;
	}

	return cJSON_inject_root;
}

/*
	返回值: 指向control块的cjson结构体指针.
*/
const cJSON *sapp_bchmk_need_process_control(benchmark_engine_t *bchmk_engine, int carray_pkt_index)
{
	const cJSON *cJSON_control_root;
	const cJSON *sub_cjson_delay_root;
	int i, array_size;

	cJSON_control_root = cJSON_GetObjectItem(bchmk_engine->benchmark_json_struct, "control");
	if(NULL == cJSON_control_root){
		errno = 0;
		sapp_bchmk_log(bchmk_engine, RLOG_LV_DEBUG, "not found object 'control'");
		return NULL;
	}

	sub_cjson_delay_root = cJSON_GetObjectItem(cJSON_control_root, "delay");
	if(NULL == sub_cjson_delay_root){
		errno = 0;
		sapp_bchmk_log(bchmk_engine, RLOG_LV_DEBUG, "not found object 'delay' in 'control'");
		return NULL;
	}

	return sub_cjson_delay_root;
}


/*
	每次测试前, 都用sapp的默认配置覆盖运行环境, 
	需要修改的配置参数, 每次也要现场修改,
	避免因默认参数错误导致测试不通过.

	将sapp的配置文件直接翻译成了.c数组, 这样cmake install, 即rpm -i时就不用装一堆文件了, 
	而且如果安装时使用--prefix参数, 程序就找不到这些文件了.
	直接从程序里copy即可.
*/

static void sapp_bchmk_write_to_file(const char *config_name, const void *content, int content_len)
{
	FILE *fp;

	fp = fopen(config_name, "w+");
	if(NULL == fp){
		return;
	}

	fwrite(content, 1, content_len, fp);
	fclose(fp);
}


extern const unsigned char templete_asymmetric_addr_layer[];
extern int templete_asymmetric_addr_layer_len;
extern const unsigned char templete_entrylist[];
extern int templete_entrylist_len;
extern const unsigned char templete_gdev[];
extern int templete_gdev_len;
extern const unsigned char templete_plugin[];
extern int templete_plugin_len;

extern const unsigned char templete_sapp_toml[];
extern int templete_sapp_toml_len;

extern const unsigned char templete_send_raw_pkt[];
extern int templete_send_raw_pkt_len;

extern const unsigned char templete_sapp_log[];
extern int templete_sapp_log_len;


void sapp_bchmk_set_default_config(void)
{
	system("mkdir -p etc");
	sapp_bchmk_write_to_file("etc/asymmetric_addr_layer.conf", templete_asymmetric_addr_layer, templete_asymmetric_addr_layer_len);
	sapp_bchmk_write_to_file("etc/entrylist.conf", templete_entrylist, templete_entrylist_len);
	sapp_bchmk_write_to_file("etc/gdev.conf", templete_gdev, templete_gdev_len);
	sapp_bchmk_write_to_file("etc/plugin.conf", templete_plugin, templete_plugin_len);
	sapp_bchmk_write_to_file("etc/sapp.toml", templete_sapp_toml, templete_sapp_toml_len);
	sapp_bchmk_write_to_file("etc/send_raw_pkt.conf", templete_send_raw_pkt, templete_send_raw_pkt_len);
	sapp_bchmk_write_to_file("etc/send_log.conf", templete_sapp_log, templete_sapp_log_len);

	/* 情况插件plug.inf内容, 只保留最基本头部字段 */
	system("mkdir -p ./plug/business/gtest_sapp");
	system("echo \"[PLUGINFO]\" > ./plug/business/gtest_sapp/gtest_sapp.inf");
	system("echo \"PLUGNAME=xxxx\" >> ./plug/business/gtest_sapp/gtest_sapp.inf");
	system("echo \"SO_PATH=xxxx\" >> ./plug/business/gtest_sapp/gtest_sapp.inf");
	system("echo \"INIT_FUNC=xxxx\" >> ./plug/business/gtest_sapp/gtest_sapp.inf");
	system("echo \"DESTROY_FUNC=xxxx\" >> ./plug/business/gtest_sapp/gtest_sapp.inf");

	system("/usr/bin/cp -f /opt/MESA/lib/test_benchmark_plug.so ./plug/business/gtest_sapp/");
}


const char *sapp_bchmk_rawpkt_ntop_v4(const struct ip *iphdr, char *res_buf, int buf_len)
{
	unsigned char inner_ip_proto;
	char ip_src_str[INET6_ADDRSTRLEN], ip_dst_str[INET6_ADDRSTRLEN];
	const struct tcphdr *inner_thdr = NULL;
	const struct udphdr *inner_uhdr = NULL;
	unsigned short sport, dport;

	inet_ntop(AF_INET, &iphdr->ip_src.s_addr, ip_src_str, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET, &iphdr->ip_dst.s_addr, ip_dst_str, INET6_ADDRSTRLEN);

	inner_ip_proto = iphdr->ip_p;		
	if(IPPROTO_TCP == inner_ip_proto){
		inner_thdr = (struct tcphdr *)((char *)iphdr + iphdr->ip_hl*4);
		sport = inner_thdr->source;
		dport = inner_thdr->dest;
		snprintf(res_buf, buf_len, "%s.%u --> %s.%u,%s,ipid:%d,tcp_syn:%d, tcp_ack:%d, tcp_fin:%d, tcp_rst:%d, tcp_sum:0x%x", 
				ip_src_str, ntohs(sport),
				ip_dst_str, ntohs(dport), 
				"TCP",ntohs(iphdr->ip_id), inner_thdr->syn,inner_thdr->ack,inner_thdr->fin,inner_thdr->rst, ntohs(inner_thdr->check));		
	}else if(IPPROTO_UDP == inner_ip_proto){
		inner_uhdr = (struct udphdr *)((char *)iphdr + iphdr->ip_hl*4);
		sport = inner_uhdr->source;
		dport = inner_uhdr->dest;		
		snprintf(res_buf, buf_len, "%s.%u --> %s.%u,%s,ipid:%d,udp_sum:0x%x", 
				ip_src_str, ntohs(sport),
				ip_dst_str, ntohs(dport), 
				"UDP",ntohs(iphdr->ip_id), ntohs(inner_uhdr->check));	
	}else if(IPPROTO_ICMP == inner_ip_proto){
		snprintf(res_buf, buf_len, "%s --> %s,ICMP, ipid:%d", 
				ip_src_str, ip_dst_str, ntohs(iphdr->ip_id));
	}else{
		snprintf(res_buf, buf_len, "%s --> %s, unknown protocol:%u, ipid:%d", 
				ip_src_str, ip_dst_str, inner_ip_proto,ntohs(iphdr->ip_id));
	}

	return res_buf;
}

const char *sapp_bchmk_rawpkt_ntop_v6(const struct ip6_hdr *ip6hdr, char *res_buf, int buf_len)
{
	unsigned char inner_ip_proto;
	char ip_src_str[INET6_ADDRSTRLEN], ip_dst_str[INET6_ADDRSTRLEN];
	const struct tcphdr *inner_thdr = NULL;
	const struct udphdr *inner_uhdr = NULL;
	unsigned short sport, dport;

	inet_ntop(AF_INET6, &ip6hdr->ip6_src, ip_src_str, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &ip6hdr->ip6_dst, ip_dst_str, INET6_ADDRSTRLEN);

	inner_ip_proto = ip6hdr->ip6_nxt;

	if(IPPROTO_TCP == inner_ip_proto){
		inner_thdr = (struct tcphdr *)((char *)ip6hdr + sizeof(struct ip6_hdr));
		sport = inner_thdr->source;
		dport = inner_thdr->dest;	
		snprintf(res_buf, buf_len, "%s.%u --> %s.%u, %s, tcp_syn:%d, tcp_ack:%d, tcp_fin:%d, tcp_rst:%d", 
				ip_src_str, ntohs(sport),ip_dst_str, ntohs(dport), "TCP", 
				inner_thdr->syn,inner_thdr->ack,inner_thdr->fin,inner_thdr->rst);
	}else if(IPPROTO_UDP == inner_ip_proto){
		inner_uhdr = (struct udphdr *)((char *)ip6hdr + sizeof(struct ip6_hdr));
		sport = inner_uhdr->source;
		dport = inner_uhdr->dest;	
		snprintf(res_buf, buf_len, "%s.%u --> %s.%u, %s", ip_src_str, ntohs(sport),
				ip_dst_str, ntohs(dport), "UDP");
	}else if(IPPROTO_ICMPV6 == inner_ip_proto){ /* 注意: ipv6的icmp头部字段与ipv4不一致!! */
		snprintf(res_buf, buf_len, "%s --> %s,ICMP", ip_src_str, ip_dst_str);
	}else{
		snprintf(res_buf, buf_len, "%s --> %s, unknown protocol:%u", ip_src_str, ip_dst_str, inner_ip_proto);
	}

	return res_buf;
}


const char *sapp_bchmk_ippkt_ntop(const unsigned char *iphdr, char *res_buf, int buf_len)
{
	if((*iphdr & 0xF0) == 0x40){
		return sapp_bchmk_rawpkt_ntop_v4((const struct ip *)iphdr, res_buf, buf_len);
	}

	return sapp_bchmk_rawpkt_ntop_v6((const struct ip6_hdr *)iphdr, res_buf, buf_len);
}


#ifdef __cplusplus
}
#endif

