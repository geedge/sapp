#include "wrap_cJSON.h"

#include "sapp_benchmark.h"
#include "sapp_bchmk_inner.h"
#include "stream.h"
#include "stream_entry.h"
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
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>


#ifdef __cplusplus
extern "C" {
#endif

/* 因为sapp插件获取不到 benchmark_engine_t 句柄, 只能暂时靠全局变量传递一下, 
   TODO: 有什么更好的方式?
*/
static benchmark_engine_t *__g_recv_plug_result_handle = NULL;

/* https://patorjk.com/software/taag/,   字体类型:Slant */
static const unsigned char g_sapp_bchmk_art_ascii[] = {
0x20,0x20,0x20,0x5F,0x5F,0x5F,0x5F,0x5F,0x20,0x5F,0x5F,0x5F,0x20,0x20,0x20,0x20,
0x5F,0x5F,0x5F,0x5F,0x20,0x20,0x5F,0x5F,0x5F,0x5F,0x20,0x20,0x20,0x20,0x20,0x5F,
0x5F,0x5F,0x5F,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,
0x20,0x20,0x20,0x20,0x20,0x5F,0x5F,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,
0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,
0x5F,0x5F,0x20,0x20,0x0A,0x20,0x20,0x2F,0x20,0x5F,0x5F,0x5F,0x2F,0x2F,0x20,0x20,
0x20,0x7C,0x20,0x20,0x2F,0x20,0x5F,0x5F,0x20,0x5C,0x2F,0x20,0x5F,0x5F,0x20,0x5C,
0x20,0x20,0x20,0x2F,0x20,0x5F,0x5F,0x20,0x29,0x5F,0x5F,0x5F,0x20,0x20,0x5F,0x5F,
0x5F,0x5F,0x20,0x20,0x5F,0x5F,0x5F,0x5F,0x5F,0x2F,0x20,0x2F,0x5F,0x20,0x20,0x5F,
0x5F,0x5F,0x5F,0x20,0x5F,0x5F,0x5F,0x20,0x20,0x5F,0x5F,0x5F,0x5F,0x20,0x5F,0x5F,
0x5F,0x5F,0x5F,0x5F,0x2F,0x20,0x2F,0x5F,0x5F,0x0A,0x20,0x20,0x5C,0x5F,0x5F,0x20,
0x5C,0x2F,0x20,0x2F,0x7C,0x20,0x7C,0x20,0x2F,0x20,0x2F,0x5F,0x2F,0x20,0x2F,0x20,
0x2F,0x5F,0x2F,0x20,0x2F,0x20,0x20,0x2F,0x20,0x5F,0x5F,0x20,0x20,0x2F,0x20,0x5F,
0x20,0x5C,0x2F,0x20,0x5F,0x5F,0x20,0x5C,0x2F,0x20,0x5F,0x5F,0x5F,0x2F,0x20,0x5F,
0x5F,0x20,0x5C,0x2F,0x20,0x5F,0x5F,0x20,0x60,0x5F,0x5F,0x20,0x5C,0x2F,0x20,0x5F,
0x5F,0x20,0x60,0x2F,0x20,0x5F,0x5F,0x5F,0x2F,0x20,0x2F,0x2F,0x5F,0x2F,0x0A,0x20,
0x5F,0x5F,0x5F,0x2F,0x20,0x2F,0x20,0x5F,0x5F,0x5F,0x20,0x7C,0x2F,0x20,0x5F,0x5F,
0x5F,0x5F,0x2F,0x20,0x5F,0x5F,0x5F,0x5F,0x2F,0x20,0x20,0x2F,0x20,0x2F,0x5F,0x2F,
0x20,0x2F,0x20,0x20,0x5F,0x5F,0x2F,0x20,0x2F,0x20,0x2F,0x20,0x2F,0x20,0x2F,0x5F,
0x5F,0x2F,0x20,0x2F,0x20,0x2F,0x20,0x2F,0x20,0x2F,0x20,0x2F,0x20,0x2F,0x20,0x2F,
0x20,0x2F,0x20,0x2F,0x5F,0x2F,0x20,0x2F,0x20,0x2F,0x20,0x20,0x2F,0x20,0x2C,0x3C,
0x20,0x20,0x20,0x0A,0x2F,0x5F,0x5F,0x5F,0x5F,0x2F,0x5F,0x2F,0x20,0x20,0x7C,0x5F,
0x2F,0x5F,0x2F,0x20,0x20,0x20,0x2F,0x5F,0x2F,0x20,0x20,0x20,0x20,0x20,0x20,0x2F,
0x5F,0x5F,0x5F,0x5F,0x5F,0x2F,0x5C,0x5F,0x5F,0x5F,0x2F,0x5F,0x2F,0x20,0x2F,0x5F,
0x2F,0x5C,0x5F,0x5F,0x5F,0x2F,0x5F,0x2F,0x20,0x2F,0x5F,0x2F,0x5F,0x2F,0x20,0x2F,
0x5F,0x2F,0x20,0x2F,0x5F,0x2F,0x5C,0x5F,0x5F,0x2C,0x5F,0x2F,0x5F,0x2F,0x20,0x20,
0x2F,0x5F,0x2F,0x7C,0x5F,0x7C,0x20,0x20,0x0A,0x0A,0x0A,0x20,0x20,0x20,0x20,0x20,
0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,
0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,
0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,
0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,
0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x0D,
0x0A,
0x00, //EOF
};


/*
	sed修改某一行后出现的内容, 因配置文件的key在[section]之后, 不一定是第几行, 这里循环多试几次.
*/
static int sapp_bchmk_update_file_by_sed(benchmark_engine_t *bch_engine, const char *filename, const char *lastline, int distance, const char *key, const char *value)
{
	char cmd_buf[1024] = {};
	int i, ret;
	const char *distance_array[10] = {
		"n",
		"n;n",
		"n;n;n",
		"n;n;n;n",
		"n;n;n;n;n",
		"n;n;n;n;n;n",
		"n;n;n;n;n;n;n",
		"n;n;n;n;n;n;n;n",
		"n;n;n;n;n;n;n;n;n",
		"n;n;n;n;n;n;n;n;n;n"
	};

	for(i = 0; i < distance; i++){
		snprintf(cmd_buf, 1024, "sed '/%s/{%s;s/.*%s=.*/%s=%s/;}' -i %s", lastline, distance_array[i], key, key, value, filename);
		ret = system(cmd_buf);
		if(ret != 0){
			sapp_bchmk_log(bch_engine, RLOG_LV_FATAL, "exec system cmd error, \n%s\n %s", cmd_buf);
			return -1;
		}
	}

	return 0;
}

static int __sapp_bchmk_update_MESA_prof_load_pattern_cb(benchmark_engine_t *bch_engine,const cJSON *cjson_file_obj, const cJSON *cjson_file_name, const cJSON *cjson_file_cont)
{
	int ret, i, array_size;
	const cJSON *cjson_file_cont_item;
	const cJSON *cjson_file_cont_section;
	const cJSON *cjson_file_cont_key;
	const cJSON *cjson_file_cont_value;
	char tmp_cfg_value[1024];
	char update_cfg_cmd_buf[1024];

	array_size = cJSON_GetArraySize(cjson_file_cont);
	if(array_size <= 0){
		return -1;
	}	
	
	for(i = 0; i < array_size; i++){
		cjson_file_cont_item = cJSON_GetArrayItem(cjson_file_cont, i);

		cjson_file_cont_section = cJSON_GetObjectItem(cjson_file_cont_item, "section");
		if(NULL == cjson_file_cont_section){
			sapp_bchmk_log(bch_engine, RLOG_LV_FATAL, "not found object 'section' in MESA_prof_load_pattern, index:%d", i);
			return -1;
		}	
		cjson_file_cont_key = cJSON_GetObjectItem(cjson_file_cont_item, "key");
		if(NULL == cjson_file_cont_key){
			sapp_bchmk_log(bch_engine, RLOG_LV_FATAL, "not found object 'key' in MESA_prof_load_pattern, index:%d", i);
			return -1;
		}
		cjson_file_cont_value = cJSON_GetObjectItem(cjson_file_cont_item, "value");
		if(NULL == cjson_file_cont_value){
			sapp_bchmk_log(bch_engine, RLOG_LV_FATAL, "not found object 'value' in MESA_prof_load_pattern, index:%d", i);
			return -1;
		}		

		if(MESA_load_profile_string_nodef(cjson_file_name->valuestring, cjson_file_cont_section->valuestring, cjson_file_cont_key->valuestring, tmp_cfg_value, sizeof(tmp_cfg_value)) < 0){
			/* 没有这个参数, 新增加 */
			snprintf(update_cfg_cmd_buf, sizeof(update_cfg_cmd_buf), "echo [%s] >> %s", cjson_file_cont_section->valuestring, cjson_file_name->valuestring);
			system(update_cfg_cmd_buf);
			snprintf(update_cfg_cmd_buf, sizeof(update_cfg_cmd_buf), "echo %s=%s >> %s", cjson_file_cont_key->valuestring, cjson_file_cont_value->valuestring, cjson_file_name->valuestring);
			system(update_cfg_cmd_buf);

			if(strncasecmp("FUNC_NAME",  cjson_file_cont_key->valuestring, strlen("FUNC_NAME")) == 0){
				/* TODO:此处优化一下, 插件新增一个entry需要两个参数 */
				snprintf(update_cfg_cmd_buf, sizeof(update_cfg_cmd_buf), "echo \"FUNC_FLAG=ALL\" >> %s", cjson_file_name->valuestring);
				system(update_cfg_cmd_buf);
			}
		}else{
			ret = sapp_bchmk_update_file_by_sed(bch_engine, cjson_file_name->valuestring, cjson_file_cont_section->valuestring, 10, 
										  cjson_file_cont_key->valuestring, cjson_file_cont_value->valuestring);
			if(ret < 0){
				sapp_bchmk_log(bch_engine,RLOG_LV_FATAL, "update config file:%s error, set %s->%s=%s fail", cjson_file_name->valuestring,
							cjson_file_cont_section->valuestring, cjson_file_cont_key->valuestring, cjson_file_cont_value->valuestring);
				return -1;
			}else{
				sapp_bchmk_log(bch_engine,RLOG_LV_DEBUG, "update config file:%s succ, set %s->%s = %s ", cjson_file_name->valuestring,
							cjson_file_cont_section->valuestring, cjson_file_cont_key->valuestring, cjson_file_cont_value->valuestring);			
			}
		}
	}

	return 0;
}

static int __sapp_bchmk_update_raw_pattern_cb(benchmark_engine_t *bch_engine,const cJSON *cjson_file_obj, const cJSON *cjson_file_name, const cJSON *cjson_file_cont)
{
	FILE *fp;

	fp = fopen(cjson_file_name->valuestring, "w+");
	if(NULL == fp){
		//sapp_bchmk_log(RLOG_LV_FATAL, "update config file:%s error, %s", cjson_file_name->valuestring, strerror(errno));
		return -1;
	}

	fprintf(fp, "%s", cjson_file_cont->valuestring);

	fclose(fp);

	return 0;
}


static int sapp_bchmk_update_cfg_file(benchmark_engine_t *bch_engine, const char *section, const cJSON *cjson_array, 
			int (*cb_fun)(benchmark_engine_t *bch_engine,const cJSON *cjson_file_obj, const cJSON *filename, const cJSON *filecont))
{
	int ret, i, array_size;
	const cJSON *array_item;
	const cJSON *cjson_file_name;
	const cJSON *cjson_file_cont;

	array_size = cJSON_GetArraySize(cjson_array);
	if(array_size <= 0){
		return -1;
	}

	for(i = 0; i < array_size; i++){
		array_item = cJSON_GetArrayItem(cjson_array, i);	
		cjson_file_name = cJSON_GetObjectItem(array_item, "file_name");
		if(NULL == cjson_file_name){
			sapp_bchmk_log(bch_engine,RLOG_LV_FATAL, "not found object 'file_name' in config_file_template->%s, index:%d", section, i);
			return -1;
		}
		
		cjson_file_cont = cJSON_GetObjectItem(array_item, "file_content");
		if(NULL == cjson_file_cont){
			sapp_bchmk_log(bch_engine,RLOG_LV_FATAL, "not found object 'file_content' in config_file_template->%s, index:%d",section, i);
			return -1;
		}
		
		ret = (*cb_fun)(bch_engine, array_item, cjson_file_name, cjson_file_cont);
		if(ret < 0){
			sapp_bchmk_log(bch_engine,RLOG_LV_FATAL, "update config file %s fail", cjson_file_name->valuestring);
			return -1;
		}else{
			sapp_bchmk_log(bch_engine,RLOG_LV_DEBUG, "update config file %s succ", cjson_file_name->valuestring);
		}
	}

	return 0;
}


static void *sapp_bchmk_timer_thread(void *arg)
{
	benchmark_engine_t *bchmk_engine = (benchmark_engine_t *)arg;

	/* 因为在接收数据包 sapp_bchmk_recv_pkt() 函数中调用了阻塞式函数read
		如果是drop动作, 或者插件错误没有转发或注入数据包, 就阻塞死锁了,
		所以此处不停的向本进程发信号, 以打断read().
	*/
	while(bchmk_engine->running_flag){
		kill(getpid(), SIGUSR1);
		usleep(1000 * 100);
	}

	return NULL;
}

static void __sapp_bchmk_sig_handler(int signo)
{
	printf("recv sig:%d\n", signo);
	return;
}

static void sapp_bchmk_start_time_thread(benchmark_engine_t *bchmk_engine)
{
	//signal(SIGUSR1, __sapp_bchmk_sig_handler);
	//pthread_create(&bchmk_engine->timer_thread_pid, NULL, sapp_bchmk_timer_thread, bchmk_engine);

	return;
}


/* 更新一些跟此次测试密切相关的配置, 将json文件里的参数写入各个配置文件 */
static int sapp_bchmk_template_update(benchmark_engine_t *bch_engine)
{
	const cJSON *cjson_cfg_obj;
	const cJSON *cjson_prof_load_cfg_obj;
	const cJSON *cjson_raw_cfg_obj;
	int ret;
	
	sapp_bchmk_set_default_config();

	cjson_cfg_obj = cJSON_GetObjectItem(bch_engine->benchmark_json_struct, "config_file_template");
	if(NULL == cjson_cfg_obj){
		sapp_bchmk_log(bch_engine, RLOG_LV_INFO, "not found object '%s', do nothing", "config_file_template");
		return 0;
	}

	cjson_prof_load_cfg_obj = cJSON_GetObjectItem(cjson_cfg_obj, "MESA_prof_load_pattern");
	if(NULL == cjson_prof_load_cfg_obj){
		sapp_bchmk_log(bch_engine,RLOG_LV_INFO, "not found object '%s', do nothing", "MESA_prof_load_pattern");
	}else{
		/* 检查一下json类型合法性 */
		if(!cJSON_IsArray(cjson_prof_load_cfg_obj)){
			sapp_bchmk_log(bch_engine,RLOG_LV_FATAL, "config_file_template sub object 'MESA_prof_load_pattern' type error, expect:%s, but actual is:%s",
						"Array", cJSON_type_ntop(cjson_prof_load_cfg_obj));
			return -1;
		}	
		ret = sapp_bchmk_update_cfg_file(bch_engine, "MESA_prof_load_pattern", cjson_prof_load_cfg_obj, __sapp_bchmk_update_MESA_prof_load_pattern_cb);
		if(ret < 0){
			return -1;
		}
	}

	cjson_raw_cfg_obj = cJSON_GetObjectItem(cjson_cfg_obj, "raw_pattern");
	if(NULL == cjson_raw_cfg_obj){
		sapp_bchmk_log(bch_engine,RLOG_LV_INFO, "not found object '%s', do nothing", "raw_pattern");
	}else{
		/* 检查一下json类型合法性 */
		if(!cJSON_IsArray(cjson_prof_load_cfg_obj)){
			sapp_bchmk_log(bch_engine,RLOG_LV_FATAL, "config_file_template sub object 'raw_pattern' type error");
			return -1;
		}		
		ret = sapp_bchmk_update_cfg_file(bch_engine, "raw_pattern",cjson_raw_cfg_obj, __sapp_bchmk_update_raw_pattern_cb);
		if(ret < 0){
			return -1;
		}		
	}

	return 0;
}


static void pcap_copy_to_mem_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	pcap_pkt_image_t *p_mem_image = (pcap_pkt_image_t *)user;
	const struct ethhdr *one_eth_pkt;

	one_eth_pkt = (struct ethhdr *)malloc(hdr->caplen);
	memcpy((void *)one_eth_pkt, data, hdr->caplen);
	
	p_mem_image->pkt_array = (pcap_pkt_detail_t *)realloc(p_mem_image->pkt_array, (p_mem_image->pkt_num+1)*sizeof(pcap_pkt_detail_t));

	p_mem_image->pkt_array[p_mem_image->pkt_num].pkt_data = one_eth_pkt;
	p_mem_image->pkt_array[p_mem_image->pkt_num].pkt_len = hdr->caplen;
	
	p_mem_image->pkt_num++;
}


/*
	将磁盘文件中的pcap, 读取到内层sapp_pt_pcap_file_image_t中.
*/
static pcap_pkt_image_t *get_pkts_from_one_pcap(benchmark_engine_t *bch_engine, const char *pcap_filename)
{
	pcap_t *pcap_handle;
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	pcap_pkt_image_t *pcap_mem_image;

	pcap_handle = pcap_open_offline(pcap_filename, pcap_errbuf);
	if(NULL == pcap_handle){
		sapp_bchmk_log(bch_engine, RLOG_LV_FATAL, "open pcap file '%s' error, %s", pcap_filename, pcap_errbuf);
		return NULL;
	}

	pcap_mem_image = (pcap_pkt_image_t *)calloc(1, sizeof(pcap_pkt_image_t));

	pcap_loop(pcap_handle, -1, pcap_copy_to_mem_cb, (u_char *)pcap_mem_image);

	pcap_close(pcap_handle);

	return pcap_mem_image;
}


static int sapp_bchmk_build_pcap_image(benchmark_engine_t *bch_engine)
{
	pcap_pkt_image_t *local_pkt_image;
	char pcap_root_dir[PATH_MAX];
	char pcap_file_name[PATH_MAX];
	char pcap_absolute_file_name[PATH_MAX];
	char expect_pcap_file_md5sum[PATH_MAX];
	const char *res;
	int opt_len;
	
	opt_len = sizeof(pcap_root_dir);
	res = sapp_bchmk_get_value_from_json(bch_engine->benchmark_json_struct, NULL, "benchmark_pcap_root_dir", pcap_root_dir, &opt_len);
	if(NULL == res){
		/* 没有指定root dir时默认使用当前目录 */
		strncpy(pcap_root_dir, "./", PATH_MAX);
	}
	
	opt_len = sizeof(pcap_file_name);
	res = sapp_bchmk_get_value_from_json(bch_engine->benchmark_json_struct, NULL,"benchmark_pcap_filename", pcap_file_name, &opt_len);
	if(NULL == res){
		sapp_bchmk_log(bch_engine, RLOG_LV_FATAL, "not found json object 'benchmark_pcap_filename'");
		return -1;
	}
	snprintf(pcap_absolute_file_name, PATH_MAX, "%s/%s", pcap_root_dir, pcap_file_name);

	if(sapp_bchmk_get_file_len(pcap_absolute_file_name) == 0){
		sapp_bchmk_log(bch_engine,RLOG_LV_FATAL, "can't open pcap file '%s'", pcap_absolute_file_name);
		return -1;
	}

	opt_len = sizeof(expect_pcap_file_md5sum);
	res = sapp_bchmk_get_value_from_json(bch_engine->benchmark_json_struct, NULL,"benchmark_pcap_md5sum", expect_pcap_file_md5sum, &opt_len);
	if(NULL != res){
		if(sapp_bchmk_md5_checksum(pcap_absolute_file_name, expect_pcap_file_md5sum) < 0){
			sapp_bchmk_log(bch_engine,RLOG_LV_FATAL, 	"pcap file '%s' md5sum is different with 'benchmark_pcap_md5sum':%s",
					pcap_absolute_file_name, expect_pcap_file_md5sum);	
			goto err;
		}
	}
	
	local_pkt_image = get_pkts_from_one_pcap(bch_engine, pcap_absolute_file_name);
	if(NULL == local_pkt_image){
		goto err;
	}
	if(local_pkt_image->pkt_num <= 0){ //空的pcap包
		sapp_bchmk_log(bch_engine,RLOG_LV_FATAL, "no valid packet in '%s'", pcap_absolute_file_name);
		goto err;
	}

	bch_engine->pcap_pkt_image = local_pkt_image;

	sapp_bchmk_log(bch_engine, RLOG_LV_DEBUG, "use pcap file '%s'", pcap_absolute_file_name);

	return 0;

err:
	/* 所有的内存资源都在最后 sapp_bchmk_engine_destroy() 统一释放 */
	return -1;
}

/* 清理临时文件 */
static void sapp_bcnmk_clear_env(void)
{
	remove(SAPP_BCHMK_TEMP_PCAP_FILE);
	remove(SAPP_BCHMK_TSHARK_PLUG_JSON_FILE);
}

/*
	根据配置文件entry.json, 准备sapp的运行环境,
	包括配置文件, 插件.so, pcap文件, 创建各种虚拟网卡, 执行shell命令, 等等....
*/
static int sapp_bchmk_env_prepare(benchmark_engine_t *bch_engine)
{	
	int ret;
	const char *json_mem_cont;

	if(bch_engine->plug_opt.plug_set_opt_flags & SAPP_BCHMK_OPT_JSON_STRING){
		json_mem_cont = bch_engine->plug_opt.json_mem_cont;
	}else if(bch_engine->plug_opt.plug_set_opt_flags & SAPP_BCHMK_OPT_JSON_FILE_NAME){
		json_mem_cont = sapp_benchmark_load_json_from_file(bch_engine->plug_opt.json_file_name);
		if(NULL == json_mem_cont){
			sapp_bchmk_log(bch_engine, RLOG_LV_FATAL, "open file '%s' error, %s", bch_engine->plug_opt.json_file_name, strerror(errno));
			return -1;
		}
		sapp_bchmk_log(bch_engine, RLOG_LV_DEBUG, "use entry json file '%s'", bch_engine->plug_opt.json_file_name);
		bch_engine->plug_opt.json_mem_cont = json_mem_cont;
	}else{
		sapp_bchmk_log(bch_engine, RLOG_LV_FATAL, "must set opt SAPP_BCHMK_OPT_JSON_STRING or SAPP_BCHMK_OPT_JSON_FILE_NAME");
		return -1;
	}
	
	bch_engine->benchmark_json_struct = cJSON_Parse(json_mem_cont) ;
	if(NULL == bch_engine->benchmark_json_struct){
		sapp_bchmk_log(bch_engine,RLOG_LV_FATAL,"benchmark_json parse error!");
		return -1;
	}

	sapp_bcnmk_clear_env();

	//将pcap包的镜像读取到内存中, 用于replay
	ret = sapp_bchmk_build_pcap_image(bch_engine);
	if(ret < 0){
		sapp_bchmk_log(bch_engine,RLOG_LV_FATAL, "read pcap file error!");
		return -1;
	}	

	//每次重启时, 将sapp.toml, sendraw_pkt.conf, gdev.conf等配置文件使用默认参数
	ret = sapp_bchmk_template_update(bch_engine);
	if(ret < 0){
		sapp_bchmk_log(bch_engine,RLOG_LV_FATAL, "update sapp config error!");
		return -1;
	}

	//获取sapp工作模式, 监听网卡 
	ret = sapp_bchmk_create_process_engine(bch_engine); 
	if(ret < 0){
		sapp_bchmk_log(bch_engine,RLOG_LV_FATAL, "sapp_bchmk_create_process_engine() error!");
		return -1;
	}	

	return 0;
}


/*
	根据内层ip确定一个传输方向, 用于双臂串联模式从哪个网卡发出.
*/
static int sapp_bchmk_determine_routedir(const struct ethhdr *eth)
{
	const void *res;
	unsigned int hash = 0;
	const struct ip *ipv4_hdr;
	const struct ip6_hdr *ipv6_hdr;
	int route_dir;

	res = MESA_jump_layer_greedy((const void *)eth, ADDR_TYPE_MAC, __ADDR_TYPE_IP_PAIR_V4);
	if(res){
		ipv4_hdr = (const struct ip *)res;
		route_dir = memcmp(&ipv4_hdr->ip_src.s_addr, &ipv4_hdr->ip_dst.s_addr, sizeof(int));
		goto bingo;
	}

	res = MESA_jump_layer_greedy((const void *)eth, ADDR_TYPE_MAC, __ADDR_TYPE_IP_PAIR_V6);
	if(res){
		ipv6_hdr = (const struct ip6_hdr *)res;
		/* 只使用IPv6地址的一部分 */
		route_dir = memcmp(&ipv6_hdr->ip6_src, &ipv6_hdr->ip6_dst, sizeof(struct in6_addr));
		goto bingo;
	}

	/* 找不到ip头部, 非IPv4, 非IPv6协议, 暂时返回0 */
	return 0;

bingo:

	return route_dir;
}


static void sapp_bchmk_replay_pkt(benchmark_engine_t *bchmk_engine, int pkt_index)
{
	pcap_pkt_image_t *pcap_pkt_image = bchmk_engine->pcap_pkt_image;
	int ret, route_dir, reply_dev_fd;

	if(DEPLOYMENT_MODE_TRANSPARENT == bchmk_engine->process_engine->sapp_deploy_mode){
		route_dir = sapp_bchmk_determine_routedir(pcap_pkt_image->pkt_array[pkt_index].pkt_data);
		if(route_dir >= 0){
			reply_dev_fd = bchmk_engine->process_engine->tap_internal_fd;
		}else{
			reply_dev_fd = bchmk_engine->process_engine->tap_external_fd;
		}
	}else{
		/* inline, mirror模式, 仅有一块网卡, 固定使用internal device */
		reply_dev_fd = bchmk_engine->process_engine->tap_internal_fd;
	}

	bchmk_engine->process_engine->last_replay_fd = reply_dev_fd;
	
	ret = write(reply_dev_fd, pcap_pkt_image->pkt_array[pkt_index].pkt_data, pcap_pkt_image->pkt_array[pkt_index].pkt_len);
	if(ret < 0){
		sapp_bchmk_log(bchmk_engine,RLOG_LV_FATAL, "write pkt to tap device error: %s, index:%d", strerror(errno), pkt_index+1);
		abort();
	}else{
		sapp_bchmk_log(bchmk_engine,RLOG_LV_DEBUG, "write pkt to tap device succ, index:%d", pkt_index+1);
	}
	
	return;
}


static void sapp_bchmk_control_delay(benchmark_engine_t *bchmk_engine, int carray_pkt_index)
{
	int delay_time_ms = 0;
	const cJSON *sub_cjson_delay_root;
	const cJSON *sub_cjson_delay_item;
	const cJSON *sub_cjson_delay_item_pkt_index;
	const cJSON *sub_cjson_delay_item_timems;
	int i, delay_array_size;

	sub_cjson_delay_root = sapp_bchmk_need_process_control(bchmk_engine, carray_pkt_index);
	if(NULL == sub_cjson_delay_root){
		return;
	}

	/* 检查一下json类型合法性 */
	if(!cJSON_IsArray(sub_cjson_delay_root)){
		sapp_bchmk_log(bchmk_engine,RLOG_LV_FATAL, "expect object 'control->delay' type is Array, but actual is:%s", cJSON_type_ntop(sub_cjson_delay_root));
		return;
	}
	
	delay_array_size = cJSON_GetArraySize(sub_cjson_delay_root);

	for(i = 0; i < delay_array_size; i++){
		sub_cjson_delay_item = cJSON_GetArrayItem(sub_cjson_delay_root, i);
		sub_cjson_delay_item_pkt_index = cJSON_GetObjectItem(sub_cjson_delay_item, "pkt_index");
		if(NULL == sub_cjson_delay_item_pkt_index){
			sapp_bchmk_log(bchmk_engine,RLOG_LV_FATAL, "not found object 'pkt_index' in 'control->delay' index:%d", i);
			return;		
		}

		if(sub_cjson_delay_item_pkt_index->valueint != (carray_pkt_index+1)){
			return;
		}
		
		sub_cjson_delay_item_timems = cJSON_GetObjectItem(sub_cjson_delay_item, "delay_before_replay");
		if(NULL == sub_cjson_delay_item_timems){
			sapp_bchmk_log(bchmk_engine,RLOG_LV_FATAL, "not found object 'delay_before_replay' in 'control->delay' index:%d", i);
			return;		
		}

		if(sub_cjson_delay_item_timems->valueint > 0){
			sapp_bchmk_log(bchmk_engine, RLOG_LV_FATAL, "found object 'delay_before_replay' in 'control->delay' index:%d, sleeping %dms ..........", i, sub_cjson_delay_item_timems->valueint);
			usleep(1000 * sub_cjson_delay_item_timems->valueint);
		}
	}

	return;
}

/* 新的tap设备创建后, 有可能会误收到一些广播、组播等包, 如IPv6 router solicitation等包, 
   并不是sapp或插件发出来的, 要丢弃！ 
 */
static int sapp_bchmk_discard_brocast(benchmark_engine_t *bchmk_engine, char *pkt_buf, int buf_len)
{
	static const unsigned char ipv6_multicast_dst_mac[2] = {0x33, 0x33};
	static const unsigned char ipv4_multicast_dst_mac[3] = {0x01, 0x00, 0x5E};
	static const unsigned char brocast_dst_mac[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	const struct ethhdr *ehdr = (struct ethhdr *)pkt_buf;
	int is_multi_broad = 0;

	if(memcmp(ehdr->h_dest, ipv6_multicast_dst_mac, sizeof(ipv6_multicast_dst_mac)) == 0){
		is_multi_broad = 1;
	}else if(memcmp(ehdr->h_dest, ipv4_multicast_dst_mac, sizeof(ipv4_multicast_dst_mac)) == 0){
		is_multi_broad = 1;
	}else if(memcmp(ehdr->h_dest, brocast_dst_mac, sizeof(brocast_dst_mac)) == 0){
		is_multi_broad = 1;
	}

	if(is_multi_broad != 0){
		sapp_bchmk_log(bchmk_engine, RLOG_LV_DEBUG, "discard broadcast or multicast, dst mac: %02x:%02x:%02x:%02x:%02x:%02x",  
					ehdr->h_dest[0],ehdr->h_dest[1],ehdr->h_dest[2],ehdr->h_dest[3],ehdr->h_dest[4],ehdr->h_dest[5]);
		/* 如果是组播或广播, 也不一定是错误, 可能测试用例就故意在测试组播和广播流量的处理,  */
		//todo
	}
	
	return is_multi_broad;
}

static int sapp_bchmk_socket_isready(int fd)
{
   int	  rc;
   fd_set	 fds;
   struct timeval	 tv;
   FD_ZERO(&fds);
   FD_SET(fd,  &fds);
   tv.tv_sec = 0;
   tv.tv_usec = 1000 * 100;

   rc = select(fd+1, &fds, NULL, NULL, &tv);
   if( rc <= 0 ){  //error
	 return -1;
	}
	
   return FD_ISSET(fd, &fds)  ? 1: 0;
}


static int sapp_bchmk_save_output_pkt(benchmark_engine_t *bchmk_engine, char *pkt_buf, int buf_len)
{
	pcap_pkt_detail_t pkt_detail;
	
	if(0 == bchmk_engine->output_pkt.pkt_index){
		sapp_bchmk_gen_pcap_header(bchmk_engine, SAPP_BCHMK_OUTPUT_PCAP_FILE);
		bchmk_engine->output_pkt.pkt_index++;
	}

	pkt_detail.pkt_data = (struct ethhdr *)pkt_buf;
	pkt_detail.pkt_len = buf_len;
	
	sapp_bchmk_append_pcap_pkt(bchmk_engine, &pkt_detail, 1, SAPP_BCHMK_OUTPUT_PCAP_FILE);
	
	return 0;
}

/*
	reverse_dir: 是否需要从另一块网卡收包, 仅trnasparent有效.

	return value:
		> 0: pkt length;
		< 0: error.
*/
static int sapp_bchmk_recv_pkt(benchmark_engine_t *bchmk_engine, char *pkt_buf, int buf_len, int reverse_dir)
{
	int recv_fd;
	int ret;
	time_t first_recv_time;
	char debug_ip_string[256];

	if(DEPLOYMENT_MODE_TRANSPARENT == bchmk_engine->process_engine->sapp_deploy_mode){
		if(reverse_dir){
			/* 双臂模式的反向还是从注入网卡读取 */
			recv_fd = bchmk_engine->process_engine->last_replay_fd;
		}else{
			if(bchmk_engine->process_engine->last_replay_fd == bchmk_engine->process_engine->tap_internal_fd){
				recv_fd = bchmk_engine->process_engine->tap_external_fd;
			}else{
				recv_fd = bchmk_engine->process_engine->tap_internal_fd;
			}
		}
	}else{
		/* mirror和inline只有一块网卡, 收包时不关心reverse_dir */
		recv_fd = bchmk_engine->process_engine->tap_internal_fd;
	}

	first_recv_time = time(NULL);

	while(first_recv_time + SAPP_BCHMK_RECV_WAIT_TIMEOUT >= time(NULL)){
		//ret = recv(recv_fd, pkt_buf, buf_len, MSG_DONTWAIT);
		if(sapp_bchmk_socket_isready(recv_fd) <= 0){
			continue;
		}
		ret = read(recv_fd, pkt_buf, buf_len);
		if(ret > 0){
			if(sapp_bchmk_discard_brocast(bchmk_engine, pkt_buf, buf_len) != 0){
				sapp_bchmk_log(bchmk_engine, RLOG_LV_DEBUG, "get pkt from tap, pkt len=%d, but is broadcast or multicast, discard it!", ret);
				first_recv_time = time(NULL); /* 重置时间 */
				continue;
			}else{
				/* debug日志, 因为网卡是tap模式, 需要跳过ethernet头部 */
				sapp_bchmk_log(bchmk_engine,RLOG_LV_DEBUG, "get pkt from tap, detail:%s", 
						sapp_bchmk_ippkt_ntop((unsigned char *)pkt_buf+sizeof(struct ethhdr), debug_ip_string, sizeof(debug_ip_string)));
				sapp_bchmk_save_output_pkt(bchmk_engine, pkt_buf, buf_len);
				return ret;
			}
		}else if(ret < 0){
			if(EINTR == errno){
				continue;
			}else{
				sapp_bchmk_log(bchmk_engine, RLOG_LV_FATAL, "read socket error, ret=%d, %s", ret, strerror(errno));
				break;
			}
		}else{
			//sapp_bchmk_log(RLOG_LV_FATAL, "read socket error, ret=%d, %s", ret, strerror(errno));
			usleep(10000);
		}
	}
	
	return -1; /* timeout */
}


static sapp_benchmark_result_t sapp_bchmk_check_input_pkt(benchmark_engine_t *bchmk_engine, int pkt_index)
{
	sapp_benchmark_result_t res = SAPP_BCHMK_RES_SUCC;
	
	//if(has input check){
		/* 如果有检查input的参数, 现场调用tshark生成json文件, 与插件输入的json文件比较
			TODO: 写一个插件, 模拟wireshark输出的json日志, 把所有层的地址信息打印出来.
		*/
		//tshark_gen_json(pcap_file_name, json_file_name);
	//}
	
	//res = sapp_bchmk_json_compare(SAPP_BCHMK_TSHARK_STD_JSON_FILE, SAPP_BCHMK_TSHARK_PLUG_JSON_FILE);

	return res;
}

static sapp_benchmark_result_t sapp_bchmk_check_inject_pkt(benchmark_engine_t *bchmk_engine, int carray_pkt_index)
{
	sapp_benchmark_result_t res = SAPP_BCHMK_RES_SUCC;
	int reverse_dir;
	char pkt_buf[SAPP_BCHMK_MTU];
	int ret, pkt_len;
	pcap_pkt_detail_t pkt_detail;
	const cJSON *cjson_inject_root;
	const cJSON *cjson_inject_pkt_detail;
	int i, inject_pkt_detail_array_size;
	cJSON_bool cmp_res;
	const cJSON * cJSON_inject_pkt_dir_reverse;
	const cJSON * cJSON_inject_pkt_tshark_json_filename;
	const cJSON * cJSON_inject_pkt_detail_item;

	cjson_inject_root = sapp_bchmk_need_check_inject_pkt(bchmk_engine, carray_pkt_index);
	if(NULL == cjson_inject_root){
		if(0 == errno){
			return SAPP_BCHMK_RES_SUCC;
		}else{
			return SAPP_BCHMK_RES_ENV_ERROR;
		}
	}

	cjson_inject_pkt_detail = cJSON_GetObjectItem(cjson_inject_root, "packet_detail");
	if(NULL == cjson_inject_pkt_detail){
		sapp_bchmk_log(bchmk_engine, RLOG_LV_FATAL, "not found object 'packet_detail' in inject root object");
		return SAPP_BCHMK_RES_ENV_ERROR;
	}

	/* 检查一下json类型合法性 */
	if(!cJSON_IsArray(cjson_inject_pkt_detail)){
		sapp_bchmk_log(bchmk_engine,RLOG_LV_FATAL, "expect pkt index:%d inject, but get 'pkt_index' object type error", carray_pkt_index+1);
		return SAPP_BCHMK_RES_ENV_ERROR;
	}

	inject_pkt_detail_array_size = cJSON_GetArraySize(cjson_inject_pkt_detail);

	for(i = 0; i < inject_pkt_detail_array_size; i++){
		cJSON_inject_pkt_detail_item = cJSON_GetArrayItem(cjson_inject_pkt_detail, i);

		cJSON_inject_pkt_dir_reverse = cJSON_GetObjectItem(cJSON_inject_pkt_detail_item, "inject_pkt_dir_reverse");
		if(NULL == cJSON_inject_pkt_dir_reverse){
			sapp_bchmk_log(bchmk_engine,RLOG_LV_FATAL, "not found object 'inject_pkt_dir_reverse' in packet_detail index:%d", i);
			return SAPP_BCHMK_RES_ENV_ERROR;		
		}
		reverse_dir = cJSON_inject_pkt_dir_reverse->valueint;

		cJSON_inject_pkt_tshark_json_filename = cJSON_GetObjectItem(cJSON_inject_pkt_detail_item, "packet_detail_json_file");
		if(NULL == cJSON_inject_pkt_tshark_json_filename){
			sapp_bchmk_log(bchmk_engine,RLOG_LV_FATAL, "not found object 'packet_detail_json_file' in packet_detail index:%d", i);
			return SAPP_BCHMK_RES_ENV_ERROR;		
		}
		if(NULL == cJSON_inject_pkt_tshark_json_filename->valuestring){
			sapp_bchmk_log(bchmk_engine,RLOG_LV_FATAL, "object 'packet_detail_json_file' value is NULL, index:%d", i);
			return SAPP_BCHMK_RES_ENV_ERROR;			
		}
	
		pkt_len = sapp_bchmk_recv_pkt(bchmk_engine, pkt_buf, SAPP_BCHMK_MTU, reverse_dir);
		if(pkt_len <= 0){
			sapp_bchmk_log(bchmk_engine,RLOG_LV_FATAL, "expect pkt index:%d inject, but not recv any pkt", carray_pkt_index+1);
			return SAPP_BCHMK_RES_FAIL;
		}		

		/* TODO: 发送的包一定要检查checksum的, 因为有些参数是动态的, 无需也不可能事先在json里指定 */
		/* 用tshark自身的检查工具, 结果存在checksum.status, 2表示succ */
		//check_inject_checksum();

		pkt_detail.pkt_data = (const struct ethhdr *)pkt_buf;
		pkt_detail.pkt_len = pkt_len;
		ret = sapp_bchmk_gen_tshark_json(bchmk_engine, &pkt_detail, 1, SAPP_BCHMK_TSHARK_PLUG_JSON_FILE);
		if(ret < 0){
			return SAPP_BCHMK_RES_ENV_ERROR;
		}

		/*
			check_cur_pkt_json_file是人工精确指定的检查参数, 数量比较少, 不会像标准tshark自动生成的json那么多参数,
			所以要加选项: CJSON_CMP_OPT_IGNORE_OBJECTA_NOT_EXIST
		*/
		
		sapp_bchmk_log(bchmk_engine,RLOG_LV_DEBUG, "starting inject cJSON Compare file_a '%s' and file_b '%s', pkt index:%d", 
						cJSON_inject_pkt_tshark_json_filename->valuestring, SAPP_BCHMK_TSHARK_PLUG_JSON_FILE, carray_pkt_index+1);
		cmp_res = sapp_bchmk_json_file_compare(bchmk_engine, cJSON_inject_pkt_tshark_json_filename->valuestring, SAPP_BCHMK_TSHARK_PLUG_JSON_FILE, 
					(cJSON_Compare_Opt_t)(CJSON_CMP_OPT_IGNORE_OBJECTA_NOT_EXIST|CJSON_CMP_OPT_IGNORE_ARRAYA_NOT_EXIST|CJSON_CMP_OPT_DUP_NAME_OBJECT));
		if(false == cmp_res){
			return SAPP_BCHMK_RES_FAIL;
		}		
	}

	return SAPP_BCHMK_RES_SUCC;
}


static void sapp_bchmk_ignore_pkt(benchmark_engine_t *bchmk_engine)
{
	char pkt_buf[SAPP_BCHMK_MTU];

	while(sapp_bchmk_recv_pkt(bchmk_engine, pkt_buf, SAPP_BCHMK_MTU, 0) > 0);
	return;
}


static sapp_benchmark_result_t sapp_bchmk_check_forward_pkt(benchmark_engine_t *bchmk_engine, int carray_pkt_index)
{
	int ret, pkt_len;
	char pkt_buf[SAPP_BCHMK_MTU];
	const cJSON *forward_option;
	pcap_pkt_detail_t pkt_detail;
	const char *check_cur_pkt_json_file;
	cJSON_bool cmp_res;
	int need_drop_flag = 0;
	int reverse_dir;

	forward_option = cJSON_GetObjectItem(bchmk_engine->benchmark_json_struct, "forward");
	if(NULL == forward_option){
		/* 没有forward检查参数, 但是要把数据包读出来, 避免一直遗留在缓冲区内把其他后续流程干扰 */
		sapp_bchmk_ignore_pkt(bchmk_engine);
		return SAPP_BCHMK_RES_SUCC;
	}

	/*********  先检查DROP策略 ************/
	need_drop_flag = sapp_bchmk_need_drop_cur_pkt(bchmk_engine, carray_pkt_index);

	if(DEPLOYMENT_MODE_TRANSPARENT == bchmk_engine->process_engine->sapp_deploy_mode){
		reverse_dir = 1;
	}else{
		reverse_dir = 0;
	}
	
	pkt_len = sapp_bchmk_recv_pkt(bchmk_engine, pkt_buf, SAPP_BCHMK_MTU, reverse_dir);
	if(pkt_len <= 0){
		/* 收包超时了, 检查是否因为此包要drop而导致没收到 */
		if(need_drop_flag != 0){
			sapp_bchmk_log(bchmk_engine, RLOG_LV_DEBUG, "pkt index:%d expect drop, and just not recv any pkt, succ", carray_pkt_index+1);
			return SAPP_BCHMK_RES_SUCC;
		}

		sapp_bchmk_log(bchmk_engine,RLOG_LV_FATAL, "expect pkt index:%d forwarding, but not recv any pkt", carray_pkt_index+1);
		return SAPP_BCHMK_RES_FAIL;
	}

	/* 如果有drop选项, 但是收到了一个包, 就是个错误 */
	if(need_drop_flag != 0){
		sapp_bchmk_log(bchmk_engine,RLOG_LV_FATAL, "expect pkt index:%d drop, but has recv a pkt", carray_pkt_index+1);
		return SAPP_BCHMK_RES_FAIL;
	}

	/************  再检查Forward策略 ************/
	check_cur_pkt_json_file = sapp_bchmk_need_check_forward_pkt(bchmk_engine, carray_pkt_index);
	if(NULL == check_cur_pkt_json_file){
		if(ENODATA == errno){
			return SAPP_BCHMK_RES_ENV_ERROR;
		}
		return SAPP_BCHMK_RES_SUCC;
	}
	
	pkt_detail.pkt_data = (const struct ethhdr *)pkt_buf;
	pkt_detail.pkt_len = pkt_len;
	ret = sapp_bchmk_gen_tshark_json(bchmk_engine, &pkt_detail, 1, SAPP_BCHMK_TSHARK_PLUG_JSON_FILE);
	if(ret < 0){
		return SAPP_BCHMK_RES_ENV_ERROR;
	}

	/*
		check_cur_pkt_json_file是人工精确指定的检查参数, 数量比较少, 不会像标准tshark自动生成的json那么多参数,
		所以要加选项: CJSON_CMP_OPT_IGNORE_OBJECTA_NOT_EXIST
	*/
	sapp_bchmk_log(bchmk_engine,RLOG_LV_DEBUG, "starting forward cJSON Compare file_a '%s' and file_b '%s', pkt index:%d", 
					check_cur_pkt_json_file, SAPP_BCHMK_TSHARK_PLUG_JSON_FILE, carray_pkt_index+1);
	cmp_res = sapp_bchmk_json_file_compare(bchmk_engine, check_cur_pkt_json_file, SAPP_BCHMK_TSHARK_PLUG_JSON_FILE, 
			(cJSON_Compare_Opt_t)(CJSON_CMP_OPT_IGNORE_OBJECTA_NOT_EXIST|CJSON_CMP_OPT_IGNORE_ARRAYA_NOT_EXIST|CJSON_CMP_OPT_DUP_NAME_OBJECT));
	if(false == cmp_res){
		return SAPP_BCHMK_RES_FAIL;
	}

	return SAPP_BCHMK_RES_SUCC;
}


/*
	为了方便生成自定义json, 输入一段二进制数据, 输出与tshark -T json格式一样的payload 十六进制格式, 
	例如:
	    "tcp.payload": "00:00:01:80:5e:a5:65:b7:72:67:d7:5d:0a:af:ce:a8:92:53:3b:2e:b8:dc:c1"
*/
const char *sapp_benchmark_payload_to_hex(const void *data, int data_len)
{
	return NULL;
}

int sapp_benchmark_set_plug_result(sapp_benchmark_result_t res)
{
	benchmark_engine_t *bchmk_engine = __g_recv_plug_result_handle;
	
	if(0 == bchmk_engine->running_flag){
		return -1;
	}

	bchmk_engine->plug_opt.plug_process_result = res;

	return 0;
}


int sapp_benchmark_set_opt(sapp_benchmark_handle h, sapp_bchmk_opt_t opt, void *value, int value_len)
{
	benchmark_engine_t *bchmk_engine = (benchmark_engine_t *)h;
	plug_opt_t *plug_opt = &bchmk_engine->plug_opt;

	if(NULL == h || NULL == value){
		return -1;
	}

	switch(opt){
		case SAPP_BCHMK_OPT_JSON_FILE_NAME:
			plug_opt->json_file_name = sapp_bchmk_strdup((char *)value);
		break;

		case SAPP_BCHMK_OPT_JSON_STRING:
			plug_opt->json_mem_cont = sapp_bchmk_strdup((char *)value);
		break;

		case SAPP_BCHMK_OPT_DEFAULT_RESULT:
			plug_opt->no_plug_defalut_result = *((sapp_benchmark_result_t *)value);
		break;

		case SAPP_BCHMK_OPT_LOG_HANDLE:
			plug_opt->MESA_log_handle = value;
		break;	

		default:
			sapp_bchmk_log(h, RLOG_LV_FATAL, "not support option type:%x", (long)opt);
			return -1;
	}

	plug_opt->plug_set_opt_flags |= (long)opt;

	return 0;
}

void sapp_benchmark_destroy(sapp_benchmark_handle h)
{
	int i;
	benchmark_engine_t *bchmk_engine = (benchmark_engine_t *)h;
	
	bchmk_engine->running_flag = 0;
	__g_recv_plug_result_handle = NULL;

	libsapp_destroy_env();
	
	if(bchmk_engine->benchmark_json_struct){
		cJSON_Delete(bchmk_engine->benchmark_json_struct);
		bchmk_engine->benchmark_json_struct = NULL;
	}
	
	if(bchmk_engine->process_engine){
		if(bchmk_engine->process_engine->tap_internal_fd > 0){
			close(bchmk_engine->process_engine->tap_internal_fd);
		}
		if(bchmk_engine->process_engine->tap_external_fd > 0){
			close(bchmk_engine->process_engine->tap_external_fd);
		}		
		free(bchmk_engine->process_engine);
		bchmk_engine->process_engine = NULL;
	}

	if(bchmk_engine->pcap_pkt_image){
		if(bchmk_engine->pcap_pkt_image->pkt_array){
			for(i = 0; i < bchmk_engine->pcap_pkt_image->pkt_num; i++){
				free((void *)bchmk_engine->pcap_pkt_image->pkt_array[i].pkt_data);
			}

			free(bchmk_engine->pcap_pkt_image->pkt_array);
			bchmk_engine->pcap_pkt_image->pkt_array  = NULL;
		}
		free(bchmk_engine->pcap_pkt_image);
		bchmk_engine->pcap_pkt_image = NULL;		
	}

	if(bchmk_engine->timer_thread_pid){
		pthread_join(bchmk_engine->timer_thread_pid, NULL);
		bchmk_engine->timer_thread_pid = 0;
	}

	if(bchmk_engine->plug_opt.json_file_name){
		free((void *)bchmk_engine->plug_opt.json_file_name);
	}
	if(bchmk_engine->plug_opt.json_mem_cont){
		free((void *)bchmk_engine->plug_opt.json_mem_cont);
	}	


	memset(bchmk_engine, 0, sizeof(benchmark_engine_t));
	free((void *)bchmk_engine);
}

static sapp_benchmark_result_t sapp_bchmk_run_custom_cmd(benchmark_engine_t *bch_engine, const char *object_name)
{	
	const cJSON *start_pre_cmd_json_root, *pre_cmd_json;
	int i,cmd_number, ret;

	start_pre_cmd_json_root = cJSON_GetObjectItem(bch_engine->benchmark_json_struct, SAPP_START_PRE_CMD_NAME);
	if(NULL == start_pre_cmd_json_root){
		/* 没有指定shell命令 */
		return SAPP_BCHMK_RES_SUCC;
	}

	cmd_number = cJSON_GetArraySize(start_pre_cmd_json_root);
	if(cmd_number <= 0){
		return SAPP_BCHMK_RES_SUCC;
	}

	for(i = 0; i < cmd_number; i++){
		pre_cmd_json = cJSON_GetArrayItem(start_pre_cmd_json_root, i);
		ret = system(pre_cmd_json->valuestring);
		if(ret < 0){
			sapp_bchmk_log(bch_engine, RLOG_LV_FATAL, "exec %s cmd:'%s' error!", object_name, pre_cmd_json->valuestring);
			return SAPP_BCHMK_RES_ENV_ERROR;
		}else{
			sapp_bchmk_log(bch_engine, RLOG_LV_DEBUG, "exec %s cmd:'%s' success", object_name, pre_cmd_json->valuestring);
		}	
	}

	return SAPP_BCHMK_RES_SUCC;
}

sapp_benchmark_result_t sapp_benchmark_run(sapp_benchmark_handle h)
{
	benchmark_engine_t *bchmk_engine = (benchmark_engine_t *)h;
	sapp_benchmark_result_t chk_res = SAPP_BCHMK_RES_SUCC;
	int i, ret;
	pcap_pkt_image_t *pcap_pkt_image;

	sapp_bchmk_log(bchmk_engine,RLOG_LV_FATAL, "\n%s", g_sapp_bchmk_art_ascii);
	printf("\n%s", g_sapp_bchmk_art_ascii);

	if(sapp_bchmk_env_prepare(bchmk_engine) < 0){
		return SAPP_BCHMK_RES_ENV_ERROR;
	}	

	chk_res = sapp_bchmk_run_custom_cmd(bchmk_engine, SAPP_START_PRE_CMD_NAME);
	if(chk_res != SAPP_BCHMK_RES_SUCC){
		return SAPP_BCHMK_RES_ENV_ERROR;
	}
	
	char *sapp_start_args[] = {(char *)"./sapp", (char *)NULL};
	ret = libsapp_setup_env(1, sapp_start_args);
	if(ret < 0){
		sapp_bchmk_log(bchmk_engine, RLOG_LV_FATAL, "call libsapp_setup_env() fail");
		return SAPP_BCHMK_RES_ENV_ERROR;
	}
	
	bchmk_engine->running_flag = 1;
	__g_recv_plug_result_handle = bchmk_engine;
	pcap_pkt_image = bchmk_engine->pcap_pkt_image;

	/* 注意: 为了方便和wireshark对比, pkt index从1开始计算, 此处数组从0开始 */
	for(i = 0; i < pcap_pkt_image->pkt_num; i++){
		sapp_bchmk_control_delay(bchmk_engine, i); 
		
		sapp_bchmk_replay_pkt(bchmk_engine, i); 
	
		chk_res = sapp_bchmk_check_input_pkt(bchmk_engine, i);
		if(SAPP_BCHMK_RES_SUCC != chk_res){
			break;
		}
		/* inject策略检查要放在forward之前, 因为插件肯定是先注入数据包再决定是否转发当前包 */
		chk_res = sapp_bchmk_check_inject_pkt(bchmk_engine, i);
		if(SAPP_BCHMK_RES_SUCC != chk_res){
			break;
		}	
	
		chk_res = sapp_bchmk_check_forward_pkt(bchmk_engine, i);
		if(SAPP_BCHMK_RES_SUCC != chk_res){
			break;
		}
	}

	/* 先判断json处理结果 */
	if(SAPP_BCHMK_RES_SUCC != chk_res){
		return chk_res;
	}

	/* 再判断插件处理结果 */
	if((int)bchmk_engine->plug_opt.plug_process_result == 0){
		return bchmk_engine->plug_opt.no_plug_defalut_result;
	}

	/* 执行stop post命令 */\
	chk_res = sapp_bchmk_run_custom_cmd(bchmk_engine, SAPP_STOP_PORT_CMD_NAME);
	if(chk_res != SAPP_BCHMK_RES_SUCC){
		return SAPP_BCHMK_RES_ENV_ERROR;
	}

	return SAPP_BCHMK_RES_SUCC;
}

sapp_benchmark_handle sapp_benchmark_create(void)
{
	benchmark_engine_t *bch_engine;
	
	bch_engine = (benchmark_engine_t *)calloc(1, sizeof(benchmark_engine_t));

	/* set default value */
	bch_engine->plug_opt.no_plug_defalut_result = SAPP_BCHMK_RES_SUCC;
	
	return (void *)bch_engine;
}

#ifdef __cplusplus
}
#endif

