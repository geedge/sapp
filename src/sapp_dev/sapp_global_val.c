#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"
#include "sapp_declaration.h"

sapp_global_t *sapp_global_val;

struct sapp_global_single_t sapp_global_single;
struct sapp_global_mthread_t sapp_global_mthread[MAX_THREAD_NUM];

//extern int g_packet_io_thread_num;
extern int tcpstate_num[MAX_TCP_STATE];
extern int udpstate_num[MAX_UDP_STATE];
extern char g_cmd_args_main_cfg_file[PATH_MAX];
extern int g_sapp_global_mem_used_block;
extern int g_sapp_global_mem_used_bytes;

/* ����ʱ��ʹ��ȫ�ֱ���, �Ժ�̬��ȡ�����ļ�,
   overlay�㶨��, ����vxlan�Ļ�����, overlay�����Ĳ�, eth[0], ipv4[1], udp[2], vxlan[3], ��Щ�㲻��ԭʼ������, ��Ϊ�˱��ڷ�����������Ĳ�, ���ܵ��ò��, 
   ��ʵ�ʻ�ע������ʱҲҪЯ��,

   TODO, ��vxlan��������ô��?  
   ��gdev_keepaliveģ���Ƶ�sapp�ڲ�, ����Ϊ���.so����, ʹ��sapp.toml���ؿ��ƶ����ǿ�plug conflist����.

   TODO: �ƶ���ȫ�ֱ���sapp_global_val��.
*/
int g_overlay_layer_set[__ADDR_TYPE_MAX][SAPP_SUPPORT_LAYER_NUM_MAX];    

/* 
   ע����޼��㶨��, ������ʱ�����˲�, 
   mirrorģʽ��, ������ע��㲻һ��ʱ, ��rst��Ҫ����vlan, mpls, gtp�Ȳ�, 
   ��Ϊ����overlay, overlay��ʽ�϶���Ԥ�ȹ涨�õ�, ����ʵ������һ����Ԥ��ָ��ĳ��Э�����Ĳ�, 
   ����֧��ģ������, ��*��ʾ, ��vlan[*], gtp[*]��, ��ʾ����ʱ�����˲�϶�����, ��������һ��,
   �����ip-in-ip, ip-gre-ip, 4over6, 6over4��������, ���������ipֱ��ע���ڲ�ip����Ԫ��, �Ƿǳ�Σ�յ�, 
   ��Ϊ������д��ip[*], Ҳ����д��ip[1], ip[2]����, ��Ѳ��������Ĵ�ip/tcp������, 

   �������ó�һ����ַ������, ����ͬʱ����ָ���������в�, ������.
*/

/*
	����ʱ����ͬʱ����һ��������prune��������, ˳���Ǵ�internal��external, 
	����֧��N����������,   mirrorģʽ��, ��ײ��ethernetд��д������, 

	����������Ŀgtpԭʼ������Ϊ:     ethernet/ipv4/udp/gtp/ipv4/tcp/http, ����gtp������: "gtp[3],udp[2],ip[1]", 

	����ĳGRE����ԭʼ������Ϊ: ethernet/ipv4/gre/ipv4/udp/dns,   �������������������: "gre[2],ip[1]", 
	TODO: �ƶ���ȫ�ֱ���sapp_global_val��.
*/

embed_layer_t g_prune_inject_layer_set[SAPP_PRUNE_LAYER_NUM_MAX];


/*
	������Щ���ǷǶԳƴ��ڲ�, ��C2S��S2C�����п���û����һ��,���´�����compare_addrʱ���಻�Գ�, ��Ҫ����һ���ղ�, ��ע���ʱ����ע��, ��Ҫ����. 
	TODO: �ƶ���ȫ�ֱ���sapp_global_val��.
*/
asymmetric_presence_layer_t g_asymmetric_presence_layer_set[__ADDR_TYPE_MAX];    


/*
	��g_asymmetric_presence_layer_set���岻ͬ, ������Щ���ǲ���һ����˫���ַ��һ�µĲ�, 
	��C2S��S2C����Ĳ�����Ȼ��һ����,��˫��ĵ�ַ��һ��, ��������gtp, gre, mpls��, ethernet, vlanҲ�п���.
	�������ע�����ݰ�, ������˫����, 
	��Ҫ���¶Բ���Ϣ, ע���ʱ����ע��. 
	����ǵ�����, �ҿ�����������, ����ע�����ʧ�ܵ�!!
	TODO: �ƶ���ȫ�ֱ���sapp_global_val��.
*/
embed_layer_t g_asymmetric_addr_layer_set; 


/* 
    ����ָ����ЩЭ�����Ϊ��ַ����, ����Ψһȷ��һ����, ���粻ͬ�����ڶ�ʹ��˽�е�ַʱ, ���п��ܳ�ͻ��, Ӧ�ðѵײ�vlan,mpls�Ȳ�Ҳ��Ϊ��ַ�Ƚϲ���,
    TODO: �ƶ���ȫ�ֱ���sapp_global_val��.
*/
embed_layer_t g_stream_compare_layer_set; 


extern char *MESA_MD5_sum_str(unsigned char *raw_data, unsigned int raw_data_len, char result[33]);

static off_t _check_hdr_get_file_length(const char *file_name)
{
	struct stat file_stat;
	
	if(stat(file_name, &file_stat) == 0)
	{
		return file_stat.st_size;
	}
	return 0;
}

static void sapp_include_header_check_file(const char *file_name, const char *std_md5_sum_str)
{
	char file_md5_sum_str[33];
	FILE *fp;
	char *tmp_file_buf;
	off_t file_len;

	fp = fopen(file_name, "r");
	if(NULL == fp){
		return;
	}

	file_len = _check_hdr_get_file_length(file_name);
	tmp_file_buf = (char *)malloc(file_len);

	fread(tmp_file_buf, file_len, 1, fp);

	MESA_MD5_sum_str((unsigned char *)tmp_file_buf, file_len, file_md5_sum_str);

	if(memcmp(file_md5_sum_str, std_md5_sum_str, 32) != 0){
		printf("\033[33m[Warning]stream_inc header file %s is disaccord with current sapp!\033[0m\n", file_name);
		usleep(200 * 1000);
	}

	fclose(fp);
	free(tmp_file_buf);

	return;
}

/* ��⵱ǰ���л����µ�.h����뻷���Ƿ�һ�� */
void sapp_include_header_check(void)
{
	const char *hdr_dir;
	char tmp_file_path[1024];
	
	hdr_dir = "/opt/MESA/include/MESA/stream_inc";
	
	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_base.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_BASE_MD5_CHECK);

	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_control.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_CONTROL_MD5_CHECK);
	
	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_entry.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_ENTRY_MD5_CHECK);

	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_inject.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_INJECT_MD5_CHECK);

	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_project.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_PROJECT_MD5_CHECK);

	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_proxy.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_PROXY_MD5_CHECK);

	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_rawpkt.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_RAWPKT_MD5_CHECK);

	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_tunnel.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_TUNNEL_MD5_CHECK);

	hdr_dir = "/usr/include/MESA/stream_inc";
	
	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_base.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_BASE_MD5_CHECK);

	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_control.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_CONTROL_MD5_CHECK);
	
	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_entry.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_ENTRY_MD5_CHECK);

	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_inject.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_INJECT_MD5_CHECK);

	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_project.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_PROJECT_MD5_CHECK);

	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_proxy.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_PROXY_MD5_CHECK);

	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_rawpkt.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_RAWPKT_MD5_CHECK);

	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_tunnel.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_TUNNEL_MD5_CHECK);
}

static inline int mem_alignment_pad(int size)
{
	return 64 - (size % 64);
}

void sapp_global_val_sanity_check(void)
{
	/* ���߳�ȫ�ֱ���size������64�ֽ�������, ������cache�����ͻ, ����Ӱ������ */
	if((sizeof(struct sapp_global_mthread_t) % 64) != 0){
		printf("\033[1;31;40msizeof(struct sapp_global_mthread_t)=%zu, is not multiple of 64B!\033[0m\n", sizeof(struct sapp_global_mthread_t));
		printf("\033[1;31;40mYou must add %d bytes padding to sapp_global_mthread_t!\033[0m\n", mem_alignment_pad(sizeof(struct sapp_global_mthread_t)));
		abort();
	}

	if((sizeof(sapp_gval_mthread_t) % 64) != 0){
		printf("\033[1;31;40msizeof(sapp_gval_mthread_t)=%zu, is not multiple of 64B!\033[0m\n", sizeof(sapp_gval_mthread_t));
		printf("\033[1;31;40mYou must add %d bytes padding to sapp_gval_mthread_t!\033[0m\n", mem_alignment_pad(sizeof(sapp_gval_mthread_t)));
		abort();
	}

	if((sizeof(sapp_gval_individual_volatile_t) % 64) != 0){
		printf("\033[1;31;40msizeof(sapp_gval_individual_volatile_t)=%zu, is not multiple of 64B!\033[0m\n", sizeof(sapp_gval_individual_volatile_t));
		printf("\033[1;31;40mYou must add %d bytes padding to sapp_gval_individual_volatile_t!\033[0m\n", mem_alignment_pad(sizeof(sapp_gval_individual_volatile_t)));
		abort();
	}
	
	if((sizeof(layer_args_t) % 64) != 0){
		printf("\033[1;31;40msizeof(struct layer_args_t)=%zu, is not multiple of 64B!\033[0m\n", sizeof(layer_args_t));
		abort();
	}

	sapp_include_header_check();
	if(INDEPENDENT_SEND_QUEUE_MAX_NUM > MAX_THREAD_NUM){
		printf("\033[1;31;40m INDEPENDENT_SEND_QUEUE_MAX_NUM(%d) > MAX_THREAD_NUM(%d)!\033[0m\n", INDEPENDENT_SEND_QUEUE_MAX_NUM, MAX_THREAD_NUM);
		abort();
	}

}

extern int tomlc99_wrap_load_int_def(const char *file,const char *section, char *key,int *val,int dval);
void sapp_gval_init(void)
{
	int tseq;

	/* �ڴ�ͳ�Ƶ������������Ǵ洢��ȫ�ֱ�����, �������м��������е�������, �˴�ֱ����ϵͳ��calloc, �������� */
	sapp_global_val = (sapp_global_t *)calloc(1, sizeof(sapp_global_t));
	g_sapp_global_mem_used_block++;
	g_sapp_global_mem_used_bytes += sizeof(sapp_global_t);
	
	sapp_global_val->individual_volatile = (sapp_gval_individual_volatile_t *)calloc(1, sizeof(sapp_gval_individual_volatile_t));
	g_sapp_global_mem_used_block++;
	g_sapp_global_mem_used_bytes += sizeof(sapp_gval_individual_volatile_t);
	
	for(tseq = 0; tseq < SAPP_MAX_THREADS; tseq++){
		sapp_global_val->mthread_volatile[tseq] = (sapp_gval_mthread_t *)calloc(1, sizeof(sapp_gval_mthread_t));
		sapp_global_val->individual_fixed.cpu_bind_core_id_per_thread[tseq] = -1; /* ��ʼ������Ϊ-1, ��ʾû�󶨵��κ�һ��cpu core */
		g_sapp_global_mem_used_block++;
		g_sapp_global_mem_used_bytes += sizeof(sapp_gval_mthread_t);
	}

	/* set default value, maybe not input by user or config file */
	snprintf(sapp_global_val->config.packet_io.pcap_dumpfile_name, NAME_MAX, "dumpfile");

	ABBR_CURRENT_TIME = time(NULL);
}

void sapp_gval_destroy(void)
{
	int tseq;

	if(sapp_global_val->cla.cmd_args_array){
		int i, args_num = sapp_global_val->cla.cmd_args_num;
		sapp_cmd_args_val_t *free_opt;

		for(i = 0; i < args_num; i++){
			free_opt = sapp_global_val->cla.cmd_args_array[i];
			SAPP_GLOBAL_FREE(free_opt->long_opt_name);
			SAPP_GLOBAL_FREE(free_opt->arg_val.string_value);
			SAPP_GLOBAL_FREE(free_opt);
		}
		
		SAPP_GLOBAL_FREE(sapp_global_val->cla.cmd_args_array);//�˴�ʹ����realloc׷��, Ҫ��sapp_mem_free()
		if (sapp_global_val->cla.dumpfie_list_array)
		{
			int num = 0;
			while (sapp_global_val->cla.dumpfie_list_array[num])
			{
				SAPP_GLOBAL_FREE(sapp_global_val->cla.dumpfie_list_array[num]);
				sapp_global_val->cla.dumpfie_list_array[num]=NULL;
				num++;
			}
			SAPP_GLOBAL_FREE(sapp_global_val->cla.dumpfie_list_array);
			sapp_global_val->cla.dumpfie_list_array=NULL;
		}
	}

	SAPP_GLOBAL_FREE(sapp_global_val->config.stream.tcp.well_known_ports_array);
	SAPP_GLOBAL_FREE(sapp_global_val->config.stream.udp.well_known_ports_array);

	sapp_config_file_link_t *pconfig = &sapp_global_val->config.cfg_file_path;
	SAPP_GLOBAL_FREE(pconfig->cfg_files_root_dir);
	SAPP_GLOBAL_FREE(pconfig->cfg_main_entry_relative);
	SAPP_GLOBAL_FREE(pconfig->cfg_main_entry_absolute);
	SAPP_GLOBAL_FREE(pconfig->cfg_sapp_log_relative);
	SAPP_GLOBAL_FREE(pconfig->cfg_sapp_log_absolute);
	SAPP_GLOBAL_FREE(pconfig->cfg_plug_list_relative);
	SAPP_GLOBAL_FREE(pconfig->cfg_plug_list_absolute);
	SAPP_GLOBAL_FREE(pconfig->cfg_project_list_relative);
	SAPP_GLOBAL_FREE(pconfig->cfg_project_list_absolute);
	SAPP_GLOBAL_FREE(pconfig->cfg_entry_list_relative);
	SAPP_GLOBAL_FREE(pconfig->cfg_entry_list_absolute);	
	SAPP_GLOBAL_FREE(pconfig->cfg_file_send_raw_pkt_relative);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_send_raw_pkt_absolute);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_vxlan_sport_map_relative);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_vxlan_sport_map_absolute);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_inline_dev_relative);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_inline_dev_absolute);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_necessary_plug_relative);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_necessary_plug_absolute);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_stream_compare_layer_relative);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_stream_compare_layer_absolute);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_vlan_flipping_relative);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_vlan_flipping_absolute);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_asymmetric_addr_layer_relative);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_asymmetric_addr_layer_absolute);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_well_known_port_relative);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_well_known_port_absolute);

	sapp_data_file_link_t *pdata = &sapp_global_val->config.data_file_path;
	SAPP_GLOBAL_FREE(pdata->data_files_root_dir);
	SAPP_GLOBAL_FREE(pdata->data_sapp_sysinfo_log_relative);
	SAPP_GLOBAL_FREE(pdata->data_sapp_sysinfo_log_absolute);
	SAPP_GLOBAL_FREE(pdata->data_sapp_fs2_log_relative);
	SAPP_GLOBAL_FREE(pdata->data_sapp_fs2_log_absolute);
	SAPP_GLOBAL_FREE(pdata->data_sapp_fs3_log_relative);
	SAPP_GLOBAL_FREE(pdata->data_sapp_fs3_log_absolute);
	SAPP_GLOBAL_FREE(pdata->data_sapp_fs4_log_relative);
	SAPP_GLOBAL_FREE(pdata->data_sapp_fs4_log_absolute);
	SAPP_GLOBAL_FREE(pdata->data_sapp_fs2_process_latency_absolute);
	SAPP_GLOBAL_FREE(pdata->data_sapp_fs2_process_latency_relative);
	SAPP_GLOBAL_FREE(pdata->data_inline_keepalive_log_relative);
	SAPP_GLOBAL_FREE(pdata->data_inline_keepalive_log_absolute);
	SAPP_GLOBAL_FREE(pdata->data_load_plugin_stat_log_relative);
	SAPP_GLOBAL_FREE(pdata->data_load_plugin_stat_log_absolute);
	SAPP_GLOBAL_FREE(pdata->data_under_ddos_stat_log_relative);
	SAPP_GLOBAL_FREE(pdata->data_under_ddos_stat_log_absolute);
	SAPP_GLOBAL_FREE(pdata->data_memory_stat_log_relative);
	SAPP_GLOBAL_FREE(pdata->data_memory_stat_log_absolute);

	SAPP_GLOBAL_FREE(sapp_global_val->config.packet_io.input_bpf_filter);

	SAPP_GLOBAL_FREE(sapp_global_val->config.library_file_path.libmarsio_file_path);
	SAPP_GLOBAL_FREE(sapp_global_val->config.tools.pkt_dump.bpf_filter);
	SAPP_GLOBAL_FREE(sapp_global_val->config.tools.pkt_dump.storge_path);

	/* individual_volatile, sapp_global_val���free */
	if(sapp_global_val->individual_volatile){
		free(sapp_global_val->individual_volatile); /* ��ʼ��ʱ��calloc, �˴�ֻ����free */
		g_sapp_global_mem_used_block--;
		g_sapp_global_mem_used_bytes -= sizeof(sapp_gval_individual_volatile_t);
	}

	for(tseq = 0; tseq < SAPP_MAX_THREADS; tseq++){
		free(sapp_global_val->mthread_volatile[tseq]); /* ��ʼ��ʱ��calloc, �˴�ֻ����free */
		g_sapp_global_mem_used_block--;
		g_sapp_global_mem_used_bytes -= sizeof(sapp_gval_mthread_t);
	}	

	memset((void *)sapp_global_val, 0xFE, sizeof(sapp_global_t));
	free(sapp_global_val);
	sapp_global_val = NULL;
}


#ifdef __cplusplus
}
#endif

